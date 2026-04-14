'use strict';

const { DEFAULTS } = require('./constants');
const { normaliseLogger } = require('./logger');

/**
 * Consumes messages from Redis Streams via XREAD (single reader) or
 * XREADGROUP (consumer group).
 *
 * Parses each entry into: { content, correlationId, meta, redelivered, _transport, ack() }
 *
 * For per-instance streams (SINGLE mode), automatically refreshes an EXPIRE on the
 * stream key so Redis auto-deletes it if the consumer dies (autoDelete equivalent).
 *
 * @example
 *   const consumer = new StreamConsumer(redisClient, { logger });
 *   consumer.subscribe('stream:reply-abc', handler, { ttlSeconds: 300 });
 *   consumer.subscribe('stream:broadcast', handler, { group: 'cg:app', consumer: 'pod-1' });
 *   await consumer.stop();
 */
class StreamConsumer {
  /**
   * @param {import('redis').RedisClientType} redisClient
   * @param {object} [opts]
   * @param {Logger} [opts.logger]
   */
  constructor(redisClient, opts = {}) {
    this._client = redisClient;
    this._log = normaliseLogger(opts.logger);
    this._running = false;
    this._pelTimers = [];
  }

  /**
   * Start consuming from a stream. Non-blocking — spawns an async loop.
   *
   * @param {string}   streamName
   * @param {function} handler
   * @param {object}   [options]
   * @param {string}   [options.group]      - consumer group (XREADGROUP mode)
   * @param {string}   [options.consumer]   - consumer name within the group
   * @param {number}   [options.blockMs]    - BLOCK timeout (default 5000)
   * @param {number}   [options.count]      - max entries per read (default 100)
   * @param {number}   [options.ttlSeconds] - EXPIRE TTL for autoDelete (SINGLE mode)
   */
  subscribe(streamName, handler, options = {}) {
    this._running = true;

    if (options.group && options.consumer) {
      this._pollGroup(streamName, handler, options);
      this._startPELReclaimer(streamName, handler, options.group, options.consumer);
    } else {
      this._pollRead(streamName, handler, options);
    }
  }

  /** Stop all polling loops and PEL reclaimers. */
  async stop() {
    this._running = false;
    for (const timer of this._pelTimers) clearInterval(timer);
    this._pelTimers = [];
  }

  // ── XREAD (per-instance, single reader) ─────────────────────────────

  async _pollRead(streamName, handler, options) {
    const blockMs = options.blockMs ?? DEFAULTS.BLOCK_MS;
    const count = options.count ?? DEFAULTS.COUNT;
    const ttlSeconds = options.ttlSeconds ?? DEFAULTS.STREAM_TTL_SECONDS;
    let lastId = '$';
    let lastTtlRefresh = 0;

    while (this._running) {
      // autoDelete: refresh EXPIRE while alive
      const now = Date.now();
      if (now - lastTtlRefresh >= DEFAULTS.TTL_REFRESH_INTERVAL_MS) {
        await this._client.expire(streamName, ttlSeconds).catch(() => {});
        lastTtlRefresh = now;
      }

      try {
        const response = await this._client.xRead(
          [{ key: streamName, id: lastId }],
          { BLOCK: blockMs, COUNT: count },
        );
        if (!response) continue;

        for (const stream of response) {
          for (const entry of stream.messages) {
            lastId = entry.id;
            await this._dispatch(entry, streamName, null, false, handler);
          }
        }
      } catch (err) {
        if (!this._running) break;
        this._log.error('StreamConsumer: XREAD error', { stream: streamName, error: err.message });
        await _sleep(1000);
      }
    }
  }

  // ── XREADGROUP (shared, consumer group) ─────────────────────────────

  async _pollGroup(streamName, handler, options) {
    const { group, consumer } = options;
    const blockMs = options.blockMs ?? DEFAULTS.BLOCK_MS;
    const count = options.count ?? DEFAULTS.COUNT;

    while (this._running) {
      try {
        const response = await this._client.xReadGroup(
          group, consumer,
          [{ key: streamName, id: '>' }],
          { BLOCK: blockMs, COUNT: count },
        );
        if (!response) continue;

        for (const stream of response) {
          for (const entry of stream.messages) {
            await this._dispatch(entry, streamName, group, false, handler);
          }
        }
      } catch (err) {
        if (!this._running) break;
        this._log.error('StreamConsumer: XREADGROUP error', { stream: streamName, group, consumer, error: err.message });
        await _sleep(1000);
      }
    }
  }

  // ── PEL reclaimer ───────────────────────────────────────────────────

  _startPELReclaimer(streamName, handler, group, consumer) {
    const timer = setInterval(async () => {
      if (!this._running) return;
      try {
        const result = await this._client.xAutoClaim(
          streamName, group, consumer,
          DEFAULTS.PEL_MIN_IDLE_MS, '0-0',
          { COUNT: DEFAULTS.PEL_COUNT },
        );
        for (const entry of (result.messages || [])) {
          if (!entry) continue;
          await this._dispatch(entry, streamName, group, true, handler);
        }
      } catch (err) {
        if (!err.message?.includes('NOGROUP')) {
          this._log.error('StreamConsumer: XAUTOCLAIM error', { stream: streamName, group, error: err.message });
        }
      }
    }, DEFAULTS.PEL_INTERVAL_MS);
    this._pelTimers.push(timer);
  }

  // ── Dispatch ────────────────────────────────────────────────────────

  async _dispatch(entry, streamName, group, redelivered, handler) {
    const msg = this._parseEntry(entry, streamName, group, redelivered);
    try {
      await handler(msg);
    } catch (err) {
      this._log.error('StreamConsumer: handler error', { stream: streamName, entryId: entry.id, error: err.message });
    }
  }

  _parseEntry(entry, streamName, group = null, redelivered = false) {
    let parsed;
    try {
      parsed = JSON.parse(entry.message.payload);
    } catch {
      this._log.error('StreamConsumer: payload parse error', { stream: streamName, entryId: entry.id });
      parsed = {};
    }

    const entryId = entry.id;
    const client = this._client;
    const log = this._log;

    return {
      content: {},
      correlationId: null,
      meta: {},
      replyTo: null,
      ...parsed,
      redelivered,
      _transport: 'redis-streams',
      ack() {
        if (!group) return Promise.resolve();
        return client.xAck(streamName, group, entryId).catch((err) => {
          log.error('StreamConsumer: XACK error', { stream: streamName, group, entryId, error: err.message });
        });
      },
    };
  }
}

function _sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { StreamConsumer };
