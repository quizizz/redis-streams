'use strict';

const { DEFAULTS } = require('./constants');

const NOOP_EMITTER = { emit() {} };
const SERVICE_NAME = 'StreamConsumer';

/**
 * Consumes messages from Redis Streams via XREAD (single reader) or XREADGROUP (consumer group).
 *
 * Parses each entry into: { content, correlationId, meta, redelivered, _transport, ack() }
 *
 * Architecture:
 *   SINGLE mode — All SINGLE subscriptions share ONE unified XREAD BLOCK call on a dedicated
 *                 duplicate connection. Redis wakes the call the instant ANY subscribed stream
 *                 receives a message. No serialization delay between streams.
 *
 *   GROUP mode  — Each GROUP subscription gets its own dedicated duplicate connection for
 *                 XREADGROUP BLOCK. Includes a PEL reclaimer (xAutoClaim) with max retry.
 *
 *   Main client — Reserved exclusively for non-blocking ops: EXPIRE, XACK, XAUTOCLAIM, XPENDING.
 *                 Never blocked by any polling loop.
 *
 * Emits:
 *   'error'  { service, message, data, err }  — on poll errors, parse failures, XACK failures
 *
 * @example
 *   const consumer = new StreamConsumer(redisClient, emitter);
 *   consumer.subscribe('stream:reply-abc', handler, { ttlSeconds: 300 });
 *   consumer.subscribe('stream:broadcast', handler, { group: 'cg:app', consumer: 'pod-1' });
 *   await consumer.stop();
 */
class StreamConsumer {
  /**
   * @param {import('redis').RedisClientType} redisClient
   * @param {EventEmitter} emitter
   */
  constructor(redisClient, emitter) {
    this._client = redisClient;      // non-blocking ops only (EXPIRE, XACK, XAUTOCLAIM)
    this._emitter = emitter || NOOP_EMITTER;
    this._running = false;
    this._pelTimers = [];
    this._dedicatedClients = [];     // duplicate connections — closed on stop()

    // SINGLE mode: all subscriptions collected here, consumed by one unified XREAD loop
    this._readSubs = new Map();      // streamName → { handler, lastId, ttlSeconds, lastTtlRefresh }
    this._readLoopStarted = false;
  }

  _error(message, data = {}) {
    this._emitter.emit('error', { service: SERVICE_NAME, message, data });
  }

  // ── Public API ───────────────────────────────────────────────────────

  /**
   * Subscribe to a stream. Non-blocking — starts/registers consumer loops in the background.
   *
   * SINGLE mode options: { ttlSeconds }
   * GROUP mode options:  { group, consumer, blockMs?, count? }
   */
  subscribe(streamName, handler, options = {}) {
    this._running = true;

    if (options.group && options.consumer) {
      this._startGroupConsumer(streamName, handler, options);
      this._startPELReclaimer(streamName, handler, options.group, options.consumer);
    } else {
      this._readSubs.set(streamName, {
        handler,
        lastId: '$',
        ttlSeconds: options.ttlSeconds ?? DEFAULTS.STREAM_TTL_SECONDS,
        count: options.count ?? DEFAULTS.COUNT,
        lastTtlRefresh: 0,
      });

      if (!this._readLoopStarted) {
        this._readLoopStarted = true;
        this._startUnifiedReadLoop();
      }
    }
  }

  /**
   * Stop all polling loops and release all duplicate connections immediately.
   */
  async stop() {
    this._running = false;

    for (const timer of this._pelTimers) clearInterval(timer);
    this._pelTimers = [];

    for (const client of this._dedicatedClients) {
      // destroy() rejects pending commands immediately — unlike close() which
      // waits for them, causing up to BLOCK_MS (5s) hang on a blocked XREAD.
      client.destroy();
    }
    this._dedicatedClients = [];
  }

  // ── SINGLE mode: unified multi-stream XREAD ──────────────────────────

  async _startUnifiedReadLoop() {
    let readClient;
    try {
      readClient = this._client.duplicate();
      readClient.on('error', (err) => this._error('readClient error', { error: err.message }));
      await readClient.connect();
      this._dedicatedClients.push(readClient);
    } catch (err) {
      this._error('readClient connect failed', { error: err.message });
      this._readLoopStarted = false;
      return;
    }

    while (this._running) {
      this._refreshTTLs();

      const streams = this._buildReadStreams();
      if (streams.length === 0) { await _sleep(100); continue; }

      try {
        const response = await readClient.xRead(streams, {
          BLOCK: DEFAULTS.BLOCK_MS,
          COUNT: this._getReadCount(),
        });
        if (!response) continue;

        const dispatches = [];
        for (const stream of response) {
          const sub = this._readSubs.get(stream.name);
          if (!sub) continue;
          for (const entry of stream.messages) {
            sub.lastId = entry.id;
            dispatches.push(this._dispatch(entry, stream.name, null, false, sub.handler));
          }
        }
        await Promise.allSettled(dispatches);
      } catch (err) {
        if (!this._running) break;
        this._error('XREAD error', { error: err.message });
        await _sleep(1000);
      }
    }
  }

  _refreshTTLs() {
    const now = Date.now();
    for (const [name, sub] of this._readSubs) {
      if (now - sub.lastTtlRefresh >= DEFAULTS.TTL_REFRESH_INTERVAL_MS) {
        this._client.expire(name, sub.ttlSeconds)
          .then((result) => {
            // result = 1 (TTL set) or 0 (key doesn't exist)
            // Only mark as refreshed if EXPIRE actually applied
            if (result) sub.lastTtlRefresh = now;
          })
          .catch((err) => {
            this._error('EXPIRE error', { stream: name, error: err.message });
          });
      }
    }
  }

  _buildReadStreams() {
    const streams = [];
    for (const [name, sub] of this._readSubs) {
      streams.push({ key: name, id: sub.lastId });
    }
    return streams;
  }

  // COUNT is a single value applied to all streams in one XREAD call.
  // Use the minimum across all subscriptions so the strictest preference wins.
  _getReadCount() {
    let count = Infinity;
    for (const [, sub] of this._readSubs) {
      if (sub.count < count) count = sub.count;
    }
    return count === Infinity ? DEFAULTS.COUNT : count;
  }

  // ── GROUP mode: dedicated connection per subscription ─────────────────

  async _startGroupConsumer(streamName, handler, options) {
    let groupClient;
    try {
      groupClient = this._client.duplicate();
      groupClient.on('error', (err) => this._error('groupClient error', { error: err.message }));
      await groupClient.connect();
      this._dedicatedClients.push(groupClient);
    } catch (err) {
      this._error('groupClient connect failed', { stream: streamName, error: err.message });
      return;
    }

    this._pollGroup(groupClient, streamName, handler, options);
  }

  async _pollGroup(client, streamName, handler, options) {
    const { group, consumer } = options;
    const blockMs = options.blockMs ?? DEFAULTS.BLOCK_MS;
    const count = options.count ?? DEFAULTS.COUNT;

    while (this._running) {
      try {
        const response = await client.xReadGroup(
          group, consumer,
          [{ key: streamName, id: '>' }],
          { BLOCK: blockMs, COUNT: count },
        );
        if (!response) continue;

        const dispatches = [];
        for (const stream of response) {
          for (const entry of stream.messages) {
            dispatches.push(this._dispatch(entry, streamName, group, false, handler));
          }
        }
        await Promise.allSettled(dispatches);
      } catch (err) {
        if (!this._running) break;
        this._error('XREADGROUP error', { stream: streamName, group, consumer, error: err.message });
        await _sleep(1000);
      }
    }
  }

  // ── PEL reclaimer ────────────────────────────────────────────────────

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

          const pending = await this._client.xPendingRange(
            streamName, group, entry.id, entry.id, 1,
          );
          const deliveriesCounter = pending?.[0]?.deliveriesCounter ?? 1;

          if (deliveriesCounter > DEFAULTS.MAX_DELIVERY_COUNT) {
            this._error('Max retries exceeded, discarding', {
              stream: streamName, entryId: entry.id, deliveriesCounter,
            });
            await this._client.xAck(streamName, group, entry.id).catch(() => {});
            continue;
          }

          this._dispatch(entry, streamName, group, true, handler);
        }
      } catch (err) {
        if (!err.message?.includes('NOGROUP')) {
          this._error('XAUTOCLAIM error', { stream: streamName, group, error: err.message });
        }
      }
    }, DEFAULTS.PEL_INTERVAL_MS);

    this._pelTimers.push(timer);
  }

  // ── Dispatch ─────────────────────────────────────────────────────────

  async _dispatch(entry, streamName, group, redelivered, handler) {
    const msg = this._parseEntry(entry, streamName, group, redelivered);
    try {
      await handler(msg);
    } catch (err) {
      this._error('Handler error', { stream: streamName, entryId: entry.id, error: err.message });
    }
  }

  _parseEntry(entry, streamName, group = null, redelivered = false) {
    let parsed;
    try {
      parsed = JSON.parse(entry.message.payload);
    } catch {
      this._error('Payload parse error', { stream: streamName, entryId: entry.id });
      parsed = {};
    }

    const entryId = entry.id;
    const client = this._client;
    const emitter = this._emitter;

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
          emitter.emit('error', {
            service: SERVICE_NAME,
            message: 'XACK error',
            data: { stream: streamName, group, entryId, error: err.message },
          });
        });
      },
    };
  }
}

function _sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { StreamConsumer };
