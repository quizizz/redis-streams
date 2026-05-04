'use strict';

const { DEFAULTS } = require('./constants');

const NOOP_EMITTER = { emit() {} };

/**
 * Produces messages to Redis Streams via XADD.
 *
 * Accepts a pre-built payload string and handles only Redis operations:
 * XADD (write) and throttled EXPIRE (TTL for per-instance streams).
 *
 * Payload construction is the caller's responsibility (StreamTransport handles this).
 *
 * @example
 *   const producer = new StreamProducer(redisClient, emitter);
 *   await producer.send('stream:topic', payload);
 *   await producer.send('stream:topic', payload, { ttlSeconds: 600, maxLen: 5000 });
 */
class StreamProducer {
  /**
   * @param {import('redis').RedisClientType} redisClient
   * @param {EventEmitter} emitter - emits 'error' events
   */
  constructor(redisClient, emitter) {
    this._client = redisClient;
    this._emitter = emitter || NOOP_EMITTER;
    this._lastExpire = new Map();  // streamName → timestamp of last EXPIRE
  }

  /**
   * @param {string}  streamName       - e.g. 'stream:socket-request'
   * @param {string}  payload          - pre-built JSON string
   * @param {object}  [streamOptions]  - Redis stream options
   * @param {number}  [streamOptions.ttlSeconds]  - EXPIRE TTL (throttled)
   * @param {number}  [streamOptions.maxLen]       - MAXLEN ~ trimming threshold
   * @returns {Promise<string>} stream entry ID
   */
  async send(streamName, payload, streamOptions = {}) {
    const maxLen = streamOptions.maxLen ?? DEFAULTS.MAX_LEN;
    const start = Date.now();
    const shouldExpire = streamOptions.ttlSeconds && this._shouldRefreshExpire(streamName, streamOptions.ttlSeconds);

  let entryId;
    // Fire XADD and EXPIRE in the same tick so node-redis pipelines them
    // into a single TCP write. EXPIRE is fire-and-forget — its failure
    // doesn't affect the send result.
    const xAddPromise = this._client.xAdd(streamName, '*', { payload }, {
      TRIM: { strategy: 'MAXLEN', strategyModifier: '~', threshold: maxLen },
    });

    if (shouldExpire) {
      this._client.expire(streamName, streamOptions.ttlSeconds).catch(() => {});
      this._lastExpire.set(streamName, Date.now());
    }

    entryId = await xAddPromise;

    return entryId;
  }

  _shouldRefreshExpire(streamName, ttlSeconds) {
    const now = Date.now();
    const last = this._lastExpire.get(streamName) || 0;
    const refreshIntervalMs = Math.min(DEFAULTS.TTL_REFRESH_INTERVAL_MS, (ttlSeconds * 1000) / 2);
    return (now - last) >= refreshIntervalMs;
  }
}

module.exports = { StreamProducer };
