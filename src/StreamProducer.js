'use strict';

const { DEFAULTS } = require('./constants');
const { normaliseLogger } = require('./logger');

/**
 * Produces messages to Redis Streams via XADD.
 *
 * Payload format: `{ content, correlationId, meta, replyTo }` JSON-stringified
 * into a single `payload` field. StreamConsumer parses it back.
 *
 * @example
 *   const producer = new StreamProducer(redisClient, { logger });
 *   await producer.send('stream:topic', content, { correlationId }, meta);
 */
class StreamProducer {
  /**
   * @param {import('redis').RedisClientType} redisClient
   * @param {object} [opts]
   * @param {Logger} [opts.logger]
   */
  constructor(redisClient, opts = {}) {
    this._client = redisClient;
    this._log = normaliseLogger(opts.logger);
  }

  /**
   * @param {string}  streamName - e.g. 'stream:socket-request'
   * @param {object}  content    - message body
   * @param {object}  [options]  - { correlationId, replyTo }
   * @param {object}  [meta]     - { traceId, startTime, ... }
   * @param {number}  [maxLen]   - MAXLEN ~ trimming threshold
   * @returns {Promise<string>}  - stream entry ID
   */
  async send(streamName, content, options = {}, meta = {}, maxLen = DEFAULTS.MAX_LEN) {
    const payload = JSON.stringify({
      content,
      correlationId: options.correlationId || null,
      meta,
      replyTo: options.replyTo || null,
    });

    return this._client.xAdd(streamName, '*', { payload }, {
      TRIM: { strategy: 'MAXLEN', strategyModifier: '~', threshold: maxLen },
    });
  }
}

module.exports = { StreamProducer };
