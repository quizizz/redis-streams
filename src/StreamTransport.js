'use strict';

const { STREAM_MODE } = require('./constants');

const NOOP_EMITTER = { emit() {} };
const SERVICE_NAME = 'StreamTransport';

/**
 * Unified transport that routes between a legacy broker (RabbitMQ etc.) and Redis Streams,
 * based on a caller-provided routing function.
 *
 * Broker-agnostic — the broker just needs `.send()` and `.subscribe()`.
 *
 * @example
 *   const transport = new StreamTransport({
 *     broker: rabbitClient,
 *     streamProducer: producer,
 *     streamConsumer: consumer,
 *     streamConfigs: [
 *       { topic: 'broadcast', streamMode: STREAM_MODE.GROUP, group: 'cg:app', consumer: podId },
 *       { topic: `reply-${podId}`, streamMode: STREAM_MODE.SINGLE, ttlSeconds: 300 },
 *     ],
 *     shouldUseStreams: (apiName) => featureFlags.isWhitelisted(apiName),
 *     emitter,
 *   });
 */
class StreamTransport {
  /**
   * @param {object}          options.broker            - legacy broker (must have send/subscribe)
   * @param {StreamProducer}  [options.streamProducer]   - null = streams disabled
   * @param {StreamConsumer}  [options.streamConsumer]   - null = streams disabled
   * @param {StreamConfig[]}  [options.streamConfigs]    - per-topic mode/group/ttl config
   * @param {function}        [options.shouldUseStreams] - (apiName: string) => boolean
   * @param {EventEmitter}    [options.emitter]
   */
  constructor(options) {
    this._broker = options.broker;
    this._streamProducer = options.streamProducer || null;
    this._streamConsumer = options.streamConsumer || null;
    this._shouldUseStreamsFn = options.shouldUseStreams || (() => false);
    this._emitter = options.emitter || NOOP_EMITTER;

    this._streamConfigMap = new Map(
      (options.streamConfigs || []).map((c) => [c.topic, c]),
    );
    this._brokerResults = {};
  }

  // ── Send ────────────────────────────────────────────────────────────

  /**
   * Drop-in replacement for broker.send(topic, content, options, meta).
   * Routes via shouldUseStreams() based on the API name extracted from content.
   */
  send(topic, content, options = {}, meta = {}) {
    const apiName = content?.api || content?.broadcast?.api || content?.type || '';

    if (this._streamProducer && this._shouldUseStreamsFn(apiName)) {
      const payload = JSON.stringify({
        content,
        correlationId: options.correlationId || null,
        meta,
        replyTo: options.replyTo || null,
      });

      const cfg = this._streamConfigMap.get(topic);
      const streamOptions = {};
      if (options.ttlSeconds ?? cfg?.ttlSeconds) {
        streamOptions.ttlSeconds = options.ttlSeconds ?? cfg.ttlSeconds;
      }
      if (options.maxLen ?? cfg?.maxLen) {
        streamOptions.maxLen = options.maxLen ?? cfg.maxLen;
      }

      return this._streamProducer.send(`stream:${topic}`, payload, streamOptions);
    }
    return this._broker.send(topic, content, options, meta);
  }

  // ── Subscribe ───────────────────────────────────────────────────────

  /**
   * Subscribe to both broker AND Redis Streams for a given topic.
   * Consumer pattern (XREAD vs XREADGROUP) is resolved from streamConfigs.
   */
  async subscribe(topic, handler) {
    const brokerResult = await this._broker.subscribe(topic, handler);
    this._brokerResults[topic] = brokerResult;

    if (this._streamConsumer) {
      const cfg = this._streamConfigMap.get(topic);
      const streamOpts = cfg?.streamMode === STREAM_MODE.GROUP
        ? { group: cfg.group, consumer: cfg.consumer, count: cfg.count, blockMs: cfg.blockMs }
        : { count: cfg.count, blockMs: cfg.blockMs };
      this._streamConsumer.subscribe(`stream:${topic}`, handler, streamOpts);
    }
  }

  // ── Unsubscribe ─────────────────────────────────────────────────────

  async unsubscribe(topic) {
    const result = this._brokerResults[topic];
    if (result) {
      await this._broker.unsubscribe(topic, result.consumerTag);
      delete this._brokerResults[topic];
    }
  }

  async stopStreams() {
    if (this._streamConsumer) {
      await this._streamConsumer.stop();
    }
  }
}

module.exports = { StreamTransport };
