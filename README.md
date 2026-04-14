# @quizizz/redis-streams

Redis Streams transport library — dual-transport routing between a legacy broker (RabbitMQ) and Redis Streams, with per-instance autoDelete and consumer group support.

## Install

```bash
npm install github:quizizz/redis-streams
```

This package lists `redis@^4` as a peer dependency. If your project doesn't already have it, install it explicitly:

```bash
npm install redis@^4
```

## Usage

```js
const {
  RedisClient, StreamProducer, StreamConsumer, StreamTransport,
  STREAM_MODE, createStreamGroups,
} = require('@quizizz/redis-streams');

// 1. Connect
const redis = new RedisClient('my-svc', { host: 'localhost', port: 6379 }, { logger });
await redis.init();

// 2. Define stream configs and create consumer groups
const configs = [
  { topic: `reply-${podId}`, streamMode: STREAM_MODE.SINGLE, ttlSeconds: 300 },
  { topic: 'broadcast',      streamMode: STREAM_MODE.GROUP, group: 'cg:app', consumer: podId },
];
await createStreamGroups(configs, redis.client);

// 3. Create transport
const transport = new StreamTransport({
  broker: rabbitClient,
  streamProducer: new StreamProducer(redis.client, { logger }),
  streamConsumer: new StreamConsumer(redis.client, { logger }),
  streamConfigs: configs,
  shouldUseStreams: (apiName) => featureFlags.isWhitelisted(apiName),
  logger,
});

// Subscribe (wires up broker + streams in one call)
await transport.subscribe('broadcast', handler);

// Send (routes based on shouldUseStreams)
transport.send('request-topic', { api: 'join' }, opts, meta);
```

## Logger

Accepts `{ info, error }` or legacy `{ infoj, errorj }`. Defaults to a silent noop.

## API

| Export | Description |
|--------|-------------|
| `RedisClient(name, config, opts?)` | Redis v4 client wrapper (single / cluster / sentinel) |
| `StreamProducer(client, opts?)` | XADD with MAXLEN trimming |
| `StreamConsumer(client, opts?)` | XREAD / XREADGROUP with PEL reclaim and autoDelete |
| `StreamTransport(options)` | Routes send/subscribe between broker and streams |
| `createStreamGroups(configs, client)` | Idempotent XGROUP CREATE for GROUP-mode configs |
| `STREAM_MODE` | `SINGLE` \| `GROUP` |
| `DEFAULTS` | Tunable constants (block ms, count, TTL, PEL intervals) |
