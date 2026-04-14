# @quizizz/redis-streams

Redis Streams transport library — producer, consumer, and dual-transport routing layer.

## Install

```bash
# From a consuming repo (game-socket, game-service, etc.)
npm install @quizizz/redis-streams
# or link locally during development
npm link ../redis-streams
```

Requires `redis@^4` as a peer dependency (must be installed in the consuming repo).

## Quick Start

```js
const {
  RedisClient, StreamProducer, StreamConsumer, StreamTransport,
  STREAM_MODE, createStreamGroups,
} = require('@quizizz/redis-streams');

// 1. Connect
const redis = new RedisClient('my-svc', { host: 'localhost', port: 6379 }, { logger });
await redis.init();

// 2. Define stream configs
const configs = [
  { topic: `reply-${podId}`, streamMode: STREAM_MODE.SINGLE, ttlSeconds: 300 },
  { topic: 'broadcast', streamMode: STREAM_MODE.GROUP, group: 'cg:app', consumer: podId },
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

// 4. Subscribe (wires up both broker + streams)
await transport.subscribe('broadcast', handler);

// 5. Send (routes based on shouldUseStreams)
transport.send('request-topic', { api: 'join', data: {} }, opts, meta);
```

## Logger

All classes accept an optional `logger` with `info(msg, meta)` and `error(msg, meta)` methods.

Falls back to:
- Legacy `.infoj()` / `.errorj()` loggers (auto-adapted)
- Silent noop if nothing is passed

## API

### `RedisClient(name, config, opts?)`
Redis v4 wrapper with cluster/sentinel/single support and retry strategy.

### `StreamProducer(redisClient, opts?)`
XADD with MAXLEN trimming. Single `payload` field per entry.

### `StreamConsumer(redisClient, opts?)`
XREAD / XREADGROUP with PEL reclaimer and autoDelete (EXPIRE on SINGLE-mode streams).

### `StreamTransport(options)`
Routes between a legacy broker and Redis Streams. Resolves consumer pattern (XREAD vs XREADGROUP) from `streamConfigs`.

### `createStreamGroups(configs, redisClient)`
Idempotent XGROUP CREATE for all GROUP-mode configs.

### Constants
- `STREAM_MODE.SINGLE` / `STREAM_MODE.GROUP`
- `DEFAULTS` — tunable block/count/ttl/PEL values
