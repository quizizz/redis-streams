'use strict';

const { createClient, createCluster, createSentinel } = require('redis');

const NOOP_EMITTER = { emit() {} };

function retryStrategy(retries) {
  if (retries > 1000) return new Error('redis-streams: exceeded 1000 retries');
  return Math.min(retries * 100, 2000);
}

function buildUrl(host, port, auth) {
  if (auth && auth.use) return `redis://:${auth.password}@${host}:${port}`;
  return `redis://${host}:${port}`;
}

/**
 * Redis v5 client wrapper with single / cluster / sentinel support.
 * Uses an EventEmitter for logging — compatible with @quizizz/mongo's convention.
 *
 * Emits:
 *   'log'     { service, message, data }  — informational
 *   'error'   { service, data, err }      — errors
 *
 * @example
 *   const redis = new RedisClient('my-svc', emitter, { host, port });
 *   await redis.init();
 *   redis.client.xAdd(...);
 *   await redis.close();
 */
class RedisClient {
  /**
   * @param {string}       name     - label for log messages
   * @param {EventEmitter} emitter  - emits 'log' and 'error' events
   * @param {object}       config   - { host, port, db?, auth?, cluster?, sentinel? }
   */
  constructor(name, emitter, config) {
    this.name = name;
    this.emitter = emitter || NOOP_EMITTER;
    this.config = {
      host: 'localhost',
      port: 6379,
      db: 0,
      ...config,
      auth: { use: false, ...config.auth },
      cluster: { use: false, ...config.cluster },
      sentinel: { use: false, ...config.sentinel },
    };
    this.client = null;
  }

  log(message, data) {
    this.emitter.emit('log', { service: this.name, message, data });
  }

  error(err, data) {
    this.emitter.emit('error', { service: this.name, data, err });
  }

  /**
   * Connect to Redis. Resolves with `this` when ready.
   * @returns {Promise<RedisClient>}
   */
  async init() {
    if (this.client) return this;

    const { host, port, db, cluster, sentinel, auth } = this.config;
    let client;
    let mode;

    if (cluster.use) {
      mode = 'CLUSTER';
      const rootNodes = cluster.hosts.map((h) => ({ url: buildUrl(h.host, h.port, auth) }));
      const defaults = { socket: { reconnectStrategy: retryStrategy } };
      if (auth.use) defaults.password = auth.password;
      client = createCluster({ rootNodes, defaults });
    } else if (sentinel.use) {
      mode = 'SENTINEL';
      const nodeClientOptions = {
        database: db,
        socket: { reconnectStrategy: retryStrategy },
      };
      if (auth.use) nodeClientOptions.password = auth.password;
      const sentinelOpts = {
        name: sentinel.name,
        sentinelRootNodes: sentinel.hosts.map((h) => ({ host: h.host, port: h.port })),
        nodeClientOptions,
      };
      client = createSentinel(sentinelOpts);
      client.duplicate = (overrides) => createSentinel({ ...sentinelOpts, ...overrides });
    } else {
      mode = 'SINGLE';
      client = createClient({
        url: buildUrl(host, port, auth),
        database: db,
        socket: { reconnectStrategy: retryStrategy },
      });
    }

    client.on('error', (err) => this.error(err, { mode }));

    try {
      await client.connect();
      this.log(`Connected in ${mode} mode`, { mode });
      this.client = client;
      return this;
    } catch (err) {
      this.error(err, { mode, phase: 'connect' });
      throw err;
    }
  }

  /**
   * Create a new connected client with the same config and error handling.
   * Use for operations that need a dedicated connection (blocking commands, pub/sub).
   *
   * @param {string} [label] - suffix for log messages (e.g. 'xread', 'pubsub')
   * @returns {Promise<import('redis').RedisClientType>} connected raw client
   */
  async duplicate(label) {
    const suffix = label ? `-${label}` : '';
    const client = this.client.duplicate();
    client.on('error', (err) => this.error(err, { mode: `duplicate${suffix}` }));
    await client.connect();
    this.log(`Duplicate connected${suffix ? ` (${label})` : ''}`, { label });
    return client;
  }

  /** Graceful close — waits for pending commands. */
  async close() {
    if (this.client) { await this.client.close(); this.client = null; }
  }

  /** @deprecated Use close() instead. */
  async quit() {
    return this.close();
  }

  /** Force close — drops pending commands immediately. */
  async destroy() {
    if (this.client) { await this.client.destroy(); this.client = null; }
  }

  /** @deprecated Use destroy() instead. */
  async disconnect() {
    return this.destroy();
  }
}

module.exports = { RedisClient };
