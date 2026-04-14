'use strict';

const { createClient, createCluster } = require('redis');

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
 * Redis v4 client wrapper with single / cluster / sentinel support.
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
 *   await redis.quit();
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
    /** @type {import('redis').RedisClientType|null} */
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
  init() {
    if (this.client) return Promise.resolve(this);

    return new Promise((resolve, reject) => {
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
        const opts = {
          sentinel: {
            name: sentinel.name,
            sentinelRootNodes: sentinel.hosts.map((h) => ({ host: h.host, port: h.port })),
          },
          database: db,
          socket: { reconnectStrategy: retryStrategy },
        };
        if (auth.use) opts.password = auth.password;
        client = createClient(opts);
      } else {
        mode = 'SINGLE';
        client = createClient({
          url: buildUrl(host, port, auth),
          database: db,
          socket: { reconnectStrategy: retryStrategy },
        });
      }

      client.on('error', (err) => this.error(err, { mode }));
      client.on('ready', () => {
        this.log(`Connected in ${mode} mode`, { mode });
        this.client = client;
        resolve(this);
      });

      client.connect().catch((err) => {
        this.error(err, { mode, phase: 'connect' });
        reject(err);
      });
    });
  }

  /** Graceful close — waits for pending commands. */
  async quit() {
    if (this.client) { await this.client.quit(); this.client = null; }
  }

  /** Force close — aborts pending commands immediately. */
  async disconnect() {
    if (this.client) { await this.client.disconnect(); this.client = null; }
  }
}

module.exports = { RedisClient };
