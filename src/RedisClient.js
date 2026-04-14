'use strict';

const { createClient, createCluster } = require('redis');
const { normaliseLogger } = require('./logger');

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
 *
 * @example
 *   const redis = new RedisClient('my-svc', { host, port }, { logger });
 *   await redis.init();
 *   redis.client.xAdd(...);
 *   await redis.quit();
 */
class RedisClient {
  /**
   * @param {string} name    - label for log messages
   * @param {object} config  - { host, port, db?, auth?, cluster?, sentinel? }
   * @param {object} [opts]
   * @param {Logger} [opts.logger]
   */
  constructor(name, config, opts = {}) {
    this.name = name;
    this._log = normaliseLogger(opts.logger);
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
        const sentinelOpts = {
          sentinel: {
            name: sentinel.name,
            sentinelRootNodes: sentinel.hosts.map((h) => ({ host: h.host, port: h.port })),
          },
          database: db,
          socket: { reconnectStrategy: retryStrategy },
        };
        if (auth.use) sentinelOpts.password = auth.password;
        client = createClient(sentinelOpts);
      } else {
        mode = 'SINGLE';
        client = createClient({
          url: buildUrl(host, port, auth),
          database: db,
          socket: { reconnectStrategy: retryStrategy },
        });
      }

      client.on('error', (err) => this._log.error('RedisClient: connection error', { name: this.name, error: err.message }));
      client.on('ready', () => {
        this._log.info('RedisClient: connected', { name: this.name, mode });
        this.client = client;
        resolve(this);
      });

      client.connect().catch((err) => {
        this._log.error('RedisClient: initial connect failed', { name: this.name, error: err.message });
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
