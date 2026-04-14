'use strict';

const { STREAM_MODE } = require('./constants');

/**
 * @typedef {Object} StreamConfig
 * @property {string}  topic       - base name (no 'stream:' prefix)
 * @property {string}  streamMode  - STREAM_MODE.SINGLE | STREAM_MODE.GROUP
 * @property {string}  [group]     - consumer group name (GROUP mode only)
 * @property {string}  [consumer]  - consumer name within group (GROUP mode only)
 * @property {number}  [ttlSeconds] - EXPIRE TTL for autoDelete (SINGLE mode, default 300)
 */

/**
 * Create consumer groups for all GROUP-mode streams.
 * Idempotent — ignores BUSYGROUP if the group already exists.
 *
 * @param {StreamConfig[]} configs
 * @param {import('redis').RedisClientType} redisClient
 */
async function createStreamGroups(configs, redisClient) {
  for (const cfg of configs) {
    if (cfg.streamMode !== STREAM_MODE.GROUP) continue;
    try {
      await redisClient.xGroupCreate(`stream:${cfg.topic}`, cfg.group, '$', { MKSTREAM: true });
    } catch (e) {
      if (!e.message?.includes('BUSYGROUP')) throw e;
    }
  }
}

module.exports = { createStreamGroups };
