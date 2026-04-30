'use strict';

/**
 * Consumer patterns for Redis Streams.
 *
 *   SINGLE — XREAD, no consumer group. One pod reads from the stream.
 *            Supports autoDelete via EXPIRE (ttlSeconds).
 *
 *   GROUP  — XREADGROUP with a consumer group. Multiple pods compete.
 *            Requires the group to be created before first use (see createStreamGroups).
 */
const STREAM_MODE = Object.freeze({
  SINGLE: 'single',
  GROUP: 'group',
});

/** Tunable defaults. Override per-call or per-subscription via options. */
const DEFAULTS = Object.freeze({
  BLOCK_MS: 5000,
  COUNT: 100,
  MAX_LEN: 10000,
  PEL_INTERVAL_MS: 30000,
  PEL_MIN_IDLE_MS: 60000,
  PEL_COUNT: 100,
  MAX_DELIVERY_COUNT: 5,
  STREAM_TTL_SECONDS: 10 * 60, // 10 minutes
  TTL_REFRESH_INTERVAL_MS: 5 * 60 * 1000, // 5 minutes
});

module.exports = { STREAM_MODE, DEFAULTS };
