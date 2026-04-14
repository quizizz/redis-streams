'use strict';

/**
 * @typedef {Object} Logger
 * @property {function(string, object=): void} info  - informational messages
 * @property {function(string, object=): void} error - error messages
 */

/** Silent logger — used when no logger is injected. */
const NOOP_LOGGER = Object.freeze({
  info() {},
  error() {},
});

/**
 * Normalise whatever the consumer passes as `logger` into a safe { info, error } shape.
 *
 * Accepts:
 *   - null / undefined → NOOP_LOGGER
 *   - object with info() + error() → used as-is
 *   - object with infoj() + errorj() → adapted (legacy game-socket / game-service loggers)
 *   - anything else → NOOP_LOGGER
 *
 * @param {any} raw
 * @returns {Logger}
 */
function normaliseLogger(raw) {
  if (!raw) return NOOP_LOGGER;

  // Standard { info, error } interface
  if (typeof raw.info === 'function' && typeof raw.error === 'function') {
    return raw;
  }

  // Legacy Quizizz loggers expose .infoj() / .errorj() (structured JSON)
  if (typeof raw.infoj === 'function' && typeof raw.errorj === 'function') {
    return {
      info(msg, meta) { raw.infoj({ msg, ...meta }); },
      error(msg, meta) { raw.errorj({ msg, ...meta }); },
    };
  }

  return NOOP_LOGGER;
}

module.exports = { normaliseLogger, NOOP_LOGGER };
