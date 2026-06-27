/**
 * Unified Logger for Frontend
 */

const LOGGER_IS_DEV = true;

export class Logger {
  static info(...args) {
    if (LOGGER_IS_DEV) console.info('[AntiScam]', ...args);
  }

  static warn(...args) {
    if (LOGGER_IS_DEV) console.warn('[AntiScam]', ...args);
  }

  static error(...args) {
    console.error('[AntiScam]', ...args);
  }

  static logRequest(requestId, status, responseBody) {
    if (LOGGER_IS_DEV) {
      console.log(`[Req: ${requestId}] Status: ${status} | Body:`, responseBody);
    }
  }
}

export const logger = Logger;
