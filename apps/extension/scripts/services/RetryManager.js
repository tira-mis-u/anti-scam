import { logger } from './Logger.js';
import { NetworkError, TimeoutError, ServerError } from './ApiClient.js';

export class RetryManager {
  /**
   * Executes a function with exponential backoff retries.
   * Only retries on specific errors (500, 502, 503, 504, NetworkError, TimeoutError).
   * 
   * @param {function} fn The async function to execute
   * @param {number} maxRetries Max number of retries
   * @param {number[]} delays Array of delays in ms (e.g. [1000, 2000, 4000])
   * @param {function} onRetry Callback when a retry happens
   */
  static async execute(fn, maxRetries = 3, delays = [1000, 2000, 4000], onRetry = null) {
    let attempt = 0;

    while (attempt <= maxRetries) {
      try {
        return await fn();
      } catch (error) {
        const isRetryable = this.isRetryableError(error);
        
        if (!isRetryable || attempt >= maxRetries) {
          throw error;
        }

        const delay = delays[attempt] || delays[delays.length - 1];
        logger.warn(`Thử lại lần ${attempt + 1} sau ${delay}ms do lỗi:`, error.message);
        
        if (onRetry) {
          onRetry(attempt + 1, delay, error);
        }

        await new Promise(resolve => setTimeout(resolve, delay));
        attempt++;
      }
    }
  }

  static isRetryableError(error) {
    if (error instanceof NetworkError || error instanceof TimeoutError) {
      return true;
    }
    if (error instanceof ServerError) {
      const status = error.status;
      if (status >= 500 && status <= 599) {
        return true;
      }
    }
    return false;
  }
}
