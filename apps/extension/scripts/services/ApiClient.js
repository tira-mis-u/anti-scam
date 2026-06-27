

import { logger } from './Logger.js';

export class TimeoutError extends Error {
  constructor(message = 'Máy chủ phản hồi quá chậm, vui lòng thử lại.') {
    super(message);
    this.name = 'TimeoutError';
  }
}

export class NetworkError extends Error {
  constructor(message = 'Lỗi kết nối mạng.') {
    super(message);
    this.name = 'NetworkError';
  }
}

export class ServerError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ServerError';
    this.status = status;
  }
}

export class ApiClient {
  /**
   * Performs an API request with timeout and upload progress tracking.
   * @param {string} url 
   * @param {object} options 
   * @param {FormData} options.body 
   * @param {number} options.timeoutMs 
   * @param {function} options.onProgress 
   * @param {AbortController} options.signal
   */
  static request(url, options = {}) {
    const { method = 'POST', body, timeoutMs = 15000, onProgress, signal } = options;

    return new Promise(async (resolve, reject) => {
      let timeoutId = null;

      const controller = new AbortController();
      const abortHandler = () => {
        controller.abort();
        reject(new Error('Request aborted'));
      };

      if (signal) {
        signal.addEventListener('abort', abortHandler);
      }

      if (timeoutMs) {
        timeoutId = setTimeout(() => {
          controller.abort();
          reject(new TimeoutError());
        }, timeoutMs);
      }

      // Simulate partial progress since fetch doesn't natively support upload progress
      if (onProgress) onProgress(30);

      try {
        const response = await fetch(url, {
          method,
          body,
          signal: controller.signal
        });

        if (timeoutId) clearTimeout(timeoutId);
        if (signal) signal.removeEventListener('abort', abortHandler);
        
        if (onProgress) onProgress(90);

        let data;
        try {
          data = await response.json();
        } catch (err) {
          throw new ServerError('Không thể phân tích phản hồi từ máy chủ.', response.status);
        }

        logger.logRequest('N/A', response.status, data);

        if (response.ok) {
          if (onProgress) onProgress(100);
          resolve(data);
        } else {
          reject(new ServerError(data.message || 'Lỗi hệ thống.', response.status));
        }

      } catch (err) {
        if (timeoutId) clearTimeout(timeoutId);
        if (signal) signal.removeEventListener('abort', abortHandler);
        
        if (err instanceof TimeoutError) {
          // Already rejected by setTimeout
        } else if (err.name === 'AbortError') {
          // Already rejected by abort handlers
        } else {
          reject(new NetworkError(err.message));
        }
      }
    });
  }
}
