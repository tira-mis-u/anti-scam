import { logger } from './Logger.js';

export class QueueManager {
  static QUEUE_KEY = 'report_offline_queue';

  static async enqueue(reportPayload) {
    try {
      const queue = await this.getQueue();
      
      // Prevent duplicates in queue by checking URL
      const exists = queue.find(r => r.url === reportPayload.url);
      if (!exists) {
        queue.push({ ...reportPayload, queuedAt: Date.now() });
        await this.saveQueue(queue);
        logger.info(`Đã lưu báo cáo vào hàng đợi offline: ${reportPayload.url}`);
      }
    } catch (err) {
      logger.error('QueueManager.enqueue', err);
    }
  }

  static async dequeue() {
    try {
      const queue = await this.getQueue();
      if (queue.length === 0) return null;

      const report = queue.shift();
      await this.saveQueue(queue);
      return report;
    } catch (err) {
      logger.error('QueueManager.dequeue', err);
      return null;
    }
  }

  static async getQueue() {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get([this.QUEUE_KEY], (result) => {
          resolve(result[this.QUEUE_KEY] || []);
        });
      } else {
        // Fallback for non-extension environments (e.g., testing)
        try {
          const item = localStorage.getItem(this.QUEUE_KEY);
          resolve(item ? JSON.parse(item) : []);
        } catch (_) {
          resolve([]);
        }
      }
    });
  }

  static async saveQueue(queue) {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ [this.QUEUE_KEY]: queue }, resolve);
      } else {
        try {
          localStorage.setItem(this.QUEUE_KEY, JSON.stringify(queue));
          resolve();
        } catch (_) {
          resolve();
        }
      }
    });
  }

  static async processQueue(processFunction) {
    if (!navigator.onLine) return;
    
    const queue = await this.getQueue();
    if (queue.length === 0) return;

    logger.info(`Bắt đầu gửi ${queue.length} báo cáo trong hàng đợi...`);
    
    // We process them one by one. If one fails, we put it back and stop.
    while (navigator.onLine) {
      const report = await this.dequeue();
      if (!report) break;

      try {
        await processFunction(report);
      } catch (err) {
        logger.warn(`Gửi báo cáo từ hàng đợi thất bại: ${report.url}`, err);
        // Put it back to the beginning of the queue
        const currentQueue = await this.getQueue();
        currentQueue.unshift(report);
        await this.saveQueue(currentQueue);
        break; // Stop processing further until next trigger
      }
    }
  }
}
