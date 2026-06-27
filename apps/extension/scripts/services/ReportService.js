import { logger } from './Logger.js';
import { ApiClient } from './ApiClient.js';
import { Validation } from './Validation.js';
import { QueueManager } from './QueueManager.js';
import { RetryManager } from './RetryManager.js';

export const REPORT_API_URL = 'https://anti-scam-6iix.onrender.com/api/report';

export class ReportService {
  /**
   * Processes a report payload from the popup.
   * @param {Object} payload 
   */
  static async handleReport(payload, onProgress) {
    try {
      // Create FormData from payload
      const formData = new FormData();
      formData.append('url', payload.url);
      formData.append('domain', payload.domain);
      formData.append('pageTitle', payload.pageTitle || '');
      formData.append('timestamp', payload.timestamp || new Date().toISOString());
      formData.append('extensionVersion', payload.extensionVersion || '');
      formData.append('browserName', payload.browserName || '');
      formData.append('browserLanguage', payload.browserLanguage || '');
      formData.append('userAgent', payload.userAgent || '');
      formData.append('category', payload.category);
      formData.append('description', payload.description);

      // Device ID and GPS
      const deviceId = await this.getDeviceId();
      formData.append('deviceId', deviceId);

      if (payload.gps) {
        formData.append('latitude', String(payload.gps.latitude));
        formData.append('longitude', String(payload.gps.longitude));
        formData.append('gpsAccuracy', String(payload.gps.accuracy));
        formData.append('locationSource', 'gps');
      } else {
        formData.append('locationSource', 'ip-fallback');
      }

      // Handle Image (Base64 to Blob)
      if (payload.screenshotBase64) {
        try {
          const res = await fetch(payload.screenshotBase64);
          const blob = await res.blob();
          formData.append('screenshot', blob, payload.screenshotName || 'screenshot.png');
        } catch (err) {
          logger.warn('Không thể chuyển đổi ảnh Base64 sang Blob', err);
        }
      }

      // Send with Retry
      return await RetryManager.execute(async () => {
        return await ApiClient.request(REPORT_API_URL, {
          method: 'POST',
          body: formData,
          timeoutMs: 15000,
          onProgress
        });
      }, 3, [1000, 2000, 4000]);

    } catch (error) {
      logger.error('ReportService.handleReport', error);
      
      // If it's a network/timeout error or 5xx, queue it for later
      if (RetryManager.isRetryableError(error)) {
        await QueueManager.enqueue(payload);
        throw new Error('Lỗi kết nối. Báo cáo đã được lưu vào hàng đợi và sẽ tự động gửi sau.');
      }
      
      throw error;
    }
  }

  static async getDeviceId() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['reportDeviceId'], (res) => {
        if (res.reportDeviceId) {
          resolve(res.reportDeviceId);
        } else {
          const newId = 'ext_' + crypto.randomUUID();
          chrome.storage.local.set({ reportDeviceId: newId }, () => {
            resolve(newId);
          });
        }
      });
    });
  }
}
