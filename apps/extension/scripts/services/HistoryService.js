/**
 * HistoryService.js
 * Quản lý lịch sử quét URL tùy chọn (custom URL scan history).
 */
import { logger } from './Logger.js';

const HISTORY_KEY = 'antiscam_url_scan_history';
const MAX_HISTORY = 20;

export class HistoryService {
  static async getAll() {
    try {
      const data = await chrome.storage.local.get(HISTORY_KEY);
      return data[HISTORY_KEY] || [];
    } catch (e) {
      logger.warn('[HistoryService.getAll]', e?.message);
      return [];
    }
  }

  static async add(entry) {
    try {
      const history = await HistoryService.getAll();
      // Deduplicate by URL
      const filtered = history.filter(h => h.url !== entry.url);
      filtered.unshift({ ...entry, addedAt: Date.now() });
      const trimmed = filtered.slice(0, MAX_HISTORY);
      await chrome.storage.local.set({ [HISTORY_KEY]: trimmed });
    } catch (e) {
      logger.warn('[HistoryService.add]', e?.message);
    }
  }

  static async remove(url) {
    try {
      const history = await HistoryService.getAll();
      const filtered = history.filter(h => h.url !== url);
      await chrome.storage.local.set({ [HISTORY_KEY]: filtered });
    } catch (e) {
      logger.warn('[HistoryService.remove]', e?.message);
    }
  }

  static async clear() {
    try {
      await chrome.storage.local.remove(HISTORY_KEY);
    } catch (e) {
      logger.warn('[HistoryService.clear]', e?.message);
    }
  }
}
