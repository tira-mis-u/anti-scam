/**
 * TabStateService.js
 * Wrapper cho chrome.storage.session để quản lý trạng thái phân tích của từng tab.
 */
import { logger } from './Logger.js';

export const ANALYSIS_STATUS = Object.freeze({
  IDLE: 'IDLE',
  ANALYZING: 'ANALYZING',
  SUCCESS: 'SUCCESS',
  FAILED: 'FAILED',
  OFFLINE: 'OFFLINE',
});

export class TabStateService {
  static _key(tabId) { return `tab_${tabId}`; }

  static async get(tabId) {
    try {
      const d = await chrome.storage.session.get(TabStateService._key(tabId));
      return d[TabStateService._key(tabId)] || null;
    } catch (e) {
      logger.warn('[TabStateService.get]', e?.message);
      return null;
    }
  }

  static async set(tabId, state) {
    try {
      await chrome.storage.session.set({
        [TabStateService._key(tabId)]: { ...state, updatedAt: Date.now() }
      });
    } catch (e) {
      logger.error('[TabStateService.set]', e?.message);
    }
  }

  static async remove(tabId) {
    try { await chrome.storage.session.remove(TabStateService._key(tabId)); } catch (_) {}
  }
}
