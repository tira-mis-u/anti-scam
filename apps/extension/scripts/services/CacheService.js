/**
 * CacheService.js
 * Quản lý session cache (chrome.storage.session) với TTL, schema version.
 */
import { logger } from './Logger.js';

const SCHEMA_VERSION = 2;

function _hash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) { h = ((h << 5) - h) + str.charCodeAt(i); h |= 0; }
  return h;
}

export class CacheService {
  /**
   * Lưu một mục vào session cache với TTL và schema version
   */
  static async set(key, data, ttlMs = 10 * 60 * 1000, extra = {}) {
    try {
      await chrome.storage.session.set({
        [key]: { ...data, ...extra, _cachedAt: Date.now(), _ttlMs: ttlMs, _schema: SCHEMA_VERSION }
      });
    } catch (e) {
      logger.warn('[CacheService.set]', e?.message);
    }
  }

  /**
   * Lấy mục từ session cache. Trả về null nếu hết hạn hoặc không tồn tại.
   */
  static async get(key, ttlMs = null) {
    try {
      const d = await chrome.storage.session.get(key);
      const item = d[key];
      if (!item) return null;
      if (item._schema !== undefined && item._schema !== SCHEMA_VERSION) return null;
      const effectiveTtl = ttlMs ?? item._ttlMs;
      if (effectiveTtl && Date.now() - item._cachedAt >= effectiveTtl) return null;
      return item;
    } catch (e) {
      logger.warn('[CacheService.get]', e?.message);
      return null;
    }
  }

  /**
   * Lấy cache cho một URL (sử dụng hash key)
   */
  static async getForUrl(url, requiredStage = 'LIVE', resultTtlMs = 10 * 60 * 1000, quickTtlMs = 30 * 60 * 1000) {
    const key = `cache_${_hash(url)}`;
    try {
      const d = await chrome.storage.session.get(key);
      const it = d[key];
      if (!it) return null;
      if (it._schema !== SCHEMA_VERSION) return null;
      if (requiredStage === 'LIVE' && it.stage === 'QUICK') return null;
      const ttl = (it.stage === 'QUICK') ? quickTtlMs : resultTtlMs;
      if (Date.now() - it._cachedAt >= ttl) return null;
      return it;
    } catch (e) {
      logger.warn('[CacheService.getForUrl]', e?.message);
      return null;
    }
  }

  /**
   * Lưu cache cho URL (sử dụng hash key)
   */
  static async setForUrl(url, data, stage = 'LIVE') {
    const key = `cache_${_hash(url)}`;
    try {
      await chrome.storage.session.set({
        [key]: { ...data, stage, _schema: SCHEMA_VERSION, _cachedAt: Date.now() }
      });
    } catch (e) {
      logger.warn('[CacheService.setForUrl]', e?.message);
    }
  }

  /**
   * Xóa cache cho một key
   */
  static async remove(key) {
    try { await chrome.storage.session.remove(key); } catch (_) {}
  }
}
