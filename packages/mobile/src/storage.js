// React Native storage — thay chrome.storage bằng AsyncStorage
// Usage: import { createRNStorage } from '@anti-scam/mobile/storage'

export const createRNStorage = (AsyncStorage) => ({
  getTabState: async () => null,              // RN không có tab
  setTabState: async () => {},
  removeTabState: async () => {},
  getUrlCache: async (url, schemaVersion, ttlMs) => {
    try {
      const key = `cache_${url}`;
      const raw = await AsyncStorage.getItem(key);
      if (!raw) return null;
      const it = JSON.parse(raw);
      if (it.schemaVersion === schemaVersion && Date.now() - it.timestamp < ttlMs) return it;
      return null;
    } catch { return null; }
  },
  setUrlCache: async (url, data, schemaVersion) => {
    try {
      await AsyncStorage.setItem(`cache_${url}`, JSON.stringify({ ...data, schemaVersion, timestamp: Date.now() }));
    } catch {}
  },
});
