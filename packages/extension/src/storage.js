// Chrome Extension storage wrappers
// Thay thế bằng AsyncStorage khi chạy trên React Native
export const createStorage = (chrome) => ({
  getTabState: async (tabId) => {
    try { const d = await chrome.storage.session.get(`tab_${tabId}`); return d[`tab_${tabId}`] || null; } catch(e){ return null; }
  },
  setTabState: async (tabId, state) => {
    try { await chrome.storage.session.set({ [`tab_${tabId}`]: { ...state, updatedAt: Date.now() } }); } catch(e){}
  },
  removeTabState: async (tabId) => {
    try { await chrome.storage.session.remove(`tab_${tabId}`); } catch(e){}
  },
  getUrlCache: async (url, schemaVersion, ttlMs) => {
    try {
      let h=0; for (let i=0;i<url.length;i++){ h=((h<<5)-h)+url.charCodeAt(i); h|=0; }
      const d = await chrome.storage.session.get(`cache_${h}`);
      const it = d[`cache_${h}`];
      if (it && it.schemaVersion === schemaVersion && Date.now()-it.timestamp < ttlMs) return it;
    } catch(e){}
    return null;
  },
  setUrlCache: async (url, data, schemaVersion) => {
    try {
      let h=0; for (let i=0;i<url.length;i++){ h=((h<<5)-h)+url.charCodeAt(i); h|=0; }
      await chrome.storage.session.set({ [`cache_${h}`]: { ...data, schemaVersion, timestamp: Date.now() } });
    } catch(e){}
  },
});

export const createLocalStorage = (chrome) => ({
  get: async (key) => { try { return await chrome.storage.local.get(key); } catch { return {}; } },
  set: async (obj) => { try { await chrome.storage.local.set(obj); } catch {} },
});
