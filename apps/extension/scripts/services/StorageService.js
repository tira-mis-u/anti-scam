export class StorageService {
  static async get(key) {
    return new Promise((resolve) => {
      chrome.storage.local.get([key], (result) => resolve(result[key] || null));
    });
  }

  static async getMultiple(keys) {
    return new Promise((resolve) => {
      chrome.storage.local.get(keys, (result) => resolve(result));
    });
  }

  static async set(key, value) {
    return new Promise((resolve) => {
      chrome.storage.local.set({ [key]: value }, resolve);
    });
  }

  static async setMultiple(obj) {
    return new Promise((resolve) => {
      chrome.storage.local.set(obj, resolve);
    });
  }

  static async remove(key) {
    return new Promise((resolve) => {
      chrome.storage.local.remove([key], resolve);
    });
  }
}
