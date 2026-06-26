/**
 * MessageRouter.js
 * Bộ điều phối message trung tâm. Tất cả chrome.runtime.onMessage đi qua đây.
 * Không chứa business logic. Chỉ map type → handler.
 */

const _handlers = new Map();

export const MessageRouter = {
  /**
   * Đăng ký handler cho 1 message type
   * @param {string} type
   * @param {(request, sender) => Promise<any>} handler - trả về Promise<kết quả>
   */
  register(type, handler) {
    _handlers.set(type, handler);
  },

  /**
   * Gắn vào chrome.runtime.onMessage — gọi 1 lần duy nhất khi khởi tạo
   */
  listen() {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      const type = request.type || request.action;
      const handler = _handlers.get(type);
      if (!handler) return false; // Không xử lý, không giữ channel mở

      // Giữ channel mở cho async handler
      handler(request, sender)
        .then((result) => {
          try { sendResponse(result ?? { ok: true }); } catch (_) {}
        })
        .catch((err) => {
          try { sendResponse({ ok: false, error: err?.message || 'Unknown error' }); } catch (_) {}
        });

      return true; // Giữ channel mở
    });
  },
};
