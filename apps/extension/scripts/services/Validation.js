/**
 * Validation rules for Report
 */

export const REPORT_CATEGORIES = new Set([
  'phishing_login', 'scam_fraud', 'malware', 'fake_store', 'spam',
  'official_brand', 'bank_finance', 'e_commerce', 'social_media', 'payment_gateway', 'educational', 'trusted_service', 'other'
]);

export const MAX_URL_LENGTH = 1000;
export const MAX_DESCRIPTION_LENGTH = 1000;
export const MIN_DESCRIPTION_LENGTH = 20;
export const MAX_FILE_SIZE = 5 * 1024 * 1024;
export const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/jpg', 'image/webp']);

export class Validation {
  static validate(payload) {
    const { url, domain, category, description, file } = payload;

    if (!url || !domain) {
      return 'URL hoặc Domain không hợp lệ.';
    }

    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return 'Chỉ hỗ trợ báo cáo cho trang web http hoặc https.';
      }
    } catch (_) {
      return 'Định dạng URL không hợp lệ.';
    }

    if (!category) {
      return 'Vui lòng chọn loại báo cáo.';
    }

    if (!REPORT_CATEGORIES.has(category) && !category.startsWith('other:')) {
      return 'Loại báo cáo không hợp lệ.';
    }

    const desc = (description || '').trim();
    if (desc.length < 20) {
      return 'Mô tả phải có tối thiểu 20 ký tự.';
    }
    if (desc.length > 1000) {
      return 'Mô tả không được vượt quá 1000 ký tự.';
    }

    if (file) {
      if (file.size > MAX_FILE_SIZE) {
        return 'File ảnh vượt quá giới hạn 5MB.';
      }
      if (!ALLOWED_MIME_TYPES.has(file.type)) {
        return 'Định dạng ảnh không được hỗ trợ (chỉ nhận PNG, JPG, WEBP).';
      }
    }

    return null; // No errors
  }
}
