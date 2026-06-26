/**
 * Shared validation logic (mirrors the frontend Validation.js).
 * Keep both in sync when changing validation rules.
 */

const REPORT_CATEGORIES = new Set([
    'phishing_login',
    'scam_fraud',
    'malware',
    'fake_store',
    'spam',
    'suspicious_website',
    'official_brand',
    'bank_finance',
    'e_commerce',
    'social_media',
    'payment_gateway',
    'educational',
    'trusted_service',
    'other'
]);

const MAX_URL_LENGTH = 1000;
const MAX_DESCRIPTION_LENGTH = 1000;
const MIN_DESCRIPTION_LENGTH = 20;
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_MIME_TYPES = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/webp']);

/**
 * Escape HTML to prevent XSS in stored strings.
 * @param {string} str 
 */
function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/**
 * Normalize a hostname (remove www prefix, lowercase).
 * @param {string} hostname 
 */
function normalizeHostname(hostname) {
    return String(hostname || '').toLowerCase().replace(/^www\./, '').trim();
}

/**
 * Validate a report payload from the request body.
 * @param {object} body 
 * @returns {{ error: string }|{ url, domain, category, description }} 
 */
function validateReportPayload(body) {
    const urlValue = String(body.url || '').trim();
    if (!urlValue || urlValue.length > MAX_URL_LENGTH) {
        return { error: 'URL không hợp lệ.' };
    }

    let parsed;
    try {
        parsed = new URL(urlValue);
    } catch (_) {
        return { error: 'URL không hợp lệ.' };
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
        return { error: 'Chỉ hỗ trợ báo cáo cho trang web http hoặc https.' };
    }

    const domainFromUrl = normalizeHostname(parsed.hostname);
    const domainFromBody = normalizeHostname(String(body.domain || ''));
    const domain = domainFromBody || domainFromUrl;

    // Domain in body must match URL hostname (or be a parent domain)
    if (domainFromBody && domainFromBody !== domainFromUrl && !domainFromUrl.endsWith('.' + domainFromBody)) {
        return { error: 'Domain không khớp với URL.' };
    }

    if (!domain) return { error: 'Domain không hợp lệ.' };

    const category = String(body.category || '').trim();
    if (!category) return { error: 'Vui lòng chọn loại báo cáo.' };
    if (!REPORT_CATEGORIES.has(category) && !category.startsWith('other:')) {
        return { error: 'Loại báo cáo không hợp lệ.' };
    }

    const description = escapeHtml(String(body.description || '').trim());
    if (description.length < MIN_DESCRIPTION_LENGTH) {
        return { error: 'Mô tả phải có tối thiểu 20 ký tự.' };
    }
    if (description.length > MAX_DESCRIPTION_LENGTH) {
        return { error: 'Mô tả không được vượt quá 1000 ký tự.' };
    }

    return {
        url: parsed.href,
        domain,
        category: escapeHtml(category),
        description
    };
}

module.exports = {
    REPORT_CATEGORIES,
    ALLOWED_MIME_TYPES,
    MAX_FILE_SIZE,
    validateReportPayload,
    escapeHtml,
    normalizeHostname
};
