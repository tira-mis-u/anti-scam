/**
 * Backend ReportService – business logic cho việc xử lý báo cáo.
 * 
 * Chịu trách nhiệm:
 *  1. Lưu file ảnh qua StorageProvider
 *  2. Lưu document vào MongoDB qua ReportRepository
 *  3. Nếu Mongo fail, rollback bằng cách xóa ảnh đã lưu
 *  4. Escape XSS và sanitize tất cả dữ liệu trước khi lưu
 */

const crypto = require('crypto');
const { storageProvider } = require('./StorageProvider');
const reportRepository = require('../repositories/ReportRepository');
const { validateFileSignature } = require('../utils/MagicBytes');
const { escapeHtml } = require('../utils/Validation');
const { logger } = require('../utils/Logger');

/**
 * Builds a device fingerprint from request data.
 * Does NOT include IP address (privacy-preserving).
 */
function buildDeviceFingerprint(deviceId, userAgent, acceptLanguage, browserLanguage) {
    const raw = [
        String(deviceId || ''),
        String(userAgent || ''),
        String(acceptLanguage || ''),
        String(browserLanguage || ''),
    ].join('|');
    return crypto.createHash('sha256').update(raw).digest('hex');
}

/**
 * Saves a report to the database, with image storage and rollback support.
 * 
 * @param {object} options
 * @param {object} options.validated   - Validated fields from validateReportPayload()
 * @param {object} options.file        - The uploaded file (from multer): { buffer, mimetype, originalname }
 * @param {object} options.meta        - Extra metadata from the request body
 * @param {string} options.ip          - The client IP address
 * @param {object} options.headers     - Request headers
 * @returns {Promise<{ reportId: string, domain: string }>}
 */
async function saveReport({ validated, file, meta, ip, headers }) {
    let screenshotUrl = '';

    // 1. Validate file signature (magic bytes) before storing
    if (file && file.buffer) {
        const { valid, detectedMime } = validateFileSignature(file.buffer, file.mimetype);
        if (!valid) {
            logger.warn('ReportService.saveReport', `Magic bytes mismatch: claimed=${file.mimetype}, detected=${detectedMime}`);
            throw Object.assign(new Error('Định dạng ảnh không được hỗ trợ hoặc nội dung file không khớp.'), { statusCode: 400 });
        }

        // 2. Upload image
        try {
            screenshotUrl = await storageProvider.upload(file.buffer, detectedMime || file.mimetype);
        } catch (uploadErr) {
            logger.error('ReportService.saveReport', 'StorageProvider.upload failed', uploadErr);
            throw Object.assign(new Error('Không thể lưu ảnh báo cáo. Vui lòng thử lại.'), { statusCode: 500 });
        }
    }

    // 3. Build device fingerprint (no IP)
    const deviceFingerprint = buildDeviceFingerprint(
        meta.deviceId,
        headers['user-agent'] || meta.userAgent,
        headers['accept-language'],
        meta.browserLanguage
    );

    const now = new Date();
    const reportDoc = {
        url: validated.url,
        domain: validated.domain,
        category: validated.category,
        description: validated.description,
        screenshotUrl,
        status: 'pending',
        ip: String(ip || '').slice(0, 100),
        browserName: escapeHtml(String(meta.browserName || '').slice(0, 80)),
        userAgent: escapeHtml(String(headers['user-agent'] || meta.userAgent || '').slice(0, 500)),
        deviceFingerprint,
        extensionVersion: escapeHtml(String(meta.extensionVersion || '').slice(0, 50)),
        browserLanguage: escapeHtml(String(meta.browserLanguage || '').slice(0, 40)),
        pageTitle: escapeHtml(String(meta.pageTitle || '').slice(0, 300)),
        // GPS location (optional, from body)
        latitude: meta.latitude ? parseFloat(meta.latitude) : null,
        longitude: meta.longitude ? parseFloat(meta.longitude) : null,
        gpsAccuracy: meta.gpsAccuracy ? parseFloat(meta.gpsAccuracy) : null,
        locationSource: escapeHtml(String(meta.locationSource || 'unknown').slice(0, 20)),
        clientTimestamp: meta.timestamp ? new Date(meta.timestamp) : null,
        createdAt: now,
        updatedAt: now,
    };

    // 4. Insert into MongoDB with rollback on failure
    try {
        const result = await reportRepository.insertReport(reportDoc);
        logger.info('ReportService.saveReport', `Report saved: id=${result.insertedId} domain=${validated.domain}`);
        return { reportId: String(result.insertedId), domain: validated.domain };
    } catch (mongoErr) {
        // 5. ROLLBACK: Delete the uploaded image if MongoDB fails
        if (screenshotUrl) {
            logger.warn('ReportService.saveReport', 'MongoDB failed — rolling back uploaded image');
            await storageProvider.delete(screenshotUrl);
        }

        // Duplicate key error
        if (mongoErr && mongoErr.code === 11000) {
            throw Object.assign(new Error('Bạn đã gửi báo cáo cho tên miền này trước đó.'), { statusCode: 409 });
        }

        logger.error('ReportService.saveReport', 'MongoDB insertOne failed', mongoErr);
        throw Object.assign(new Error('Không thể gửi báo cáo. Vui lòng thử lại.'), { statusCode: 500 });
    }
}

module.exports = { saveReport };
