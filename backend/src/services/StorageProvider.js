/**
 * StorageProvider – abstraction cho việc lưu trữ file ảnh.
 * Mặc định: LocalFileStorage (lưu vào thư mục public/report-screenshots).
 * Có thể thay bằng S3Provider, CloudinaryProvider v.v. sau này.
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { logger } = require('../utils/Logger');

const UPLOAD_DIR = path.join(__dirname, '..', '..', 'public', 'report-screenshots');

class LocalFileStorage {
    /**
     * Saves a file buffer to disk and returns the public URL path.
     * @param {Buffer} buffer
     * @param {string} mimetype
     * @returns {Promise<string>} The relative public URL path
     */
    async upload(buffer, mimetype) {
        const extMap = {
            'image/png':  '.png',
            'image/jpeg': '.jpg',
            'image/jpg':  '.jpg',
            'image/webp': '.webp',
        };
        const ext = extMap[mimetype] || '.bin';

        await fs.promises.mkdir(UPLOAD_DIR, { recursive: true });

        const filename = `${Date.now()}-${crypto.randomBytes(12).toString('hex')}${ext}`;
        const fullPath = path.join(UPLOAD_DIR, filename);

        await fs.promises.writeFile(fullPath, buffer);
        logger.info('StorageProvider', `File saved: ${filename}`);
        return `/report-screenshots/${filename}`;
    }

    /**
     * Deletes a file by its public URL path (used for rollback).
     * @param {string} publicUrl  e.g. '/report-screenshots/abc.png'
     */
    async delete(publicUrl) {
        if (!publicUrl) return;
        try {
            const filename = path.basename(publicUrl);
            const fullPath = path.join(UPLOAD_DIR, filename);
            await fs.promises.unlink(fullPath);
            logger.info('StorageProvider', `File deleted (rollback): ${filename}`);
        } catch (err) {
            logger.warn('StorageProvider', `Could not delete file: ${publicUrl}`, err);
        }
    }
}

// Export a singleton instance
const storageProvider = new LocalFileStorage();
module.exports = { storageProvider };
