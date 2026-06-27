/**
 * Magic-bytes validator – kiểm tra header bytes của buffer ảnh để tránh file giả mạo extension.
 */

// Signature map: [extension, [byte offset, expected bytes]]
const SIGNATURES = [
    { ext: '.png',  mime: 'image/png',  sig: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
    { ext: '.jpg',  mime: 'image/jpeg', sig: [0xFF, 0xD8, 0xFF] },
    { ext: '.webp', mime: 'image/webp', sig: null, webp: true },
];

/**
 * @param {Buffer} buffer
 * @returns {string|null} The detected MIME type, or null if unknown.
 */
function detectMimeFromBuffer(buffer) {
    if (!buffer || buffer.length < 8) return null;

    // PNG
    if (
        buffer[0] === 0x89 && buffer[1] === 0x50 &&
        buffer[2] === 0x4E && buffer[3] === 0x47 &&
        buffer[4] === 0x0D && buffer[5] === 0x0A
    ) return 'image/png';

    // JPEG
    if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return 'image/jpeg';

    // WEBP: bytes 0-3 = "RIFF", bytes 8-11 = "WEBP"
    if (buffer.length >= 12) {
        const riff = buffer.slice(0, 4).toString('ascii');
        const webp = buffer.slice(8, 12).toString('ascii');
        if (riff === 'RIFF' && webp === 'WEBP') return 'image/webp';
    }

    return null;
}

/**
 * Validates that a file's contents match its claimed MIME type.
 * @param {Buffer} buffer
 * @param {string} claimedMime
 * @returns {{ valid: boolean, detectedMime: string|null }}
 */
function validateFileSignature(buffer, claimedMime) {
    const ALLOWED = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/webp']);

    const detected = detectMimeFromBuffer(buffer);

    if (!detected) return { valid: false, detectedMime: null };
    if (!ALLOWED.has(detected)) return { valid: false, detectedMime: detected };

    // jpg and jpeg are interchangeable
    const normalize = m => m === 'image/jpg' ? 'image/jpeg' : m;
    if (normalize(detected) !== normalize(claimedMime)) {
        return { valid: false, detectedMime: detected };
    }

    return { valid: true, detectedMime: detected };
}

module.exports = { detectMimeFromBuffer, validateFileSignature };
