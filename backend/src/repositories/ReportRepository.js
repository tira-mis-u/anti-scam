/**
 * ReportRepository – Data Access Layer cho collection 'reports'.
 * Bọc các query MongoDB để tách biệt logic business khỏi database.
 */

const { logger } = require('../utils/Logger');

let _db = null;

/**
 * Initialize with a Mongo db handle.
 * @param {import('mongodb').Db} db 
 */
function init(db) {
    _db = db;
}

function getCollection() {
    if (!_db) throw new Error('ReportRepository not initialized. Call init(db) first.');
    return _db.collection('reports');
}

/**
 * Insert a new report document.
 * @param {object} reportDoc 
 * @returns {Promise<import('mongodb').InsertOneResult>}
 */
async function insertReport(reportDoc) {
    const col = getCollection();
    try {
        return await col.insertOne(reportDoc);
    } catch (err) {
        logger.error('ReportRepository.insertReport', 'MongoDB insertOne failed', err);
        throw err;
    }
}

/**
 * Check if a report already exists for this device+domain combo.
 * @param {string} deviceFingerprint 
 * @param {string} domain 
 * @returns {Promise<boolean>}
 */
async function hasExistingReport(deviceFingerprint, domain) {
    const col = getCollection();
    const count = await col.countDocuments({ deviceFingerprint, domain });
    return count > 0;
}

module.exports = { init, insertReport, hasExistingReport };
