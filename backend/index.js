require('dotenv').config({ quiet: true });
const config = require('config');
const express = require('express');

const cors = require('cors');
const { status } = require('http-status');
const jwt = require('jsonwebtoken');
const rateLimit = require("express-rate-limit");

const path = require('path');
const fs = require('fs');
const morgan = require('morgan');
const axios = require('axios');
const multer = require('multer');

const { MongoClient, ObjectId } = require('mongodb');
const dns = require('dns').promises;
const crypto = require('crypto');
const querystring = require('querystring');


var refreshTokens = [];
const APP_VERSION = process.env.APP_VERSION || config.get("app.version");
const APP_PORT = process.env.PORT || config.get("app.port");
const APP_DOMAIN = process.env.APP_DOMAIN || config.get("app.domain");
const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET || 'dev-access-token-secret';
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET || 'dev-refresh-token-secret';
const maxLengthUrl = Number(process.env.MAX_LENGTH_URL || config.get("maxLengthUrl") || 1000);

const apiLimiter = rateLimit({
    windowMs: 55 * 60 * 1000,
    max: 100,
    message: "Too many request from this IP, please try again after an hour"
  });
const reportLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 20,
    message: { message: "Bạn gửi báo cáo quá nhanh. Vui lòng thử lại sau." }
  });


const app = express();
app.set('trust proxy', 1);
const isAdminRequestPath = (req) => req.path === '/admin' || req.path === '/admin/' || req.path.startsWith('/api/admin');

// Do not expose admin endpoints to cross-origin preflight handled by the global CORS middleware.
app.use((req, res, next) => {
    if (isAdminRequestPath(req) && req.method === 'OPTIONS') return res.sendStatus(404);
    next();
});

// Enable CORS for public extension APIs. Admin paths remove these headers below.
app.use(cors());
app.use((req, res, next) => {
    if (isAdminRequestPath(req)) {
        res.removeHeader('Access-Control-Allow-Origin');
        res.removeHeader('Access-Control-Allow-Credentials');
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Referrer-Policy', 'no-referrer');
        res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
    }
    next();
});
app.use(express.static('public'));

// Enable the use of request body parsing middleware
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
const upload = multer();
const REPORT_ALLOWED_MIME = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/webp']);
const reportUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (!REPORT_ALLOWED_MIME.has(file.mimetype)) return cb(new Error('UNSUPPORTED_REPORT_IMAGE'));
        cb(null, true);
    }
});

// Enable logging
const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' })
app.use(morgan('combined', { stream: accessLogStream }))
// Health check cho Render/Railway/VPS
app.get('/', (req, res) => res.status(200).send({ ok: true, service: 'AntiScam API' }));
app.get('/health', (req, res) => res.status(200).send({ ok: true, service: 'AntiScam API' }));
app.get(['/admin', '/admin/'], (req, res) => {
    if (process.env.ENABLE_ADMIN_UI !== 'true') return res.status(404).send('Not found');
    if (!isAdminIpAllowed(req)) return res.status(403).send('Forbidden');
    res.sendFile(path.join(__dirname, 'admin', 'index.html'));
});

// Classifier ML là tín hiệu phụ ở extension. Nếu chưa có model public trong backend,
// trả về null để extension bỏ qua ML an toàn thay vì fail request /classifier.json.
app.get('/classifier.json', (req, res) => res.status(200).json(null));

// Rate limit
app.use(`/${APP_VERSION}/rate`, apiLimiter);

// TODO: authentication / authorization functions
const clients = config.get("auth.clients");

const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, accessTokenSecret, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};


// Threat intelligence helpers (server-side only). API keys are read from
// environment variables, never from the browser extension.
const getCfg = (pathName, fallback = null) => {
    try { return config.has(pathName) ? config.get(pathName) : fallback; } catch (_) { return fallback; }
};
const normalizeHostname = (value) => {
    if (!value || typeof value !== 'string') return '';
    let raw = value.trim();
    try {
        if (!/^https?:\/\//i.test(raw)) raw = 'http://' + raw;
        return new URL(raw).hostname.toLowerCase().replace(/^www\./, '');
    } catch (_) {
        return raw.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].replace(/^www\./, '');
    }
};
const normalizeUrlInput = (value) => {
    if (!value || typeof value !== 'string') return '';
    const trimmed = value.trim();
    if (/^https?:\/\//i.test(trimmed)) return trimmed;
    return 'http://' + trimmed;
};

const LIST_COLLECTIONS = new Set(['blacklist', 'whitelist', 'pornlist']);
const isValidListType = (value) => LIST_COLLECTIONS.has(String(value || '').trim());
const normalizeListDocument = (item, listType = 'blacklist') => {
    const raw = typeof item === 'string' ? { url: item } : (item || {});
    const urlValue = String(raw.url || raw.domain || raw.host || '').trim();
    const domain = normalizeHostname(urlValue);
    if (!domain) return null;
    return {
        ...raw,
        url: urlValue,
        domain,
        type: listType,
        status: raw.status || 'active',
        source: raw.source || 'manual-import',
        updatedAt: new Date(),
        createdAt: raw.createdAt ? new Date(raw.createdAt) : new Date()
    };
};
const chunkArray = (items, size) => {
    const chunks = [];
    for (let i = 0; i < items.length; i += size) chunks.push(items.slice(i, i + size));
    return chunks;
};

const withTimeout = (promise, ms, fallback) => Promise.race([
    promise.catch(() => fallback),
    new Promise(resolve => setTimeout(() => resolve(fallback), ms))
]);
const rdapDate = (events, names) => {
    if (!Array.isArray(events)) return null;
    const wanted = names.map(x => String(x).toLowerCase());
    const e = events.find(ev => wanted.includes(String(ev.eventAction || '').toLowerCase()));
    return e && e.eventDate ? e.eventDate : null;
};
const getDomainAgeRdap = async (domain) => {
    if (!domain) return { ageDays: -1, source: 'rdap', status: 'invalid' };
    return withTimeout((async () => {
        const resp = await axios.get(`https://rdap.org/domain/${domain}`, { timeout: 4500 });
        const registrationDate = rdapDate(resp.data && resp.data.events, ['registration']);
        const expirationDate = rdapDate(resp.data && resp.data.events, ['expiration', 'expiry']);
        const ageDays = registrationDate ? Math.floor((Date.now() - new Date(registrationDate).getTime()) / (1000 * 60 * 60 * 24)) : -1;
        return { ageDays, registrationDate, expirationDate, source: 'rdap' };
    })(), 5000, { ageDays: -1, source: 'rdap', status: 'timeout' });
};
const urlIdForVirusTotal = (url) => Buffer.from(url).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const checkVirusTotal = async (url) => {
    const key = process.env.VIRUSTOTAL_API_KEY;
    if (!key) return null;
    return withTimeout((async () => {
        const vtUrl = `https://www.virustotal.com/api/v3/urls/${urlIdForVirusTotal(url)}`;
        const resp = await axios.get(vtUrl, { headers: { 'x-apikey': key }, timeout: 6500 });
        const stats = (((resp.data || {}).data || {}).attributes || {}).last_analysis_stats || {};
        const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
        return { source: 'VirusTotal', malicious, rawStats: stats, dangerous: malicious > 0 };
    })(), 7000, null);
};
const checkUrlHaus = async (url, domain) => withTimeout((async () => {
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    const urlResp = await axios.post('https://urlhaus-api.abuse.ch/v1/url/', querystring.stringify({ url }), { headers, timeout: 5500 }).catch(() => null);
    const hostResp = await axios.post('https://urlhaus-api.abuse.ch/v1/host/', querystring.stringify({ host: domain }), { headers, timeout: 5500 }).catch(() => null);
    const hitUrl = urlResp && urlResp.data && urlResp.data.query_status === 'ok';
    const hitHost = hostResp && hostResp.data && hostResp.data.query_status === 'ok';
    return { source: 'URLhaus', dangerous: !!(hitUrl || hitHost), urlStatus: urlResp && urlResp.data && urlResp.data.query_status, hostStatus: hostResp && hostResp.data && hostResp.data.query_status };
})(), 7000, null);
const checkThreatFox = async (domain) => withTimeout((async () => {
    const key = process.env.THREATFOX_API_KEY;
    const headers = { 'Content-Type': 'application/json' };
    if (key) headers['Auth-Key'] = key;
    const resp = await axios.post('https://threatfox-api.abuse.ch/api/v1/', { query: 'search_ioc', search_term: domain }, { headers, timeout: 5500 });
    return { source: 'ThreatFox', dangerous: resp.data && resp.data.query_status === 'ok', status: resp.data && resp.data.query_status };
})(), 6500, null);
const resolveIp = async (domain) => {
    try { const r = await dns.lookup(domain); return r && r.address; } catch (_) { return null; }
};
const checkAbuseIPDB = async (ip) => {
    const key = process.env.ABUSEIPDB_API_KEY;
    if (!key || !ip) return null;
    return withTimeout((async () => {
        const resp = await axios.get('https://api.abuseipdb.com/api/v2/check', {
            params: { ipAddress: ip, maxAgeInDays: 90 },
            headers: { Key: key, Accept: 'application/json' }, timeout: 5500
        });
        const score = resp.data && resp.data.data ? resp.data.data.abuseConfidenceScore : 0;
        return { source: 'AbuseIPDB', ip, abuseConfidenceScore: score || 0, dangerous: (score || 0) >= 50 };
    })(), 6500, null);
};
const checkMalwareReputation = async (url, domain, ip) => {
    const results = await Promise.all([
        checkVirusTotal(url), checkUrlHaus(url, domain), checkThreatFox(domain), checkAbuseIPDB(ip)
    ]);
    const sources = results.filter(r => r && r.dangerous).map(r => r.source);
    return { checked: results.filter(Boolean).map(r => r.source), sources, maliciousSources: sources.length, dangerous: sources.length > 0, details: results.filter(Boolean) };
};
const getDnsIntel = async (domain, ip) => withTimeout((async () => {
    const ns = await dns.resolveNs(domain).catch(() => []);
    const mx = await dns.resolveMx(domain).catch(() => []);
    let asn = null, asName = null, hosting = null;
    if (ip) {
        const bgp = await axios.get(`https://api.bgpview.io/ip/${ip}`, { timeout: 4500 }).catch(() => null);
        const prefixes = bgp && bgp.data && bgp.data.data && bgp.data.data.prefixes ? bgp.data.data.prefixes : [];
        const first = prefixes && prefixes[0];
        if (first && first.asn) { asn = first.asn.asn; asName = first.asn.name; hosting = first.name || first.description; }
    }
    const riskyAsn = getCfg('threatIntel.riskyAsn', []);
    const riskyNs = getCfg('threatIntel.riskyNameserverKeywords', ['bulletproof', 'fastflux', 'privacy', 'dynamic-dns']);
    const nsText = (ns || []).join(' ').toLowerCase();
    const riskyInfrastructure = (asn && riskyAsn.includes(asn)) || riskyNs.some(k => nsText.includes(String(k).toLowerCase()));
    return { ip, asn, asName, hosting, nameservers: ns, mxRecords: mx, riskyInfrastructure: !!riskyInfrastructure };
})(), 6500, { ip, asn: null, nameservers: [], mxRecords: [], riskyInfrastructure: false });
const getCommunityReportSummary = async (domain) => {
    try {
        if (!db) return { reportCount: 0 };
        const approvedQuery = { domain, status: 'approved' };
        const count = await db.collection('reports').countDocuments(approvedQuery);
        const latest = await db.collection('reports').find(approvedQuery).sort({ reviewedAt: -1, createdAt: -1 }).limit(3).toArray();
        return { reportCount: count, latest: latest.map(x => ({ category: x.category, description: x.description, time: x.createdAt })) };
    } catch (_) { return { reportCount: 0 }; }
};

const REPORT_CATEGORIES = new Set([
    'phishing_login',
    'scam_fraud',
    'malware',
    'fake_store',
    'spam',
    'suspicious_website',
    'other'
]);

const firstHeaderValue = (value) => Array.isArray(value) ? value[0] : value;
const normalizeClientIp = (value) => {
    let ip = String(firstHeaderValue(value) || '').split(',')[0].trim();
    if (!ip) return '';
    ip = ip.replace(/^::ffff:/, '').trim();
    if (ip.startsWith('[')) ip = ip.slice(1).split(']')[0];
    return ip;
};
const getClientIp = (req) => {
    const candidates = [
        req.headers['cf-connecting-ip'],
        req.headers['x-real-ip'],
        Array.isArray(req.ips) && req.ips.length ? req.ips[0] : '',
        req.headers['x-forwarded-for'],
        req.ip,
        req.socket && req.socket.remoteAddress,
        req.connection && req.connection.remoteAddress
    ];
    return candidates.map(normalizeClientIp).find(Boolean) || '';
};
const getAdminAllowedIps = () => String(process.env.ADMIN_ALLOWED_IPS || '')
    .split(',')
    .map(x => x.trim())
    .filter(Boolean);
const isAdminIpAllowed = (req) => {
    const allowedIps = getAdminAllowedIps();
    if (!allowedIps.length) return true;
    return allowedIps.includes(getClientIp(req));
};

const isPrivateIp = (ip) => /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|::1|localhost)/.test(String(ip || ''));

const lookupGeoIp = async (ip) => {
    try {
        if (!ip || isPrivateIp(ip)) return { country: '', region: '', city: '' };
        const resp = await axios.get(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,regionName,city`, { timeout: 2500 });
        if (!resp.data || resp.data.status !== 'success') return { country: '', region: '', city: '' };
        return { country: resp.data.country || '', region: resp.data.regionName || '', city: resp.data.city || '' };
    } catch (_) {
        return { country: '', region: '', city: '' };
    }
};

const buildDeviceFingerprint = (req, ip) => {
    const raw = [
        req.body && req.body.deviceId || '',
        req.headers['user-agent'] || '',
        req.headers['accept-language'] || '',
        req.body && req.body.browserLanguage || '',
        ip || ''
    ].join('|');
    return crypto.createHash('sha256').update(raw).digest('hex');
};

const validateReportPayload = (body) => {
    const urlValue = String(body.url || '').trim();
    let parsed;
    try { parsed = new URL(urlValue); } catch (_) { return { error: 'URL không hợp lệ.' }; }
    if (!['http:', 'https:'].includes(parsed.protocol)) return { error: 'URL không hợp lệ.' };
    if (urlValue.length > maxLengthUrl) return { error: 'URL không hợp lệ.' };

    const domain = normalizeHostname(body.domain || parsed.hostname);
    if (!domain || domain !== normalizeHostname(parsed.hostname)) return { error: 'URL không hợp lệ.' };

    const category = String(body.category || '').trim();
    if (!REPORT_CATEGORIES.has(category)) return { error: 'Vui lòng chọn loại báo cáo.' };

    const description = String(body.description || '').trim();
    if (description.length < 20) return { error: 'Mô tả phải có tối thiểu 20 ký tự.' };
    if (description.length > 1000) return { error: 'Mô tả không được vượt quá 1000 ký tự.' };

    return { url: parsed.href, domain, category, description };
};

const validateAdminReportPayload = (body) => {
    const urlValue = String(body.url || '').trim();
    let parsed;
    try { parsed = new URL(/^https?:\/\//i.test(urlValue) ? urlValue : 'https://' + urlValue); }
    catch (_) { return { error: 'URL không hợp lệ.' }; }
    if (!['http:', 'https:'].includes(parsed.protocol)) return { error: 'URL không hợp lệ.' };
    if (parsed.href.length > maxLengthUrl) return { error: 'URL quá dài.' };

    const urlDomain = normalizeHostname(parsed.hostname);
    const providedDomain = normalizeHostname(body.domain || '');
    const domain = providedDomain || urlDomain;
    if (!domain) return { error: 'Domain không hợp lệ.' };
    if (providedDomain && providedDomain !== urlDomain && !urlDomain.endsWith('.' + providedDomain)) {
        return { error: 'Domain phải trùng hostname của URL hoặc là domain cha của hostname.' };
    }

    const category = String(body.category || '').trim();
    if (!REPORT_CATEGORIES.has(category)) return { error: 'Vui lòng chọn loại báo cáo.' };

    const description = String(body.description || '').trim();
    if (description.length < 5) return { error: 'Mô tả phải có tối thiểu 5 ký tự.' };
    if (description.length > 1000) return { error: 'Mô tả không được vượt quá 1000 ký tự.' };

    const manualAction = String(body.action || body.decision || 'pending').trim();
    if (manualAction !== 'pending' && !ADMIN_DECISIONS.has(manualAction)) {
        return { error: 'Action phải là pending, blacklist, whitelist hoặc pornlist.' };
    }

    return { url: parsed.href, domain, category, description, action: manualAction };
};

const saveReportScreenshot = async (file) => {
    if (!file) return '';
    const extMap = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/jpg': '.jpg', 'image/webp': '.webp' };
    const ext = extMap[file.mimetype] || path.extname(file.originalname || '').toLowerCase();
    if (!['.png', '.jpg', '.jpeg', '.webp'].includes(ext)) throw new Error('UNSUPPORTED_REPORT_IMAGE');
    const uploadDir = path.join(__dirname, 'public', 'report-screenshots');
    await fs.promises.mkdir(uploadDir, { recursive: true });
    const filename = `${Date.now()}-${crypto.randomBytes(12).toString('hex')}${ext === '.jpeg' ? '.jpg' : ext}`;
    await fs.promises.writeFile(path.join(uploadDir, filename), file.buffer);
    return `/report-screenshots/${filename}`;
};

// Admin authentication, moderation and list-management helpers.
// Source code is public; only environment secrets, admin passwords and cookies
// are private. Never put admin secrets in the browser extension/frontend.
const ADMIN_COOKIE_NAME = process.env.ADMIN_COOKIE_NAME || 'admin_session';
const ADMIN_SESSION_TTL_MS = Number(process.env.ADMIN_SESSION_TTL_MS || 8 * 60 * 60 * 1000);
const isAdminApiEnabled = () => process.env.ENABLE_ADMIN_API === 'true';
const ADMIN_ROLES = new Set(['admin', 'moderator', 'viewer']);
const ADMIN_DECISIONS = new Set(['blacklist', 'whitelist', 'pornlist']);
const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Bạn đăng nhập sai quá nhiều lần. Vui lòng thử lại sau.' }
});

const parseCookies = (req) => {
    const header = String(req.headers.cookie || '');
    return header.split(';').reduce((acc, part) => {
        const index = part.indexOf('=');
        if (index === -1) return acc;
        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();
        if (!key) return acc;
        try { acc[key] = decodeURIComponent(value); } catch (_) { acc[key] = value; }
        return acc;
    }, {});
};
const hashSessionToken = (token) => crypto.createHash('sha256').update(String(token || '')).digest('hex');
const normalizeAdminEmail = (email) => String(email || '').trim().toLowerCase();
const scryptAsync = (password, salt, keyLength, options) => new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keyLength, options, (err, derivedKey) => err ? reject(err) : resolve(derivedKey));
});
const hashPassword = async (password) => {
    const salt = crypto.randomBytes(16).toString('hex');
    const params = { N: 16384, r: 8, p: 1 };
    const key = await scryptAsync(String(password), salt, 64, params);
    return `scrypt$${params.N}$${params.r}$${params.p}$${salt}$${key.toString('hex')}`;
};
const verifyPassword = async (password, storedHash) => {
    const parts = String(storedHash || '').split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
    const [, N, r, p, salt, keyHex] = parts;
    const expected = Buffer.from(keyHex, 'hex');
    const actual = await scryptAsync(String(password), salt, expected.length, { N: Number(N), r: Number(r), p: Number(p) });
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
};
const sanitizeAdmin = (admin) => admin ? ({
    id: String(admin._id),
    email: admin.email,
    role: admin.role,
    status: admin.status,
    createdAt: admin.createdAt,
    lastLoginAt: admin.lastLoginAt
}) : null;
const requireDb = (req, res, next) => {
    if (!db) return res.status(status.SERVICE_UNAVAILABLE).send({ message: 'Database is not ready.' });
    next();
};
const requireAdminApiEnabled = (req, res, next) => {
    if (!isAdminApiEnabled()) return res.status(status.NOT_FOUND).send({ message: 'Not found' });
    if (!isAdminIpAllowed(req)) return res.status(status.FORBIDDEN).send({ message: 'Forbidden' });
    next();
};
const requireAdminCsrf = (req, res, next) => {
    const providedToken = String(req.headers['x-csrf-token'] || '');
    const expectedToken = String(req.adminSession && req.adminSession.csrfToken || '');
    if (!providedToken || !expectedToken || providedToken !== expectedToken) {
        return res.status(status.FORBIDDEN).send({ message: 'CSRF token không hợp lệ.' });
    }
    next();
};
const requireAdmin = async (req, res, next) => {
    try {
        if (!db) return res.status(status.SERVICE_UNAVAILABLE).send({ message: 'Database is not ready.' });
        const cookies = parseCookies(req);
        const token = cookies[ADMIN_COOKIE_NAME];
        if (!token) return res.status(status.UNAUTHORIZED).send({ message: 'Unauthorized' });

        const tokenHash = hashSessionToken(token);
        const session = await db.collection('admin_sessions').findOne({
            tokenHash,
            revokedAt: null,
            expiresAt: { $gt: new Date() }
        });
        if (!session) return res.status(status.UNAUTHORIZED).send({ message: 'Session expired' });

        const admin = await db.collection('admin_users').findOne({ _id: session.adminId, status: 'active' });
        if (!admin) return res.status(status.FORBIDDEN).send({ message: 'Admin disabled' });

        req.admin = sanitizeAdmin(admin);
        req.adminRaw = admin;
        req.adminSession = session;
        db.collection('admin_sessions').updateOne({ _id: session._id }, { $set: { lastSeenAt: new Date() } }).catch(() => {});
        next();
    } catch (err) {
        console.log('admin auth error', err && err.message);
        res.status(status.UNAUTHORIZED).send({ message: 'Unauthorized' });
    }
};
const requireRole = (...roles) => (req, res, next) => {
    if (!req.admin || !roles.includes(req.admin.role)) return res.status(status.FORBIDDEN).send({ message: 'Forbidden' });
    next();
};
const writeAuditLog = async (req, action, targetType, targetId, metadata = {}) => {
    try {
        if (!db) return;
        await db.collection('audit_logs').insertOne({
            adminId: req.adminRaw && req.adminRaw._id,
            adminEmail: req.admin && req.admin.email,
            action,
            targetType,
            targetId,
            metadata,
            ip: getClientIp(req),
            userAgent: String(req.headers['user-agent'] || '').slice(0, 500),
            createdAt: new Date()
        });
    } catch (err) {
        console.log('audit log error', err && err.message);
    }
};
const escapeRegex = (value) => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const parsePositiveInt = (value, fallback, max = 200) => {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
    return Math.min(parsed, max);
};
const objectIdFromParam = (value) => ObjectId.isValid(String(value || '')) ? new ObjectId(String(value)) : null;
const getActiveListFilter = () => ({ $or: [{ status: { $exists: false } }, { status: 'active' }] });

const bootstrapInitialAdmin = async () => {
    const count = await db.collection('admin_users').countDocuments({});
    if (count > 0) return;

    const email = normalizeAdminEmail(process.env.ADMIN_EMAIL || process.env.ADMIN_INITIAL_EMAIL);
    const password = process.env.ADMIN_PASSWORD || process.env.ADMIN_INITIAL_PASSWORD;
    if (!email || !password) {
        console.warn('No admin user exists. Set ADMIN_EMAIL and ADMIN_PASSWORD once to bootstrap the first admin.');
        return;
    }
    if (String(password).length < 12) {
        console.warn('ADMIN_PASSWORD must be at least 12 characters. Initial admin was not created.');
        return;
    }

    const now = new Date();
    await db.collection('admin_users').insertOne({
        email,
        passwordHash: await hashPassword(password),
        role: 'admin',
        status: 'active',
        source: 'env-bootstrap',
        createdAt: now,
        updatedAt: now
    });
    console.info('Bootstrapped initial admin user:', email);
};

const buildListPayload = (body, type, actorSource = 'manual-admin') => {
    const rawUrl = String(body.url || body.domain || '').trim();
    const domain = normalizeHostname(rawUrl);
    if (!domain) return { error: 'URL/domain không hợp lệ.' };
    const url = rawUrl || domain;
    return {
        url,
        domain,
        type,
        status: ['active', 'inactive'].includes(String(body.status || '').trim()) ? String(body.status).trim() : 'active',
        source: String(body.source || actorSource).slice(0, 80),
        reason: String(body.reason || body.reviewNote || '').slice(0, 500)
    };
};

const approveReportDocument = async (req, report, decision, reviewNote = '') => {
    const now = new Date();
    const listUrl = String(report.url || report.domain || '').trim();
    const listDomain = normalizeHostname(report.domain || listUrl);
    if (!listDomain) throw new Error('INVALID_REPORT_DOMAIN');

    const listResult = await db.collection(decision).updateOne(
        { domain: listDomain },
        {
            $set: {
                url: listUrl || listDomain,
                domain: listDomain,
                type: decision,
                status: 'active',
                source: report.source === 'manual-admin' ? 'manual-admin-report' : 'community-report',
                reason: reviewNote || report.description || '',
                updatedBy: req.admin.email,
                updatedAt: now
            },
            $addToSet: { evidenceReportIds: report._id },
            $setOnInsert: { createdAt: now, createdBy: req.admin.email }
        },
        { upsert: true }
    );
    const listEntry = await db.collection(decision).findOne({ domain: listDomain });
    await db.collection('reports').updateOne(
        { _id: report._id },
        {
            $set: {
                status: 'approved',
                decision,
                reviewedBy: req.admin.email,
                reviewedById: req.adminRaw._id,
                reviewedAt: now,
                reviewNote,
                listEntryId: listEntry && listEntry._id,
                updatedAt: now
            }
        }
    );
    return { listEntry, listResult, domain: listDomain };
};

const importListHandler = async (req, res) => {
    const type = String(req.params.typelist || '').trim();
    if (!isValidListType(type)) return res.status(status.BAD_REQUEST).send(`${type} is not a valid type of list`);
    if (!req.file || !req.file.buffer) return res.status(status.BAD_REQUEST).send({ message: 'file is required' });

    let parsed;
    try { parsed = JSON.parse(req.file.buffer.toString()); }
    catch (_) { return res.status(status.BAD_REQUEST).send({ message: 'File JSON không hợp lệ.' }); }

    const rows = Array.isArray(parsed) ? parsed : [parsed];
    const normalizedRows = rows.map(item => normalizeListDocument({ ...(typeof item === 'string' ? { url: item } : item), source: (item && item.source) || 'admin-import' }, type)).filter(Boolean);
    const chunkData = chunkArray(normalizedRows, 1000);
    let upserted = 0;

    for (let i = 0; i < chunkData.length; i++) {
        try {
            const ops = chunkData[i].map(item => ({
                updateOne: {
                    filter: { domain: item.domain },
                    update: { $set: { ...item, updatedAt: new Date() }, $setOnInsert: { createdAt: item.createdAt || new Date() } },
                    upsert: true
                }
            }));
            if (ops.length) {
                const result = await db.collection(type).bulkWrite(ops, { ordered: false });
                upserted += (result.upsertedCount || 0) + (result.modifiedCount || 0);
            }
        } catch(err) {
            console.log(`${type} import error`, err && err.message);
        }
    }

    await writeAuditLog(req, 'import_list', type, null, { type, received: rows.length, valid: normalizedRows.length, upserted });
    res.status(status.OK).send({ message: 'INSERT SUCCESS', type, received: rows.length, valid: normalizedRows.length, upserted });
};

app.post(`/${APP_VERSION}/initSession`, (req, res) => {
    const { app, secret } = req.body;
    const client = clients.find(u => { return u.app === app && u.secret === secret });

    if (client) {
        //TODO: generate an access token
        const accessToken = jwt.sign({
            username: client.app,
            role: client.role
        },
        accessTokenSecret,
        {
            expiresIn: config.get("auth.expiration")
        });

        const refreshToken = jwt.sign({
            username: client.app,
            role: client.role
            },
            refreshTokenSecret);

        refreshTokens.push(refreshToken);


        res.json({
            version: APP_VERSION,
            requestedOn: new Date(),
            token: accessToken,
            refresh: refreshToken,
        });
    }
    else {
        res.status(status.FORBIDDEN).send({
            version: APP_VERSION,
            requestedOn: new Date(),
            message: `Client application credential incorrect. ${status['401_MESSAGE']}`});
    }
});

app.post(`/${APP_VERSION}/token`, (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.sendStatus(401);
    }

    if (!refreshTokens.includes(token)) {
        return res.sendStatus(403);
    }

    jwt.verify(token, refreshTokenSecret, (err, client) => {
        if (err) {
            return res.sendStatus(403);
        }

        const accessToken = jwt.sign({
            username: client.app,
            role: client.role
        },
        accessTokenSecret,
        {
            expiresIn: config.get("auth.expiration")
        });

        res.json({
            status: status.OK,
            version: APP_VERSION,
            requestedOn: new Date(),
            token: accessToken
        });
    });
});

app.post(`/${APP_VERSION}/closeSession`, (req, res) => {
    const { token } = req.body;
    refreshTokens = refreshTokens.filter(t => t !== token);

    res.status(status.OK).send({
        status: status.OK,
        version: APP_VERSION,
        requestedOn: new Date(),
        message: "Session closed"
      });
});

app.get(`/${APP_VERSION}/ping`, function(req, res){
  res.status(status.OK).send({
      status: status.OK,
      version: APP_VERSION,
      requestedOn: new Date(),
    });
})

app.post(`/${APP_VERSION}/rate`, authenticateJWT, function(req, res) {
    //TODO: store request to file
    const params = {  time: new Date(), ...req.body, ip: req.ip};
    const msg = validateSubmitting(params);
    if (msg.indexOf("ok") == -1) {
        res.status(status.BAD_REQUEST).send({
            status: status.BAD_REQUEST,
            version: APP_VERSION,
            requestedOn: new Date(),
            "message": msg
        });
    }
    else {
        if (params) {
            db.collection("rating").insertOne(params);
        }

        res.status(status.OK).send({
            status: status.OK,
            version: APP_VERSION,
            requestedOn: new Date(),
            "message":"ok"
        });
    }
})


app.get(`/${APP_VERSION}/intel`, async function(req, res) {
    try {
        const rawUrl = req.query.url || req.query.domain;
        if (!rawUrl || String(rawUrl).length > maxLengthUrl) return res.sendStatus(status.BAD_REQUEST);
        const url = normalizeUrlInput(String(rawUrl));
        const domain = normalizeHostname(String(rawUrl));
        if (!domain) return res.sendStatus(status.BAD_REQUEST);
        const ip = await resolveIp(domain);
        const [domainAge, malware, dnsIntel, community] = await Promise.all([
            getDomainAgeRdap(domain),
            checkMalwareReputation(url, domain, ip),
            getDnsIntel(domain, ip),
            getCommunityReportSummary(domain)
        ]);
        res.status(status.OK).send({
            status: status.OK,
            version: APP_VERSION,
            requestedOn: new Date(),
            domain,
            domainAge,
            malware,
            dns: dnsIntel,
            community
        });
    } catch (err) {
        console.log('intel error', err && err.message);
        res.status(status.OK).send({ status: status.OK, version: APP_VERSION, requestedOn: new Date(), malware: { dangerous: false, sources: [] }, community: { reportCount: 0 } });
    }
});

app.post('/api/report', reportLimiter, function(req, res, next) {
    reportUpload.single('screenshot')(req, res, function(err) {
        if (!err) return next();
        if (err.code === 'LIMIT_FILE_SIZE') return res.status(status.BAD_REQUEST).send({ message: 'File vượt quá 5MB.' });
        if (err.message === 'UNSUPPORTED_REPORT_IMAGE') return res.status(status.BAD_REQUEST).send({ message: 'Định dạng ảnh không được hỗ trợ.' });
        return res.status(status.BAD_REQUEST).send({ message: 'Không thể gửi báo cáo. Vui lòng thử lại.' });
    });
}, async function(req, res) {
    try {
        const validated = validateReportPayload(req.body || {});
        if (validated.error) return res.status(status.BAD_REQUEST).send({ message: validated.error });
        if (!db) return res.status(status.SERVICE_UNAVAILABLE).send({ message: 'Không thể gửi báo cáo. Vui lòng thử lại.' });

        const ip = getClientIp(req);
        const geo = await lookupGeoIp(ip);
        const deviceFingerprint = buildDeviceFingerprint(req, ip);
        const now = new Date();
        const screenshotUrl = await saveReportScreenshot(req.file);

        const report = {
            url: validated.url,
            domain: validated.domain,
            category: validated.category,
            description: validated.description,
            screenshotUrl,
            status: 'pending',
            ip,
            country: geo.country,
            region: geo.region,
            city: geo.city,
            deviceFingerprint,
            extensionVersion: String(req.body.extensionVersion || '').slice(0, 50),
            browserName: String(req.body.browserName || '').slice(0, 80),
            browserLanguage: String(req.body.browserLanguage || '').slice(0, 40),
            userAgent: String(req.body.userAgent || req.headers['user-agent'] || '').slice(0, 500),
            pageTitle: String(req.body.pageTitle || '').slice(0, 300),
            clientTimestamp: req.body.timestamp ? new Date(req.body.timestamp) : null,
            createdAt: now,
            updatedAt: now
        };

        await db.collection('reports').insertOne(report);
        res.status(status.OK).send({
            status: status.OK,
            version: APP_VERSION,
            requestedOn: new Date(),
            message: 'Báo cáo đã được gửi thành công.',
            reportId: report._id,
            domain: report.domain
        });
    } catch (err) {
        if (err && err.code === 11000) {
            return res.status(status.CONFLICT).send({ message: 'Bạn đã gửi báo cáo cho tên miền này trước đó.' });
        }
        console.log('report error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể gửi báo cáo. Vui lòng thử lại.' });
    }
});

// Admin API. The UI at /admin uses these endpoints through httpOnly cookies.
app.use('/api/admin', requireAdminApiEnabled);

app.post('/api/admin/login', adminLoginLimiter, requireDb, async (req, res) => {
    try {
        const email = normalizeAdminEmail(req.body && req.body.email);
        const password = String(req.body && req.body.password || '');
        if (!email || !password) return res.status(status.UNAUTHORIZED).send({ message: 'Email hoặc mật khẩu không đúng.' });

        const admin = await db.collection('admin_users').findOne({ email, status: 'active' });
        if (!admin || !(await verifyPassword(password, admin.passwordHash))) {
            return res.status(status.UNAUTHORIZED).send({ message: 'Email hoặc mật khẩu không đúng.' });
        }

        const rawToken = crypto.randomBytes(32).toString('base64url');
        const csrfToken = crypto.randomBytes(32).toString('base64url');
        const tokenHash = hashSessionToken(rawToken);
        const now = new Date();
        const expiresAt = new Date(now.getTime() + ADMIN_SESSION_TTL_MS);
        const sessionDoc = {
            adminId: admin._id,
            tokenHash,
            csrfToken,
            ip: getClientIp(req),
            userAgent: String(req.headers['user-agent'] || '').slice(0, 500),
            createdAt: now,
            lastSeenAt: now,
            expiresAt,
            revokedAt: null
        };
        await db.collection('admin_sessions').insertOne(sessionDoc);
        await db.collection('admin_users').updateOne({ _id: admin._id }, { $set: { lastLoginAt: now, updatedAt: now } });

        const cookieSecure = process.env.ADMIN_COOKIE_SECURE ? process.env.ADMIN_COOKIE_SECURE === 'true' : process.env.NODE_ENV === 'production';
        res.cookie(ADMIN_COOKIE_NAME, rawToken, {
            httpOnly: true,
            secure: cookieSecure,
            sameSite: 'strict',
            maxAge: ADMIN_SESSION_TTL_MS,
            path: '/'
        });
        await writeAuditLog({ headers: req.headers, ips: req.ips, ip: req.ip, socket: req.socket, connection: req.connection, admin: sanitizeAdmin(admin), adminRaw: admin }, 'admin_login', 'admin_user', admin._id, {});
        res.status(status.OK).send({ ok: true, admin: sanitizeAdmin(admin), csrfToken, expiresAt });
    } catch (err) {
        console.log('admin login error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể đăng nhập.' });
    }
});

app.post('/api/admin/logout', requireAdmin, requireAdminCsrf, async (req, res) => {
    try {
        if (req.adminSession) {
            await db.collection('admin_sessions').updateOne({ _id: req.adminSession._id }, { $set: { revokedAt: new Date() } });
        }
        await writeAuditLog(req, 'admin_logout', 'admin_user', req.adminRaw && req.adminRaw._id, {});
        res.clearCookie(ADMIN_COOKIE_NAME, { path: '/' });
        res.status(status.OK).send({ ok: true });
    } catch (err) {
        console.log('admin logout error', err && err.message);
        res.status(status.OK).send({ ok: true });
    }
});

app.get('/api/admin/me', requireAdmin, (req, res) => {
    res.status(status.OK).send({ ok: true, admin: req.admin, csrfToken: req.adminSession && req.adminSession.csrfToken });
});

app.get('/api/admin/users', requireAdmin, requireRole('admin'), async (req, res) => {
    const users = await db.collection('admin_users')
        .find({})
        .project({ passwordHash: 0 })
        .sort({ createdAt: -1 })
        .toArray();
    res.status(status.OK).send({ items: users });
});

app.post('/api/admin/users', requireAdmin, requireAdminCsrf, requireRole('admin'), async (req, res) => {
    try {
        const email = normalizeAdminEmail(req.body && req.body.email);
        const password = String(req.body && req.body.password || '');
        const role = String(req.body && req.body.role || 'moderator').trim();
        if (!email || !email.includes('@')) return res.status(status.BAD_REQUEST).send({ message: 'Email không hợp lệ.' });
        if (!ADMIN_ROLES.has(role)) return res.status(status.BAD_REQUEST).send({ message: 'Role không hợp lệ.' });
        if (password.length < 12) return res.status(status.BAD_REQUEST).send({ message: 'Mật khẩu phải có tối thiểu 12 ký tự.' });
        const now = new Date();
        const doc = {
            email,
            passwordHash: await hashPassword(password),
            role,
            status: 'active',
            createdBy: req.admin.email,
            createdAt: now,
            updatedAt: now
        };
        await db.collection('admin_users').insertOne(doc);
        await writeAuditLog(req, 'create_admin_user', 'admin_user', doc._id, { email, role });
        delete doc.passwordHash;
        res.status(status.OK).send({ ok: true, item: doc });
    } catch (err) {
        if (err && err.code === 11000) return res.status(status.CONFLICT).send({ message: 'Email admin đã tồn tại.' });
        console.log('create admin user error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể tạo admin user.' });
    }
});

app.patch('/api/admin/users/:id', requireAdmin, requireAdminCsrf, requireRole('admin'), async (req, res) => {
    try {
        const _id = objectIdFromParam(req.params.id);
        if (!_id) return res.status(status.BAD_REQUEST).send({ message: 'ID không hợp lệ.' });
        const updates = { updatedAt: new Date(), updatedBy: req.admin.email };
        if ('role' in req.body) {
            const role = String(req.body.role || '').trim();
            if (!ADMIN_ROLES.has(role)) return res.status(status.BAD_REQUEST).send({ message: 'Role không hợp lệ.' });
            updates.role = role;
        }
        if ('status' in req.body) {
            const nextStatus = String(req.body.status || '').trim();
            if (!['active', 'disabled'].includes(nextStatus)) return res.status(status.BAD_REQUEST).send({ message: 'Status không hợp lệ.' });
            if (String(_id) === String(req.adminRaw._id) && nextStatus === 'disabled') return res.status(status.BAD_REQUEST).send({ message: 'Không thể tự disable tài khoản đang đăng nhập.' });
            updates.status = nextStatus;
        }
        if ('password' in req.body && String(req.body.password || '')) {
            const password = String(req.body.password || '');
            if (password.length < 12) return res.status(status.BAD_REQUEST).send({ message: 'Mật khẩu phải có tối thiểu 12 ký tự.' });
            updates.passwordHash = await hashPassword(password);
            updates.passwordChangedAt = new Date();
        }
        const shouldRevokeSessions = !!(updates.passwordHash || updates.status === 'disabled' || updates.role);
        const result = await db.collection('admin_users').updateOne({ _id }, { $set: updates });
        if (!result.matchedCount) return res.status(status.NOT_FOUND).send({ message: 'Không tìm thấy admin user.' });
        if (shouldRevokeSessions) {
            await db.collection('admin_sessions').updateMany(
                { adminId: _id, revokedAt: null },
                { $set: { revokedAt: new Date(), revokeReason: 'admin_user_updated' } }
            );
        }
        const item = await db.collection('admin_users').findOne({ _id }, { projection: { passwordHash: 0 } });
        await writeAuditLog(req, 'update_admin_user', 'admin_user', _id, { updates: { ...updates, passwordHash: updates.passwordHash ? '[changed]' : undefined } });
        res.status(status.OK).send({ ok: true, item });
    } catch (err) {
        console.log('update admin user error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể cập nhật admin user.' });
    }
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    try {
        const [pendingReports, approvedReports, rejectedReports, blacklistCount, whitelistCount, pornlistCount] = await Promise.all([
            db.collection('reports').countDocuments({ status: 'pending' }),
            db.collection('reports').countDocuments({ status: 'approved' }),
            db.collection('reports').countDocuments({ status: 'rejected' }),
            db.collection('blacklist').countDocuments(getActiveListFilter()),
            db.collection('whitelist').countDocuments(getActiveListFilter()),
            db.collection('pornlist').countDocuments(getActiveListFilter())
        ]);
        res.status(status.OK).send({ pendingReports, approvedReports, rejectedReports, blacklistCount, whitelistCount, pornlistCount });
    } catch (err) {
        console.log('admin stats error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể lấy thống kê.' });
    }
});

app.get('/api/admin/audit-logs', requireAdmin, requireRole('admin'), async (req, res) => {
    try {
        const limit = parsePositiveInt(req.query.limit, 50, 200);
        const page = parsePositiveInt(req.query.page, 1, 100000);
        const search = String(req.query.search || '').trim();
        const filter = {};
        if (search) {
            const regex = new RegExp(escapeRegex(search), 'i');
            filter.$or = [{ action: regex }, { adminEmail: regex }, { targetType: regex }];
        }
        const [total, items] = await Promise.all([
            db.collection('audit_logs').countDocuments(filter),
            db.collection('audit_logs').find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).toArray()
        ]);
        res.status(status.OK).send({ total, page, limit, items });
    } catch (err) {
        console.log('admin audit logs error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể lấy audit logs.' });
    }
});

app.get('/api/admin/reports', requireAdmin, async (req, res) => {
    try {
        const limit = parsePositiveInt(req.query.limit, 25, 100);
        const page = parsePositiveInt(req.query.page, 1, 100000);
        const reportStatus = String(req.query.status || 'pending').trim();
        const search = String(req.query.search || '').trim();
        const filter = {};
        if (reportStatus && reportStatus !== 'all') filter.status = reportStatus;
        if (search) {
            const regex = new RegExp(escapeRegex(search), 'i');
            filter.$or = [{ url: regex }, { domain: regex }, { description: regex }, { category: regex }];
        }
        const [total, items] = await Promise.all([
            db.collection('reports').countDocuments(filter),
            db.collection('reports').find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).toArray()
        ]);
        res.status(status.OK).send({ total, page, limit, items });
    } catch (err) {
        console.log('admin reports error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể lấy danh sách báo cáo.' });
    }
});

app.post('/api/admin/reports', requireAdmin, requireAdminCsrf, requireRole('admin', 'moderator'), async (req, res) => {
    try {
        const validated = validateAdminReportPayload(req.body || {});
        if (validated.error) return res.status(status.BAD_REQUEST).send({ message: validated.error });

        const now = new Date();
        const report = {
            url: validated.url,
            domain: validated.domain,
            category: validated.category,
            description: validated.description,
            screenshotUrl: '',
            status: 'pending',
            decision: '',
            source: 'manual-admin',
            submittedBy: 'admin',
            createdBy: req.admin.email,
            createdById: req.adminRaw._id,
            adminIp: getClientIp(req),
            ip: '',
            country: '',
            region: '',
            city: '',
            deviceFingerprint: crypto.createHash('sha256').update(`manual-admin|${req.adminRaw._id}|${validated.url}|${Date.now()}|${crypto.randomBytes(8).toString('hex')}`).digest('hex'),
            extensionVersion: 'admin-panel',
            browserName: 'admin-panel',
            browserLanguage: String(req.body.browserLanguage || '').slice(0, 40),
            userAgent: String(req.headers['user-agent'] || '').slice(0, 500),
            pageTitle: String(req.body.pageTitle || '').slice(0, 300),
            clientTimestamp: null,
            createdAt: now,
            updatedAt: now
        };

        await db.collection('reports').insertOne(report);
        let approval = null;
        if (validated.action !== 'pending') {
            approval = await approveReportDocument(req, report, validated.action, String(req.body.reviewNote || req.body.description || '').slice(0, 1000));
        }
        await writeAuditLog(req, 'create_manual_report', 'report', report._id, { domain: report.domain, action: validated.action, category: report.category });
        const savedReport = await db.collection('reports').findOne({ _id: report._id });
        res.status(status.OK).send({ ok: true, report: savedReport, listEntry: approval && approval.listEntry });
    } catch (err) {
        console.log('admin create report error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể tạo báo cáo thủ công.' });
    }
});

app.get('/api/admin/reports/:id', requireAdmin, async (req, res) => {
    const _id = objectIdFromParam(req.params.id);
    if (!_id) return res.status(status.BAD_REQUEST).send({ message: 'ID không hợp lệ.' });
    const report = await db.collection('reports').findOne({ _id });
    if (!report) return res.status(status.NOT_FOUND).send({ message: 'Không tìm thấy báo cáo.' });
    res.status(status.OK).send(report);
});

app.patch('/api/admin/reports/:id/approve', requireAdmin, requireAdminCsrf, requireRole('admin', 'moderator'), async (req, res) => {
    try {
        const _id = objectIdFromParam(req.params.id);
        if (!_id) return res.status(status.BAD_REQUEST).send({ message: 'ID không hợp lệ.' });
        const decision = String(req.body.decision || '').trim();
        if (!ADMIN_DECISIONS.has(decision)) return res.status(status.BAD_REQUEST).send({ message: 'Decision phải là blacklist, whitelist hoặc pornlist.' });

        const report = await db.collection('reports').findOne({ _id });
        if (!report) return res.status(status.NOT_FOUND).send({ message: 'Không tìm thấy báo cáo.' });

        const reviewNote = String(req.body.reviewNote || req.body.note || '').slice(0, 1000);
        let approval;
        try { approval = await approveReportDocument(req, report, decision, reviewNote); }
        catch (err) {
            if (err && err.message === 'INVALID_REPORT_DOMAIN') return res.status(status.BAD_REQUEST).send({ message: 'Domain của báo cáo không hợp lệ.' });
            throw err;
        }
        await writeAuditLog(req, 'approve_report', 'report', report._id, { decision, domain: approval.domain, listUpsertedId: approval.listResult.upsertedId || null, reviewNote });
        const updatedReport = await db.collection('reports').findOne({ _id });
        res.status(status.OK).send({ ok: true, report: updatedReport, listEntry: approval.listEntry });
    } catch (err) {
        console.log('admin approve report error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể duyệt báo cáo.' });
    }
});

app.patch('/api/admin/reports/:id/reject', requireAdmin, requireAdminCsrf, requireRole('admin', 'moderator'), async (req, res) => {
    try {
        const _id = objectIdFromParam(req.params.id);
        if (!_id) return res.status(status.BAD_REQUEST).send({ message: 'ID không hợp lệ.' });
        const now = new Date();
        const reviewNote = String(req.body.reviewNote || req.body.note || '').slice(0, 1000);
        const result = await db.collection('reports').updateOne(
            { _id },
            { $set: { status: 'rejected', decision: 'no_action', reviewedBy: req.admin.email, reviewedById: req.adminRaw._id, reviewedAt: now, reviewNote, updatedAt: now } }
        );
        if (!result.matchedCount) return res.status(status.NOT_FOUND).send({ message: 'Không tìm thấy báo cáo.' });
        await writeAuditLog(req, 'reject_report', 'report', _id, { reviewNote });
        res.status(status.OK).send({ ok: true });
    } catch (err) {
        console.log('admin reject report error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể từ chối báo cáo.' });
    }
});

app.patch('/api/admin/reports/:id/status', requireAdmin, requireAdminCsrf, requireRole('admin', 'moderator'), async (req, res) => {
    const _id = objectIdFromParam(req.params.id);
    if (!_id) return res.status(status.BAD_REQUEST).send({ message: 'ID không hợp lệ.' });
    const nextStatus = String(req.body.status || '').trim();
    if (!['pending', 'under_review', 'duplicate'].includes(nextStatus)) return res.status(status.BAD_REQUEST).send({ message: 'Status không hợp lệ.' });
    const now = new Date();
    const reviewNote = String(req.body.reviewNote || req.body.note || '').slice(0, 1000);
    const result = await db.collection('reports').updateOne({ _id }, { $set: { status: nextStatus, reviewNote, reviewedBy: req.admin.email, reviewedById: req.adminRaw._id, reviewedAt: now, updatedAt: now } });
    if (!result.matchedCount) return res.status(status.NOT_FOUND).send({ message: 'Không tìm thấy báo cáo.' });
    await writeAuditLog(req, 'update_report_status', 'report', _id, { status: nextStatus, reviewNote });
    res.status(status.OK).send({ ok: true });
});

app.get('/api/admin/lists/:type', requireAdmin, async (req, res) => {
    try {
        const type = String(req.params.type || '').trim();
        if (!isValidListType(type)) return res.status(status.BAD_REQUEST).send({ message: 'List type không hợp lệ.' });
        const limit = parsePositiveInt(req.query.limit, 50, 200);
        const page = parsePositiveInt(req.query.page, 1, 100000);
        const listStatus = String(req.query.status || 'active').trim();
        const search = String(req.query.search || '').trim();
        const filter = {};
        if (listStatus === 'active') Object.assign(filter, getActiveListFilter());
        else if (listStatus !== 'all') filter.status = listStatus;
        if (search) {
            const regex = new RegExp(escapeRegex(search), 'i');
            filter.$and = filter.$and || [];
            filter.$and.push({ $or: [{ url: regex }, { domain: regex }, { reason: regex }, { source: regex }] });
        }
        const [total, items] = await Promise.all([
            db.collection(type).countDocuments(filter),
            db.collection(type).find(filter).sort({ updatedAt: -1, createdAt: -1 }).skip((page - 1) * limit).limit(limit).toArray()
        ]);
        res.status(status.OK).send({ total, page, limit, items });
    } catch (err) {
        console.log('admin list get error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể lấy danh sách.' });
    }
});

app.post('/api/admin/lists/:type', requireAdmin, requireAdminCsrf, requireRole('admin', 'moderator'), async (req, res) => {
    try {
        const type = String(req.params.type || '').trim();
        if (!isValidListType(type)) return res.status(status.BAD_REQUEST).send({ message: 'List type không hợp lệ.' });
        const payload = buildListPayload(req.body || {}, type, 'manual-admin');
        if (payload.error) return res.status(status.BAD_REQUEST).send({ message: payload.error });
        const now = new Date();
        const result = await db.collection(type).updateOne(
            { domain: payload.domain },
            { $set: { ...payload, updatedBy: req.admin.email, updatedAt: now }, $setOnInsert: { createdAt: now, createdBy: req.admin.email } },
            { upsert: true }
        );
        const item = await db.collection(type).findOne({ domain: payload.domain });
        await writeAuditLog(req, 'upsert_list_entry', type, item && item._id, { type, domain: payload.domain, upsertedId: result.upsertedId || null });
        res.status(status.OK).send({ ok: true, item });
    } catch (err) {
        if (err && err.code === 11000) return res.status(status.CONFLICT).send({ message: 'URL/domain đã tồn tại.' });
        console.log('admin list post error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể lưu domain.' });
    }
});

app.patch('/api/admin/lists/:type/:id', requireAdmin, requireAdminCsrf, requireRole('admin', 'moderator'), async (req, res) => {
    try {
        const type = String(req.params.type || '').trim();
        const _id = objectIdFromParam(req.params.id);
        if (!isValidListType(type) || !_id) return res.status(status.BAD_REQUEST).send({ message: 'Tham số không hợp lệ.' });
        const updates = {};
        if ('url' in req.body || 'domain' in req.body) {
            const payload = buildListPayload({ ...req.body, url: req.body.url || req.body.domain }, type, 'manual-admin');
            if (payload.error) return res.status(status.BAD_REQUEST).send({ message: payload.error });
            Object.assign(updates, { url: payload.url, domain: payload.domain, type: payload.type });
        }
        if ('status' in req.body && ['active', 'inactive'].includes(String(req.body.status))) updates.status = String(req.body.status);
        if ('reason' in req.body) updates.reason = String(req.body.reason || '').slice(0, 500);
        if ('source' in req.body) updates.source = String(req.body.source || '').slice(0, 80);
        updates.updatedAt = new Date();
        updates.updatedBy = req.admin.email;
        const result = await db.collection(type).updateOne({ _id }, { $set: updates });
        if (!result.matchedCount) return res.status(status.NOT_FOUND).send({ message: 'Không tìm thấy item.' });
        const item = await db.collection(type).findOne({ _id });
        await writeAuditLog(req, 'update_list_entry', type, _id, { updates });
        res.status(status.OK).send({ ok: true, item });
    } catch (err) {
        if (err && err.code === 11000) return res.status(status.CONFLICT).send({ message: 'URL/domain đã tồn tại.' });
        console.log('admin list patch error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể cập nhật item.' });
    }
});

app.delete('/api/admin/lists/:type/:id', requireAdmin, requireAdminCsrf, requireRole('admin'), async (req, res) => {
    const type = String(req.params.type || '').trim();
    const _id = objectIdFromParam(req.params.id);
    if (!isValidListType(type) || !_id) return res.status(status.BAD_REQUEST).send({ message: 'Tham số không hợp lệ.' });
    const result = await db.collection(type).updateOne({ _id }, { $set: { status: 'inactive', updatedAt: new Date(), updatedBy: req.admin.email } });
    if (!result.matchedCount) return res.status(status.NOT_FOUND).send({ message: 'Không tìm thấy item.' });
    await writeAuditLog(req, 'disable_list_entry', type, _id, {});
    res.status(status.OK).send({ ok: true });
});

app.post('/api/admin/import/:typelist', requireAdmin, requireAdminCsrf, requireRole('admin', 'moderator'), upload.single('file'), importListHandler);

/**
 * The route to get blacklist or whitelist sites from DB
 * this is public so the request shouldn't be authenticated
 * @param {String} typelist  type of list we wanna get ('blacklist' or 'whitelist')
 * @return {JSON} array of objects
 */
app.get(`/${APP_VERSION}/:typelist`, async function(req, res) {
    const type = String(req.params.typelist || '').trim();
    if (!isValidListType(type)) return res.status(status.BAD_REQUEST).send(`${type} is not a valid type of list`);
    if (!db) return res.status(status.SERVICE_UNAVAILABLE).send([]);

    try {
        const result = await db.collection(type)
            .find({ $or: [{ status: { $exists: false } }, { status: 'active' }] })
            .project({ url: 1, domain: 1, type: 1, source: 1, updatedAt: 1 })
            .toArray();
        res.status(status.OK).send(result.map(item => ({
            ...item,
            url: item.url || item.domain
        })).filter(item => item.url));
    } catch (err) {
        console.log(`${type} list error`, err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send([]);
    }

})

app.post(`/${APP_VERSION}/res/:resId`, authenticateJWT, function(req, res) {
    if (!req.params.resId || ['blacklist', 'whitelist'].indexOf(req.params.resId) == -1) {
        res.status(status.NOT_FOUND).send({
            status: status.NOT_FOUND,
            version: APP_VERSION,
            requestedOn: new Date(),
            message: `${req.params.resId} not found`
        });
    }

    //get encrypted data
    fs.readFile(`secure/${req.params.resId}.json`, "utf8", function(err, data){
        if(err) throw err;

        if (data) {
            return res.status(status.OK).send({
                status: status.OK,
                version: APP_VERSION,
                requestedOn: new Date(),
                data
            });
        }
    });
});

// Legacy import route is now admin-only. Prefer /api/admin/import/:typelist from the admin UI.
app.post(`/${APP_VERSION}/importFiles/:typelist`, requireAdmin, requireAdminCsrf, requireRole('admin', 'moderator'), upload.single('file'), importListHandler);

app.post(`/${APP_VERSION}/safecheck`, function(req, res) {
    let { url } = req.body;

    if(!url || url.length > maxLengthUrl) {
        return res.sendStatus(status.BAD_REQUEST);
    }
    db.collection('blacklist').find(getActiveListFilter()).toArray().then(result => {
        // Check if current url exist in our Blacklist :
        for(let blacksite of result) {
            let site = blacksite.url.replace('https://', '').replace('http://', '').replace('www.', '')
            let appendix = "[/]?(?:index\.[a-z0-9]+)?[/]?$";
            let trail = site.substr(site.length - 2);
            let match = false

            if (trail == "/*") {
                site = site.substr(0, site.length - 2);
                appendix = "(?:$|/.*$)";
                site = "^(?:[a-z0-9\\-_]+:\/\/)?(?:www\\.)?" + site + appendix;

                let regex = new RegExp(site, "i");
                match = url.match(regex)
                match = match ? (match.length > 0) : false
            } else {
                match = encodeURIComponent(site) == encodeURIComponent(url.replace('https://', '').replace('http://', '').replace('www.', ''))
            }

            // Check if the URL has suffix or not, for ex: https://www.facebook.com/profile.php?id=100060251539767
            let suffix = false
            if (blacksite.url.match(/(?:id=)(\d+)/) && url.match(/(?:id=)(\d+)/))
                suffix = (blacksite.url.match(/(?:id=)(\d+)/)[1] == url.match(/(?:id=)(\d+)/)[1])

            if(match || suffix)
                return res.status(status.OK).send({type: "unsafe"});
        }

        db.collection('whitelist').find({ $and: [getActiveListFilter(), { url: {'$regex': url, '$options': 'i'} }] }).toArray().then(result => {
            if(result.length > 0) {
                res.status(status.OK).send({type: "safe"});
            } else {
                res.status(status.OK).send({type: "nodata"});
            }
        })

    })
});

app.post(`/${APP_VERSION}/safecheck-phishtank`, function(req, res) {
    // https://www.phishtank.com/developer_info.php
    let { url } = req.body;
    url = preProcessDomainUrl(url);

    axios({
        method: 'get',
        url: `https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt`,
        headers: {
            "Content-Type": "application/json"
        },
    }).then((result) => {
      if(result && result.data) {
        if(result.data.split('\n').includes(url)) {
            res.status(status.OK).send({type: "unsafe"});
        } else {
            res.status(status.OK).send({type: "safe"});
        }
      } else {
        res.status(status.OK).send({type: "nodata"});
      }
    });            
});

app.post(`/${APP_VERSION}/safecheck-hellsh`, function(req, res) {
    // https://hell.sh/hosts/
    let { url } = req.body;
    url = preProcessDomainUrl(url);

    axios({
        method: 'get',
        url: `https://hell.sh/hosts/domains.txt`,
        headers: {
            "Content-Type": "application/json"
        },
    }).then((result) => {
      if(result && result.data) {
        if(result.data.split('\n').includes(url)) {
            res.status(status.OK).send({type: "unsafe"});
        } else {
            res.status(status.OK).send({type: "safe"});
        }
      } else {
        res.status(status.OK).send({type: "nodata"});
      }
    });            
});

app.post(`/${APP_VERSION}/safecheck-oisd`, function(req, res) {
    // https://oisd.nl/?p=dl
    let { url } = req.body;
    url = preProcessDomainUrl(url);

    axios({
        method: 'get',
        url: `https://dbl.oisd.nl/`,
        headers: {
            "Content-Type": "application/json"
        },
    }).then((result) => {
      if(result && result.data) {
        if(result.data.split('\n').includes(url)) {
            res.status(status.OK).send({type: "unsafe"});
        } else {
            res.status(status.OK).send({type: "safe"});
        }
      } else {
        res.status(status.OK).send({type: "nodata"});
      }
    });            
});

app.post(`/${APP_VERSION}/safecheck-matrix`, function(req, res) {
    // https://github.com/mypdns/matrix/tree/master/source
    let { url } = req.body;
    url = preProcessDomainUrl(url);

    let matrixPhishPromise = new Promise((resolve, reject) => {
        axios({
            method: 'get',
            url: `https://raw.githubusercontent.com/mypdns/matrix/master/source/phishing/domains.list`,
            headers: {
                "Content-Type": "application/json"
            },
        }).then((res) => {
          if(res && res.data) {
            if(res.data.split('\n').includes(url)) {
                resolve(false);
            } else {
                resolve(true);
            }
          } else {
            resolve(true);
          }
        });
    })

    let matrixAdsPromise = new Promise((resolve, reject) => {
            axios({
                method: 'get',
                url: `https://raw.githubusercontent.com/mypdns/matrix/master/source/adware/domains.list`,
                headers: {
                    "Content-Type": "application/json"
                },
            }).then((res) => {
            if(res && res.data) {
                if(res.data.split('\n').includes(url)) {
                    resolve(false);
                } else {
                    resolve(true);
                }
            } else {
                resolve(true);
            }
            });
    })

    let matrixSpywarePromise = new Promise((resolve, reject) => {
            axios({
                method: 'get',
                url: `https://raw.githubusercontent.com/mypdns/matrix/master/source/spyware/domains.list`,
                headers: {
                    "Content-Type": "application/json"
                },
            }).then((res) => {
            if(res && res.data) {
                if(res.data.split('\n').includes(url)) {
                    resolve(false);
                } else {
                    resolve(true);
                }
            } else {
                resolve(true);
            }
            });
    })

    let matrixScammingPromise = new Promise((resolve, reject) => {
            axios({
                method: 'get',
                url: `https://raw.githubusercontent.com/mypdns/matrix/master/source/scamming/domains.list`,
                headers: {
                    "Content-Type": "application/json"
                },
            }).then((res) => {
            if(res && res.data) {
                if(res.data.split('\n').includes(url)) {
                    resolve(false);
                } else {
                    resolve(true);
                }
            } else {
                resolve(true);
            }
            });
    })

    let matrixPornPromise = new Promise((resolve, reject) => {
            axios({
                method: 'get',
                url: `https://raw.githubusercontent.com/mypdns/matrix/master/source/porno-sites/domains.list`,
                headers: {
                    "Content-Type": "application/json"
                },
            }).then((res) => {
            if(res && res.data) {
                if(res.data.split('\n').includes(url)) {
                    resolve(false);
                } else {
                    resolve(true);
                }
            } else {
                resolve(true);
            }
            });
    })

    let matrixMaliciousPromise = new Promise((resolve, reject) => {
            axios({
                method: 'get',
                url: `https://raw.githubusercontent.com/mypdns/matrix/master/source/malicious/domains.list`,
                headers: {
                    "Content-Type": "application/json"
                },
            }).then((res) => {
            if(res && res.data) {
                if(res.data.split('\n').includes(url)) {
                    resolve(false);
                } else {
                    resolve(true);
                }
            } else {
                resolve(true);
            }
            });
    })    
    
    Promise.all([
        matrixPhishPromise,
        matrixAdsPromise,
        matrixSpywarePromise,
        matrixScammingPromise,
        matrixPornPromise,
        matrixMaliciousPromise,
    ]).then((result) => {
        if(result.every(val => val == true)) {
            res.status(status.OK).send({type: "safe"});
        } else {
            res.status(status.OK).send({type: "unsafe"});
        }
    });
});

app.post(`/${APP_VERSION}/safecheck-segasec`, function(req, res) {
    // https://github.com/Segasec/feed
    let { url } = req.body;
    let rawUrl = url;
    url = preProcessDomainUrl(url);

    let segasecDomainPromise = new Promise((resolve, reject) => {
        axios({
            method: 'get',
            url: `https://raw.githubusercontent.com/Segasec/feed/master/phishing-domains.json`,
            headers: {
                "Content-Type": "application/json"
            },
        }).then((res) => {
          if(res && res.data) {
            if(res.data.includes(url)) {
                resolve(false);
            } else {
                resolve(true);
            }
          } else {
            resolve(true);
          }
        });
    })

    let segasecUrlPromise = new Promise((resolve, reject) => {
        axios({
            method: 'get',
            url: `https://raw.githubusercontent.com/Segasec/feed/master/phishing-urls.json`,
            headers: {
                "Content-Type": "application/json"
            },
        }).then((res) => {
          if(res && res.data) {
            if(res.data.includes(rawUrl)) {
                resolve(false);
            } else {
                resolve(true);
            }
          } else {
            resolve(true);
          }
        });
    })
    
    Promise.all([
        segasecDomainPromise,
        segasecUrlPromise
    ]).then((result) => {
        if(result.every(val => val == true)) {
            res.status(status.OK).send({type: "safe"});
        } else {
            res.status(status.OK).send({type: "unsafe"});
        }
    });
});

app.post(`/${APP_VERSION}/safecheck-energized`, function(req, res) {
    // https://energized.pro/
    let { url } = req.body;
    url = preProcessDomainUrl(url);

    axios({
        method: 'get',
        url: `https://block.energized.pro/basic/formats/one-line.txt`,
        headers: {
            "Content-Type": "application/json"
        },
    }).then((result) => {
        if(result && result.data) {
            const rawData = result.data.split('\n');
            if(rawData[59].split(",").includes(url)) {
                res.status(status.OK).send({type: "unsafe"});
            } else {
                res.status(status.OK).send({type: "safe"});
            }
          } else {
            res.status(status.OK).send({type: "nodata"});
        }
    });

});

const preProcessDomainUrl = (url) => {
    const indices = [];

    for(let i=0; i < url.length; i++) {
        if (url[i] === "/") indices.push(i);
    }
    
    if(url.includes('http') || url.includes('https')) {
        url = url.substring(0, indices[2])
        if(url.includes('http')) {
            url = url.substring(8, url.length)
        } else if(url.includes('https')) {
            url = url.substring(9, url.length)
        }
    } else {
        url = url.substring(0, indices[0])
    }
    return url;
}

function validateSubmitting(params) {
    const { rating, url } = params;
    const expUrl = /[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)?/gi;

    if (rating < 1 || rating > 5) {
        return "Rating is out of range";
    }
    else if (!url.match(new RegExp(expUrl))) {
        return `Incorrect URL ${url}`;
    }
    return "ok";
}


var db = null;
const mongoUsername = process.env.MONGO_USERNAME || config.get("db.username");
const mongoPassword = process.env.MONGO_PASSWORD || config.get("db.password");
const mongoHost = process.env.MONGO_HOST || config.get("db.url");
const mongoPort = process.env.MONGO_PORT || config.get("db.port");
const fallbackMongoDatabase = process.env.MONGO_DATABASE || config.get("db.name");
const mongoUrl = process.env.MONGO_URI || `mongodb://${mongoUsername}:${mongoPassword}@${mongoHost}:${mongoPort}/${fallbackMongoDatabase}`;
const getMongoDatabaseName = () => {
    if (process.env.MONGO_DATABASE) return process.env.MONGO_DATABASE;
    if (process.env.MONGO_URI) {
        try {
            const parsed = new URL(process.env.MONGO_URI);
            const dbName = decodeURIComponent((parsed.pathname || '').replace(/^\//, '').trim());
            if (dbName) return dbName;
        } catch (_) {}
    }
    return fallbackMongoDatabase;
};
const mongoClient = new MongoClient(mongoUrl, {
    serverSelectionTimeoutMS: Number(process.env.MONGO_SERVER_SELECTION_TIMEOUT_MS || 15000)
});

const ensureCollection = async (collectionName) => {
    const existing = await db.listCollections({ name: collectionName }, { nameOnly: true }).toArray();
    if (!existing.length) await db.createCollection(collectionName);
};

async function startServer() {
    try {
        await mongoClient.connect();

        db = mongoClient.db(getMongoDatabaseName());
        console.info('Connected to MongoDB database:', db.databaseName);
        for (const collectionName of ['reports', 'rating', 'blacklist', 'whitelist', 'pornlist', 'admin_users', 'admin_sessions', 'audit_logs']) {
            await ensureCollection(collectionName).catch(err => console.log(`${collectionName} collection error`, err && err.message));
        }
        await db.collection('reports').createIndex({ deviceFingerprint: 1, domain: 1 }, { unique: true }).catch(err => console.log('reports index error', err && err.message));
        await db.collection('reports').createIndex({ domain: 1, createdAt: -1 }).catch(err => console.log('reports domain index error', err && err.message));
        await db.collection('reports').createIndex({ status: 1, createdAt: -1 }).catch(err => console.log('reports status index error', err && err.message));
        for (const type of ['blacklist', 'whitelist', 'pornlist']) {
            await db.collection(type).createIndex({ url: 1 }, { unique: true, sparse: true }).catch(err => console.log(`${type} url index error`, err && err.message));
            await db.collection(type).createIndex({ domain: 1, status: 1 }).catch(err => console.log(`${type} domain index error`, err && err.message));
        }
        await db.collection('rating').createIndex({ url: 1, time: -1 }).catch(err => console.log('rating index error', err && err.message));
        await db.collection('admin_users').createIndex({ email: 1 }, { unique: true }).catch(err => console.log('admin users email index error', err && err.message));
        await db.collection('admin_sessions').createIndex({ tokenHash: 1 }, { unique: true }).catch(err => console.log('admin sessions token index error', err && err.message));
        await db.collection('admin_sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }).catch(err => console.log('admin sessions ttl index error', err && err.message));
        await db.collection('audit_logs').createIndex({ createdAt: -1 }).catch(err => console.log('audit logs created index error', err && err.message));
        await db.collection('audit_logs').createIndex({ targetType: 1, targetId: 1, createdAt: -1 }).catch(err => console.log('audit logs target index error', err && err.message));
        await bootstrapInitialAdmin().catch(err => console.log('admin bootstrap error', err && err.message));

        app.listen(APP_PORT, () => {
            console.info("Launch the API Server at ", APP_DOMAIN, ":", APP_PORT);
        });
    } catch (err) {
        console.error('MongoDB connection failed:', err);
        process.exit(1);
    }
}

startServer();
