/**
 * background.js — ES Module Service Worker Controller
 * Nhiệm vụ: Khởi tạo Services theo thứ tự an toàn, đăng ký Message Router.
 * Không chứa business logic. Chỉ orchestrate.
 */

/* global chrome, self, psl, computeLiveScore, analyzeUrl, isTrustedHost,
   REPUTATION_WHITELIST, isOfficialBrandDomain, getRegistrableDomain */

// ─── Import Services ────────────────────────────────────────────────────────
import { logger } from '../services/Logger.js';
import { CacheService } from '../services/CacheService.js';
import { TabStateService, ANALYSIS_STATUS } from '../services/TabStateService.js';
import { MessageRouter } from '../services/MessageRouter.js';
import { ReportService } from '../services/ReportService.js';
import { QueueManager } from '../services/QueueManager.js';

// Heuristic engine chạy ngầm (non-module, vẫn cần importScripts với cách khác
// khi manifest "type":"module" thì phải import thay vì importScripts)
import '../shared/heuristic.js';

// ─── Constants ───────────────────────────────────────────────────────────────
const ANALYSIS_STATUS_IDLE     = ANALYSIS_STATUS.IDLE;
const ANALYSIS_STATUS_ANALYZING = ANALYSIS_STATUS.ANALYZING;
const ANALYSIS_STATUS_SUCCESS  = ANALYSIS_STATUS.SUCCESS;
const ANALYSIS_STATUS_FAILED   = ANALYSIS_STATUS.FAILED;

const BLACKLIST_TTL_MS  = 60 * 60 * 1000;
const OPENPHISH_TTL_MS  = 15 * 60 * 1000;
const CLASSIFIER_TTL_MS = 5  * 60 * 1000;
const RESULT_CACHE_TTL_MS = 10 * 60 * 1000;
const QUICK_CACHE_TTL_MS  = 30 * 60 * 1000;
const INTEL_CACHE_TTL_MS  = 30 * 60 * 1000;
const DOMAIN_AGE_TTL_MS   = 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 30_000;
const API_BASE = 'https://anti-scam-6iix.onrender.com';
const BACKEND_BASE = API_BASE;
const OPENPHISH_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';
const PORT_REDIRECT = 'REDIRECT_PORT_NAME';
const PORT_CLOSE_TAB = 'CLOSE_TAB_PORT_NAME';
const RISK_BLOCK_THRESHOLD = 55;
const RISK_BLOCK_ALLOW_MS = 5 * 60 * 1000;
const DEEP_SCAN_HARD_TIMEOUT_MS = 15_000;
const DEEP_SCAN_DWELL_MS = 2_500;
const SCAN_STORAGE_KEY = 'antiscam_url_scan_results';
const ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;

// ─── Runtime State ───────────────────────────────────────────────────────────
const riskBlockAllowUntil = new Map();
const deepScanTabs = new Map();
const redirectChains = new Map();
const pendingDownloads = new Map();
let blackListing = [], blackListingSet = new Set(), whiteListingSet = new Set();
let inputBlockLenient = false;
let startupInProgress = false;

// ─── Circuit Breaker ─────────────────────────────────────────────────────────
const circuitBreaker = {
  antiScamApi:  { failures: 0, openUntil: 0 },
  openPhish:    { failures: 0, openUntil: 0 },
  backendIntel: { failures: 0, openUntil: 0 },
};
const CB_THRESHOLD = 3;

const checkCB = (service) => {
  const cb = circuitBreaker[service]; if (!cb) return true;
  const now = Date.now();
  if (cb.openUntil > 0 && now >= cb.openUntil) { cb.failures = 0; cb.openUntil = 0; return true; }
  if (now < cb.openUntil) { logger.warn(`[CB_OPEN] ${service}`); return false; }
  return true;
};
const recFail = (service) => {
  const cb = circuitBreaker[service]; if (!cb) return;
  cb.failures++;
  if (cb.failures >= CB_THRESHOLD) {
    const t = Math.min(10_000 * Math.pow(2, Math.floor(cb.failures / CB_THRESHOLD)), 120_000);
    cb.openUntil = Date.now() + t;
    logger.error(`[CB_TRIPPED] ${service} — ${t / 1000}s`);
  }
};
const recOK = (service) => { const cb = circuitBreaker[service]; if (cb) { cb.failures = 0; cb.openUntil = 0; } };

const fetchWithRetry = async (url, service, isJson = true, retries = 3) => {
  if (!checkCB(service)) return null;
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const ctrl = new AbortController();
      const tid = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
      const res = await fetch(url, { signal: ctrl.signal });
      clearTimeout(tid);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = isJson ? await res.json() : await res.text();
      recOK(service); return data;
    } catch (err) {
      logger.warn(`[FETCH_FAIL] ${service} attempt ${attempt + 1}/${retries}: ${err.name === 'AbortError' ? 'timeout' : err.message}`);
      if (attempt < retries - 1) await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
    }
  }
  recFail(service); return null;
};

// ─── Utility ─────────────────────────────────────────────────────────────────
const getDomain = (url) => { try { return new URL(url).hostname; } catch (_) { const m = url.match(/^https?:\/\/([^/?#]+)/i); return (m && m[1].split(':')[0]) || ''; } };
const createUrlObject = (url) => { try { return new URL(url); } catch { return null; } };
const getRegistrable = (domain) => {
  if (typeof getRegistrableDomain !== 'undefined') return getRegistrableDomain(domain);
  if (typeof self !== 'undefined' && self.getRegistrableDomain) return self.getRegistrableDomain(domain);
  let h = (domain || '').toLowerCase().replace(/^www\./, '');
  return h.split('.').slice(-2).join('.');
};
const updateBadge = (isPhishing, finalScore, tabId) => {
  const title = isPhishing ? `AntiScam: ⚠ Cảnh báo (${finalScore}% an toàn)` : `AntiScam: ✓ An toàn (${finalScore}%)`;
  chrome.action.setTitle({ title, tabId }).catch(() => {});
  chrome.action.setIcon({ path: 'assets/antiScamLogo.png', tabId }).catch(() => {});
};
const isRiskBlockAllowed = (tabId) => { const until = riskBlockAllowUntil.get(tabId) || 0; if (Date.now() < until) return true; riskBlockAllowUntil.delete(tabId); return false; };

// ─── Tab State wrappers (backward compat) ────────────────────────────────────
const getTabState = (tabId) => TabStateService.get(tabId);
const setTabState = (tabId, state) => TabStateService.set(tabId, state);
const removeTabState = (tabId) => TabStateService.remove(tabId);

// ─── URL Scan Storage ─────────────────────────────────────────────────────────
const getUrlScanResult = async (url) => {
  try { const d = await chrome.storage.local.get(SCAN_STORAGE_KEY); return (d[SCAN_STORAGE_KEY] || {})[url] || null; } catch { return null; }
};
const setUrlScanResult = async (url, state) => {
  try {
    const d = await chrome.storage.local.get(SCAN_STORAGE_KEY);
    const all = d[SCAN_STORAGE_KEY] || {};
    all[url] = { ...state, updatedAt: Date.now() };
    await chrome.storage.local.set({ [SCAN_STORAGE_KEY]: all });
  } catch (e) { logger.error('[SCAN] setUrlScanResult failed', e); }
};
const removeUrlScanResult = async (url) => {
  try { const d = await chrome.storage.local.get(SCAN_STORAGE_KEY); const all = d[SCAN_STORAGE_KEY] || {}; delete all[url]; await chrome.storage.local.set({ [SCAN_STORAGE_KEY]: all }); } catch {}
};

// ─── Cache helpers ───────────────────────────────────────────────────────────
const getUrlCache = (url, requiredStage = 'LIVE') => CacheService.getForUrl(url, requiredStage, RESULT_CACHE_TTL_MS, QUICK_CACHE_TTL_MS);
const setUrlCache = (url, data, stage = 'LIVE') => CacheService.setForUrl(url, data, stage);

// ─── Domain Age ───────────────────────────────────────────────────────────────
const _pickRdapDate = (events, names) => {
  if (!Array.isArray(events)) return null;
  const wanted = names.map(n => String(n).toLowerCase());
  const ev = events.find(e => wanted.includes(String(e.eventAction || '').toLowerCase()));
  return ev && ev.eventDate ? ev.eventDate : null;
};
const fetchDomainAge = async (domain) => {
  try {
    let base = domain;
    try { if (typeof psl !== 'undefined') base = psl.parse(domain).domain || domain; } catch (e) {}
    const key = `age_${base}`;
    const cached = await chrome.storage.session.get(key);
    if (cached && cached[key] !== undefined) {
      const c = cached[key];
      if (c._cachedAt && Date.now() - c._cachedAt < DOMAIN_AGE_TTL_MS) return typeof c === 'number' ? { ageDays: c, source: 'rdap-cache' } : c;
      if (!c._cachedAt) return typeof c === 'number' ? { ageDays: c, source: 'rdap-cache' } : c;
    }
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 3500);
    const res = await fetch(`https://rdap.org/domain/${base}`, { signal: ctrl.signal }); clearTimeout(t);
    if (!res.ok) return { ageDays: -1, source: 'rdap', status: 'nodata' };
    const data = await res.json();
    const registrationDate = _pickRdapDate(data && data.events, ['registration']);
    const expirationDate = _pickRdapDate(data && data.events, ['expiration', 'expiry']);
    const ageDays = registrationDate ? (Date.now() - new Date(registrationDate).getTime()) / (1000 * 60 * 60 * 24) : -1;
    const info = { ageDays, registrationDate, expirationDate, source: 'rdap', _cachedAt: Date.now() };
    await chrome.storage.session.set({ [key]: info }); return info;
  } catch (err) { logger.warn(`fetchDomainAge ${domain}:`, err.message); }
  return { ageDays: -1, source: 'rdap', status: 'error' };
};

const fetchBackendIntel = async (urlString, domain) => {
  try {
    let base = domain;
    try { if (typeof psl !== 'undefined') base = psl.parse(domain).domain || domain; } catch (e) {}
    const key = `intel_${base}`;
    const cached = await chrome.storage.session.get(key);
    if (cached && cached[key] && Date.now() - cached[key].timestamp < INTEL_CACHE_TTL_MS) return cached[key].data;
    const payload = encodeURIComponent(urlString || domain || '');
    const data = await fetchWithRetry(`${BACKEND_BASE}/v1/intel?url=${payload}`, 'backendIntel', true, 2);
    if (data && data.status !== 'error') { await chrome.storage.session.set({ [key]: { data, timestamp: Date.now() } }); return data; }
  } catch (err) { logger.warn(`fetchBackendIntel ${domain}:`, err.message); }
  return null;
};

const mergeDomainAge = (rdapAge, backendAge) => {
  if (backendAge && backendAge.ageDays != null && backendAge.ageDays >= 0) return backendAge;
  if (rdapAge && rdapAge.ageDays != null) return rdapAge;
  return { ageDays: -1 };
};

// ─── Classifier ML ───────────────────────────────────────────────────────────
const fetchCLF = async () => {
  try {
    const { classifierCache, classifierCacheTime } = await chrome.storage.local.get(['classifierCache', 'classifierCacheTime']);
    if (classifierCache && classifierCacheTime && Date.now() - classifierCacheTime < CLASSIFIER_TTL_MS) return classifierCache;
    const data = await fetchWithRetry(`${API_BASE}/classifier.json`, 'antiScamApi', true);
    if (data) { await chrome.storage.local.set({ classifierCache: data, classifierCacheTime: Date.now() }); return data; }
    if (classifierCache) return classifierCache;
  } catch (e) { logger.error('fetchCLF', e); }
  return null;
};
const decisionTree = (root) => { const p1 = (x) => { let n = root; while (n.type === 'split') { const th = n.threshold.split(' <= '); n = x[th[0]] <= th[1] ? n.left : n.right; } return n.value[0]; }; return { predict: (X) => X.map(p1) }; };
const randomForest = (clf) => {
  const predict = (X) => { let pred = [clf.estimators.map(r => decisionTree(r).predict(X))]; pred = pred[0].map((c, i) => pred.map(r => r[i])); const res = []; for (const p in pred) { let pos = 0, neg = 0; for (const i in pred[p]) { pos += pred[p][i][1]; neg += pred[p][i][0]; } res.push([pos >= neg, Math.max(pos, neg)]); } return res; };
  return { predict };
};

// ─── Blacklist / Whitelist ────────────────────────────────────────────────────
const loadListsFromCache = async () => {
  try {
    const { blacklist, blacklistTime, whitelist, whitelistTime, openPhishList, openPhishTime } = await chrome.storage.local.get(['blacklist', 'blacklistTime', 'whitelist', 'whitelistTime', 'openPhishList', 'openPhishTime']);
    blackListing = []; blackListingSet.clear(); whiteListingSet.clear();
    if (blacklist && blacklistTime && Date.now() - blacklistTime < BLACKLIST_TTL_MS) blacklist.forEach(u => blackListing.push(u));
    if (openPhishList && openPhishTime && Date.now() - openPhishTime < OPENPHISH_TTL_MS) openPhishList.forEach(u => blackListingSet.add(u));
    if (whitelist && whitelistTime && Date.now() - whitelistTime < BLACKLIST_TTL_MS) whitelist.forEach(u => whiteListingSet.add(u));
  } catch (e) { logger.error('loadListsFromCache', e); }
};

// ─── Startup ─────────────────────────────────────────────────────────────────
const startup = async () => {
  if (startupInProgress) return; startupInProgress = true;
  try {
    await loadListsFromCache();
    const { blacklistTime } = await chrome.storage.local.get('blacklistTime');
    if (!blacklistTime || Date.now() - blacklistTime >= BLACKLIST_TTL_MS) {
      const data = await fetchWithRetry(`${API_BASE}/v1/blacklist`, 'antiScamApi', true);
      if (data && Array.isArray(data)) { const list = data.map(i => i.url).filter(Boolean); await chrome.storage.local.set({ blacklist: list, blacklistTime: Date.now() }); blackListing = list; }
    }
    const { openPhishTime } = await chrome.storage.local.get('openPhishTime');
    if (!openPhishTime || Date.now() - openPhishTime >= OPENPHISH_TTL_MS) {
      const text = await fetchWithRetry(OPENPHISH_URL, 'openPhish', false);
      if (text) { const list = text.split('\n').map(l => l.trim()).filter(l => l.length > 0); await chrome.storage.local.set({ openPhishList: list, openPhishTime: Date.now() }); list.forEach(u => blackListingSet.add(u)); }
    }
    const { whitelistTime } = await chrome.storage.local.get('whitelistTime');
    if (!whitelistTime || Date.now() - whitelistTime >= BLACKLIST_TTL_MS) {
      const data = await fetchWithRetry(`${API_BASE}/v1/whitelist`, 'antiScamApi', true);
      if (data && Array.isArray(data)) { const list = data.map(i => i.url).filter(Boolean); await chrome.storage.local.set({ whitelist: list, whitelistTime: Date.now() }); whiteListingSet.clear(); list.forEach(u => whiteListingSet.add(u)); }
    }
  } catch (e) { logger.error('startup', e); }
  finally { startupInProgress = false; }
};

// ─── Redirect Chain ───────────────────────────────────────────────────────────
const getRedirectChain = (tabId) => redirectChains.get(tabId) || [];

// ─── Reputation ───────────────────────────────────────────────────────────────
const _isKnownBadUrl = (urlString) => {
  if (!urlString) return false;
  const cur = createUrlObject(String(urlString));
  const normalized = String(urlString).replace(/\/$/, '');
  if (blackListingSet.has(normalized) || blackListingSet.has(String(urlString))) return true;
  if (!cur || !blackListing || !blackListing.length) return false;
  const curHost = cur.hostname.replace(/^www\./, '').toLowerCase();
  const curHref = cur.href.replace(/\/$/, '');
  let curReg = curHost; try { curReg = getRegistrable(curHost); } catch (_) {}
  for (const raw of blackListing) {
    const item = String(raw || '').trim(); if (!item) continue;
    const bs = createUrlObject(item);
    if (!bs) { const plain = item.replace(/^\*\./, '').replace(/\/$/, '').toLowerCase(); if (plain && (curHost === plain || curReg === plain || curHost.endsWith('.' + plain))) return true; continue; }
    const bHost = bs.hostname.replace(/^www\./, '').toLowerCase();
    const bHref = bs.href.replace(/\/$/, '');
    if (curHref === bHref) return true;
    if (bs.pathname === '/' || bs.pathname === '/*') { if (curHost === bHost || curHost.endsWith('.' + bHost)) return true; }
  }
  return false;
};

const _analyzePageLinks = async (links, pageDomain) => {
  const out = []; const seen = new Set();
  if (!Array.isArray(links)) return out;
  for (const raw of links.slice(0, 160)) {
    if (!raw || seen.has(raw)) continue; seen.add(raw);
    let host = ''; try { host = new URL(raw).hostname; } catch (_) {}
    const knownBad = _isKnownBadUrl(raw);
    let linkReg = ''; try { linkReg = getRegistrable(host); } catch (_) {}
    const pageReg = getRegistrable(pageDomain || '');
    const benignHost = host && (linkReg === pageReg || (typeof isTrustedHost !== 'undefined' && isTrustedHost(host)) || (typeof REPUTATION_WHITELIST !== 'undefined' && REPUTATION_WHITELIST.has(linkReg)) || (typeof isOfficialBrandDomain !== 'undefined' && !!isOfficialBrandDomain(host)));
    const local = (!knownBad && benignHost) ? { findings: [] } : (typeof analyzeUrl !== 'undefined' ? analyzeUrl(raw) : { findings: [] });
    // Accept both V3 uppercase IDs and legacy PascalCase
    const suspiciousIds = new Set(['DangerousDownload','Typosquat','Homograph','BrandInDomain','BrandInPath','Punycode','UnicodeHost','VNScamKeyword','IPHost','OpenRedirect','DOUBLE_EXT','EXE_DOWNLOAD','TYPOSQUAT','HOMOGRAPH','BRAND_IN_DOMAIN','PUNYCODE','SCAM_KEYWORDS','IP_HOST']);
    const suspicious = (local.findings || []).filter(f => suspiciousIds.has(f.id || f.key));
    let keys = suspicious.map(f => f.id || f.key).slice(0, 5);
    let points = (knownBad ? 45 : 0) + suspicious.reduce((sum, f) => sum + Math.min(f.points || 0, 18), 0);
    if (!knownBad && suspicious.some(f => ['DangerousDownload','Typosquat','Homograph','BrandInDomain','BrandInPath','OpenRedirect','DOUBLE_EXT','EXE_DOWNLOAD','TYPOSQUAT','HOMOGRAPH','BRAND_IN_DOMAIN'].includes(f.id || f.key)) && host && !benignHost && out.length < 3) {
      try { const age = await fetchDomainAge(host); if (age && age.ageDays >= 0 && age.ageDays < 14) { keys.push('LinkNewDomain'); points += 10; } } catch (_) {}
    }
    if (knownBad || keys.length) { out.push({ url: raw, host, knownBad, keys: keys.slice(0, 6), points }); }
    if (out.length >= 12) break;
  }
  return out;
};

const resolveReputation = (domain, registrable, urlString, backendIntel = null) => {
  const whitelist = (typeof REPUTATION_WHITELIST !== 'undefined') ? REPUTATION_WHITELIST : new Set();
  const inBuiltWhitelist = whitelist.has(registrable);
  let inCldWhitelist = false;
  for (const w of whiteListingSet) { if (w.includes(domain) || w.includes(registrable)) { inCldWhitelist = true; break; } }
  let inBlacklist = blackListingSet.has(urlString) || blackListingSet.has(urlString.replace(/\/$/, ''));
  if (!inBlacklist && blackListing.length) { for (const b of blackListing) { if (urlString.includes(b.replace(/\/$/, ''))) { inBlacklist = true; break; } } }
  const checkBrand = typeof isOfficialBrandDomain !== 'undefined' ? isOfficialBrandDomain : null;
  const officialBrand = checkBrand ? checkBrand(domain) : null;
  const intel = backendIntel || {};
  return {
    inWhitelist: inBuiltWhitelist || inCldWhitelist,
    inBlacklist: inBlacklist || !!(intel.malware && intel.malware.dangerous),
    isOfficialBrand: !!officialBrand,
    malware: intel.malware || {}, dns: intel.dns || {},
    community: intel.community || null,
    communityReports: intel.community && intel.community.reportCount ? intel.community.reportCount : 0,
    checked: true,
  };
};

const shouldAutoBlock = (assessment, reputation) => {
  if (!assessment || !reputation) return false;
  if (reputation.inWhitelist || reputation.isOfficialBrand) return false;
  if ((assessment.finalScore || 0) >= 50) return false;
  // Accept both new uppercase IDs (Layer-based V3) and legacy PascalCase IDs
  const criticalIds = new Set([
    // V3 Layer 1 (Threat Intel)
    'BLACKLIST', 'MALWARE',
    // V3 Layer 4/5 (Heuristic + Runtime)
    'FORM_HIJACK', 'MALICIOUS_JS', 'HOMOGRAPH', 'TYPOSQUAT', 'DOUBLE_EXT',
    // Legacy PascalCase fallback
    'MalwareReputation', 'FormHijack', 'FormDest', 'DataExfil', 'Keylogger',
    'DangerousDownload', 'RedirectBadHop', 'BrandImpersonation', 'Homograph', 'Typosquat'
  ]);
  const findings = assessment.findings || [];
  const hasCritical = findings.some(f => criticalIds.has(f.id || f.key));
  const highRisk = findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL' || (f.points || 0) >= 15).length;
  return assessment.confidence >= 45 && (hasCritical || highRisk >= 2 || (assessment.riskScore || 0) >= 60);
};

// ─── Blocking ────────────────────────────────────────────────────────────────
const blockingFunction = (url, blackSite, tabId, opts = {}) => {
  const listType = opts.listType || (opts.summary ? 'riskblock' : 'blacklist');
  chrome.tabs.get(tabId).then(tabInfo => {
    if (!tabInfo) return; return getTabState(tabId);
  }).then(state => {
    if (!state) return;
    const message = { site: url, match: blackSite, title: url, lenient: inputBlockLenient, riskBlock: !!opts.summary, listType, reason: opts.summary || '', favicon: `https://www.google.com/s2/favicons?domain=${url}`, result: (state && state.result) || {}, explanations: (state && state.explanations) || [], finalScore: (state && state.legitimatePercent) || 0, confidence: (state && state.confidence) || 0 };
    setTabState(tabId, { status: ANALYSIS_STATUS_SUCCESS, isBlocked: url, isPhish: true, legitimatePercent: state ? state.legitimatePercent : 0, confidence: state ? state.confidence : 95, result: state ? state.result : {}, summary: opts.summary || 'Trang này nằm trong danh sách đen đã xác nhận.', url }).catch(() => {});
    chrome.tabs.update(tabId, { url: `${chrome.runtime.getURL('pages/blocking/index.html')}#${JSON.stringify(message)}` }).catch(e => logger.warn('blocking', e.message));
  }).catch(e => logger.warn('[blocking]', tabId, e.message));
};

const safeCheck = async ({ url, tabId }) => {
  if (!url || url.startsWith('chrome://') || url.startsWith(chrome.runtime.getURL('/'))) return;
  const cur = createUrlObject(url); if (!cur) return;
  const domain = cur.hostname.toLowerCase(); const registrable = getRegistrable(domain);
  let inWhitelist = (typeof REPUTATION_WHITELIST !== 'undefined' && REPUTATION_WHITELIST.has(registrable));
  if (!inWhitelist) { for (const w of whiteListingSet) { if (w.includes(domain) || w.includes(registrable)) { inWhitelist = true; break; } } }
  if (inWhitelist) return;
  if (blackListingSet.has(url) || blackListingSet.has(url.replace(/\/$/, ''))) { blockingFunction(url, url, tabId); return; }
  if (!blackListing || !blackListing.length) return;
  let curDom = ''; try { if (typeof psl !== 'undefined') curDom = psl.parse(cur.host).domain || ''; } catch { curDom = cur.host; }
  const curPath = cur.href.replaceAll('/', '');
  for (let i = 0; i < blackListing.length; ++i) {
    const bs = createUrlObject(blackListing[i]); if (!bs) continue;
    const prefix = bs.host.split('.')[0], suffix = bs.pathname;
    if (prefix === '%2A' && curDom) { const bd = bs.host.slice(4); if (bd === curDom) { blockingFunction(url, bs.host, tabId); return; } }
    if (suffix === '/*' && cur.host === bs.host) { blockingFunction(url, bs.host, tabId); return; }
    if (curPath && curPath === bs.href.replaceAll('/', '')) { blockingFunction(url, bs.host, tabId); return; }
  }
};

// ─── Classify ────────────────────────────────────────────────────────────────
const classify = async (tabId, featuresResult, urlString, domInput = {}, isUpdate = false) => {
  let reputation = null;
  try {
    const domain = getDomain(urlString);
    const registrable = getRegistrable(domain);
    let inCldWhitelist = false;
    for (const w of whiteListingSet) { if (w.includes(domain) || w.includes(registrable)) { inCldWhitelist = true; break; } }
    if (inCldWhitelist) {
      await setTabState(tabId, { status: ANALYSIS_STATUS_SUCCESS, isWhiteList: domain, isPhish: false, legitimatePercent: 100, confidence: 95, listType: 'whitelist', result: {}, summary: 'Trang nằm trong danh sách tin cậy.', url: urlString });
      updateBadge(false, 100, tabId); return;
    }
    if (!isUpdate) {
      const cached = await getUrlCache(urlString, 'LIVE');
      if (cached) {
        await setTabState(tabId, { status: ANALYSIS_STATUS_SUCCESS, isPhish: cached.isPhish, legitimatePercent: cached.legitimatePercent, confidence: cached.confidence, riskScore: cached.riskScore || 0, trustScore: cached.trustScore || 0, trustContext: cached.trustContext || null, result: cached.result || {}, summary: cached.summary || '', explanations: cached.explanations || [], isUnknown: cached.isUnknown, url: urlString });
        updateBadge(cached.isPhish, cached.legitimatePercent, tabId); return;
      }
    }
    const prev = await getTabState(tabId);
    const rdapAge = await fetchDomainAge(domain);
    const backendIntel = await fetchBackendIntel(urlString, domain);
    const domainAge = mergeDomainAge(rdapAge, backendIntel && backendIntel.domainAge);
    const domainAgeDays = domainAge.ageDays != null ? domainAge.ageDays : -1;
    reputation = resolveReputation(domain, registrable, urlString, backendIntel);
    const redirectChain = getRedirectChain(tabId);
    let analysisStart = prev && prev.analysisStart ? prev.analysisStart : Date.now();
    const prevRisk = prev && prev.riskScore != null ? prev.riskScore : 0;
    const stabilityMs = Date.now() - analysisStart;
    const enrichedDom = { ...(domInput || {}) };
    const suspiciousLinks = await _analyzePageLinks(enrichedDom.pageLinks || [], domain);
    if (suspiciousLinks.length) { enrichedDom.suspiciousLinks = suspiciousLinks; enrichedDom.suspiciousLinkCount = suspiciousLinks.length; }
    const redirectHopRisk = ((c) => { if (!Array.isArray(c)) return { bad: false, badHops: [] }; const bh = []; for (const u of c) { if (_isKnownBadUrl(u)) bh.push(u); } return { bad: bh.length > 0, badHops: bh.slice(0, 6) }; })(redirectChain);
    if (redirectHopRisk.bad) { enrichedDom.redirectBadHop = true; enrichedDom.redirectBadHops = redirectHopRisk.badHops; }
    const assessment = computeLiveScore(urlString, { dom: enrichedDom, domainAgeDays, domainAge, reputation, redirectChain, stabilityMs, intel: backendIntel || {} });
    let riskScore = assessment.riskScore, finalScore = assessment.finalScore, confidence = assessment.confidence;
    const resultValues = Object.entries(featuresResult || {}).filter(([k]) => k !== 'tab').map(([, v]) => parseInt(v));
    const clf = await fetchCLF();
    if (clf && resultValues.length) { try { const isPhishML = randomForest(clf).predict([resultValues])[0][0]; if (isPhishML && riskScore < 40) { riskScore += 8; finalScore = Math.max(0, finalScore - 8); } } catch (e) {} }
    if (riskScore > prevRisk + 3) analysisStart = Date.now();
    const mergedResult = {};
    for (const k in (featuresResult || {})) { if (k !== 'tab') mergedResult[k] = featuresResult[k]; }
    for (const k in (assessment.result || {})) { mergedResult[k] = assessment.result[k]; }
    const isPhish = finalScore <= 30;
    const finalState = {
      status: ANALYSIS_STATUS_SUCCESS, isPhish, legitimatePercent: finalScore, confidence,
      stage: assessment.stage || 'LIVE',
      trustScore: assessment.trustScore, riskScore, trustContext: assessment.trustContext, isUnknown: assessment.isUnknown,
      result: mergedResult, summary: assessment.summary, explanations: assessment.explanations || [],
      domainAge: assessment.domainAge || domainAge, reputation,
      counts: (() => { if (!enrichedDom || !enrichedDom.counts) return null; const c = { ...enrichedDom.counts, suspiciousLinks: enrichedDom.suspiciousLinkCount || 0, deceptiveLinks: enrichedDom.deceptiveLinkCount || 0 }; if (c.links) { c.links = { ...c.links }; c.links.dangerous = enrichedDom.suspiciousLinkCount || 0; c.links.warning = Math.max(0, (c.links.warning || 0) - c.links.dangerous); c.links.safe = Math.max(0, (c.links.total || 0) - c.links.warning - c.links.dangerous); } return c; })(),
      // V5 Identity fields
      ownershipStatus: assessment.ownershipStatus || 'UNKNOWN',
      ownershipConfidence: assessment.ownershipConfidence || 'LOW',
      matchedBrand: assessment.matchedBrand || null,
      analysisStart, url: urlString,
    };
    await setTabState(tabId, finalState);
    if (deepScanTabs.has(tabId)) {
      logger.info(`[DEEP_SCAN_INTERIM] tabId=${tabId} score=${finalScore}`);
      await setUrlScanResult(urlString, { ...finalState, scanSource: 'CUSTOM_URL', isInterim: true }); return;
    }
    if (!isUpdate) { await setUrlCache(urlString, { isPhish, legitimatePercent: finalScore, confidence, riskScore, trustScore: assessment.trustScore, trustContext: assessment.trustContext, result: mergedResult, summary: assessment.summary, explanations: assessment.explanations || [], isUnknown: assessment.isUnknown, ownershipStatus: assessment.ownershipStatus || 'UNKNOWN', ownershipConfidence: assessment.ownershipConfidence || 'LOW', matchedBrand: assessment.matchedBrand || null }, 'LIVE'); }
    updateBadge(isPhish, finalScore, tabId);
    if (!isRiskBlockAllowed(tabId) && shouldAutoBlock(assessment, reputation)) {
      try { const ti = await chrome.tabs.get(tabId); if (ti) blockingFunction(urlString, `Mức rủi ro ${riskScore}/100`, tabId, { summary: assessment.summary || 'Trang có nhiều tín hiệu nguy hiểm.' }); } catch (_) {}
    }
  } catch (err) {
    logger.error(`classify ${tabId}:`, err);
    await setTabState(tabId, { status: ANALYSIS_STATUS_FAILED, isPhish: false, legitimatePercent: null, confidence: 0, result: featuresResult || {}, summary: 'Không thể phân tích trang này.', url: urlString });
  }
};

const finalizeDeepScan = async (tabId) => {
  const meta = deepScanTabs.get(tabId); if (!meta) return;
  const { url: urlString } = meta;
  logger.info(`[DEEP_SCAN_FINALIZE_START] tabId=${tabId}`);
  let state = await getTabState(tabId);
  for (let i = 0; i < 30; i++) {
    if (state && state.status !== ANALYSIS_STATUS_ANALYZING) break;
    await new Promise(r => setTimeout(r, 500));
    state = await getTabState(tabId);
  }
  deepScanTabs.delete(tabId);
  removeTabState(tabId);
  try {
    if (state && state.status === ANALYSIS_STATUS_SUCCESS) {
      await setUrlScanResult(urlString, { ...state, scanSource: 'CUSTOM_URL', isInterim: false });
      logger.info(`[DEEP_SCAN_FINAL] url=${urlString} score=${state.legitimatePercent}`);
    } else {
      logger.warn(`[DEEP_SCAN_FINALIZE] No SUCCESS for tabId=${tabId}`);
      const currentRes = await getUrlScanResult(urlString);
      if (currentRes && currentRes.isInterim) { await setUrlScanResult(urlString, { ...currentRes, isInterim: false }); }
      else if (!currentRes || currentRes.status === 'ANALYZING') { await setUrlScanResult(urlString, { status: 'FAILED', isPhish: false, legitimatePercent: null, confidence: 0, result: {}, summary: 'Không thể phân tích trang web.', url: urlString, scanSource: 'CUSTOM_URL', isInterim: false }); }
    }
  } catch (e) { logger.error('[DEEP_SCAN_FINALIZE]', e); }
  try { chrome.tabs.remove(tabId); } catch (e) {}
};

const startHiddenTabScan = async (urlString) => {
  logger.info(`[HIDDEN_TAB_SCAN_START] url=${urlString}`);
  try {
    const tab = await chrome.tabs.create({ url: urlString, active: false });
    const tabId = tab.id;
    const hardTimeout = setTimeout(async () => { logger.warn(`[HIDDEN_TAB_TIMEOUT] tabId=${tabId}`); await finalizeDeepScan(tabId); }, DEEP_SCAN_HARD_TIMEOUT_MS);
    deepScanTabs.set(tabId, { url: urlString, hardTimeout, dwellTimer: null });
    logger.info(`[HIDDEN_TAB_CREATED] tabId=${tabId}`);
  } catch (e) {
    logger.error(`[HIDDEN_TAB_CREATE_FAIL] url=${urlString}`, e.message);
    await setUrlScanResult(urlString, { status: 'LOW_CONFIDENCE', isPhish: false, legitimatePercent: null, confidence: 15, result: {}, summary: 'Không thể khởi động quét sâu.', url: urlString, scanSource: 'CUSTOM_URL', updatedAt: Date.now() });
  }
};

// ─── Download Guard ───────────────────────────────────────────────────────────
const DANGEROUS_DOWNLOAD_EXTS = ['.exe', '.scr', '.bat', '.cmd', '.apk', '.jar', '.ps1', '.msi', '.dll', '.vbs', '.zip', '.rar', '.7z'];
const _downloadExt = (u, filename = '', mime = '') => {
  const raw = (filename || u || '').split('?')[0].split('#')[0].toLowerCase();
  const doubleExt = /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|rtf)\.(exe|scr|bat|cmd|ps1|vbs|jar|apk|msi|dll)$/i.exec(raw);
  if (doubleExt) return '.' + doubleExt[2].toLowerCase();
  const ext = DANGEROUS_DOWNLOAD_EXTS.find(ext => raw.endsWith(ext)); if (ext) return ext;
  const m = String(mime || '').toLowerCase();
  if (/application\/(x-msdownload|x-msdos-program|x-msi|vnd.android.package-archive|java-archive|x-sh|x-bat|x-powershell|zip|x-7z-compressed|vnd.rar)/.test(m)) return m.includes('zip') ? '.zip' : (m.includes('7z') ? '.7z' : (m.includes('rar') ? '.rar' : '.bin'));
  return null;
};
const _isDownloadFromRiskyContext = async (item) => {
  try {
    const tabs = await chrome.tabs.query({ currentWindow: true, active: true }); const tab = tabs && tabs[0];
    const state = tab ? await getTabState(tab.id) : null;
    const itemHost = createUrlObject(item.finalUrl || item.url || '')?.hostname || '';
    const tabHost = createUrlObject((state && state.url) || (tab && tab.url) || '')?.hostname || '';
    const sameContext = item.referrer ? ((createUrlObject(item.referrer)?.hostname || '') === tabHost) : (itemHost === tabHost || !itemHost || !tabHost);
    if (state && sameContext && (state.isPhish || state.riskScore >= 30 || state.legitimatePercent <= 55)) return true;
    const local = typeof analyzeUrl !== 'undefined' ? analyzeUrl(item.finalUrl || item.url || '') : { findings: [] };
    const dangerKeys = new Set(['DangerousDownload','Typosquat','Homograph','BrandInDomain','DOUBLE_EXT','EXE_DOWNLOAD','TYPOSQUAT','HOMOGRAPH','BRAND_IN_DOMAIN']);
    return !!(local.findings || []).find(f => dangerKeys.has(f.id || f.key));
  } catch (_) { return false; }
};

// ─── Message Handlers ─────────────────────────────────────────────────────────

MessageRouter.register('ANALYSIS_RESULT', async (request, sender) => {
  const tabId = sender.tab ? sender.tab.id : null;
  if (!tabId) return { ok: false };
  await setTabState(tabId, { status: ANALYSIS_STATUS_ANALYZING, result: request.result, url: sender.tab.url, isPhish: false, legitimatePercent: null });
  await classify(tabId, request.result, sender.tab.url, request.dom, false);
  return { ok: true };
});

MessageRouter.register('ANALYSIS_UPDATE', async (request, sender) => {
  const tabId = sender.tab ? sender.tab.id : null;
  if (!tabId) return { ok: false };
  const currentState = await getTabState(tabId);
  await setTabState(tabId, { ...(currentState || {}), status: ANALYSIS_STATUS_ANALYZING, result: request.result, url: sender.tab.url });
  await classify(tabId, request.result, sender.tab.url, request.dom, true);
  return { ok: true };
});

MessageRouter.register('GET_TAB_STATE', async (request) => {
  if (!request.tabId) return null;
  return await getTabState(request.tabId) || null;
});

MessageRouter.register('SET_WHITELIST_TEMP', async (request) => {
  if (!request.tabId) return { ok: false };
  riskBlockAllowUntil.set(request.tabId, Date.now() + RISK_BLOCK_ALLOW_MS);
  await setTabState(request.tabId, { status: ANALYSIS_STATUS_IDLE, isWhiteList: null, isBlocked: null, url: null });
  return { ok: true };
});

MessageRouter.register('SEND_REPORT', async (request) => {
  const payload = request.payload || {};
  try {
    await ReportService.handleReport(payload, (percent) => {
      chrome.runtime.sendMessage({ action: 'REPORT_PROGRESS', percent }).catch(() => {});
    });
    return { success: true };
  } catch (err) {
    logger.error('SEND_REPORT', err);
    return { success: false, error: err.message || 'Lỗi không xác định.' };
  }
});

MessageRouter.register('SET_ICON', async (request) => {
  chrome.action.setIcon({ path: request.path, tabId: request.tabId }).catch(() => {});
  return { ok: true };
});

MessageRouter.register('SCAN_URL', async (request) => {
  const urlString = request.url;
  if (!urlString) return { ok: false, error: 'Missing url' };
  logger.info(`[SCAN_JOB_CREATED] url=${urlString}`);

  // Run async, return ack immediately
  (async () => {
    try {
      const domain = getDomain(urlString);
      const registrable = getRegistrable(domain);
      let inCldWhitelist = false;
      for (const w of whiteListingSet) { if (w.includes(domain) || w.includes(registrable)) { inCldWhitelist = true; break; } }
      if (inCldWhitelist || (typeof REPUTATION_WHITELIST !== 'undefined' && REPUTATION_WHITELIST.has(registrable))) {
        await setUrlScanResult(urlString, { status: 'SUCCESS', isWhiteList: domain, isPhish: false, legitimatePercent: 100, confidence: 95, listType: 'whitelist', result: {}, summary: 'Trang nằm trong danh sách tin cậy.', url: urlString, scanSource: 'CUSTOM_URL', updatedAt: Date.now() }); return;
      }
      if (_isKnownBadUrl(urlString)) {
        await setUrlScanResult(urlString, { status: 'SUCCESS', isPhish: true, legitimatePercent: 5, confidence: 95, result: {}, summary: 'URL nằm trong danh sách đen đã xác nhận.', url: urlString, scanSource: 'CUSTOM_URL', updatedAt: Date.now() }); return;
      }
      const cached = await getUrlCache(urlString, 'LIVE');
      if (cached) { await setUrlScanResult(urlString, { status: 'SUCCESS', ...cached, url: urlString, scanSource: 'CUSTOM_URL', updatedAt: Date.now() }); return; }
      await setUrlScanResult(urlString, { status: 'ANALYZING', isPhish: false, legitimatePercent: null, confidence: 0, result: {}, url: urlString, scanSource: 'CUSTOM_URL', updatedAt: Date.now() });
      await startHiddenTabScan(urlString);
    } catch (err) {
      logger.error(`[SCAN_URL FAILED] ${urlString}:`, err);
      await setUrlScanResult(urlString, { status: 'FAILED', isPhish: false, legitimatePercent: null, confidence: 0, result: {}, url: urlString, scanSource: 'CUSTOM_URL', updatedAt: Date.now() });
    }
  })();

  return { ok: true };
});

MessageRouter.register('GET_URL_SCAN_STATE', async (request) => {
  if (!request.url) return null;
  return await getUrlScanResult(request.url) || null;
});

MessageRouter.register('CLEAR_URL_SCAN_RESULT', async (request) => {
  if (request.url) await removeUrlScanResult(request.url).catch(() => {});
  return { ok: true };
});

// ─── Event Listeners ──────────────────────────────────────────────────────────
MessageRouter.listen();

chrome.webRequest.onBeforeRequest.addListener((details) => {
  if (details.type === 'main_frame' && details.tabId >= 0) redirectChains.set(details.tabId, [details.url]);
}, { urls: ['*://*/*'], types: ['main_frame'] });

chrome.webRequest.onBeforeRedirect.addListener((details) => {
  if (details.type === 'main_frame' && details.tabId >= 0 && details.redirectUrl) {
    const chain = redirectChains.get(details.tabId) || [];
    if (!chain.includes(details.redirectUrl)) chain.push(details.redirectUrl);
    redirectChains.set(details.tabId, chain);
  }
}, { urls: ['*://*/*'], types: ['main_frame'] });

chrome.tabs.onRemoved.addListener((tabId) => {
  redirectChains.delete(tabId); riskBlockAllowUntil.delete(tabId);
  if (deepScanTabs.has(tabId)) {
    const meta = deepScanTabs.get(tabId);
    if (meta.dwellTimer) clearTimeout(meta.dwellTimer);
    if (meta.hardTimeout) clearTimeout(meta.hardTimeout);
    finalizeDeepScan(tabId).catch(() => {});
  } else { removeTabState(tabId); }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    redirectChains.set(tabId, [changeInfo.url]);
    if (!deepScanTabs.has(tabId)) {
      setTabState(tabId, { status: ANALYSIS_STATUS_ANALYZING, result: null, url: changeInfo.url, isPhish: false, legitimatePercent: null }).catch(() => {});
    }
  }
  if (changeInfo.status === 'complete' && deepScanTabs.has(tabId)) {
    const meta = deepScanTabs.get(tabId);
    if (!meta.dwellTimer) {
      logger.info(`[DEEP_SCAN_DWELL_START] tabId=${tabId} url=${meta.url}`);
      meta.dwellTimer = setTimeout(() => {
        logger.info(`[DEEP_SCAN_DWELL_DONE] tabId=${tabId}`);
        if (meta.hardTimeout) clearTimeout(meta.hardTimeout);
        try { chrome.tabs.remove(tabId); } catch (e) {}
      }, DEEP_SCAN_DWELL_MS);
    }
  }
});

chrome.runtime.onConnect.addListener((port) => {
  switch (port.name) {
    case PORT_REDIRECT: port.onMessage.addListener((msg) => { chrome.tabs.query({ currentWindow: true, active: true }, ([tab]) => { if (tab && msg.redirect) chrome.tabs.update(tab.id, { url: msg.redirect }); }); }); break;
    case PORT_CLOSE_TAB: port.onMessage.addListener((msg) => { if (msg.close_tab) chrome.tabs.query({ currentWindow: true, active: true }, ([tab]) => { if (tab) chrome.tabs.remove(tab.id); }); }); break;
  }
});

chrome.webRequest.onBeforeRequest.addListener(safeCheck, { urls: ['*://*/*'], types: ['main_frame'] });

if (chrome.downloads && chrome.downloads.onCreated) {
  chrome.downloads.onCreated.addListener(async (item) => {
    const ext = _downloadExt(item.finalUrl || item.url, item.filename, item.mime); if (!ext) return;
    const risky = await _isDownloadFromRiskyContext(item); if (!risky) return;
    try { chrome.downloads.pause(item.id); } catch (_) {}
    const nid = `download-risk-${item.id}`; pendingDownloads.set(nid, item.id);
    chrome.notifications.create(nid, { type: 'basic', iconUrl: chrome.runtime.getURL('assets/antiScamLogo.png'), title: 'Cảnh báo tải xuống', message: `File ${ext.toUpperCase()} từ website đáng ngờ có thể gây hại.`, buttons: [{ title: 'Tiếp tục tải' }, { title: 'Hủy tải' }], requireInteraction: true }).catch(() => {});
  });
  chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (!pendingDownloads.has(notificationId)) return;
    const id = pendingDownloads.get(notificationId); pendingDownloads.delete(notificationId);
    if (buttonIndex === 0) chrome.downloads.resume(id).catch(() => {}); else chrome.downloads.cancel(id).catch(() => {});
    chrome.notifications.clear(notificationId).catch(() => {});
  });
  chrome.notifications.onClosed.addListener((notificationId) => {
    if (pendingDownloads.has(notificationId)) { const id = pendingDownloads.get(notificationId); pendingDownloads.delete(notificationId); chrome.downloads.cancel(id).catch(() => {}); }
  });
}

// ─── Queue flush khi online trở lại ──────────────────────────────────────────
self.addEventListener('online', () => {
  QueueManager.processQueue((payload) => ReportService.handleReport(payload, () => {}));
});

// ─── Startup ──────────────────────────────────────────────────────────────────
chrome.runtime.onStartup.addListener(() => startup().catch(() => {}));
chrome.runtime.onInstalled.addListener(() => {
  startup().catch(() => {});
  chrome.notifications.create({ type: 'basic', iconUrl: chrome.runtime.getURL('assets/antiScamLogo.png'), title: 'Cài đặt thành công!', message: 'AntiScam — engine Trust/Risk/Confidence đã sẵn sàng.' });
});
startup().catch(() => {});
