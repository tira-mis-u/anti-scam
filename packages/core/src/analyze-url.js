// ============================================================
// @anti-scam/core — URL analysis: findings, redirect, trust
// ============================================================
import { RISK_PTS, FINDING_CONFIDENCE, REDIRECT_PARAM_NAMES,
  EXECUTABLE_EXTS, ARCHIVE_EXTS, DOUBLE_EXT_RE, SHORT_BRAND_KEYS,
  VN_SCAM_KEYWORDS, REPUTATION_WHITELIST, BRANDS } from './constants.js';
import { getRegistrableDomain, isTrustedHost } from './url.js';
import { toUnicodeDomain, dehomoglyph, levenshtein, jaroWinkler,
  hasSuspiciousUnicode } from './brand.js';

const ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;

const findOpenRedirectTarget = (urlObj) => {
  try {
    const currentHost = getRegistrableDomain(urlObj.hostname);
    for (const name of REDIRECT_PARAM_NAMES) {
      const vals = urlObj.searchParams.getAll(name);
      for (const val of vals) {
        if (!val || val.length < 4) continue;
        let decoded = val;
        try { decoded = decodeURIComponent(val); } catch (_) {}
        if (!/^https?:\/\//i.test(decoded) && !/^\/\//.test(decoded)) continue;
        const target = new URL(decoded.startsWith('//') ? urlObj.protocol + decoded : decoded, urlObj.href);
        const targetHost = getRegistrableDomain(target.hostname);
        if (targetHost && currentHost && targetHost !== currentHost && !isTrustedHost(target.hostname)) return target.href;
      }
    }
  } catch (_) {}
  return null;
};

export const analyzeUrl = (urlString) => {
  const findings = [];
  let matchedBrand = null;
  if (!urlString || typeof urlString !== 'string' || !/^https?:\/\//i.test(urlString)) {
    return { findings, matchedBrand: null };
  }
  let url;
  try { url = new URL(urlString); } catch (_) { return { findings, matchedBrand: null }; }

  const hostname = url.hostname.toLowerCase();
  const unicodeHostname = toUnicodeDomain(hostname).toLowerCase();
  const registrable = getRegistrableDomain(hostname);
  const unicodeRegistrable = toUnicodeDomain(registrable).toLowerCase();
  const sld = unicodeRegistrable.split('.')[0] || unicodeHostname.replace(/^www\./, '').split('.')[0];
  const hostNoWww = unicodeHostname.replace(/^www\./, '');
  const asciiHostNoWww = hostname.replace(/^www\./, '');
  const pathLower = url.pathname.toLowerCase();
  const fullLower = urlString.toLowerCase();
  const add = (key, label, points, group, decays = true) => findings.push({ key, label, points, group, decays });

  // Punycode / Unicode
  if (hostname.includes('xn--')) add('Punycode', 'Tên miền có dấu hiệu giả mạo ký tự.', RISK_PTS.PUNYCODE, 'punycode', false);
  if (hasSuspiciousUnicode(unicodeHostname)) add('UnicodeHost', 'Tên miền có dấu hiệu giả mạo ký tự.', RISK_PTS.UNICODE_HOST, 'punycode', false);

  // Brand mimic
  const isOfficial = (b) => b.official.some(od => asciiHostNoWww === od || asciiHostNoWww.endsWith('.' + od) || hostNoWww === od || hostNoWww.endsWith('.' + od));
  const candidates = new Set([sld, hostNoWww, asciiHostNoWww]);
  hostNoWww.split('.').forEach(p => { if (p && p.length >= 3) candidates.add(p); });
  asciiHostNoWww.split('.').forEach(p => { if (p && p.length >= 3) candidates.add(p); });
  let brandFound = false;
  for (const token of candidates) {
    if (!token || token.length < 3 || brandFound) continue;
    const deh = dehomoglyph(token);
    for (const b of BRANDS) {
      if (isOfficial(b)) continue;
      if (b.keys.some(bk => deh === bk) && !b.keys.includes(token)) {
        matchedBrand = b.name;
        add('Homograph', 'Tên miền có dấu hiệu giả mạo ký tự.', RISK_PTS.HOMOGLYPH, 'brand', false);
        brandFound = true; break;
      }
    }
    if (brandFound) break;
    for (const b of BRANDS) {
      if (isOfficial(b)) continue;
      for (const bk of b.keys) {
        if (bk.length < 5) continue;
        if (token.length < Math.max(4, bk.length - 2)) continue;
        const dehToken = dehomoglyph(token);
        const d = levenshtein(dehToken, bk);
        const jw = jaroWinkler(dehToken, bk);
        if ((d === 1 || d === 2) || (jw >= 0.92 && dehToken !== bk && Math.abs(dehToken.length - bk.length) <= 3)) {
          matchedBrand = matchedBrand || b.name;
          add('Typosquat', 'Tên miền có dấu hiệu giả mạo thương hiệu.', d === 1 || jw >= 0.96 ? RISK_PTS.TYPOSQUAT_1 : RISK_PTS.TYPOSQUAT_2, 'brand', false);
          brandFound = true; break;
        }
      }
      if (brandFound) break;
    }
    if (brandFound) break;
  }
  if (!brandFound) {
    for (const b of BRANDS) {
      if (isOfficial(b)) continue;
      let hit = false;
      for (const bk of b.keys) {
        if (bk.length < 5 && !SHORT_BRAND_KEYS.has(bk)) continue;
        const re = new RegExp(`(^|[-_.0-9])${bk}([-_.0-9]|$)`);
        if (re.test(hostNoWww) || sld.includes(bk)) { hit = true; break; }
      }
      if (hit) {
        matchedBrand = matchedBrand || b.name;
        add('BrandInDomain', 'Tên miền có dấu hiệu giả mạo thương hiệu.', RISK_PTS.BRAND_IN_DOMAIN, 'brand', false);
        break;
      }
    }
  }
  if (!matchedBrand) {
    for (const b of BRANDS) {
      for (const bk of b.keys) {
        if (bk.length < 5 && !SHORT_BRAND_KEYS.has(bk)) continue;
        if (pathLower.includes(bk) && !isOfficial(b)) {
          add('BrandInPath', `Đường dẫn nhắc đến thương hiệu ${b.name}`, RISK_PTS.BRAND_IN_PATH, 'brand-path', true);
          matchedBrand = matchedBrand || b.name; break;
        }
      }
    }
  }

  if (fullLower.includes('@')) add('AtSymbol', 'URL chứa ký tự @', RISK_PTS.AT_SYMBOL, 'misc', true);
  if (ipRe.test(hostNoWww)) add('IPHost', 'Truy cập bằng địa chỉ IP', RISK_PTS.IP_HOST, 'misc', true);
  if (urlString.length > 100) add('LongURL', 'Đường dẫn quá dài', RISK_PTS.LONG_URL, 'misc', true);
  if (['.xyz', '.tk', '.ml', '.ga', '.cf', '.click', '.top', '.country', '.kim', '.review', '.work', '.date', '.racing', '.stream'].some(t => hostname.endsWith(t)))
    add('SuspiciousTLD', 'Đuôi tên miền dễ bị lạm dụng', RISK_PTS.SUSPICIOUS_TLD, 'misc', true);
  if (url.protocol !== 'https:') add('NoHTTPS', 'Không dùng HTTPS', RISK_PTS.NO_HTTPS, 'misc', true);
  const openRedirectTarget = findOpenRedirectTarget(url);
  if (openRedirectTarget) add('OpenRedirect', 'URL có tham số chuyển hướng sang tên miền khác.', RISK_PTS.OPEN_REDIRECT, 'redirect', false);

  let vnHits = 0;
  for (const kw of VN_SCAM_KEYWORDS) if (fullLower.includes(kw)) vnHits++;
  if (vnHits > 0) add('VNScamKeyword', `URL chứa ${vnHits} từ khoá thường thấy trong trang lừa đảo`, Math.min(RISK_PTS.VN_SCAM_KW + (vnHits - 1) * 4, 20), 'vn-scam', true);

  const fileName = decodeURIComponent((pathLower.split('/').pop() || '').split('?')[0].split('#')[0]);
  if (DOUBLE_EXT_RE.test(fileName)) {
    add('DangerousDownload', 'Tên file tải xuống có đuôi kép đáng ngờ.', RISK_PTS.DOWNLOAD + 8, 'download', false);
  } else {
    for (const ext of EXECUTABLE_EXTS) {
      if (pathLower.endsWith(ext) || pathLower.includes(ext + '?') || pathLower.includes(ext + '#')) {
        add('DangerousDownload', `Trang yêu cầu tải file ${ext.toUpperCase()} nguy hiểm`, RISK_PTS.DOWNLOAD, 'download', false);
        break;
      }
    }
  }
  if (!findings.some(f => f.key === 'DangerousDownload')) {
    for (const ext of ARCHIVE_EXTS) {
      if (pathLower.endsWith(ext) || pathLower.includes(ext + '?') || pathLower.includes(ext + '#')) {
        add('ArchiveDownload', `URL tải file nén ${ext.toUpperCase()}`, RISK_PTS.ARCHIVE_DOWNLOAD, 'download', true);
        break;
      }
    }
  }
  return { findings, matchedBrand };
};

export const analyzeRedirectChain = (chain) => {
  if (!chain || !Array.isArray(chain) || chain.length <= 1) {
    return { points: 0, hops: 0, distinctDomains: 0, label: null, openRedirects: [] };
  }
  const hosts = [];
  const openRedirects = [];
  for (const u of chain) {
    try {
      const obj = new URL(u);
      hosts.push(getRegistrableDomain(obj.hostname));
      const target = findOpenRedirectTarget(obj);
      if (target) openRedirects.push({ from: u, to: target });
    } catch (_) {}
  }
  const distinct = [...new Set(hosts.filter(Boolean))];
  const hops = chain.length - 1;
  let points = 0;
  if (hops > 2) points += 10;
  if (hops > 4) points += 10;
  if (distinct.length > 2) points += 12;
  if (distinct.length > 3) points += 8;
  if (openRedirects.length) points += RISK_PTS.OPEN_REDIRECT;
  if (distinct.length >= 2 && hosts[0] && hosts[hosts.length - 1] && hosts[0] !== hosts[hosts.length - 1]) points += 5;
  points = Math.min(points, 40);
  let label = null;
  if (openRedirects.length) label = 'Chuỗi chuyển hướng có dấu hiệu open redirect sang tên miền khác.';
  else if (points > 0) label = 'Website chuyển hướng qua nhiều miền khác nhau.';
  return { points, hops, distinctDomains: distinct.length, label, openRedirects };
};

export const getTrustContext = (urlString, rep, domainAgeDays) => {
  let host = '', registrable = '';
  try { host = new URL(urlString).hostname; registrable = getRegistrableDomain(host); } catch (_) {}
  const https = /^https:/i.test(urlString || '');
  const knownGood = !!(rep.inWhitelist || rep.isOfficialBrand || REPUTATION_WHITELIST.has(registrable));
  const confirmedDanger = !!(rep.inBlacklist || (rep.malware && rep.malware.dangerous));
  if (confirmedDanger) return 'LOW_TRUST';
  if (knownGood) return 'HIGH_TRUST';
  if (https && domainAgeDays > 365) return 'MEDIUM_TRUST';
  if (https && domainAgeDays > 90 && rep.checked) return 'MEDIUM_TRUST';
  return 'LOW_TRUST';
};