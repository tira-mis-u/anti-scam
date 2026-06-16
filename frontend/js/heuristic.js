// js/heuristic.js  —  ENGINE V2
// ─────────────────────────────────────────────────────────────────────────────
// MÔ HÌNH MỚI:  Final Score = clamp( 50 + TrustScore − RiskScore , 0, 100 )
//
//   • Trust Score  — TĂNG khi domain lâu năm, SSL ổn, nằm whitelist, reputation tốt.
//   • Risk Score   — TĂNG khi phishing/malware/obfuscation/brand spoof/redirect lạ.
//   • Confidence   — mức độ chắc chắn (dựa trên lượng dữ liệu thu thập được).
//   • isUnknown    — nếu Confidence thấp → KHÔNG được kết luận "rất an toàn",
//                    điểm tối đa bị khoá ở 60 cho đến khi đủ dữ liệu.
//
// Giải quyết nghịch lý:
//   ChatGPT (iframe + password + external) nhưng domain cũ + reputation → cao.
//   Trang trắng vô danh (không gì) → ≈ 50, KHÔNG 95.
//
// Chạy trong Service Worker. Tín hiệu DOM/features.js + redirect chain +
// reputation + network được truyền qua `context`.
// ─────────────────────────────────────────────────────────────────────────────

/* global chrome */

// ═══════════════════════════════════════════════════════════════════════════
// 1. CƠ SỞ DỮ LIỆU THƯƠNG HIỆU  (giả mạo / typosquatting)
// ═══════════════════════════════════════════════════════════════════════════
const BRANDS = [
  { name: 'Google',       keys: ['google', 'googl'],     official: ['google.com', 'google.vn', 'g.co', 'gstatic.com', 'googleusercontent.com', 'gmail.com', 'youtube.com', 'yt.be', 'blogger.com', 'android.com'] },
  { name: 'Microsoft',    keys: ['microsoft', 'microsft'],official: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'microsoftonline.com', 'msn.com', 'bing.com', 'azure.com', 'windows.com', 'xbox.com', 'skype.com', 'live.cn'] },
  { name: 'Facebook',     keys: ['facebook', 'facebok'],  official: ['facebook.com', 'fb.com', 'fb.me', 'instagram.com', 'whatsapp.com', 'meta.com', 'messenger.com', 'oculus.com'] },
  { name: 'Apple',        keys: ['apple'],                official: ['apple.com', 'icloud.com', 'me.com', 'mac.com', 'itunes.com', 'appstore.com'] },
  { name: 'OpenAI',       keys: ['openai'],               official: ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com'] },
  { name: 'Telegram',     keys: ['telegram'],             official: ['telegram.org', 't.me', 'telegram.me'] },
  { name: 'Zalo',         keys: ['zalo'],                 official: ['zalo.me', 'zaloapp.com', 'zadn.vn'] },
  { name: 'Vietcombank',  keys: ['vietcombank', 'vcb'],   official: ['vietcombank.com.vn', 'vcb.com.vn', 'vcbdirect.com'] },
  { name: 'BIDV',         keys: ['bidv'],                 official: ['bidv.com.vn'] },
  { name: 'MB Bank',      keys: ['mbbank'],               official: ['mbbank.com.vn'] },
  { name: 'ACB',          keys: ['acb'],                  official: ['acb.com.vn'] },
  { name: 'Techcombank',  keys: ['techcombank', 'tcb'],   official: ['techcombank.com.vn'] },
  { name: 'TPBank',       keys: ['tpbank'],               official: ['tpb.vn', 'tpbank.vn'] },
  { name: 'Agribank',     keys: ['agribank', 'agri'],     official: ['agribank.com.vn'] },
  { name: 'VietinBank',   keys: ['vietinbank', 'vtb'],    official: ['vietinbank.vn', 'vietinbank.com.vn'] },
  { name: 'VPBank',       keys: ['vpbank'],               official: ['vpbank.vn'] },
  { name: 'Sacombank',    keys: ['sacombank', 'stb'],     official: ['sacombank.com'] },
  { name: 'MoMo',         keys: ['momo'],                 official: ['momo.vn'] },
  { name: 'ZaloPay',      keys: ['zalopay'],              official: ['zalopay.vn'] },
  { name: 'PayPal',       keys: ['paypal'],               official: ['paypal.com', 'pypl.com'] },
  { name: 'Amazon',       keys: ['amazon', 'amazn'],      official: ['amazon.com', 'amazon.co', 'amzn.com', 'aws.amazon.com'] },
  { name: 'Netflix',      keys: ['netflix'],              official: ['netflix.com', 'nflxvideo.net'] },
  { name: 'GitHub',       keys: ['github'],               official: ['github.com', 'githubusercontent.com', 'githubassets.com'] },
  { name: 'Shopee',       keys: ['shopee'],               official: ['shopee.vn', 'shopee.com', 'shopeemobile.com'] },
  { name: 'Lazada',       keys: ['lazada'],               official: ['lazada.vn', 'lazada.com', 'lazada.co.th'] },
  { name: 'Tiki',         keys: ['tiki'],                 official: ['tiki.vn'] },
  { name: 'Stripe',       keys: ['stripe'],               official: ['stripe.com', 'stripecdn.com'] },
  { name: 'Viettel',      keys: ['viettel'],              official: ['viettel.com.vn', 'viettel.vn'] },
  { name: 'VNPT',         keys: ['vnpt'],                 official: ['vnpt.vn', 'vnpt.com.vn'] },
  { name: 'VNG',          keys: ['vng'],                  official: ['vng.com.vn', 'vngcloud.vn'] },
];

// ═══════════════════════════════════════════════════════════════════════════
// 2. REPUTATION WHITELIST (built-in) — tăng trust score
//    (bổ sung cho whitelist tải từ API ChongLuaDao — chạy được cả khi offline)
// ═══════════════════════════════════════════════════════════════════════════
const REPUTATION_WHITELIST = new Set([
  'google.com', 'youtube.com', 'github.com', 'githubusercontent.com', 'microsoft.com',
  'openai.com', 'chatgpt.com', 'cloudflare.com', 'facebook.com', 'instagram.com',
  'zalo.me', 'zaloapp.com', 'apple.com', 'amazon.com', 'paypal.com', 'netflix.com',
  'linkedin.com', 'twitter.com', 'x.com', 'wikipedia.org', 'mozilla.org', 'stripe.com',
  'vietcombank.com.vn', 'bidv.com.vn', 'mbbank.com.vn', 'techcombank.com.vn',
  'tpb.vn', 'agribank.com.vn', 'vietinbank.vn', 'vpbank.vn', 'sacombank.com',
  'momo.vn', 'zalopay.vn', 'shopee.vn', 'lazada.vn', 'tiki.vn', 'acb.com.vn',
  'outlook.com', 'live.com', 'office.com', 'bing.com', 'whatsapp.com', 'telegram.org',
]);

// ═══════════════════════════════════════════════════════════════════════════
// 3. TRUSTED CDN / dịch vụ phổ biến — tài nguyên từ đây = 0 rủi ro
// ═══════════════════════════════════════════════════════════════════════════
const TRUSTED_HOSTS = new Set([
  // Google
  'google.com', 'googleapis.com', 'ajax.googleapis.com', 'fonts.googleapis.com',
  'fonts.gstatic.com', 'www.gstatic.com', 'storage.googleapis.com', 'apis.google.com',
  'maps.googleapis.com', 'www.google.com', 'google-analytics.com', 'googletagmanager.com',
  'www.googletagmanager.com', 'ssl.gstatic.com', 'youtube.com', 'i.ytimg.com',
  'ytimg.com', 'www.youtube-nocookie.com', 'accounts.google.com', 'googlevideo.com',
  // Cloudflare
  'cdnjs.cloudflare.com', 'cdn.cloudflare.com', 'ajax.cloudflare.com',
  'challenges.cloudflare.com', 'static.cloudflareinsights.com',
  // jsDelivr / npm / unpkg
  'cdn.jsdelivr.net', 'jsdelivr.net', 'unpkg.com', 'npmcdn.com',
  'cdn.skypack.dev', 'esm.sh', 'esm.run',
  // Bootstrap
  'stackpath.bootstrapcdn.com', 'maxcdn.bootstrapcdn.com', 'netdna.bootstrapcdn.com',
  'getbootstrap.com',
  // Font Awesome
  'use.fontawesome.com', 'kit.fontawesome.com', 'ka-f.fontawesome.com',
  // Microsoft
  'ajax.aspnetcdn.com', 'ajax.microsoft.com', 'msecnd.net',
  // jQuery
  'code.jquery.com',
  // Facebook / Meta
  'connect.facebook.net', 'static.xx.fbcdn.net', 'scontent.xx.fbcdn.net',
  // Twitter / X
  'platform.twitter.com', 'cdn.syndication.twimg.com', 'abs.twimg.com',
  // Stripe
  'js.stripe.com', 'm.stripe.com', 'm.stripe.network', 'r.stripe.com', 'api.stripe.com',
  // GitHub
  'github.githubassets.com',
  // Phổ biến khác
  'cdn.tailwindcss.com', 'polyfill.io', 'cdn.polyfill.io', 'static.addtoany.com',
  'c.disquscdn.com', 'disqus.com', 'ws.audioscrobbler.com',
]);

const isTrustedHost = (host) => {
  if (!host) return false;
  const h = host.toLowerCase().replace(/^www\./, '');
  if (TRUSTED_HOSTS.has(h)) return true;
  for (const t of TRUSTED_HOSTS) {
    if (h.endsWith('.' + t)) return true;
  }
  if (h.endsWith('.googleusercontent.com') || h.endsWith('.fbcdn.net') ||
      h.endsWith('.doubleclick.net') || h.endsWith('.googletagmanager.com') ||
      h.endsWith('.cloudfront.net') || h.endsWith('.akamai.net') ||
      h.endsWith('.akamaized.net') || h.endsWith('.fastly.net') ||
      h.endsWith('.jsdelivr.net') || h.endsWith('.msecnd.net') ||
      h.endsWith('.stripe.com') || h.endsWith('.githubassets.com') ||
      h.endsWith('.googlevideo.com') || h.endsWith('.ytimg.com')) {
    return true;
  }
  return false;
};

// ═══════════════════════════════════════════════════════════════════════════
// 4. TỪ KHÓA & tiện ích
// ═══════════════════════════════════════════════════════════════════════════
const VN_SCAM_KEYWORDS = [
  'xacminh', 'xac-minh', 'dinhdanh', 'dinh-danh', 'e-kyc', 'ekyc',
  'capnhat-thongtin', 'cap-nhat-thong-tin', 'khoiphuc', 'khoi-phuc',
  'baomat', 'bao-mat', 'xac-thuc', 'xacthuc', 'nang-cap-bao-mat',
  'dong-bo-du-lieu', 'dongbodulieu', 'xac-minh-tai-khoan', 'xacminhtaikhoan',
  'kichhoat', 'kich-hoat', 'napthe', 'nap-the', 'vongquay', 'vong-quay',
  'nhan-qua', 'tang-qua', 'hoan-tien', 'khoa-tai-khoan', 'vohieuhoa',
];
const DANGEROUS_EXTS = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.apk', '.msi', '.dll', '.vbs', '.jar'];

const MULTI_PART_TLDS = new Set([
  'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn', 'ac.vn', 'biz.vn',
  'info.vn', 'name.vn', 'pro.vn', 'health.vn', 'io.vn',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.jp', 'com.au', 'net.au',
  'com.br', 'com.cn', 'com.hk', 'com.sg', 'com.my', 'com.tw', 'co.kr',
  'co.nz', 'co.in', 'com.mx', 'com.ar', 'co.za',
]);

const getRegistrableDomain = (host) => {
  if (!host) return '';
  let h = host.toLowerCase().replace(/^www\./, '');
  if (typeof psl !== 'undefined') {
    try { const d = psl.parse(h).domain; if (d) return d; } catch (_) {}
  }
  const parts = h.split('.');
  if (parts.length <= 2) return h;
  const lastTwo = parts.slice(-2).join('.');
  const lastThree = parts.slice(-3).join('.');
  if (MULTI_PART_TLDS.has(lastThree) && parts.length >= 4) return lastThree;
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) return parts.slice(-3).join('.');
  return lastTwo;
};

const isOfficialBrandDomain = (host) => {
  if (!host) return null;
  const h = host.toLowerCase().replace(/^www\./, '');
  for (const b of BRANDS) {
    if (b.official.some(od => h === od || h.endsWith('.' + od))) return b;
  }
  return null;
};

const levenshtein = (a, b) => {
  if (a === b) return 0;
  const al = a.length, bl = b.length;
  if (al === 0) return bl;
  if (bl === 0) return al;
  let prev = new Array(bl + 1), curr = new Array(bl + 1);
  for (let j = 0; j <= bl; j++) prev[j] = j;
  for (let i = 1; i <= al; i++) {
    curr[0] = i;
    for (let j = 1; j <= bl; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[bl];
};

const dehomoglyph = (s) => {
  let r = s.toLowerCase();
  r = r.replace(/rn/g, 'm');
  r = r.replace(/[0]/g, 'o');
  r = r.replace(/[1|!¡]/g, 'l');
  r = r.replace(/[3]/g, 'e');
  r = r.replace(/[4@àáâãäå]/g, 'a');
  r = r.replace(/[5$]/g, 's');
  r = r.replace(/[7]/g, 't');
  r = r.replace(/[8]/g, 'b');
  r = r.replace(/[6]/g, 'g');
  r = r.replace(/[íìîï]/g, 'i');
  r = r.replace(/vv/g, 'w');
  return r;
};

const hasSuspiciousUnicode = (host) => {
  for (let i = 0; i < host.length; i++) {
    const c = host.charCodeAt(i);
    if (c > 0x7e || (c < 0x30 && c !== 0x2d && c !== 0x2e)) return true;
  }
  return false;
};

// ═══════════════════════════════════════════════════════════════════════════
// 5. PHÂN TÍCH URL → findings rủi ro
//    Mỗi finding: { key, label, points, group, decays }
//    decays=true → rủi ro "mềm", giảm dần theo thời gian ổn định
// ═══════════════════════════════════════════════════════════════════════════
const RISK_PTS = {
  HOMOGLYPH: 30, TYPOSQUAT_1: 28, TYPOSQUAT_2: 18, BRAND_IN_DOMAIN: 14,
  BRAND_IN_PATH: 8, BRAND_IMPERSONATION_STRONG: 26, BRAND_IMPERSONATION_WEAK: 10,
  FORM_HIJACK: 26, OBFUSCATION: 18, SUSPICIOUS_EXT_IP: 16, SUSPICIOUS_EXT_DOMAIN: 7,
  KEYLOGGER: 22, CLIPBOARD: 18, DOWNLOAD: 18, VN_SCAM_KW: 12, HIDDEN_IFRAME: 12,
  REDIRECT_ABUSE: 20, PUNYCODE: 12, UNICODE_HOST: 12, IP_HOST: 10,
  NO_HTTPS: 5, AT_SYMBOL: 3, LONG_URL: 3, SUSPICIOUS_TLD: 7,
};

const analyzeUrl = (urlString) => {
  const findings = [];
  let matchedBrand = null;
  if (!urlString || typeof urlString !== 'string' || !/^https?:\/\//i.test(urlString)) {
    return { findings, matchedBrand: null };
  }
  let url;
  try { url = new URL(urlString); } catch (_) { return { findings, matchedBrand: null }; }

  const hostname = url.hostname.toLowerCase();
  const registrable = getRegistrableDomain(hostname);
  const sld = registrable.split('.')[0] || hostname.replace(/^www\./, '').split('.')[0];
  const hostNoWww = hostname.replace(/^www\./, '');
  const pathLower = url.pathname.toLowerCase();
  const fullLower = urlString.toLowerCase();
  const add = (key, label, points, group, decays = true) => findings.push({ key, label, points, group, decays });

  // Punycode / Unicode
  if (hostname.includes('xn--')) add('Punycode', 'Tên miền chứa ký tự mã hoá (Punycode)', RISK_PTS.PUNYCODE, 'punycode', false);
  if (hasSuspiciousUnicode(hostname)) add('UnicodeHost', 'Tên miền có ký tự Unicode bất thường', RISK_PTS.UNICODE_HOST, 'punycode', false);

  // Brand mimic (homograph / typosquat / brand-in-domain)
  const isOfficial = (b) => b.official.some(od => hostNoWww === od || hostNoWww.endsWith('.' + od));
  const candidates = new Set([sld, hostNoWww]);
  hostNoWww.split('.').forEach(p => { if (p && p.length >= 3) candidates.add(p); });
  let brandFound = false;
  for (const token of candidates) {
    if (!token || token.length < 3 || brandFound) continue;
    const deh = dehomoglyph(token);
    for (const b of BRANDS) {
      if (isOfficial(b)) continue;
      if (deh === b.keys[0] && token !== b.keys[0]) {
        matchedBrand = b.name;
        add('Homograph', `Tên miền giả mạo thương hiệu ${b.name} (ký tự nhìn giống)`, RISK_PTS.HOMOGLYPH, 'brand', false);
        brandFound = true; break;
      }
    }
    if (brandFound) break;
    for (const b of BRANDS) {
      if (isOfficial(b)) continue;
      for (const bk of b.keys) {
        if (bk.length < 5) continue;
        if (token.length < Math.max(4, bk.length - 2)) continue;
        const d = levenshtein(token, bk);
        if (d === 1 || d === 2) {
          matchedBrand = matchedBrand || b.name;
          add('Typosquat', `Tên miền gần giống thương hiệu ${b.name}`, d === 1 ? RISK_PTS.TYPOSQUAT_1 : RISK_PTS.TYPOSQUAT_2, 'brand', false);
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
        if (bk.length < 5) continue;
        const re = new RegExp(`(^|[-_.0-9])${bk}([-_.0-9]|$)`);
        if (re.test(hostNoWww) || sld.includes(bk)) { hit = true; break; }
      }
      if (hit) {
        matchedBrand = matchedBrand || b.name;
        add('BrandInDomain', `Tên miền chứa thương hiệu ${b.name} nhưng không thuộc hệ thống chính thức`, RISK_PTS.BRAND_IN_DOMAIN, 'brand', false);
        break;
      }
    }
  }
  // Brand in path
  if (!matchedBrand) {
    for (const b of BRANDS) {
      for (const bk of b.keys) {
        if (bk.length < 5) continue;
        if (pathLower.includes(bk) && !isOfficial(b)) {
          add('BrandInPath', `Đường dẫn nhắc đến thương hiệu ${b.name}`, RISK_PTS.BRAND_IN_PATH, 'brand-path', true);
          matchedBrand = matchedBrand || b.name; break;
        }
      }
    }
  }

  // Misc yếu tố nhẹ
  if (fullLower.includes('@')) add('AtSymbol', 'URL chứa ký tự @', RISK_PTS.AT_SYMBOL, 'misc', true);
  const ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipRe.test(hostNoWww)) add('IPHost', 'Truy cập bằng địa chỉ IP', RISK_PTS.IP_HOST, 'misc', true);
  if (urlString.length > 100) add('LongURL', 'Đường dẫn quá dài', RISK_PTS.LONG_URL, 'misc', true);
  if (['.xyz', '.tk', '.ml', '.ga', '.cf', '.click', '.top', '.country', '.kim', '.review', '.work', '.date', '.racing', '.stream'].some(t => hostname.endsWith(t)))
    add('SuspiciousTLD', 'Đuôi tên miền dễ bị lạm dụng', RISK_PTS.SUSPICIOUS_TLD, 'misc', true);
  if (url.protocol !== 'https:') add('NoHTTPS', 'Không dùng HTTPS', RISK_PTS.NO_HTTPS, 'misc', true);

  // Từ khoá lừa đảo VN
  let vnHits = 0;
  for (const kw of VN_SCAM_KEYWORDS) if (fullLower.includes(kw)) vnHits++;
  if (vnHits > 0) add('VNScamKeyword', `URL chứa ${vnHits} từ khoá thường thấy trong trang lừa đảo`, Math.min(RISK_PTS.VN_SCAM_KW + (vnHits - 1) * 4, 20), 'vn-scam', true);

  // File tải xuống nguy hiểm
  for (const ext of DANGEROUS_EXTS) {
    if (pathLower.endsWith(ext) || pathLower.includes(ext + '?') || pathLower.includes(ext + '#')) {
      add('DangerousDownload', `Trang yêu cầu tải file ${ext.toUpperCase()} nguy hiểm`, RISK_PTS.DOWNLOAD, 'download', false);
      break;
    }
  }
  return { findings, matchedBrand };
};

// ═══════════════════════════════════════════════════════════════════════════
// 6. PHÂN TÍCH REDIRECT CHAIN
// ═══════════════════════════════════════════════════════════════════════════
const analyzeRedirectChain = (chain) => {
  if (!chain || !Array.isArray(chain) || chain.length <= 1) {
    return { points: 0, hops: 0, distinctDomains: 0, label: null };
  }
  const hosts = [];
  for (const u of chain) {
    try { hosts.push(getRegistrableDomain(new URL(u).hostname)); } catch (_) {}
  }
  const distinct = [...new Set(hosts.filter(Boolean))];
  const hops = chain.length - 1;
  let points = 0;
  if (hops > 2) points += 10;
  if (hops > 4) points += 10;
  if (distinct.length > 2) points += 12;
  if (distinct.length > 3) points += 8;
  // origin khác final
  if (distinct.length >= 2 && hosts[0] && hosts[hosts.length - 1] && hosts[0] !== hosts[hosts.length - 1]) points += 5;
  points = Math.min(points, 35);
  const label = points > 0 ? `Chuỗi chuyển hướng phức tạp (${hops} bước, ${distinct.length} tên miền)` : null;
  return { points, hops, distinctDomains: distinct.length, label };
};

// ═══════════════════════════════════════════════════════════════════════════
// 7. ENGINE CHÍNH — computeScore
// ═══════════════════════════════════════════════════════════════════════════
const computeScore = (urlString, context = {}) => {
  const ctx = context || {};
  const dom = ctx.dom || {};
  const domainAgeDays = ctx.domainAgeDays != null ? ctx.domainAgeDays : -1;
  const rep = ctx.reputation || { checked: false };
  const redirectChain = ctx.redirectChain || [];
  const stabilityMs = ctx.stabilityMs || 0;

  const urlPart = analyzeUrl(urlString);
  const findings = urlPart.findings.slice();
  const matchedBrand = urlPart.matchedBrand || dom.matchedBrand;

  // ── 7.1 DOM findings ──────────────────────────────────────────────────────
  // BRAND IMPERSONATION qua nhiều bề mặt (title/favicon/logo/h1/h2/meta)
  if (dom.brandInContent) {
    const surfaces = dom.brandSurfaces || 1;
    const strong = surfaces >= 2;
    const lbl = matchedBrand
      ? `Trang dùng logo/tiêu đề thương hiệu ${matchedBrand} nhưng tên miền không chính thức`
      : 'Trang hiển thị thương hiệu quen thuộc nhưng tên miền không chính thức';
    findings.push({ key: 'BrandImpersonation', label: lbl,
      points: strong ? RISK_PTS.BRAND_IMPERSONATION_STRONG : RISK_PTS.BRAND_IMPERSONATION_WEAK,
      group: 'brand', decays: false });
  }
  if (dom.formHijack) findings.push({ key: 'FormHijack', label: 'Biểu mẫu gửi thông tin sang một tên miền khác lạ', points: RISK_PTS.FORM_HIJACK, group: 'form', decays: false });
  if (dom.obfuscatedScript) findings.push({ key: 'ObfuscatedScript', label: 'Mã JavaScript bị làm rối bất thường', points: RISK_PTS.OBFUSCATION, group: 'obfuscation', decays: false });
  if (dom.suspiciousExternalScript) findings.push({ key: 'SuspiciousExternal', label: 'Tải mã từ nguồn không phổ biến / địa chỉ IP', points: RISK_PTS.SUSPICIOUS_EXT_IP, group: 'external', decays: false });
  if (dom.keylogger) findings.push({ key: 'Keylogger', label: 'Có dấu hiệu theo dõi thao tác gõ phím', points: RISK_PTS.KEYLOGGER, group: 'malware', decays: false });
  if (dom.clipboardHijack) findings.push({ key: 'ClipboardHijack', label: 'Có dấu hiệu can thiệp bộ nhớ tạm (clipboard)', points: RISK_PTS.CLIPBOARD, group: 'malware', decays: false });
  if (dom.downloadFile) findings.push({ key: 'DangerousDownload', label: 'Trang yêu cầu tải ngay phần mềm/file khả nghi', points: RISK_PTS.DOWNLOAD, group: 'download', decays: false });
  // IFRAME — dùng Iframe Risk Score chi tiết từ features.js
  if (dom.iframeRiskScore > 0) {
    const detail = dom.iframeDetails && dom.iframeDetails[0];
    const lbl = detail
      ? `Khung trang (iFrame) đáng ngờ: ${detail.reasons.join(', ')}`
      : 'Phát hiện khung trang ẩn (iFrame vô hình)';
    // Map điểm iframe → risk points (cap 35)
    const pts = Math.min(Math.round(dom.iframeRiskScore * 0.5), 35);
    findings.push({ key: 'iFrames', label: lbl, points: pts, group: 'malware', decays: false });
  }
  // Network: upload dữ liệu ra domain lạ
  if (dom.networkUploadToExternal) findings.push({ key: 'DataExfil', label: 'Có dấu hiệu gửi dữ liệu ra tên miền lạ', points: RISK_PTS.KEYLOGGER, group: 'malware', decays: false });
  // FORM DESTINATION ENGINE (V3): endpoint thực tế nhận dữ liệu form
  if (dom.hasUntrustedFormDest && (dom.sensitiveForm || dom.passwordField || dom.otpField)) {
    const dests = dom.formDestinations || [];
    findings.push({ key: 'FormDest', label: `Biểu mẫu gửi dữ liệu đến ${dests.length > 1 ? dests.length + ' tên miền lạ' : 'tên miền lạ'}`, points: RISK_PTS.FORM_HIJACK, group: 'form', decays: false });
  }

  // Redirect chain
  const rc = analyzeRedirectChain(redirectChain);
  if (rc.points > 0 && rc.label) {
    findings.push({ key: 'RedirectChain', label: rc.label, points: rc.points, group: 'redirect', decays: true });
  }

  // SFH — hành vi submit form
  //   '0' (vàng): form không có action / action="#" 
  //     → RẤT phổ biến ở SPA (React/Vue/Angular xử lý submit bằng JS)
  //     → KHÔNG phạt nếu không có form nhạy cảm (gần như false positive)
  //     → Chỉ phạt nhẹ khi đi kèm password/OTP
  //   '1' (đỏ) : form gửi cross-domain → FormHijack đã xử lý
  if (dom.sfh === '0' && (dom.sensitiveForm || dom.passwordField || dom.otpField)) {
    findings.push({
      key: 'SFH',
      label: 'Biểu mẫu nhập liệu không chỉ rõ nơi nhận dữ liệu',
      points: 8, group: 'form', decays: true,
    });
  }

  // ── 7.2 TÍNH RISK SCORE (base + corroboration) ────────────────────────────
  const groupMax = { 'brand': 45, 'brand-path': 12, 'punycode': 15, 'form': 45, 'malware': 40,
    'obfuscation': 20, 'external': 16, 'download': 18, 'vn-scam': 18, 'redirect': 25, 'misc': 18 };
  const byGroup = {};
  for (const f of findings) byGroup[f.group] = (byGroup[f.group] || 0) + f.points;
  let baseRisk = 0;
  for (const g in byGroup) baseRisk += Math.min(byGroup[g], groupMax[g] != null ? groupMax[g] : 25);

  const has = (g) => (byGroup[g] || 0) > 0;
  const hasBrand = has('brand') || has('brand-path');
  const hasMalware = has('malware');
  const hasObf = has('obfuscation') || has('external');
  const hasVnScam = has('vn-scam');
  const hasRedirect = has('redirect');

  const veryNew = domainAgeDays >= 0 && domainAgeDays < 7;
  const young = domainAgeDays >= 0 && domainAgeDays < 30;
  const noRep = !rep.inWhitelist && !rep.isOfficialBrand;

  let bonus = 0;
  const reasons = [];

  // Password Risk Context: password + (brand spoof | new domain + no rep) mới nguy hiểm
  if (dom.passwordField || dom.otpField) {
    if (hasBrand) {
      bonus += 25;
      reasons.push(matchedBrand
        ? `Trang yêu cầu nhập mật khẩu/OTP và có dấu hiệu giả mạo thương hiệu ${matchedBrand}.`
        : 'Trang yêu cầu nhập mật khẩu/OTP và có dấu hiệu giả mạo thương hiệu.');
    } else if (veryNew && noRep) {
      bonus += 12;
      reasons.push('Tên miền mới đăng ký yêu cầu nhập mật khẩu/OTP mà chưa có uy tín.');
    }
    // password/otp đơn lẻ trên site cũ/uy tín → KHÔNG cộng (bình thường)
  }
  if (dom.formHijack && dom.passwordField) { bonus += 15; }
  if (hasBrand && young) { bonus += 18; reasons.push('Tên miền vừa mới đăng ký lại có dấu hiệu giả mạo thương hiệu.'); }
  if (hasObf && (dom.passwordField || dom.otpField)) { bonus += 14; reasons.push('Trang vừa yêu cầu nhập mật khẩu vừa dùng mã bị làm rối.'); }
  if (hasMalware && (dom.passwordField || hasBrand || young)) { bonus += 16; reasons.push('Trang có dấu hiệu mã độc đi kèm các yếu tố đáng ngờ khác.'); }
  if (hasVnScam && (dom.passwordField || dom.otpField)) { bonus += 15; reasons.push('URL chứa từ khoá "xác minh/định danh/OTP" và trang yêu cầu nhập thông tin nhạy cảm.'); }
  if (hasRedirect && hasBrand) { bonus += 15; reasons.push('Chuỗi chuyển hướng phức tạp kết hợp giả mạo thương hiệu.'); }

  let riskScore = Math.min(100, baseRisk + bonus);

  // Nếu corroboration tạo bonus nhưng không có finding cụ thể → thêm contextual finding
  // (để summary và badge có thể hiển thị đúng)
  if (bonus > 0 && findings.length === 0 && reasons.length > 0) {
    findings.push({ key: 'ContextRisk', label: reasons[0], points: bonus, group: 'context', decays: true });
  }

  // WebSocket: chỉ tăng nhẹ khi đã có rủi ro khác
  if (dom.websocket && riskScore >= 20) riskScore = Math.min(100, riskScore + 5);

  // ── 7.3 RISK DECAY — rủi ro "mềm" giảm dần nếu trang ổn định lâu ──────────
  if (stabilityMs > 20000 && riskScore > 0 && !rep.inBlacklist) {
    const softRisk = findings.filter(f => f.decays).reduce((s, f) => s + f.points, 0);
    const hardRisk = riskScore - Math.min(softRisk, 25);
    const decay = Math.max(0.5, 1 - stabilityMs / 240000); // sau 4 phút ổn định → giảm nửa phần mềm
    riskScore = Math.round(hardRisk + Math.min(softRisk, 25) * decay);
    riskScore = Math.max(hardRisk, riskScore);
  }

  // ── 7.4 TRUST SCORE ───────────────────────────────────────────────────────
  let trustScore = 0;
  const trustBadges = [];
  if (domainAgeDays >= 0) {
    if (domainAgeDays > 730) { trustScore += 38; trustBadges.push({ key: 'EstablishedDomain', label: 'Tên miền lâu đời (trên 2 năm)' }); }
    else if (domainAgeDays > 365) { trustScore += 30; trustBadges.push({ key: 'EstablishedDomain', label: 'Tên miền hoạt động trên 1 năm' }); }
    else if (domainAgeDays > 90) { trustScore += 18; trustBadges.push({ key: 'EstablishedDomain', label: 'Tên miền đã hoạt động vài tháng' }); }
    else if (domainAgeDays > 30) { trustScore += 8; }
  }
  if (rep.inWhitelist) { trustScore += 20; trustBadges.push({ key: 'ReputationVerified', label: 'Nằm trong danh sách tin cậy' }); }
  if (rep.isOfficialBrand) { trustScore += 15; trustBadges.push({ key: 'OfficialBrand', label: 'Tên miền chính thức của thương hiệu lớn' }); }
  if (/^https:/.test(urlString || '')) { trustScore += 3; trustBadges.push({ key: 'SSL', label: 'Có chứng chỉ bảo mật HTTPS' }); }
  if (rep.trustedCdnOnly !== false && dom.scanned && !dom.suspiciousExternalScript) {
    trustBadges.push({ key: 'TrustedResources', label: 'Tài nguyên từ các nguồn phổ biến' });
  }
  trustScore = Math.min(trustScore, 45);

  // Blacklist → rủi ro cực mạnh, phủ quyết trust
  if (rep.inBlacklist) { riskScore = Math.max(riskScore, 90); trustScore = 0; }

  // ── CLEAN SCAN TRUST ──────────────────────────────────────────────────────
  //    "Quét 25 yếu tố, TẤT CẢ đều an toàn" CHÍNH LÀ bằng chứng uy tín.
  //    Giúp site vô danh nhưng sạch sẽ đạt điểm hợp lý (70-80%) thay vì kẹt ở 53%.
  //    CHỈ áp dụng khi chưa có đủ trust từ reputation → không đẩy site uy tín lên cao hơn.
  if (!rep.inBlacklist && dom.scanned && dom.contentRich && trustScore < 32) {
    if (riskScore === 0) {
      trustScore = Math.max(trustScore, 32); // site quét sạch → tối thiểu 82%
      trustBadges.push({ key: 'CleanScan', label: 'Quét toàn diện: không phát hiện mối đe dọa' });
    } else if (riskScore < 8) {
      trustScore = Math.max(trustScore, 24);
    }
  }

  // ── 7.5 CONFIDENCE ────────────────────────────────────────────────────────
  let confidence = 0;
  if (domainAgeDays >= 0) confidence += 30;
  if (rep.checked) confidence += 25;
  if (dom.scanned) confidence += 25;
  if (redirectChain.length > 0) confidence += 10;
  if (dom.contentRich) confidence += 10;
  confidence = Math.min(confidence, 100);
  if (rep.inWhitelist || rep.isOfficialBrand) confidence = Math.max(confidence, 80);

  // ── 7.6 FINAL SCORE ───────────────────────────────────────────────────────
  let finalScore = Math.round(Math.max(0, Math.min(100, 50 + trustScore - riskScore)));
  const isUnknown = confidence < 45;
  // Unknown cap LINH HOẠT theo mức rủi ro (không phải cứng 60 cho mọi trường hợp)
  if (isUnknown) {
    let cap;
    if (riskScore === 0) cap = 75;        // sạch nhưng thiếu dữ liệu → điểm khá
    else if (riskScore < 10) cap = 65;    // gần sạch
    else if (riskScore < 20) cap = 55;    // có chút ngờ
    else cap = 45;                         // có rủi ro + thiếu dữ liệu → thận trọng
    if (finalScore > cap) finalScore = cap;
    if (finalScore < 25) finalScore = 25;
  }
  const isPhish = finalScore <= 30;

  // ── 7.7 BADGES cho UI (result map: '-1' an toàn / '0' vàng / '1' đỏ) ─────
  const result = {};
  // Trust badges → xanh (-1)
  for (const tb of trustBadges) result[tb.key] = '-1';
  // Risk badges (V3: 4 cấp độ SAFE/NEUTRAL/SUSPICIOUS/DANGEROUS)
  for (const f of findings) {
    if (result[f.key] !== undefined) continue;
    let value;
    // Đỏ (DANGEROUS): bằng chứng mạnh
    if (f.points >= 22 || (f.group === 'brand' && riskScore >= 35) || f.key === 'FormHijack')
      value = '1';
    // Cam (SUSPICIOUS): đáng ngờ rõ ràng
    else if (f.points >= 14 || (f.group === 'malware' && riskScore >= 25))
      value = '2';
    // Vàng (NEUTRAL): cần để ý
    else if (f.points >= 7)
      value = '0';
    else
      value = '0';
    // yếu tố nhẹ đơn lẻ → an toàn khi không có corroboration
    if (['NoHTTPS', 'AtSymbol', 'LongURL', 'SuspiciousTLD', 'IPHost'].includes(f.key) && riskScore < 22) value = '-1';
    result[f.key] = value;
  }
  // 'Sensitive Form' — 4 cấp độ theo ngữ cảnh
  if (dom.sensitiveForm) {
    if (hasBrand || dom.formHijack) result['Sensitive Form'] = '1';       // đỏ
    else if (veryNew && noRep) result['Sensitive Form'] = '2';              // cam
    else result['Sensitive Form'] = '0';                                    // vàng — trung tính
  }

  // ── 7.8 SUMMARY (V3 — giải thích dễ hiểu, nhất quán với điểm) ─────────────
  let summary;
  const sortedFindings = findings.slice().sort((a, b) => b.points - a.points);
  const topFinding = sortedFindings[0];

  if (isUnknown) {
    summary = 'Chưa đủ dữ liệu để đánh giá chính xác độ tin cậy. Hãy thận trọng khi nhập thông tin.';
  } else if (finalScore >= 80) {
    const t = [];
    if (rep.inWhitelist) t.push('nằm trong danh sách tin cậy');
    if (rep.isOfficialBrand) t.push('là tên miền chính thức của thương hiệu lớn');
    if (domainAgeDays > 365) t.push('đã hoạt động lâu năm');
    if (riskScore === 0) t.push('không phát hiện dấu hiệu nguy hiểm');
    summary = 'Trang này ' + t.join(', ') + '.';
  } else if (riskScore >= 55) {
    // Nguy hiểm cao — dùng lý do corroboration hoặc finding nổi bật
    let detail = reasons[0];
    if (!detail && topFinding) {
      detail = matchedBrand
        ? `Phát hiện dấu hiệu giả mạo thương hiệu ${matchedBrand}`
        : topFinding.label;
    }
    summary = '⚠️ Nguy cơ lừa đảo cao. ' + (detail || 'Phát hiện nhiều dấu hiệu đáng ngờ') + '.';
  } else if (riskScore >= 30) {
    summary = 'Trang có dấu hiệu đáng ngờ. ' + (reasons[0] || (topFinding ? topFinding.label + '.' : 'Nên kiểm tra kỹ trước khi nhập thông tin.'));
  } else if (riskScore > 0 && topFinding) {
    // warning nhẹ: nhắc yếu tố nổi bật nhất + khẳng định nhìn chung an toàn
    const tf = topFinding;
    // Nếu có reason từ corroboration, ưu tiên dùng
    if (reasons.length > 0) {
      summary = 'Trang nhìn chung an toàn, nhưng ' + reasons[0].toLowerCase() + '.';
    } else {
      summary = 'Trang nhìn chung an toàn, nhưng ' + tf.label.toLowerCase() + '.';
    }
  } else {
    summary = 'Trang này không phát hiện dấu hiệu giả mạo thương hiệu, mã độc hay thu thập dữ liệu nhạy cảm.';
  }

  const riskLevel = finalScore <= 20 ? 'critical' : finalScore <= 35 ? 'dangerous' :
    finalScore <= 55 ? 'suspicious' : finalScore <= 75 ? 'caution' : 'safe';

  return {
    finalScore, trustScore, riskScore, confidence, isUnknown, isPhish,
    summary, result, findings, matchedBrand, riskLevel, redirectHops: rc.hops,
  };
};

// ═══════════════════════════════════════════════════════════════════════════
// 8. COMPAT — wrappers giữ tương thích với caller cũ
// ═══════════════════════════════════════════════════════════════════════════
const assessRisk = (urlString, domSignals = {}, domainAgeDays = -1) => {
  const r = computeScore(urlString, { dom: domSignals || {}, domainAgeDays });
  return {
    riskScore: r.riskScore, riskLevel: r.riskLevel,
    findings: Object.entries(r.result).map(([key, value]) => ({ key, label: key, value })),
    summary: r.summary, matchedBrand: r.matchedBrand,
  };
};
const computeHeuristicScore = (urlString) => {
  const r = computeScore(urlString, {});
  return { score: r.riskScore, flags: [], riskLevel: r.riskLevel };
};

// Exports
if (typeof self !== 'undefined') {
  self.computeScore = computeScore;
  self.analyzeUrl = analyzeUrl;
  self.analyzeRedirectChain = analyzeRedirectChain;
  self.assessRisk = assessRisk;
  self.computeHeuristicScore = computeHeuristicScore;
  self.isTrustedHost = isTrustedHost;
  self.isOfficialBrandDomain = isOfficialBrandDomain;
  self.getRegistrableDomain = getRegistrableDomain;
  self.REPUTATION_WHITELIST = REPUTATION_WHITELIST;
  self.BRANDS = BRANDS;
  self.levenshtein = levenshtein;
}
if (typeof window !== 'undefined') {
  window.computeScore = computeScore;
  window.isTrustedHost = isTrustedHost;
  window.getRegistrableDomain = getRegistrableDomain;
  window.isOfficialBrandDomain = isOfficialBrandDomain;
}
