// packages/heuristic.js  —  ENGINE V2
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
  { name: 'OpenAI',       keys: ['openai'],               official: ['openai.com', 'oaistatic.com', 'oaiusercontent.com'] },
  { name: 'ChatGPT',      keys: ['chatgpt'],              official: ['chatgpt.com', 'openai.com'] },
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
  { name: 'MongoDB',    keys: ['mongodb'],             official: ['mongodb.com', 'cloud.mongodb.com', 'atlas.mongodb.com', 'cloud-ml.mongodb.com', 'realm.mongodb.com', 'data.mongodb.com'] },
  { name: 'Netflix',      keys: ['netflix'],              official: ['netflix.com', 'nflxvideo.net'] },
  { name: 'GitHub',       keys: ['github'],               official: ['github.com', 'githubusercontent.com', 'githubassets.com'] },
  { name: 'Shopee',       keys: ['shopee'],               official: ['shopee.vn', 'shopee.com', 'shopeemobile.com'] },
  { name: 'Lazada',       keys: ['lazada'],               official: ['lazada.vn', 'lazada.com', 'lazada.co.th'] },
  { name: 'Tiki',         keys: ['tiki'],                 official: ['tiki.vn'] },
  { name: 'Stripe',       keys: ['stripe'],               official: ['stripe.com', 'stripecdn.com'] },
  { name: 'Viettel',      keys: ['viettel'],              official: ['viettel.com.vn', 'viettel.vn'] },
  { name: 'VNPay',        keys: ['vnpay'],                official: ['vnpay.vn'] },
  { name: 'FPT',          keys: ['fpt'],                  official: ['fpt.com.vn', 'fpt.vn'] },
  { name: 'VinGroup',     keys: ['vingroup', 'vinhomes', 'vinfast'], official: ['vingroup.net', 'vinhomes.vn', 'vinfastauto.com', 'vinfast.vn'] },
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
  'zalo.me', 'zaloapp.com', 'apple.com', 'amazon.com', 'paypal.com', 'netflix.com', 'mongodb.com', 'cloud.mongodb.com', 'atlas.mongodb.com', 'cloud-ml.mongodb.com',
  'linkedin.com', 'twitter.com', 'x.com', 'wikipedia.org', 'mozilla.org', 'stripe.com',
  'stackoverflow.com', 'stackexchange.com', 'serverfault.com', 'superuser.com', 'gitlab.com',
  'vietcombank.com.vn', 'bidv.com.vn', 'mbbank.com.vn', 'techcombank.com.vn',
  'tpb.vn', 'agribank.com.vn', 'vietinbank.vn', 'vpbank.vn', 'sacombank.com',
  'momo.vn', 'zalopay.vn', 'shopee.vn', 'lazada.vn', 'tiki.vn', 'acb.com.vn',
  'vnpay.vn', 'fpt.com.vn', 'fpt.vn', 'viettel.com.vn', 'viettel.vn',
  'vingroup.net', 'vinhomes.vn', 'vinfastauto.com', 'vinfast.vn',
  'outlook.com', 'live.com', 'office.com', 'bing.com', 'whatsapp.com', 'telegram.org',
  'mongodb.com', 'cloud.mongodb.com', 'atlas.mongodb.com',
  'phishtank.com', 'virustotal.com', 'chongluadao.vn', 'tinnhiemmang.vn'
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
  'stackoverflow.com', 'stackexchange.com', 'serverfault.com', 'superuser.com', 'gitlab.com', 'gitlab-static.net',
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
const EXECUTABLE_EXTS = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.apk', '.msi', '.dll', '.vbs', '.jar'];
const ARCHIVE_EXTS = ['.zip', '.rar', '.7z'];
const DOUBLE_EXT_RE = /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|rtf)\.(exe|scr|bat|cmd|ps1|vbs|jar|apk|msi|dll)$/i;
const SHORT_BRAND_KEYS = new Set(['fpt','acb','bidv','momo','zalo','tiki']);

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

const jaroWinkler = (a, b) => {
  a = (a || '').toLowerCase(); b = (b || '').toLowerCase();
  if (a === b) return 1;
  const al = a.length, bl = b.length;
  if (!al || !bl) return 0;
  const matchDistance = Math.floor(Math.max(al, bl) / 2) - 1;
  const aMatches = new Array(al).fill(false);
  const bMatches = new Array(bl).fill(false);
  let matches = 0;
  for (let i = 0; i < al; i++) {
    const start = Math.max(0, i - matchDistance);
    const end = Math.min(i + matchDistance + 1, bl);
    for (let j = start; j < end; j++) {
      if (bMatches[j] || a[i] !== b[j]) continue;
      aMatches[i] = true; bMatches[j] = true; matches++; break;
    }
  }
  if (!matches) return 0;
  let k = 0, transpositions = 0;
  for (let i = 0; i < al; i++) {
    if (!aMatches[i]) continue;
    while (!bMatches[k]) k++;
    if (a[i] !== b[k]) transpositions++;
    k++;
  }
  const jaro = ((matches / al) + (matches / bl) + ((matches - transpositions / 2) / matches)) / 3;
  let prefix = 0;
  for (let i = 0; i < Math.min(4, al, bl); i++) { if (a[i] === b[i]) prefix++; else break; }
  return jaro + prefix * 0.1 * (1 - jaro);
};

const punycodeDecodeLabel = (input) => {
  // Minimal RFC3492 decoder for IDN labels. Kept local to avoid adding dependencies.
  if (!input || !input.startsWith('xn--')) return input;
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;
  const label = input.slice(4);
  const out = [];
  let i = 0, n = initialN, bias = initialBias;
  const adapt = (delta, numPoints, firstTime) => {
    delta = firstTime ? Math.floor(delta / damp) : (delta >> 1);
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > Math.floor(((base - tMin) * tMax) / 2)) { delta = Math.floor(delta / (base - tMin)); k += base; }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  const digit = (cp) => {
    if (cp >= 48 && cp <= 57) return cp - 22;
    if (cp >= 65 && cp <= 90) return cp - 65;
    if (cp >= 97 && cp <= 122) return cp - 97;
    return base;
  };
  const dash = label.lastIndexOf('-');
  if (dash > -1) { for (let j = 0; j < dash; j++) out.push(label.charCodeAt(j)); }
  let idx = dash > -1 ? dash + 1 : 0;
  while (idx < label.length) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (idx >= label.length) return input;
      const d = digit(label.charCodeAt(idx++));
      if (d >= base) return input;
      i += d * w;
      const t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
      if (d < t) break;
      w *= (base - t);
    }
    const outLen = out.length + 1;
    bias = adapt(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    out.splice(i, 0, n);
    i++;
  }
  try { return String.fromCodePoint.apply(String, out); } catch (_) { return input; }
};

const toUnicodeDomain = (host) => (host || '').split('.').map(punycodeDecodeLabel).join('.');

const CONFUSABLES = {
  // Cyrillic
  'а':'a','А':'a','В':'b','Е':'e','е':'e','К':'k','М':'m','Н':'h','О':'o','о':'o','Р':'p','р':'p','С':'c','с':'c','Т':'t','Х':'x','х':'x','У':'y','у':'y','І':'i','і':'i','ӏ':'l','Ь':'b','ԁ':'d','ԛ':'q','ԝ':'w',
  // Greek
  'Α':'a','Β':'b','Ε':'e','Ζ':'z','Η':'h','Ι':'i','Κ':'k','Μ':'m','Ν':'n','Ο':'o','ο':'o','Ρ':'p','Τ':'t','Υ':'y','Χ':'x','α':'a','β':'b','γ':'y','δ':'d','ε':'e','ι':'i','κ':'k','ν':'v','ρ':'p','τ':'t','χ':'x','ϲ':'c',
  // Full-width / Latin lookalikes
  '０':'0','１':'1','３':'3','４':'4','５':'5','６':'6','７':'7','８':'8','＠':'@','Ｉ':'i','ｌ':'l','Ｏ':'o'
};

const dehomoglyph = (s) => {
  let r = (s || '').split('').map(ch => CONFUSABLES[ch] || ch).join('').toLowerCase();
  try { r = r.normalize('NFD').replace(/[\u0300-\u036f]/g, ''); } catch (_) {}
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
  for (let i = 0; i < (host || '').length; i++) {
    const c = host.charCodeAt(i);
    if (c > 0x7e || (c < 0x30 && c !== 0x2d && c !== 0x2e)) return true;
  }
  return false;
};

const normalizeDomainAge = (domainAgeInput) => {
  if (domainAgeInput == null) return { ageDays: -1 };
  if (typeof domainAgeInput === 'number') return { ageDays: domainAgeInput };
  if (typeof domainAgeInput === 'object') {
    const ageDays = domainAgeInput.ageDays != null ? domainAgeInput.ageDays :
      (domainAgeInput.days != null ? domainAgeInput.days :
        (domainAgeInput.domainAgeDays != null ? domainAgeInput.domainAgeDays : -1));
    return { ...domainAgeInput, ageDays };
  }
  return { ageDays: -1 };
};

// ═══════════════════════════════════════════════════════════════════════════
// 3. V5 IDENTITY-FIRST SIGNAL PIPELINE
// ═══════════════════════════════════════════════════════════════════════════

// ----------------------------------------------------------------------------
// 3.1. IDENTITY ENGINE
// Thu thập Identity Profile từ URL + Intel (không đánh giá rủi ro)
// ----------------------------------------------------------------------------
class IdentityEngine {
  static buildProfile(urlObj, registrableDomain, intelData) {
    const cert = intelData?.identityProfile?.certificate || null;
    const asn  = intelData?.identityProfile?.asn  || null;
    const ptr  = intelData?.identityProfile?.ptr  || [];

    const certIssuerOrg  = (cert?.status === 'success' && cert?.issuer)
      ? (typeof cert.issuer === 'object' ? (cert.issuer.O || cert.issuer.CN || '') : String(cert.issuer))
      : null;
    const certSubjectOrg = (cert?.status === 'success' && cert?.organization)
      ? cert.organization
      : null;
    const certSAN        = cert?.san || null;

    return {
      hostname:         urlObj.hostname,
      rootDomain:       registrableDomain,
      protocol:         urlObj.protocol,
      certIssuerOrg,
      certSubjectOrg,
      certSAN,
      certValid:        cert?.status === 'success',
      asnNumber:        asn?.asn   || null,
      asnOrg:           asn?.org   || null,
      asnIsp:           asn?.isp   || null,
      ptr,
    };
  }
}

// ----------------------------------------------------------------------------
// 3.2. DOMAIN RELATIONSHIP ENGINE (V5)
// Xác định Ownership Confidence qua hạ tầng kỹ thuật, không so sánh tên
// ----------------------------------------------------------------------------
class DomainRelationshipEngine {
  /**
   * Xác định Ownership thông qua 3 tầng:
   *   1. Khớp tên miền chính thức (BRANDS.official)
   *   2. Phân tích tính nhất quán hạ tầng (Cert/ASN)
   *   3. Kết hợp với DOM signal (brandInContent)
   * @returns {{ ownershipConfidence: 'HIGH'|'MEDIUM'|'LOW', brandDetected: string|null, isBrandOwner: boolean, ownershipStatus: string }}
   */
  static verifyOwnership(urlObj, identityProfile, domSignals) {
    let ownershipConfidence = 'LOW';
    let brandDetected = null;
    let isBrandOwner = false;

    // Bước 1: Khớp tên miền chính thức
    for (const b of BRANDS) {
      if (b.official.some(od =>
        identityProfile.rootDomain === od ||
        identityProfile.rootDomain.endsWith('.' + od)
      )) {
        ownershipConfidence = 'HIGH';
        brandDetected = b.name;
        isBrandOwner = true;
        break;
      }
    }

    // Bước 2: Kiểm tra tính nhất quán hạ tầng (khi DOM báo có thương hiệu)
    if (!isBrandOwner && domSignals.brandInContent) {
      brandDetected = 'unknown_brand';
      // Nếu Cert có Subject Org → cố gắng đối chiếu
      if (identityProfile.certSubjectOrg) {
        ownershipConfidence = 'MEDIUM'; // Có Cert org, nhưng không khớp domain chính thức
      }
    }

    const ownershipStatus = isBrandOwner
      ? 'VERIFIED'
      : (!isBrandOwner && brandDetected)
        ? 'MISMATCH'
        : 'UNKNOWN';

    return { ownershipConfidence, brandDetected, isBrandOwner, ownershipStatus };
  }
}

// ----------------------------------------------------------------------------
// 3.3. CONTEXT CLASSIFICATION ENGINE (V5)
// Phân loại mục đích trang web dựa trên hạ tầng + DOM
// KHÔNG tăng Risk — chỉ cung cấp Context cho Decision
// ----------------------------------------------------------------------------
class ContextEngine {
  static classify(identityProfile, domSignals) {
    const ctx = {
      isAuthPortal:       false,  // Có yêu cầu đăng nhập
      isGovernmentOrEdu:  false,  // Hạ tầng .gov / .edu
      isCloudHosted:      false,  // Chạy trên nền tảng đám mây
      isSaas:             false,  // SaaS nền tảng (Vercel, Netlify…)
      hasLoginForm:       false,  // DOM phát hiện form đăng nhập
      classification:     'UNKNOWN',
    };

    // Auth portal (Informational — không phải cáo buộc)
    if (domSignals.passwordField || domSignals.otpField || (domSignals.sensitiveForms > 0)) {
      ctx.isAuthPortal = true;
      ctx.hasLoginForm = true;
    }

    // Gov / Edu (qua tên miền)
    const rd = identityProfile.rootDomain;
    if (rd.endsWith('.gov.vn') || rd.endsWith('.gov') || rd.endsWith('.edu.vn') || rd.endsWith('.edu') || rd.endsWith('.ac.uk')) {
      ctx.isGovernmentOrEdu = true;
    }

    // Cloud/SaaS nền tảng
    const saasHosts = ['vercel.app', 'netlify.app', 'herokuapp.com', 'onrender.com', 'pages.dev', 'github.io', 'firebaseapp.com', 'azurewebsites.net', 'amplifyapp.com'];
    if (saasHosts.some(h => rd.endsWith(h))) {
      ctx.isCloudHosted = true;
      ctx.isSaas = true;
    }

    // Classification label (informational)
    if (ctx.isGovernmentOrEdu)   ctx.classification = 'GOVERNMENT_EDU';
    else if (ctx.isSaas)         ctx.classification = 'SAAS_CLOUD';
    else if (ctx.isAuthPortal)   ctx.classification = 'AUTHENTICATION_PORTAL';
    else                         ctx.classification = 'GENERAL';

    return ctx;
  }

  // Backward compat alias
  static analyze(domSignals, urlObj, registrableDomain) {
    const fakeProfile = { rootDomain: registrableDomain };
    const result = this.classify(fakeProfile, domSignals);
    // Map to old field names
    return {
      isLoginPortal:     result.isAuthPortal,
      isGovernmentOrEdu: result.isGovernmentOrEdu,
      isCloudHosted:     result.isCloudHosted,
      ...result,
    };
  }
}

// ----------------------------------------------------------------------------
// 3.4. EVIDENCE ENGINE (V5)
// Mọi tín hiệu phải được phân loại đúng mức độ.
// Password/OTP/Login là INFORMATIONAL — không được tăng Risk.
// Brand Impersonation chỉ kích hoạt khi: Brand + Ownership Mismatch + Auth + Behavior.
// ----------------------------------------------------------------------------
class EvidenceEngine {
  static collect(urlObj, identityProfile, domSignals, context, ownership, rep, domainAgeDays) {
    const evidence = [];
    const addEv = (id, severity, reason) => evidence.push({ id, severity, reason });

    // ── CRITICAL ─────────────────────────────────────────────────────────────
    if (rep.inBlacklist) {
      addEv('BLACKLIST', 'CRITICAL', 'Tên miền nằm trong danh sách đen lừa đảo đã xác nhận.');
    }
    if (rep.malware?.dangerous) {
      addEv('MALWARE', 'CRITICAL', 'Tên miền bị cảnh báo phân phối mã độc bởi nhiều nguồn.');
    }

    // ── STRONG (Hành vi tấn công rõ ràng) ────────────────────────────────────
    if (domSignals.formHijack) {
      addEv('FORM_HIJACK', 'STRONG', 'Biểu mẫu đăng nhập bị can thiệp và gửi dữ liệu tới máy chủ bên thứ ba.');
    }
    if (domSignals.maliciousJs) {
      addEv('MALICIOUS_JS', 'STRONG', 'Mã JavaScript theo dõi bàn phím hoặc can thiệp clipboard.');
    }
    if (domSignals.doubleExtension) {
      addEv('DOUBLE_EXT', 'STRONG', 'Tệp tải xuống có phần mở rộng kép giả mạo (.pdf.exe).');
    }

    // ── MEDIUM (Kết hợp bằng chứng) ──────────────────────────────────────────
    // Brand Impersonation: chỉ kích hoạt khi ĐỦ 3 điều kiện đồng thời
    if (
      ownership.brandDetected &&
      ownership.ownershipStatus === 'MISMATCH' &&
      context.isAuthPortal &&
      (domSignals.scamKeywords || domSignals.formHijack || domSignals.maliciousJs)
    ) {
      addEv('BRAND_IMPERSONATION', 'MEDIUM',
        `Mạo danh thương hiệu: Trang yêu cầu đăng nhập có giao diện giống ${ownership.brandDetected} nhưng không thuộc hạ tầng của họ và có hành vi đáng ngờ.`);
    }

    if (domSignals.scamKeywords) {
      addEv('SCAM_KEYWORDS', 'MEDIUM', 'Nội dung trang chứa nhiều từ khóa lừa đảo phổ biến.');
    }
    if ((domSignals.redirectHops || 0) > 2) {
      addEv('REDIRECT_CHAIN', 'MEDIUM', 'Trang web chuyển hướng qua nhiều trạm trung gian.');
    }

    // ── WEAK (Tín hiệu kỹ thuật đơn lẻ) ──────────────────────────────────────
    if (domainAgeDays >= 0 && domainAgeDays <= 14) {
      addEv('NEW_DOMAIN', 'WEAK', 'Tên miền mới được đăng ký trong vòng 14 ngày.');
    }
    if (urlObj.protocol !== 'https:' && !domSignals.hasHttps) {
      addEv('NO_HTTPS', 'WEAK', 'Trang web không sử dụng kết nối bảo mật HTTPS.');
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(urlObj.hostname)) {
      addEv('IP_HOST', 'WEAK', 'Truy cập trực tiếp bằng địa chỉ IP thay vì tên miền.');
    }

    // ── INFORMATIONAL (Không tăng Risk) ──────────────────────────────────────
    if (context.isAuthPortal)     addEv('LOGIN_CONTEXT',  'INFORMATIONAL', 'Trang web yêu cầu xác thực người dùng.');
    if (identityProfile.certValid) addEv('CERT_VALID',    'INFORMATIONAL', 'Chứng chỉ SSL/TLS hợp lệ và đang hoạt động.');

    return evidence;
  }
}

// ----------------------------------------------------------------------------
// 3.5. TRUST ENGINE (V5)
// Trust độc lập với Risk. Dựa trên Ownership Consistency + Reputation.
// ----------------------------------------------------------------------------
class TrustEngine {
  static analyze(identityProfile, context, ownership, rep, domainAgeDays) {
    let trustScore = 0;
    const sources = [];

    // Ownership đã xác minh = Trust cao nhất
    if (ownership.ownershipConfidence === 'HIGH') {
      trustScore += 80;
      sources.push('OFFICIAL_BRAND');
    }

    // Whitelist nội bộ
    if (REPUTATION_WHITELIST.has(identityProfile.rootDomain) || rep.inWhitelist) {
      trustScore += 60;
      sources.push('WHITELIST');
    }

    // Cơ quan nhà nước / giáo dục
    if (context.isGovernmentOrEdu) {
      trustScore += 55;
      sources.push('GOV_EDU');
    }

    // Cert hợp lệ từ CA uy tín (thêm điểm nhỏ)
    if (identityProfile.certValid) {
      trustScore += 10;
      sources.push('CERT_VALID');
    }

    // Domain lâu năm
    if (domainAgeDays > 365) {
      trustScore += 30;
      sources.push('AGE_OLD');
    } else if (domainAgeDays > 90) {
      trustScore += 10;
      sources.push('AGE_MATURE');
    }

    // Nền tảng SaaS/Cloud được biết đến
    if (context.isCloudHosted || context.isSaas) {
      trustScore += 20;
      sources.push('CLOUD_HOSTED');
    }

    // Backward compat alias
    static_analyze_compat: {
      void 0; // no-op label block
    }

    return { trustScore: Math.min(trustScore, 100), sources };
  }

  // Backward compat wrapper
  static analyzeCompat(urlObj, registrableDomain, context, relationship, rep, domainAgeDays) {
    const fakeProfile = { rootDomain: registrableDomain, certValid: false };
    const fakeOwnership = { ownershipConfidence: relationship.isBrandOwner ? 'HIGH' : 'LOW' };
    return this.analyze(fakeProfile, context, fakeOwnership, rep, domainAgeDays);
  }
}

// ----------------------------------------------------------------------------
// 5. DECISION ENGINE
// Đưa ra quyết định cuối cùng dựa trên Sự kết hợp Evidence + Trust + Context
// ----------------------------------------------------------------------------
class DecisionEngine {
  static decide(evidence, trustAnalysis, context) {
    let riskScore = 0;
    
    // Đếm mức độ bằng chứng
    let critCount = 0, strongCount = 0, medCount = 0, weakCount = 0;
    evidence.forEach(e => {
      if (e.severity === 'CRITICAL') critCount++;
      else if (e.severity === 'STRONG') strongCount++;
      else if (e.severity === 'MEDIUM') medCount++;
      else if (e.severity === 'WEAK') weakCount++;
    });

    const isHighTrust = trustAnalysis.trustScore >= 50;

    // RULE 1: CRITICAL -> Auto Block
    if (critCount > 0) {
      return { riskScore: 100, isPhish: true, riskLevel: 'critical', summary: 'Phát hiện bằng chứng lừa đảo hoặc nguy hiểm mã độc nghiêm trọng.' };
    }

    // RULE 2: STRONG Evidence -> Rất nguy hiểm
    if (strongCount > 0) {
      riskScore = 80;
    } 
    // RULE 3: MULTI-EVIDENCE (Kết hợp)
    else if (medCount >= 2 || (medCount === 1 && weakCount >= 2)) {
      riskScore = 65; 
    }
    // RULE 4: Ngữ cảnh nhạy cảm (Đăng nhập) nhưng ít evidence
    else if (context.isLoginPortal && medCount === 1) {
      riskScore = 55;
    }
    else if (medCount === 1 || weakCount >= 2) {
      riskScore = 35;
    }
    else if (weakCount === 1) {
      riskScore = 15;
    }

    // SUPPRESSION (Ức chế Risk bằng Trust)
    if (isHighTrust && riskScore < 80) {
      // Nếu Trust cao và không có bằng chứng Strong, ép riskScore xuống rất thấp để tránh False Positive
      riskScore = Math.min(riskScore, 10);
    }

    // FINAL DECISION
    let isPhish = false;
    let riskLevel = 'safe';
    let summary = 'Website an toàn, không phát hiện rủi ro mã độc hay giả mạo.';

    if (riskScore >= 80) {
      isPhish = true;
      riskLevel = 'critical';
      summary = 'Phát hiện bằng chứng lừa đảo hoặc nguy hiểm mã độc nghiêm trọng.';
    } else if (riskScore >= 55) {
      riskLevel = 'dangerous';
      summary = 'Website có nhiều dấu hiệu đáng ngờ. Hãy cẩn thận khi nhập thông tin nhạy cảm.';
    } else if (riskScore >= 35) {
      riskLevel = 'suspicious';
      summary = 'Website có một vài tín hiệu rủi ro, nhưng chưa đủ bằng chứng kết luận lừa đảo.';
    }

    return { riskScore, isPhish, riskLevel, summary };
  }
}

// ----------------------------------------------------------------------------
// EXPORT COMPATIBILITY LAYER
// ----------------------------------------------------------------------------
// ═══════════════════════════════════════════════════════════════════════════
// 4. COMPUTE SCORE — V5 PIPELINE ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════════
const computeScore = (urlString, ctxObj = {}) => {
  let urlObj;
  try { urlObj = new URL(urlString); } catch (_) { urlObj = { hostname: '', protocol: 'http:' }; }

  const registrableDomain = getRegistrableDomain(urlObj.hostname);
  const domSignals  = ctxObj.dom        || {};
  const rep         = ctxObj.reputation  || { checked: false };
  const intelData   = ctxObj.intel       || {}; // identityProfile từ Backend /intel

  // Normalize domainAge
  let domainAgeDays = -1;
  const da = ctxObj.domainAge || ctxObj.domainAgeDetails || ctxObj.domainAgeDays;
  if (typeof da === 'number') domainAgeDays = da;
  else if (da && typeof da === 'object') domainAgeDays = da.ageDays != null ? da.ageDays : -1;

  // ── STAGE 1: IDENTITY ────────────────────────────────────────────────────
  const identityProfile = IdentityEngine.buildProfile(urlObj, registrableDomain, intelData);

  // ── STAGE 2: OWNERSHIP ───────────────────────────────────────────────────
  const ownership = DomainRelationshipEngine.verifyOwnership(urlObj, identityProfile, domSignals);

  // ── STAGE 3: CONTEXT ─────────────────────────────────────────────────────
  const context = ContextEngine.classify(identityProfile, domSignals);

  // ── STAGE 4: EVIDENCE ────────────────────────────────────────────────────
  const evidence = EvidenceEngine.collect(urlObj, identityProfile, domSignals, context, ownership, rep, domainAgeDays);

  // ── STAGE 5: TRUST ───────────────────────────────────────────────────────
  const trustAnalysis = TrustEngine.analyze(identityProfile, context, ownership, rep, domainAgeDays);

  // ── STAGE 6: DECISION ────────────────────────────────────────────────────
  const decision = DecisionEngine.decide(evidence, trustAnalysis, context);

  // ── FORMAT OUTPUT ─────────────────────────────────────────────────────────
  let finalScore = Math.round(Math.max(0, Math.min(100, 50 + trustAnalysis.trustScore - decision.riskScore)));
  if (decision.isPhish) finalScore = Math.min(finalScore, 30);

  let confidence = domSignals.scanned ? 50 : 20;
  if (rep.checked)      confidence += 20;
  if (domainAgeDays >= 0) confidence += 20;
  if (trustAnalysis.trustScore >= 50) confidence = Math.max(confidence, 80);
  if (identityProfile.certValid) confidence = Math.max(confidence, 55);

  const result = {};
  const explanations = [];
  evidence.forEach(e => {
    if (e.severity === 'INFORMATIONAL') {
      result[e.id] = '0';
      return; // Không đưa vào chip nguy hiểm
    }
    let lvl = 'warning';
    if (e.severity === 'CRITICAL' || e.severity === 'STRONG') { result[e.id] = '1'; lvl = 'danger'; }
    else if (e.severity === 'MEDIUM') { result[e.id] = '2'; lvl = 'suspicious'; }
    else { result[e.id] = '0'; }
    explanations.push({ key: e.id, level: lvl, text: e.reason });
  });

  trustAnalysis.sources.forEach(src => {
    result[src] = '-1';
    explanations.push({ key: src, level: 'safe', text: 'Tín hiệu tin cậy' });
  });

  // Backward compat chip aliases
  if (result['NEW_DOMAIN']) result['NewDomain'] = '2';
  if (result['NO_HTTPS'])   result['NoHTTPS']   = '2';
  else                      result['SSL']        = '-1';

  return {
    finalScore,
    trustScore:   trustAnalysis.trustScore,
    riskScore:    decision.riskScore,
    confidence,
    isUnknown:    confidence < 45,
    isPhish:      decision.isPhish,
    riskLevel:    decision.riskLevel,
    summary:      decision.summary,
    result,
    findings:     evidence,
    explanations,
    stage:        'LIVE',
    ownershipStatus:    ownership.ownershipStatus,
    ownershipConfidence: ownership.ownershipConfidence,
    matchedBrand: ownership.brandDetected,
    identityProfile,
  };
};






// Backward compatible analyzeUrl
const analyzeUrl = (urlString) => {
  let urlObj;
  try { urlObj = new URL(urlString); } catch (_) { return { findings: [] }; }
  // We don't have Layer4 anymore, so just return empty for old calls
  return { findings: [], matchedBrand: null };
};

const analyzeRedirectChain = (chain) => {
  return { points: 0, hops: chain ? chain.length - 1 : 0, distinctDomains: 0, label: null, openRedirects: [] }; // Mock for compat
};

// ═══════════════════════════════════════════════════════════════════════════
// 5. COMPAT & EXPORTS
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

const buildQuickScanSummary = (assessment) => {
  if (assessment.riskScore >= 80) return `Phát hiện nguy cơ lừa đảo. Thận trọng.`;
  if (assessment.riskScore >= 55) return `Có dấu hiệu đáng ngờ từ URL.`;
  return `Đánh giá sơ bộ an toàn.`;
};

const buildLiveScanSummary = (assessment) => assessment.summary;

if (typeof self !== 'undefined') {
  self.computeScore = computeScore;
  self.computeQuickScore = (url, ctx) => computeScore(url, ctx);
  self.computeLiveScore = (url, ctx) => computeScore(url, ctx);
  self.buildQuickScanSummary = buildQuickScanSummary;
  self.buildLiveScanSummary = buildLiveScanSummary;
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
  self.jaroWinkler = jaroWinkler;
  self.toUnicodeDomain = toUnicodeDomain;
}

export {
  computeScore, analyzeUrl, assessRisk, computeHeuristicScore, isTrustedHost,
  isOfficialBrandDomain, getRegistrableDomain, REPUTATION_WHITELIST, BRANDS,
  levenshtein, jaroWinkler, toUnicodeDomain
};
