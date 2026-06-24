// ============================================================
// @anti-scam/core — Constants & Data registries
// Extracted from packages/heuristic.js (sections 1-4)
// ============================================================

// ── 1. BRAND DATABASE ──
export const BRANDS = [
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
  { name: 'MongoDB',      keys: ['mongodb'],              official: ['mongodb.com', 'cloud.mongodb.com', 'atlas.mongodb.com', 'cloud-ml.mongodb.com', 'realm.mongodb.com', 'data.mongodb.com'] },
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

// ── 2. REPUTATION WHITELIST ──
export const REPUTATION_WHITELIST = new Set([
  'google.com', 'youtube.com', 'github.com', 'githubusercontent.com', 'microsoft.com',
  'openai.com', 'chatgpt.com', 'cloudflare.com', 'facebook.com', 'instagram.com',
  'zalo.me', 'zaloapp.com', 'apple.com', 'amazon.com', 'paypal.com', 'netflix.com',
  'mongodb.com', 'cloud.mongodb.com', 'atlas.mongodb.com', 'cloud-ml.mongodb.com',
  'linkedin.com', 'twitter.com', 'x.com', 'wikipedia.org', 'mozilla.org', 'stripe.com',
  'stackoverflow.com', 'stackexchange.com', 'serverfault.com', 'superuser.com', 'gitlab.com',
  'vietcombank.com.vn', 'bidv.com.vn', 'mbbank.com.vn', 'techcombank.com.vn',
  'tpb.vn', 'agribank.com.vn', 'vietinbank.vn', 'vpbank.vn', 'sacombank.com',
  'momo.vn', 'zalopay.vn', 'shopee.vn', 'lazada.vn', 'tiki.vn', 'acb.com.vn',
  'vnpay.vn', 'fpt.com.vn', 'fpt.vn', 'viettel.com.vn', 'viettel.vn',
  'vingroup.net', 'vinhomes.vn', 'vinfastauto.com', 'vinfast.vn',
  'outlook.com', 'live.com', 'office.com', 'bing.com', 'whatsapp.com', 'telegram.org',
  'phishtank.com', 'virustotal.com', 'chongluadao.vn', 'tinnhiemmang.vn'
]);

// ── 3. TRUSTED CDN / HOSTS ──
export const TRUSTED_HOSTS = new Set([
  'google.com', 'googleapis.com', 'ajax.googleapis.com', 'fonts.googleapis.com',
  'fonts.gstatic.com', 'www.gstatic.com', 'storage.googleapis.com', 'apis.google.com',
  'maps.googleapis.com', 'www.google.com', 'google-analytics.com', 'googletagmanager.com',
  'www.googletagmanager.com', 'ssl.gstatic.com', 'youtube.com', 'i.ytimg.com',
  'ytimg.com', 'www.youtube-nocookie.com', 'accounts.google.com', 'googlevideo.com',
  'cdnjs.cloudflare.com', 'cdn.cloudflare.com', 'ajax.cloudflare.com',
  'challenges.cloudflare.com', 'static.cloudflareinsights.com',
  'cdn.jsdelivr.net', 'jsdelivr.net', 'unpkg.com', 'npmcdn.com',
  'cdn.skypack.dev', 'esm.sh', 'esm.run',
  'stackpath.bootstrapcdn.com', 'maxcdn.bootstrapcdn.com', 'netdna.bootstrapcdn.com',
  'getbootstrap.com',
  'use.fontawesome.com', 'kit.fontawesome.com', 'ka-f.fontawesome.com',
  'ajax.aspnetcdn.com', 'ajax.microsoft.com', 'msecnd.net',
  'code.jquery.com',
  'connect.facebook.net', 'static.xx.fbcdn.net', 'scontent.xx.fbcdn.net',
  'platform.twitter.com', 'cdn.syndication.twimg.com', 'abs.twimg.com',
  'js.stripe.com', 'm.stripe.com', 'm.stripe.network', 'r.stripe.com', 'api.stripe.com',
  'github.githubassets.com',
  'stackoverflow.com', 'stackexchange.com', 'serverfault.com', 'superuser.com',
  'gitlab.com', 'gitlab-static.net',
  'cdn.tailwindcss.com', 'polyfill.io', 'cdn.polyfill.io', 'static.addtoany.com',
  'c.disquscdn.com', 'disqus.com', 'ws.audioscrobbler.com',
]);

// ── 4. VN SCAM KEYWORDS ──
export const VN_SCAM_KEYWORDS = [
  'xacminh', 'xac-minh', 'dinhdanh', 'dinh-danh', 'e-kyc', 'ekyc',
  'capnhat-thongtin', 'cap-nhat-thong-tin', 'khoiphuc', 'khoi-phuc',
  'baomat', 'bao-mat', 'xac-thuc', 'xacthuc', 'nang-cap-bao-mat',
  'dong-bo-du-lieu', 'dongbodulieu', 'xac-minh-tai-khoan', 'xacminhtaikhoan',
  'kichhoat', 'kich-hoat', 'napthe', 'nap-the', 'vongquay', 'vong-quay',
  'nhan-qua', 'tang-qua', 'hoan-tien', 'khoa-tai-khoan', 'vohieuhoa',
];

// ── 5. EXTENSION LISTS ──
export const EXECUTABLE_EXTS = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.apk', '.msi', '.dll', '.vbs', '.jar'];
export const ARCHIVE_EXTS = ['.zip', '.rar', '.7z'];
export const DOUBLE_EXT_RE = /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|rtf)\.(exe|scr|bat|cmd|ps1|vbs|jar|apk|msi|dll)$/i;
export const SHORT_BRAND_KEYS = new Set(['fpt','acb','bidv','momo','zalo','tiki']);

export const MULTI_PART_TLDS = new Set([
  'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn', 'ac.vn', 'biz.vn',
  'info.vn', 'name.vn', 'pro.vn', 'health.vn', 'io.vn',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.jp', 'com.au', 'net.au',
  'com.br', 'com.cn', 'com.hk', 'com.sg', 'com.my', 'com.tw', 'co.kr',
  'co.nz', 'co.in', 'com.mx', 'com.ar', 'co.za',
]);

export const RISK_PTS = {
  HOMOGLYPH: 30, TYPOSQUAT_1: 28, TYPOSQUAT_2: 18, BRAND_IN_DOMAIN: 14,
  BRAND_IN_PATH: 8, BRAND_IMPERSONATION_STRONG: 26, BRAND_IMPERSONATION_WEAK: 10,
  FORM_HIJACK: 26, OBFUSCATION: 18, SUSPICIOUS_EXT_IP: 16, SUSPICIOUS_EXT_DOMAIN: 7,
  KEYLOGGER: 22, CLIPBOARD: 18, DOWNLOAD: 18, ARCHIVE_DOWNLOAD: 6, VN_SCAM_KW: 12, HIDDEN_IFRAME: 12,
  REDIRECT_ABUSE: 20, PUNYCODE: 12, UNICODE_HOST: 12, IP_HOST: 10,
  NO_HTTPS: 5, AT_SYMBOL: 3, LONG_URL: 3, SUSPICIOUS_TLD: 7,
  NEW_DOMAIN_7: 16, NEW_DOMAIN_30: 10, MALWARE_REPUTATION: 45, DNS_RISK: 16,
  COMMUNITY_REPORT: 22, JS_RISK: 18, SCAM_CONTENT: 16, HIDDEN_FORM: 14,
  LINK_RISK: 18, DECEPTIVE_LINK: 16, PERMISSION_ABUSE: 16, OPEN_REDIRECT: 18,
  META_REFRESH: 12, SCRIPT_REDIRECT: 14,
};

export const FINDING_CONFIDENCE = {
  MalwareReputation: 0.99, CommunityReport: 0.92, RedirectBadHop: 0.95,
  Homograph: 0.9, Typosquat: 0.88, BrandInDomain: 0.82, BrandImpersonation: 0.85,
  FormHijack: 0.9, FormDest: 0.88, Keylogger: 0.86, DataExfil: 0.9,
  DangerousDownload: 0.9, OpenRedirect: 0.82, RedirectChain: 0.45,
  NewDomain: 0.55, PermissionAbuse: 0.35, SuspiciousLinks: 0.45, DeceptiveLinks: 0.55,
  ObfuscatedScript: 0.45, JavaScriptRisk: 0.35, SuspiciousExternal: 0.25,
  iFrames: 0.15, ArchiveDownload: 0.2, ScamContent: 0.45,
  MetaRefreshRedirect: 0.35, ScriptRedirect: 0.4,
  NoHTTPS: 0.2, AtSymbol: 0.2, LongURL: 0.15, SuspiciousTLD: 0.2, IPHost: 0.45,
};

export const REDIRECT_PARAM_NAMES = ['url','u','redirect','redirect_url','redirect_uri','next','target','to','dest','destination','continue','return','return_url','returnUrl','callback','goto','r'];

export const VN_SCAM_PATTERNS = [
  { re: /loi\s*nhuan\s*\d+\s*%|\d+\s*%.*(?:moi\s*ngay|\/\s*ngay|ngay)/, label: 'lợi nhuận cao bất thường' },
  { re: /dau\s*tu|tien\s*dien\s*tu|crypto|coin|forex/, label: 'đầu tư/tiền điện tử' },
  { re: /da\s*cap|he\s*thong\s*tuyen\s*duoi|kim\s*tu\s*thap/, label: 'đa cấp' },
  { re: /vay\s*nong|vay\s*nhanh|giai\s*ngan\s*trong\s*ngay/, label: 'vay nóng' },
  { re: /viec\s*nhe\s*luong\s*cao|kiem\s*tien\s*online|khong\s*can\s*von/, label: 'việc nhẹ lương cao' },
  { re: /nhan\s*thuong|trung\s*thuong|hoa\s*hong\s*khung/, label: 'nhận thưởng bất thường' },
];

export const BRAND_KEYS_SCAN = [
  ['vietcombank','Vietcombank'],['bidv','BIDV'],['mbbank','MB'],['techcombank','Techcombank'],
  ['tpbank','TPBank'],['agribank','Agribank'],['vietinbank','VietinBank'],['vpbank','VPBank'],
  ['sacombank','Sacombank'],['momo','MoMo'],['zalopay','ZaloPay'],['zalo','Zalo'],
  ['shopee','Shopee'],['lazada','Lazada'],['tiki','Tiki'],['google','Google'],
  ['microsoft','Microsoft'],['facebook','Facebook'],['apple','Apple'],['paypal','PayPal'],
  ['amazon','Amazon'],['netflix','Netflix'],['openai','OpenAI'],['chatgpt','ChatGPT'],
  ['telegram','Telegram'],['github','GitHub'],
];

export const BRAND_OFFICIAL_SCAN = {
  'vietcombank':['vietcombank.com.vn'],'bidv':['bidv.com.vn'],'mbbank':['mbbank.com.vn'],
  'techcombank':['techcombank.com.vn'],'tpbank':['tpb.vn','tpbank.vn'],'agribank':['agribank.com.vn'],
  'vietinbank':['vietinbank.vn'],'vpbank':['vpbank.vn'],'sacombank':['sacombank.com'],
  'momo':['momo.vn'],'zalopay':['zalopay.vn'],'zalo':['zalo.me'],'shopee':['shopee.vn'],
  'lazada':['lazada.vn'],'tiki':['tiki.vn'],'google':['google.com'],'microsoft':['microsoft.com'],
  'facebook':['facebook.com'],'apple':['apple.com'],'paypal':['paypal.com'],'amazon':['amazon.com'],
  'netflix':['netflix.com'],'openai':['openai.com','chatgpt.com'],'chatgpt':['chatgpt.com','openai.com'],
  'telegram':['telegram.org'],'github':['github.com'],
};