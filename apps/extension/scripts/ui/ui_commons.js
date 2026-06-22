/* UI Commons for AntiScam */

const featureTranslations = {
  // Nhóm thuộc tính địa chỉ
  'IP Address':'Dùng địa chỉ IP','URL Length':'Địa chỉ web quá dài','Tiny URL':'Dùng địa chỉ rút ngắn',
  '@ Symbol':'Địa chỉ chứa ký tự @','Redirecting using //':'Chuyển hướng ẩn //',
  '(-) Prefix/Suffix in domain':'Tên miền chứa dấu gạch','No. of Sub Domains':'Quá nhiều tên miền phụ',
  'HTTPS':'Bảo mật HTTPS','Favicon':'Biểu tượng trang chuẩn','Port':'Cổng mạng bất thường',
  "HTTPS in URL's domain part":'Tên miền giả danh HTTPS','Request URL':'Tải dữ liệu từ web ngoài',
  'Anchor':'Chứa liên kết ngoài','Script & Link':'Chèn mã từ web ngoài','SFH':'Nơi nhận dữ liệu không an toàn',
  'mailto':'Gửi tin qua Email','iFrames':'Dùng khung trang ẩn',
  'Sensitive Form':'Hỏi mật khẩu hoặc OTP','Form Hijacking':'Biểu mẫu bị chiếm đoạt',
  'Obfuscated Script':'Chứa mã độc ẩn giấu','ObfuscatedScript':'Chứa mã độc ẩn giấu','Domain Age':'Web mới hoạt động',
  
  // V2 — Các tín hiệu rủi ro (Risk)
  'Punycode':'Tên miền giả mạo','UnicodeHost':'Tên miền ký tự lạ',
  'Homograph':'Giả mạo thương hiệu tinh vi','Typosquat':'Viết sai tên thương hiệu',
  'BrandInDomain':'Mượn danh thương hiệu lớn','BrandInPath':'Địa chỉ chứa tên thương hiệu',
  'BrandImpersonation':'Mạo danh nội dung chính chủ','VNScamKeyword':'Từ khóa lừa đảo tiếng Việt',
  'Keylogger':'Theo dõi bàn phím','ClipboardHijack':'Can thiệp bộ nhớ tạm',
  'DangerousDownload':'Tệp tải về gây hại','ArchiveDownload':'Tệp nén cần kiểm tra kỹ','SuspiciousExternal':'Tải mã từ máy chủ lạ',
  'NoHTTPS':'Không có bảo mật HTTPS','AtSymbol':'Địa chỉ chứa @ đáng ngờ','LongURL':'Địa chỉ web quá dài',
  'SuspiciousTLD':'Đuôi tên miền đáng ngờ','IPHost':'Dùng địa chỉ IP trực tiếp',
  'RedirectChain':'Chuyển hướng nhiều lần','OpenRedirect':'Chuyển hướng trung gian','RedirectBadHop':'Qua trang web độc hại',
  'SuspiciousLinks':'Chứa liên kết nguy hiểm','DeceptiveLinks':'Liên kết lừa dối người dùng','PermissionAbuse':'Đòi quyền truy cập lạ','MetaRefreshRedirect':'Tự động chuyển trang','ScriptRedirect':'Ép buộc chuyển trang',
  'DataExfil':'Âm thầm gửi dữ liệu ra ngoài','FormDest':'Gửi dữ liệu đến trang web lạ',
  'HiddenForm':'Ô nhập liệu ẩn đáng ngờ',
  'Hidden Form':'Ô nhập liệu ẩn đáng ngờ',
  'JavaScriptRisk':'Mã lệnh đáng ngờ',
  'JavaScript Risk':'Mã lệnh đáng ngờ',
  'ScamContent':'Có nội dung lừa đảo',
  'Scam Content':'Có nội dung lừa đảo',
  'NewDomain':'Web mới hoạt động gần đây', 'MalwareReputation':'Bị cảnh báo độc hại',
  'DNSRisk':'Máy chủ rủi ro', 'CommunityReport':'Cộng đồng báo cáo vi phạm',
  
  // V2 — Các tín hiệu an toàn (Trust)
  'EstablishedDomain':'Hoạt động lâu năm','ReputationVerified':'Đã xác thực an toàn',
  'OfficialBrand':'Web chính chủ thương hiệu','SSL':'Chứng chỉ HTTPS hợp lệ',
  'TrustedResources':'Nguồn uy tín (CDN)','NoPhishingForm':'Không có biểu mẫu đánh cắp',
};

const _levelFromValue = (val) => val === '-1' ? 'safe' : (val === '1' ? 'danger' : (val === '2' ? 'suspicious' : 'warning'));
const _prefixForLevel = (level) => level === 'safe' ? '✓' : (level === 'danger' ? '✕' : '⚠');
const _stripSentence = (text) => (text || '').toString().replace(/\s+/g, ' ').trim().replace(/[.。]+$/, '');

const _countData = (key, counts) => {
  if (!counts) return null;
  const k = key.replace(/\s/g, '');
  switch (k) {
    case 'iFrames':
      if (counts.hiddenIframes > 0) return { text: counts.hiddenIframes > 1 ? '×' + counts.hiddenIframes : '1' };
      if (counts.iframes && counts.iframes.total > 0) return { text: counts.iframes.total };
      return null;
    case 'SensitiveForm':
      if (counts.sensitiveForms > 0) return { text: '×' + counts.sensitiveForms };
      return null;
    case 'SuspiciousLinks':
      if (counts.suspiciousLinks > 0) return { text: '×' + counts.suspiciousLinks };
      break;
    case 'DeceptiveLinks':
      if (counts.deceptiveLinks > 0) return { text: '×' + counts.deceptiveLinks };
      break;
    case 'PermissionAbuse':
      if (counts.permissionRequests > 0) return { text: '×' + counts.permissionRequests };
      break;
  }
  return null;
};

const _createChip = (item, counts) => {
  const li = document.createElement('li');
  const level = item.level || 'warning';
  li.className = `feature-chip chip-${level}`;
  const icon = document.createElement('span');
  icon.className = 'chip-icon';
  icon.textContent = _prefixForLevel(level);
  const label = document.createElement('span');
  label.className = 'chip-label';
  label.textContent = item.label;
  li.appendChild(icon);
  li.appendChild(label);
  const cd = item.count ? { text: item.count } : _countData(item.key, counts);
  if (cd) {
    const count = document.createElement('span');
    count.className = 'chip-count';
    count.textContent = cd.text;
    li.appendChild(count);
  }
  return li;
};

const _appendChipGroup = (featureList, title, items, counts) => {
  if (!items.length) return;
  const heading = document.createElement('li');
  heading.className = 'feature-group-title';
  heading.textContent = title;
  featureList.appendChild(heading);
  items.forEach(item => featureList.appendChild(_createChip(item, counts)));
};

const _labelForSignal = (key, val, fallbackText) => {
  const levelWords = ['safe', 'warning', 'suspicious', 'danger'];
  const level = (typeof val === 'string' && levelWords.includes(val)) ? val : (typeof val === 'string' ? _levelFromValue(val) : (val || 'warning'));
  const safe = level === 'safe';
  const translated = featureTranslations[key] || featureTranslations[fallbackText] || fallbackText || key;
  
  // Logic xử lý nhãn động dựa trên trạng thái An toàn/Nguy hiểm
  if (safe) {
    switch (key) {
      case 'HTTPS': case 'SSL': case 'NoHTTPS': return 'Kết nối bảo mật HTTPS';
      case 'OfficialBrand': return 'Web chính chủ xác thực';
      case 'EstablishedDomain': return 'Hoạt động lâu năm';
      case 'TrustedResources': return 'Nguồn uy tín (CDN)';
      case 'SFH': return 'Nơi nhận dữ liệu an toàn';
      case 'Form Hijacking': return 'Biểu mẫu an toàn';
      case 'Sensitive Form': return 'Không yêu cầu thông tin nhạy cảm';
      case 'Obfuscated Script': case 'ObfuscatedScript': return 'Mã nguồn minh bạch';
      case 'JavaScriptRisk': case 'JavaScript Risk': return 'Hành vi mã lệnh an toàn';
      case 'Keylogger': return 'Không theo dõi bàn phím';
      case 'ClipboardHijack': return 'Bộ nhớ tạm an toàn';
      case 'DangerousDownload': return 'Tệp tải về an toàn';
      case 'ArchiveDownload': return 'Không có tệp nén đáng ngờ';
      case 'HiddenForm': case 'Hidden Form': return 'Không có ô nhập liệu ẩn';
      case 'ScamContent': case 'Scam Content': return 'Nội dung tin cậy';
      case 'IP Address': case 'IPHost': return 'Sử dụng tên miền chuẩn';
      case 'URL Length': case 'LongURL': return 'Địa chỉ web ngắn gọn';
      case 'Tiny URL': return 'Địa chỉ trực tiếp';
      case 'NoPhishingForm': return 'Không có biểu mẫu đánh cắp';
      case 'Favicon': return 'Biểu tượng trang chuẩn';
      case 'RedirectBadHop': return 'Không đi qua web độc hại';
      case 'DeceptiveLinks': return 'Liên kết minh bạch';
      default: 
        // Nếu là tín hiệu an toàn khác, cố gắng chuyển câu từ cho tích cực
        return _stripSentence(translated).replace('Chứa ', 'Không chứa ').replace('Dùng ', 'Không dùng ');
    }
  }

  // Nếu là tín hiệu Cảnh báo/Nguy hiểm thì dùng bảng dịch gốc
  return _stripSentence(translated);
};

const _normLabel = (text) => _stripSentence(text).toLowerCase()
  .normalize ? _stripSentence(text).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '') : _stripSentence(text).toLowerCase();

const semanticKeyMap = {
  'HTTPS':'https', 'SSL':'https', 'NoHTTPS':'https',
  'OfficialBrand':'official-domain',
  'EstablishedDomain':'domain-age-established', 'Domain Age':'domain-age-new', 'NewDomain':'domain-age-new',
  'TrustedResources':'trusted-resources',
  'NoPhishingForm':'no-phishing-form', 'Sensitive Form':'no-phishing-form',
  'Form Hijacking':'form-destination', 'FormDest':'form-destination', 'SFH':'form-unknown-action',
  'Punycode':'unicode-spoof', 'UnicodeHost':'unicode-spoof', 'Homograph':'unicode-spoof',
  'Typosquat':'brand-spoof', 'BrandInDomain':'brand-spoof', 'BrandImpersonation':'brand-spoof',
  'Obfuscated Script':'js-risk', 'JavaScript Risk':'js-risk', 'JavaScriptRisk':'js-risk', 'ObfuscatedScript':'js-risk',
  'Scam Content':'scam-content', 'ScamContent':'scam-content',
  'MalwareReputation':'malware-reputation', 'DNSRisk':'dns-risk', 'CommunityReport':'community-report',
  'DangerousDownload':'download-risk', 'ArchiveDownload':'download-risk', 'SuspiciousLinks':'link-risk', 'DeceptiveLinks':'link-risk',
  'PermissionAbuse':'permission-risk', 'OpenRedirect':'redirect-risk', 'RedirectBadHop':'redirect-risk',
  'MetaRefreshRedirect':'redirect-risk', 'ScriptRedirect':'redirect-risk'
};

const _canonicalKey = (key, text) => semanticKeyMap[key] || _normLabel(featureTranslations[key] || text || key);
const _groupFromLevel = (level) => level === 'safe' ? 'positive' : (level === 'danger' ? 'danger' : 'warning');

const _collectFeatureChips = (state) => {
  const counts = state.counts || null;
  const chips = [];
  const used = new Map();
  
  const addChip = (raw) => {
    const key = raw.key || raw.label || raw.text;
    const level = raw.level || _levelFromValue(String(raw.value));
    const label = _labelForSignal(key, raw.value != null ? String(raw.value) : level, raw.text || raw.label);
    const canonical = _canonicalKey(key, label);
    const group = _groupFromLevel(level);
    const priority = { danger:0, suspicious:1, warning:2, safe:3 }[level] ?? 4;
    const chip = { key, label, level, group, priority, canonical, count: raw.count || null };
    const previous = used.get(canonical);
    if (!previous || chip.priority < previous.priority) used.set(canonical, chip);
  };

  const explanations = Array.isArray(state.explanations) ? state.explanations : [];
  explanations
    .filter(item => item && item.key !== 'CleanScan')
    .forEach(item => addChip({ key:item.key, level:item.level, text:item.text }));

  const result = state.result || {};
  Object.keys(result).forEach(key => {
    if (key === 'tab' || key === 'CleanScan') return;
    if (['Anchor', 'Script & Link', 'Request URL'].includes(key) && counts) return;
    const value = String(result[key]);
    if (!['-1', '0', '1', '2'].includes(value)) return;
    addChip({ key, value, label:featureTranslations[key] || key });
  });

  if (counts) {
    const specs = [['links', 'Liên kết'], ['scripts', 'Mã lệnh'], ['images', 'Hình ảnh'], ['iframes', 'Khung trang'], ['forms', 'Biểu mẫu']];
    specs.forEach(([key, name]) => {
      const st = counts[key];
      if (!st || !st.total) return;
      const safe = Number(st.safe || 0), warning = Number(st.warning || 0), dangerous = Number(st.dangerous || 0);
      if (safe > 0) addChip({ key: `${key}Safe`, level: 'safe', label: `${name} an toàn`, count: '×' + safe });
      if (warning > 0) addChip({ key: `${key}Warning`, level: 'warning', label: `${name} chưa xác minh`, count: '×' + warning });
      if (dangerous > 0) addChip({ key: `${key}Danger`, level: 'danger', label: `${name} nguy hiểm`, count: '×' + dangerous });
    });
  }

  used.forEach(v => chips.push(v));
  const order = { positive:0, warning:1, danger:2 };
  chips.sort((a, b) => (order[a.group] - order[b.group]) || (a.priority - b.priority) || a.label.localeCompare(b.label, 'vi'));
  return { chips, counts };
};

const renderUnifiedChips = (featureListEl, state) => {
  if (!featureListEl) return;
  featureListEl.innerHTML = '';
  const { chips, counts } = _collectFeatureChips(state);
  
  const positive = chips.filter(c => c.group === 'positive');
  const warning = chips.filter(c => c.group === 'warning');
  const danger = chips.filter(c => c.group === 'danger');

  _appendChipGroup(featureListEl, 'TÍN HIỆU TÍCH CỰC', positive, counts);
  _appendChipGroup(featureListEl, 'TÍN HIỆU CẢNH BÁO', warning, counts);
  _appendChipGroup(featureListEl, 'TÍN HIỆU NGUY HIỂM', danger, counts);

  if (!chips.length) {
    const empty = document.createElement('li');
    empty.className = 'feature-empty';
    empty.textContent = 'Chưa có tín hiệu.';
    featureListEl.appendChild(empty);
  }
};

// Device identification and reporting helpers
const getReportDeviceId = async () => {
  const key = 'antiScamReportDeviceId';
  try {
    const stored = await chrome.storage.local.get(key);
    if (stored && stored[key]) return stored[key];
    const id = crypto.randomUUID();
    await chrome.storage.local.set({ [key]: id });
    return id;
  } catch (_) {
    return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }
};

const hasReportedThisDomain = async (domain) => {
  const key = `reported_${domain}`;
  try {
    const stored = await chrome.storage.local.get(key);
    return !!stored[key];
  } catch (_) { return false; }
};

const markAsReported = async (domain) => {
  const key = `reported_${domain}`;
  try {
    await chrome.storage.local.set({ [key]: true });
  } catch (_) {}
};
