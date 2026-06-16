/* global chrome */
/* global $ */

// ─────────────────────────────────────────────────────────────────────────────
// Màu sắc badge (giữ nguyên)
// ─────────────────────────────────────────────────────────────────────────────
// Badge values V3: SAFE(-1) NEUTRAL(0) SUSPICIOUS(2) DANGEROUS(1)
// '-1' xanh (an toàn) | '0' vàng (trung tính) | '2' cam (đáng ngờ) | '1' đỏ (nguy hiểm)
const colors = { '-1':'#28a745', '0':'#ffeb3c', '2':'#ff8c00', '1':'#cc0000' };

// ─────────────────────────────────────────────────────────────────────────────
// Cấu hình polling — V2: liên tục (dynamic score)
// ─────────────────────────────────────────────────────────────────────────────
const POLL_INTERVAL_MS = 800;       // giai đoạn chờ phân tích đầu
const UPDATE_INTERVAL_MS = 1500;    // sau khi có kết quả → cập nhật realtime
const POLL_MAX_ATTEMPTS = 19;

// ─────────────────────────────────────────────────────────────────────────────
// Collapsible "Xem chi tiết" (giữ nguyên)
// ─────────────────────────────────────────────────────────────────────────────
[...document.getElementsByClassName('collapsible')].forEach((el) => {
  el.addEventListener('click', function () {
    this.classList.toggle('active');
    const content = this.nextElementSibling;
    if (content.style.maxHeight) { content.style.maxHeight = null; }
    else { content.style.maxHeight = `${content.scrollHeight}px`; }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Bảng dịch thuật (giữ key cũ + thêm key V2)
// ─────────────────────────────────────────────────────────────────────────────
const featureTranslations = {
  // gốc
  'IP Address':'Địa chỉ IP','URL Length':'Độ dài đường dẫn','Tiny URL':'URL rút gọn',
  '@ Symbol':'Chứa ký tự @','Redirecting using //':'Chuyển hướng ẩn (//)',
  '(-) Prefix/Suffix in domain':'Có dấu (-) trong tên miền','No. of Sub Domains':'Nhiều tên miền phụ',
  'HTTPS':'Bảo mật HTTPS','Favicon':'Biểu tượng trang (Favicon)','Port':'Cổng mạng (Port)',
  "HTTPS in URL's domain part":'HTTPS giả mạo','Request URL':'Tài nguyên từ trang khác',
  'Anchor':'Liên kết ngoài','Script & Link':'Mã nhúng từ trang khác','SFH':'Biểu mẫu không rõ nơi nhận dữ liệu',
  'mailto':'Gửi dữ liệu qua email','iFrames':'Khung trang ẩn (iFrame)',
  'Sensitive Form':'Yêu cầu nhập Mật khẩu/OTP','Form Hijacking':'Chiếm đoạt dữ liệu Form',
  'Obfuscated Script':'Mã độc ẩn (Obfuscated)','Domain Age':'Tên miền mới đăng ký',
  // V2 — risk badges
  'Punycode':'Tên miền mã hoá (Punycode)','UnicodeHost':'Ký tự Unicode bất thường',
  'Homograph':'Giả mạo thương hiệu (ký tự giống)','Typosquat':'Tên miền gần giống thương hiệu',
  'BrandInDomain':'Tên miền chứa tên thương hiệu lạ','BrandInPath':'Đường dẫn nhắc thương hiệu',
  'BrandImpersonation':'Giả mạo thương hiệu trong nội dung','VNScamKeyword':'URL chứa từ khoá lừa đảo (VN)',
  'Keylogger':'Theo dõi thao tác gõ phím','ClipboardHijack':'Can thiệp bộ nhớ tạm',
  'DangerousDownload':'Yêu cầu tải file nguy hiểm','SuspiciousExternal':'Tải mã từ nguồn lạ',
  'NoHTTPS':'Không dùng HTTPS','AtSymbol':'URL chứa ký tự @','LongURL':'Đường dẫn quá dài',
  'SuspiciousTLD':'Đuôi tên miền dễ lạm dụng','IPHost':'Truy cập bằng địa chỉ IP',
  'RedirectChain':'Chuỗi chuyển hướng phức tạp',
  'DataExfil':'Gửi dữ liệu ra tên miền lạ',
  'FormDest':'Biểu mẫu gửi dữ liệu đến tên miền lạ',
  // V2 — trust badges (xanh)
  'EstablishedDomain':'Tên miền lâu đời','ReputationVerified':'Nằm trong danh sách tin cậy',
  'OfficialBrand':'Thương hiệu chính thức','SSL':'Có chứng chỉ HTTPS',
  'TrustedResources':'Tài nguyên từ nguồn phổ biến',
  'CleanScan':'Quét toàn diện: không phát hiện mối đe dọa',
};

// ─────────────────────────────────────────────────────────────────────────────
// Theo dõi class động để xoá khi re-render (idempotent — không trùng lớp)
// ─────────────────────────────────────────────────────────────────────────────
let _dynClasses = { pct:[], score:[], msg:[] };
const _cleanDyn = () => {
  const pc = document.getElementById('percentage_content');
  const ss = document.getElementById('site_score');
  const sm = document.getElementById('site_msg');
  _dynClasses.pct.forEach(c => pc && pc.classList.remove(c));
  _dynClasses.score.forEach(c => ss && ss.classList.remove(c));
  _dynClasses.msg.forEach(c => sm && sm.classList.remove(c));
  _dynClasses = { pct:[], score:[], msg:[] };
};

// ─────────────────────────────────────────────────────────────────────────────
// Map key badge → số lượng (lấy từ state.counts)
// Trả về HTML <span class="badge-count"> cho thống nhất
// - Số LƯỢNG tuyệt đối (iframe, form): ×3
// - TỶ LỆ (anchor, script, image): 2/12
// ĐỒNG NHẤT: luôn dùng cú pháp [số] trong tag riêng (badge-count)
// ─────────────────────────────────────────────────────────────────────────────
const _countData = (key, counts) => {
  if (!counts) return null;
  switch (key) {
    case 'iFrames':
      if (counts.hiddenIframes > 0) return { text: counts.hiddenIframes > 1 ? '×' + counts.hiddenIframes : '1' };
      break;
    case 'Anchor':
      if (counts.externalAnchors > 0) return { text: counts.externalAnchors + '/' + counts.totalAnchors };
      break;
    case 'Script & Link':
      if (counts.externalScripts > 0) return { text: counts.externalScripts + '/' + counts.totalScripts };
      break;
    case 'Request URL':
      if (counts.externalImages > 0) return { text: counts.externalImages + '/' + counts.totalImages };
      break;
    case 'Sensitive Form':
      if (counts.sensitiveForms > 1) return { text: '×' + counts.sensitiveForms };
      break;
  }
  return null;
};

// Tạo text + HTML count badge cho một key
const _buildBadge = (key, val, counts) => {
  const label = featureTranslations[key] || key;
  const cd = _countData(key, counts);
  if (!cd) return { text: label, html: label, hasCount: false };
  // text thuần (cho fallback)
  const fullText = label + ' (' + cd.text + ')';
  // HTML có span count style riêng (cho CẢ safe + warn)
  const html = label + ' <span style="display:inline-block;background:rgba(0,0,0,0.3);border-radius:0.6rem;padding:0.05rem 0.5rem;margin-left:0.3rem;font-size:0.85em;font-weight:600;opacity:0.9;">' + cd.text + '</span>';
  return { text: fullText, html: html, hasCount: true };
};

// ─────────────────────────────────────────────────────────────────────────────
// Render (không thay đổi cấu trúc HTML/CSS)
// ─────────────────────────────────────────────────────────────────────────────
const renderState = (state, domain) => {
  const { isWhiteList, isBlocked, isPhish, legitimatePercent, result, status, confidence, isUnknown } = state;

  if (isWhiteList) {
    $('#pluginBody').hide(); $('#isSafe').show(); $('#isSafe .site-url').text(domain); return;
  }
  if (isBlocked) {
    $('#pluginBody').hide(); $('#isPhishing').show(); $('#isPhishing .site-url').text(isBlocked); return;
  }

  // Xoá class động từ lần render trước
  _cleanDyn();

  const featureList = document.getElementById('features');
  featureList.innerHTML = '';

  if (result && typeof result === 'object') {
    const counts = state.counts || null;
    const seen = new Set(); // tránh trùng key
    const safeItems = [], warnItems = [];
    for (const key in result) {
      if (key === 'tab' || seen.has(key)) continue;
      seen.add(key);
      const val = result[key];
      const badge = _buildBadge(key, val, counts);
      if (val === '-1') {
        safeItems.push(badge.html); // dùng HTML để giữ span count
      } else {
        const li = document.createElement('li');
        if (badge.hasCount) {
          li.innerHTML = badge.html; // có span count
        } else {
          li.textContent = badge.text;
        }
        li.style.backgroundColor = colors[val];
        if (val === '0' || val === '2') li.style.color = '#000';
        warnItems.push(li);
      }
    }
    warnItems.forEach(li => featureList.appendChild(li));

    if (safeItems.length > 0) {
      const safeLi = document.createElement('li');
      safeLi.textContent = `✓ ${safeItems.length} đặc điểm an toàn (Xem)`;
      safeLi.style.backgroundColor = '#1a3a2a'; safeLi.style.color = '#00ff66';
      safeLi.style.border = '1px solid #00ff6644'; safeLi.style.fontSize = '1.1rem';
      safeLi.style.opacity = '0.85'; safeLi.style.cursor = 'pointer'; safeLi.style.textAlign = 'center';
      safeLi.style.transition = 'all 0.2s ease';
      safeLi.addEventListener('mouseenter', () => { safeLi.style.opacity='1'; safeLi.style.backgroundColor='#1e4630'; });
      safeLi.addEventListener('mouseleave', () => { safeLi.style.opacity='0.85'; safeLi.style.backgroundColor='#1a3a2a'; });
      let expanded = false; const rendered = [];
      const toggleExpand = () => {
        const pc = safeLi.closest('.feature-content');
        if (!expanded) {
          safeLi.textContent = `✓ ${safeItems.length} đặc điểm an toàn`;
          safeItems.forEach(text => {
            const il = document.createElement('li');
            il.innerHTML = text;
            il.style.backgroundColor='#28a745'; il.style.color='#fff'; il.style.opacity='0.85';
            il.style.fontSize='1.0rem'; il.style.border='1px solid #28a74544';
            featureList.appendChild(il); rendered.push(il);
          });
          const cl = document.createElement('li'); cl.textContent = 'Thu gọn';
          cl.style.backgroundColor='#374151'; cl.style.color='#e5e7eb'; cl.style.border='1px solid #4b5563';
          cl.style.fontSize='1.1rem'; cl.style.cursor='pointer'; cl.style.textAlign='center'; cl.style.opacity='0.85';
          cl.addEventListener('mouseenter', () => { cl.style.opacity='1'; cl.style.backgroundColor='#4b5563'; });
          cl.addEventListener('mouseleave', () => { cl.style.opacity='0.85'; cl.style.backgroundColor='#374151'; });
          cl.addEventListener('click', (e) => { e.stopPropagation(); toggleExpand(); });
          featureList.appendChild(cl); rendered.push(cl); expanded = true;
        } else {
          rendered.forEach(el => { if (el.parentNode) el.parentNode.removeChild(el); });
          rendered.length = 0; safeLi.textContent = `✓ ${safeItems.length} đặc điểm an toàn (Xem)`; expanded = false;
        }
        if (pc && pc.style.maxHeight) pc.style.maxHeight = `${pc.scrollHeight}px`;
      };
      safeLi.addEventListener('click', toggleExpand);
      featureList.appendChild(safeLi);
    }
  }

  const pct = parseInt(legitimatePercent);
  const isValidPct = !isNaN(pct) && isFinite(pct);
  const conf = (confidence != null && !isNaN(parseInt(confidence))) ? parseInt(confidence) : null;

  const site_score = document.getElementById('site_score');
  const pct_content = document.getElementById('percentage_content');
  const site_msg = document.getElementById('site_msg');

  // Class động cho vòng tròn % + trạng thái
  const pctCls = `p${isValidPct ? pct : 0}`;
  pct_content.classList.add(pctCls); _dynClasses.pct.push(pctCls);
  if (isPhish) { pct_content.classList.add('orange'); _dynClasses.pct.push('orange'); }

  if (isPhish) {
    site_score.classList.add('warning'); _dynClasses.score.push('warning');
    site_msg.classList.add('warning'); _dynClasses.msg.push('warning');
  } else {
    site_score.classList.add('safe'); _dynClasses.score.push('safe');
    site_msg.classList.add('safe'); _dynClasses.msg.push('safe');
  }

  // ── Thông báo trạng thái (confidence-gated — Vấn đề 10) ──
  let message;
  if (status === 'OFFLINE') message = 'Không thể kết nối máy chủ phân tích.';
  else if (status === 'FAILED') message = 'Không thể phân tích trang này.';
  else if (isUnknown) message = state.summary || 'Chưa đủ dữ liệu để đánh giá độ tin cậy.';
  else if (state.summary) message = state.summary;
  else message = isPhish ? 'Website này có thể không an toàn.' : 'Website này có thể an toàn.';

  // Vòng tròn chỉ hiển thị % gọn gàng — KHÔNG nhồi confidence vào
  $('#site_score').text(isValidPct ? `${pct}%` : '...');

  // Confidence hiển thị dưới message (dòng phụ nhỏ, không thêm phần tử DOM mới)
  if (isValidPct) {
    const confLine = (conf != null && !isUnknown)
      ? `<div style="font-size:0.72em;font-weight:400;opacity:0.65;margin-top:0.3rem;">Độ tin cậy: ${conf}%</div>`
      : (isUnknown
        ? `<div style="font-size:0.72em;font-weight:400;opacity:0.65;margin-top:0.3rem;">Độ tin cậy thấp — chưa đủ dữ liệu</div>`
        : '');
    $('#site_msg').html(message + confLine);
  } else {
    $('#site_msg').text('...');
  }
  $('#domain_url').text(domain);
};

// ─────────────────────────────────────────────────────────────────────────────
// Main — polling LIÊN TỤC (dynamic score — Vấn đề 8, 9)
// ─────────────────────────────────────────────────────────────────────────────
chrome.tabs.query({ currentWindow: true, active: true }, ([tab]) => {
  if (!tab) return;
  const tabId = tab.id;
  let url; try { url = new URL(tab.url); } catch { return; }
  const domain = url.hostname;

  if (!['https:', 'http:'].includes(url.protocol)) {
    $('#pluginBody').hide(); $('#domain_url').text(domain); return;
  }

  $('#site_msg').text('Đang phân tích...'); $('#site_score').text('...'); $('#domain_url').text(domain);

  let attempts = 0;
  let hasResult = false;
  let lastUpdatedAt = 0;

  const poll = () => {
    chrome.runtime.sendMessage({ type: 'GET_TAB_STATE', tabId }, (state) => {
      if (chrome.runtime.lastError) {
        if (attempts < POLL_MAX_ATTEMPTS) { attempts++; setTimeout(poll, POLL_INTERVAL_MS); }
        else { $('#site_msg').text('Tiện ích chưa sẵn sàng. Thử tải lại trang.'); $('#site_score').text('...'); }
        return;
      }

      const stillAnalyzing = !state || state.status === 'ANALYZING' || state.status === 'IDLE';
      if (stillAnalyzing) {
        if (attempts < POLL_MAX_ATTEMPTS) { attempts++; setTimeout(poll, POLL_INTERVAL_MS); }
        else if (state && state.result) { renderState(state, domain); hasResult = true; }
        else { $('#site_msg').text('Trang chưa được phân tích. Thử tải lại trang.'); $('#site_score').text('...'); $('#domain_url').text(domain); }
        return;
      }

      // Có kết quả → render + TIẾP TỤC polling để cập nhật realtime
      const updatedNow = state && state.updatedAt && state.updatedAt !== lastUpdatedAt;
      if (updatedNow || !hasResult) {
        renderState(state, domain);
        lastUpdatedAt = state ? state.updatedAt : 0;
        hasResult = true;
      }
      // Poll tiếp với nhịp chậm hơn để bắt ANALYSIS_UPDATE
      setTimeout(poll, UPDATE_INTERVAL_MS);
    });
  };

  poll();
});
