/* global chrome */
/* global $ */

// ─────────────────────────────────────────────────────────────────────────────
// Màu sắc badge (giữ nguyên)
// ─────────────────────────────────────────────────────────────────────────────
const colors = { '-1':'#22c55e', '0':'#facc15', '2':'#fb923c', '1':'#dc2626' };
const reasonColors = { safe:'#22c55e', warning:'#facc15', suspicious:'#fb923c', danger:'#dc2626' };
let currentTabUrl = '';
let currentDomain = '';
let currentPageTitle = '';

const initTheme = () => {
  const stored = localStorage.getItem('antiscam-theme');
  const saved = (stored === 'light' || stored === 'dark') ? stored : 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  localStorage.setItem('antiscam-theme', saved);
  const btn = document.getElementById('themeToggle');
  if (btn) {
    btn.checked = saved === 'light';
    btn.setAttribute('aria-label', saved === 'light' ? 'Đang dùng giao diện sáng' : 'Đang dùng giao diện tối');
  }
};
const toggleTheme = (event) => {
  const checked = event && event.target ? !!event.target.checked : (document.documentElement.getAttribute('data-theme') !== 'light');
  const next = checked ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('antiscam-theme', next);
  const btn = document.getElementById('themeToggle');
  if (btn) {
    btn.checked = next === 'light';
    btn.setAttribute('aria-label', next === 'light' ? 'Đang dùng giao diện sáng' : 'Đang dùng giao diện tối');
  }
};
initTheme();
const themeBtn = document.getElementById('themeToggle');
if (themeBtn) themeBtn.addEventListener('change', toggleTheme);

// ─────────────────────────────────────────────────────────────────────────────
// Cấu hình polling — V2: liên tục (dynamic score)
// ─────────────────────────────────────────────────────────────────────────────
const POLL_INTERVAL_MS = 800;       // giai đoạn chờ phân tích đầu
const UPDATE_INTERVAL_MS = 1500;    // sau khi có kết quả → cập nhật realtime
const POLL_MAX_ATTEMPTS = 19;

// ─────────────────────────────────────────────────────────────────────────────
// Collapsible "Xem chi tiết" (giữ nguyên)
// ─────────────────────────────────────────────────────────────────────────────
const setupCollapsible = () => {
  [...document.getElementsByClassName('collapsible')].forEach((el) => {
    // Remove old listeners to avoid multiple attachments
    const newEl = el.cloneNode(true);
    el.parentNode.replaceChild(newEl, el);
    newEl.addEventListener('click', function () {
      this.classList.toggle('active');
      const content = this.nextElementSibling;
      if (content.style.maxHeight) { content.style.maxHeight = null; }
      else { content.style.maxHeight = `${content.scrollHeight}px`; }
    });
  });
};
setupCollapsible();

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
// Render unified feature chips
// ─────────────────────────────────────────────────────────────────────────────
const renderState = (state, domain) => {
  const { isWhiteList, isBlocked, isPhish, legitimatePercent, confidence, status, isUnknown } = state;

  if (isWhiteList) {
    $('#pluginBody').hide(); $('#isSafe').show(); $('#isSafe .site-url').text(domain); return;
  }
  if (isBlocked) {
    $('#pluginBody').hide(); $('#isPhishing').show(); $('#isPhishing .site-url').text(isBlocked); return;
  }

  _cleanDyn();

  const featureList = document.getElementById('features');
  if (typeof renderUnifiedChips === 'function') {
      renderUnifiedChips(featureList, state);
  }

  const featureContent = featureList.closest('.feature-content');
  if (featureContent && featureContent.style.maxHeight) featureContent.style.maxHeight = `${featureContent.scrollHeight}px`;

  const pct = parseInt(legitimatePercent);
  const confidencePct = parseInt(confidence);
  const isValidPct = !isNaN(pct) && isFinite(pct);
  const isValidConfidence = !isNaN(confidencePct) && isFinite(confidencePct);

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

  // Thông báo tổng quan không lặp lại nội dung từng chip.
  let message;
  if (status === 'OFFLINE') message = 'Không thể kết nối máy chủ phân tích.';
  else if (status === 'FAILED') message = 'Không thể phân tích trang này.';
  else if (isUnknown) message = 'Chưa đủ dữ liệu để đánh giá độ tin cậy.';
  else message = isPhish ? 'Website có nguy cơ cao.' : 'Website đã được phân tích.';

  // Vòng tròn chỉ hiển thị % gọn gàng — KHÔNG nhồi confidence vào
  $('#site_score').text(isValidPct ? `${pct}%` : '...');

  if (isValidPct) {
    const accuracyLine = document.createElement('div');
    accuracyLine.className = 'sub-note accuracy-note';
    accuracyLine.textContent = `Độ tin cậy: ${isValidConfidence ? confidencePct : 0}%`;
    
    $('#site_msg').text(message);
    $('#site_msg').append(accuracyLine);
    
    if (isUnknown) {
      const unknownLine = document.createElement('div');
      unknownLine.className = 'sub-note';
      unknownLine.textContent = 'Chưa đủ dữ liệu — không nhập thông tin nhạy cảm nếu chưa chắc chắn.';
      $('#site_msg').append(unknownLine);
    }
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
  currentTabUrl = tab.url;
  currentDomain = domain.replace(/^www\./i, '');
  currentPageTitle = tab.title || '';
  updateReportTargetInfo();

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


// Community report UI
const REPORT_API_URL = 'https://anti-scam-6iix.onrender.com/api/report';
const REPORT_MAX_FILE_SIZE = 5 * 1024 * 1024;
const REPORT_ALLOWED_TYPES = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];

const reportToggle = document.getElementById('reportToggle');
const reportForm = document.getElementById('reportForm');
const sendReport = document.getElementById('sendReport');
const reportCancel = document.getElementById('reportCancel');
const reportCategory = document.getElementById('reportCategory');
const reportDescription = document.getElementById('reportDescription');
const reportDescriptionCount = document.getElementById('reportDescriptionCount');
const reportScreenshot = document.getElementById('reportScreenshot');
const reportFileName = document.getElementById('reportFileName');
const reportImagePreviewWrap = document.getElementById('reportImagePreviewWrap');
const reportImagePreview = document.getElementById('reportImagePreview');
const reportRemoveImage = document.getElementById('reportRemoveImage');

let selectedReportFile = null;

const setReportStatus = (message, type = '') => {
  const statusEl = document.getElementById('reportStatus');
  if (!statusEl) return;
  statusEl.textContent = message || '';
  statusEl.classList.remove('success', 'error', 'loading');
  if (type) statusEl.classList.add(type);
};

function updateReportTargetInfo() {
  const urlEl = document.getElementById('reportCurrentUrl');
  const domainEl = document.getElementById('reportCurrentDomain');
  if (urlEl) urlEl.textContent = currentTabUrl || 'Không lấy được URL hiện tại';
  if (domainEl) domainEl.textContent = currentDomain || 'Không lấy được tên miền';
}

const resetReportImage = () => {
  selectedReportFile = null;
  if (reportScreenshot) reportScreenshot.value = '';
  if (reportFileName) reportFileName.textContent = 'PNG, JPG, JPEG, WEBP · tối đa 5MB';
  if (reportImagePreview) reportImagePreview.removeAttribute('src');
  if (reportImagePreviewWrap) reportImagePreviewWrap.hidden = true;
};

const resetReportForm = () => {
  if (reportCategory) reportCategory.value = '';
  if (reportDescription) reportDescription.value = '';
  if (reportDescriptionCount) reportDescriptionCount.textContent = '0/1000 ký tự';
  resetReportImage();
  setReportStatus('');
};

const closeReportPanel = () => {
  if (!reportForm) return;
  reportForm.hidden = true;
  reportToggle && reportToggle.setAttribute('aria-expanded', 'false');
  setReportStatus('');
};

const getBrowserName = () => {
  const ua = navigator.userAgent || '';
  if (/Edg\//.test(ua)) return 'Microsoft Edge';
  if (/OPR\//.test(ua) || /Opera\//.test(ua)) return 'Opera';
  if (/Firefox\//.test(ua)) return 'Firefox';
  if (/Chrome\//.test(ua) || /Chromium\//.test(ua)) return 'Chrome';
  if (/Safari\//.test(ua)) return 'Safari';
  return 'Không xác định';
};


// ═══════════════════════════════════════════════════════
// LẤY VỊ TRÍ GPS THỰC TẾ (chính xác 100% — thay thế IP-based)
// ═══════════════════════════════════════════════════════
let _cachedGpsLocation = null;
let _gpsLocationError = null;

const getLocationFromGPS = () => {
  return new Promise((resolve) => {
    if (_cachedGpsLocation) {
      resolve(_cachedGpsLocation);
      return;
    }
    if (!navigator.geolocation) {
      _gpsLocationError = 'Trình duyệt không hỗ trợ Geolocation';
      resolve(null);
      return;
    }
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        _cachedGpsLocation = {
          latitude: pos.coords.latitude,
          longitude: pos.coords.longitude,
          accuracy: pos.coords.accuracy,
          source: 'gps'
        };
        resolve(_cachedGpsLocation);
      },
      (err) => {
        _gpsLocationError = err.message;
        resolve(null);
      },
      { enableHighAccuracy: true, timeout: 8000, maximumAge: 300000 }
    );
  });
};

const validateReportForm = () => {
  let parsedUrl = null;
  try { parsedUrl = new URL(currentTabUrl); } catch (_) {}
  if (!parsedUrl || !['http:', 'https:'].includes(parsedUrl.protocol)) return 'URL không hợp lệ.';
  if (!reportCategory || !reportCategory.value) return 'Vui lòng chọn loại báo cáo.';
  
  if (reportCategory.value === 'other') {
    const otherVal = (document.getElementById('reportCategoryOther')?.value || '').trim();
    if (otherVal.length < 3) return 'Vui lòng nhập lý do cụ thể (tối thiểu 3 ký tự).';
  }

  const description = (reportDescription && reportDescription.value || '').trim();
  if (description.length < 20) return 'Mô tả phải có tối thiểu 20 ký tự.';
  if (description.length > 1000) return 'Mô tả không được vượt quá 1000 ký tự.';
  if (selectedReportFile && selectedReportFile.size > REPORT_MAX_FILE_SIZE) return 'File vượt quá 5MB.';
  if (selectedReportFile && !REPORT_ALLOWED_TYPES.includes(selectedReportFile.type)) return 'Định dạng ảnh không được hỗ trợ.';
  return '';
};

const buildReportFormData = async () => {
  const manifest = chrome.runtime.getManifest ? chrome.runtime.getManifest() : {};
  const formData = new FormData();
  formData.append('url', currentTabUrl);
  formData.append('domain', currentDomain);
  formData.append('pageTitle', currentPageTitle || document.title || '');
  formData.append('timestamp', new Date().toISOString());
  formData.append('extensionVersion', manifest.version || '');
  formData.append('browserName', getBrowserName());
  formData.append('browserLanguage', navigator.language || '');
  formData.append('userAgent', navigator.userAgent || '');
  formData.append('deviceId', await getReportDeviceId());
  
  let category = reportCategory.value;
  if (category === 'other') {
    const otherVal = (document.getElementById('reportCategoryOther')?.value || '').trim();
    category = `other: ${otherVal}`;
  }
  formData.append('category', category);
  
  formData.append('description', (reportDescription.value || '').trim());

  // ═══ GPS thật — chính xác 100%
  const gpsLoc = await getLocationFromGPS();
  if (gpsLoc) {
    formData.append('latitude', String(gpsLoc.latitude));
    formData.append('longitude', String(gpsLoc.longitude));
    formData.append('gpsAccuracy', String(gpsLoc.accuracy));
    formData.append('locationSource', 'gps');
  } else {
    formData.append('locationSource', 'ip-fallback');
  }

  if (selectedReportFile) formData.append('screenshot', selectedReportFile, selectedReportFile.name);
  return formData;
};

if (reportToggle && reportForm) {
  reportToggle.setAttribute('aria-expanded', 'false');
  reportToggle.addEventListener('click', () => {
    reportForm.hidden = !reportForm.hidden;
    reportToggle.setAttribute('aria-expanded', String(!reportForm.hidden));
    updateReportTargetInfo();
    setReportStatus('');
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(()=>{}, ()=>{}, {timeout: 5000});
    }
  });
}

// Logic chuyển đổi optgroup dựa trên radio button
document.querySelectorAll('input[name="reportType"]').forEach(radio => {
  radio.addEventListener('change', (e) => {
    const isMalicious = e.target.value === 'malicious';
    const malGroup = document.getElementById('maliciousCategories');
    const safeGroup = document.getElementById('safeCategories');
    const categorySelect = document.getElementById('reportCategory');
    
    if (malGroup && safeGroup && categorySelect) {
      malGroup.hidden = !isMalicious;
      safeGroup.hidden = isMalicious;
      categorySelect.value = ''; // Reset selection
      document.getElementById('otherCategoryWrap').hidden = true; 
      
      const descArea = document.getElementById('reportDescription');
      const hintDiv = document.getElementById('reportHint');
      if (isMalicious) {
        descArea.placeholder = "Lý do bạn báo cáo website này độc hại...";
        hintDiv.textContent = "Ví dụ: Website giả mạo ngân hàng, yêu cầu nhập OTP, mạo danh Shopee.";
      } else {
        descArea.placeholder = "Lý do bạn cho rằng website này an toàn...";
        hintDiv.textContent = "Ví dụ: Đây là website chính thức của một tổ chức giáo dục hoặc doanh nghiệp uy tín.";
      }
    }
  });
});

document.getElementById('reportCategory').addEventListener('change', (e) => {
  const otherWrap = document.getElementById('otherCategoryWrap');
  if (otherWrap) {
    otherWrap.hidden = e.target.value !== 'other';
    if (e.target.value === 'other') {
      document.getElementById('reportCategoryOther').focus();
    }
  }
});

if (reportDescription && reportDescriptionCount) {
  reportDescription.addEventListener('input', () => {
    const len = (reportDescription.value || '').length;
    reportDescriptionCount.textContent = `${len}/1000 ký tự`;
  });
}

if (reportScreenshot) {
  reportScreenshot.addEventListener('change', () => {
    setReportStatus('');
    const file = reportScreenshot.files && reportScreenshot.files[0];
    if (!file) { resetReportImage(); return; }
    if (!REPORT_ALLOWED_TYPES.includes(file.type)) {
      resetReportImage();
      setReportStatus('Định dạng ảnh không được hỗ trợ.', 'error');
      return;
    }
    if (file.size > REPORT_MAX_FILE_SIZE) {
      resetReportImage();
      setReportStatus('File vượt quá 5MB.', 'error');
      return;
    }
    selectedReportFile = file;
    if (reportFileName) reportFileName.textContent = file.name;
    const reader = new FileReader();
    reader.onload = () => {
      if (reportImagePreview) reportImagePreview.src = reader.result;
      if (reportImagePreviewWrap) reportImagePreviewWrap.hidden = false;
    };
    reader.readAsDataURL(file);
  });
}

if (reportRemoveImage) reportRemoveImage.addEventListener('click', resetReportImage);

if (reportCancel) {
  reportCancel.addEventListener('click', () => {
    resetReportForm();
    closeReportPanel();
  });
}

if (sendReport) {
  sendReport.addEventListener('click', async () => {
    if (await hasReportedThisDomain(currentDomain)) {
      setReportStatus('Bạn đã gửi báo cáo cho trang web này rồi.', 'error');
      return;
    }

    const error = validateReportForm();
    if (error) { setReportStatus(error, 'error'); return; }

    setReportStatus('Đang gửi báo cáo...', 'loading');
    sendReport.disabled = true;
    try {
      const response = await fetch(REPORT_API_URL, { method: 'POST', body: await buildReportFormData() });
      if (!response.ok) throw new Error('Network response was not ok');
      
      await markAsReported(currentDomain);
      resetReportForm();
      setReportStatus('Báo cáo thành công.', 'success');
      setTimeout(closeReportPanel, 1600);
    } catch (_) {
      setReportStatus('Không thể gửi báo cáo.', 'error');
    } finally {
      sendReport.disabled = false;
    }
  });
}
