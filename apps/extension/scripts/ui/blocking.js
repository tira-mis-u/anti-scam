/*global chrome*/
/*global $*/
/*global featureTranslations, _levelFromValue, _labelForSignal, getReportDeviceId, hasReportedThisDomain, markAsReported, _createChip, _appendChipGroup */
let message = {};

document.getElementById('allow').addEventListener('click', () => {
  chrome.tabs.getCurrent((tab) => {
    const tabId = tab ? tab.id : null;
    chrome.runtime.sendMessage({ type: 'SET_WHITELIST_TEMP', tabId: tabId }, () => {
      chrome.tabs.update({ url: message.site });
    });
  });
});

document.getElementById('whitelistGo').addEventListener('click', () => {
  chrome.tabs.update({ url: message.site });
});

document.getElementById('toggleDetails').addEventListener('click', function() {
  this.classList.toggle('active');
  const content = document.getElementById('featureContent');
  if (content.style.maxHeight) {
    content.style.maxHeight = null;
  } else {
    content.style.maxHeight = content.scrollHeight + "px";
  }
});

const renderScanUI = (state) => {
  const pct = parseInt(state.legitimatePercent || 0);
  const site_score = document.getElementById('site_score');
  const pct_content = document.getElementById('percentage_content');
  const site_msg = document.getElementById('site_msg');

  pct_content.className = 'c100 center';
  site_msg.className = '';

  pct_content.classList.add(`p${pct}`);
  if (pct <= 50) pct_content.classList.add('orange');
  
  site_score.textContent = `${pct}%`;
  
  if (pct <= 30) {
    site_msg.textContent = 'Website có nguy cơ cực kỳ nguy hiểm!';
    site_msg.classList.add('warning');
  } else if (pct < 50) {
    site_msg.textContent = 'Website có dấu hiệu rủi ro cao.';
    site_msg.classList.add('warning');
  } else {
    site_msg.textContent = state.summary || 'Trang web đã được phân tích rủi ro.';
  }

  const accuracyNote = document.createElement('div');
  accuracyNote.className = 'accuracy-note';
  accuracyNote.textContent = `Độ tin cậy: ${state.confidence || 0}%`;
  site_msg.appendChild(accuracyNote);

  const featureList = document.getElementById('features');
  renderUnifiedChips(featureList, state);
};

// Initialize from hash
const hash = window.location.hash.substring(1);
try {
  message = JSON.parse(decodeURI(hash));
  if (message.listType === 'whitelist') {
    document.getElementById('whitelistOverlay').classList.add('show');
    document.getElementById('wlDomain').textContent = message.site || '';
  } else {
    document.getElementById('blockWrap').style.display = 'flex';
    document.getElementById('blockDomain').textContent = message.site || '';
    renderScanUI({
      legitimatePercent: message.finalScore || 0,
      confidence: message.confidence || 95,
      summary: message.reason || 'Trang nằm trong danh sách đen.',
      result: message.result || {},
      explanations: message.explanations || []
    });
  }
} catch (e) { console.error(e); }

// ─────────────────────────────────────────────────────────────────────────────
// Community Report Logic (Replicated from plugin_ui.js)
// ─────────────────────────────────────────────────────────────────────────────
const REPORT_API_URL = 'https://anti-scam-6iix.onrender.com/api/report';
const REPORT_MAX_FILE_SIZE = 5 * 1024 * 1024;
const REPORT_ALLOWED_TYPES = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];

const reportToggle = document.getElementById('reportToggle');
const reportForm = document.getElementById('community_report');
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

const setReportStatus = (msg, type = '') => {
  const statusEl = document.getElementById('reportStatus');
  if (!statusEl) return;
  statusEl.textContent = msg || '';
  statusEl.className = type;
};

const updateReportTargetInfo = () => {
  const urlEl = document.getElementById('reportCurrentUrl');
  const domainEl = document.getElementById('reportCurrentDomain');
  if (urlEl) urlEl.textContent = message.site || '';
  if (domainEl) {
    try {
      domainEl.textContent = (new URL(message.site)).hostname.replace(/^www\./i, '');
    } catch(e) { domainEl.textContent = message.site; }
  }
};

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

const getBrowserName = () => {
  const ua = navigator.userAgent || '';
  if (/Edg\//.test(ua)) return 'Microsoft Edge';
  if (/OPR\//.test(ua) || /Opera\//.test(ua)) return 'Opera';
  if (/Firefox\//.test(ua)) return 'Firefox';
  if (/Chrome\//.test(ua) || /Chromium\//.test(ua)) return 'Chrome';
  if (/Safari\//.test(ua)) return 'Safari';
  return 'Không xác định';
};

const buildReportFormData = async () => {
  const formData = new FormData();
  formData.append('url', message.site);
  const domain = (new URL(message.site)).hostname.replace(/^www\./i, '');
  formData.append('domain', domain);
  formData.append('timestamp', new Date().toISOString());
  formData.append('browserName', getBrowserName());
  formData.append('deviceId', await getReportDeviceId());
  
  let category = reportCategory.value;
  if (category === 'other') {
    category = `other: ${(document.getElementById('reportCategoryOther')?.value || '').trim()}`;
  }
  formData.append('category', category);
  formData.append('description', (reportDescription.value || '').trim());

  if (selectedReportFile) formData.append('screenshot', selectedReportFile, selectedReportFile.name);
  return formData;
};

if (reportToggle) {
  reportToggle.addEventListener('click', () => {
    $(reportForm).slideToggle();
    updateReportTargetInfo();
  });
}

document.querySelectorAll('input[name="reportType"]').forEach(radio => {
  radio.addEventListener('change', (e) => {
    const isMalicious = e.target.value === 'malicious';
    const malGroup = document.getElementById('maliciousCategories');
    const safeGroup = document.getElementById('safeCategories');
    if (malGroup) malGroup.hidden = !isMalicious;
    if (safeGroup) safeGroup.hidden = isMalicious;
    if (reportCategory) reportCategory.value = '';
    const otherWrap = document.getElementById('otherCategoryWrap');
    if (otherWrap) otherWrap.hidden = true;
  });
});

if (reportCategory) {
  reportCategory.addEventListener('change', (e) => {
    const otherWrap = document.getElementById('otherCategoryWrap');
    if (otherWrap) otherWrap.hidden = e.target.value !== 'other';
  });
}

if (reportDescription && reportDescriptionCount) {
  reportDescription.addEventListener('input', () => {
    reportDescriptionCount.textContent = `${reportDescription.value.length}/1000 ký tự`;
  });
}

if (reportScreenshot) {
  reportScreenshot.addEventListener('change', () => {
    const file = reportScreenshot.files[0];
    if (!file) { resetReportImage(); return; }
    if (!REPORT_ALLOWED_TYPES.includes(file.type) || file.size > REPORT_MAX_FILE_SIZE) {
      setReportStatus('Ảnh không hợp lệ hoặc quá lớn.', 'error');
      return;
    }
    selectedReportFile = file;
    reportFileName.textContent = file.name;
    const reader = new FileReader();
    reader.onload = () => {
      reportImagePreview.src = reader.result;
      reportImagePreviewWrap.hidden = false;
    };
    reader.readAsDataURL(file);
  });
}

if (reportRemoveImage) reportRemoveImage.addEventListener('click', resetReportImage);

if (sendReport) {
  sendReport.addEventListener('click', async () => {
    const domain = (new URL(message.site)).hostname.replace(/^www\./i, '');
    if (await hasReportedThisDomain(domain)) {
      setReportStatus('Bạn đã gửi báo cáo cho trang web này rồi.', 'error');
      return;
    }
    if (!reportCategory.value || reportDescription.value.length < 20) {
      setReportStatus('Vui lòng chọn loại và nhập mô tả chi tiết (min 20 ký tự).', 'error');
      return;
    }
    setReportStatus('Đang gửi báo cáo...', 'loading');
    try {
      const res = await fetch(REPORT_API_URL, { method: 'POST', body: await buildReportFormData() });
      if (res.ok) {
        await markAsReported(domain);
        setReportStatus('Gửi báo cáo thành công!', 'success');
        setTimeout(() => { $(reportForm).slideUp(); resetReportForm(); }, 2000);
      } else {
        const data = await res.json().catch(() => ({}));
        setReportStatus(data.message || 'Lỗi khi gửi báo cáo.', 'error');
      }
    } catch (e) {
      setReportStatus('Không thể kết nối máy chủ.', 'error');
    }
  });
}

if (reportCancel) {
  reportCancel.addEventListener('click', () => {
    $(reportForm).slideUp();
    resetReportForm();
  });
}
