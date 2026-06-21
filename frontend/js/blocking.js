/*global chrome*/
const REDIRECT_PORT_NAME = 'REDIRECT_PORT_NAME';
const CLOSE_TAB_PORT_NAME = 'CLOSE_TAB_PORT_NAME';
let message = {};

const redirectPort = chrome.runtime.connect({ name: REDIRECT_PORT_NAME });
const closeTabPort = chrome.runtime.connect({ name: CLOSE_TAB_PORT_NAME });

document.getElementById('close').addEventListener('click', () => {
  closeTabPort.postMessage({ close_tab: true });
  return false;
});

document.getElementById('allow').addEventListener('click', () => {
  chrome.tabs.query({ currentWindow: true, active: true }, ([tab]) => {
    chrome.runtime.sendMessage({ type: 'SET_WHITELIST_TEMP', tabId: tab.id }, () => {
      redirectPort.postMessage({ redirect: message.site });
    });
  });
});

// Whitelist overlay — tiếp tục truy cập
document.getElementById('whitelistGo').addEventListener('click', () => {
  redirectPort.postMessage({ redirect: message.site });
});

const hash = window.location.hash.substring(1);
try {
  message = JSON.parse(decodeURI(hash));
  if (!message.v3) {
    message.v3 = true;
    window.location.hash = JSON.stringify(message);
  }

  // Favicon
  const link = document.createElement('link');
  link.type = 'image/x-icon';
  link.rel = 'icon';
  link.href = message.favicon;
  document.head.appendChild(link);

  // sitename / sitetitle / sitematch
  let spans = document.getElementsByClassName('sitename');
  for (let i = 0; i < spans.length; ++i) spans[i].textContent = message.site;
  spans = document.getElementsByClassName('sitetitle');
  for (let i = 0; i < spans.length; ++i) spans[i].textContent = message.title;
  spans = document.getElementsByClassName('sitematch');
  let match;
  for (let i = 0; i < spans.length; ++i) {
    if (!match) {
      match = message.match.replace(/\\([.+?^${}()|[\]\\]{1})/g, '$1').replace(/[.]{1}[*]{1}/g, '*');
    }
    spans[i].textContent = match;
  }
  document.title = `${document.title} ${message.title}`;

  // ═══════════════════════════════════════════════════
  // HIỂN THỊ THEO LOẠI TÍN HIỆU — VIỆT HOÁ NGẮN
  // 3 loại: ĐỎ (danh sách đen) | CAM (nội dung người lớn) | XANH LÁ (đạt chuẩn)
  // KHÔNG CÓ VÀNG
  // ═══════════════════════════════════════════════════
  if (message.listType === 'whitelist') {
    // Whitelist — hiện overlay xanh
    const overlay = document.getElementById('whitelistOverlay');
    const wlDomain = document.getElementById('wlDomain');
    if (overlay) overlay.classList.add('show');
    if (wlDomain) wlDomain.textContent = message.site || '';

  } else {
    // Blocking page
    const blockWrap = document.getElementById('blockWrap');
    const blockDomain = document.getElementById('blockDomain');
    const blockHeadline = document.getElementById('blockHeadline');
    const badge = document.getElementById('listTypeBadge');
    const badgeContent = document.getElementById('listTypeBadgeContent');
    const reason = document.getElementById('listTypeReason');

    if (blockWrap) blockWrap.style.display = 'flex';
    if (blockDomain) blockDomain.textContent = message.site || '';

    if (message.riskBlock) {
      if (blockHeadline) blockHeadline.textContent = message.reason || `Trang ${message.title} có nguy cơ nguy hiểm cao`;
    }

    // Badge tín hiệu riêng — VIỆT HOÁ NGẮN (chỉ ĐỎ + CAM, KHÔNG VÀNG)
    if (message.listType && badge && badgeContent) {
      badge.classList.remove('hidden');

      if (message.listType === 'blacklist') {
        badgeContent.className = 'badge-row badge-den';
        badgeContent.innerHTML = '<span class="b-icon">🚫</span> Danh sách đen';
        if (reason) {
          reason.classList.remove('hidden');
          reason.textContent = 'Trang web bị cấm — đã được xác nhận lừa đảo hoặc giả mạo.';
        }
        if (blockHeadline && !message.riskBlock) blockHeadline.textContent = 'Trang web bị cấm truy cập';

      } else if (message.listType === 'pornlist') {
        badgeContent.className = 'badge-row badge-cam';
        badgeContent.innerHTML = '<span class="b-icon">🔞</span> Nội dung người lớn';
        if (reason) {
          reason.classList.remove('hidden');
          reason.textContent = 'Trang chứa nội dung 18+ — không phù hợp trẻ em.';
        }
        if (blockHeadline && !message.riskBlock) blockHeadline.textContent = 'Nội dung không phù hợp';

      } else if (message.listType === 'riskblock') {
        // Vẫn giữ riskblock dạng đỏ (nguy cơ cao), KHÔNG vàng
        badgeContent.className = 'badge-row badge-den';
        badgeContent.innerHTML = '<span class="b-icon">⚠️</span> Nguy cơ cao';
        if (reason) {
          reason.classList.remove('hidden');
          reason.textContent = message.reason || 'Phát hiện nhiều tín hiệu nguy hiểm — hãy thận trọng.';
        }
        if (blockHeadline && !message.riskBlock) blockHeadline.textContent = message.reason || 'Phát hiện nguy cơ cao';
      }
    }
  }

} catch (e) {
  console.trace(e);
}
