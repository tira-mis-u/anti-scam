/*global chrome*/
/*global $*/

// MV3: Không dùng chrome.extension.getBackgroundPage() nữa
// Thay bằng chrome.runtime.sendMessage để lấy state từ service worker

const colors = {
  '-1': '#28a745',
  '0': '#ffeb3c',
  '1': '#cc0000'
};

[...document.getElementsByClassName('collapsible')].forEach((el) => {
  el.addEventListener('click', function () {
    this.classList.toggle('active');
    const content = this.nextElementSibling;
    if (content.style.maxHeight) {
      content.style.maxHeight = null;
    } else {
      content.style.maxHeight = `${content.scrollHeight}px`;
    }
  });
});

chrome.tabs.query({currentWindow: true, active: true}, ([tab,]) => {
  const tabId = tab.id;
  const url = new URL(tab.url);
  const domain = url.hostname;

  // Display nothing if protocol is neither http or https
  if (!['https:', 'http:'].includes(url.protocol)) {
    $('#pluginBody').hide();
    $('#domain_url').text(domain);
    return;
  }

  // MV3: Lấy state từ service worker qua message
  chrome.runtime.sendMessage({type: 'GET_STATE'}, (background) => {
    if (!background) {
      $('#domain_url').text(domain);
      return;
    }

    if (background.isWhiteList[tabId] == domain) {
      $('#pluginBody').hide();
      $('#isSafe').show();
      $('#isSafe .site-url').text(domain);

      // MV3: chrome.action thay cho chrome.browserAction
      chrome.action.setIcon({
        path: '../assets/cldvn128.png',
        tabId
      });

    } else if(background.isBlocked[tabId] == domain){
      $('#pluginBody').hide();
      $('#isPhishing').show();
      $('#isPhishing .site-url').text(background.isBlocked[tabId]);

      chrome.action.setIcon({
        path: '../assets/cldvn_red.png',
        tabId
      });
    } else {
      const result = background.results[tabId];
      const isPhish = background.isPhish[tabId];
      const legitimatePercent = background.legitimatePercents[tabId];

      for (const key in result) {
        const newFeature = document.createElement('li');
        newFeature.textContent = key;
        newFeature.style.backgroundColor = colors[result[key]];
        const featureList = document.getElementById('features');
        featureList.appendChild(newFeature);
      }

      const phishingMessage = isPhish ? 'Website này có thể không an toàn.' : 'Website này có thể an toàn.';

      const site_score = document.getElementById('site_score');
      const percentage_content = document.getElementById('percentage_content');
      const site_msg = document.getElementById('site_msg');
      percentage_content.classList.add(`p${parseInt(legitimatePercent)}`);

      if (isPhish) {
        percentage_content.classList.add('orange');
        site_score.classList.add('warning');
        site_msg.classList.add('warning');
      }
      else {
        site_score.classList.add('safe');
        site_msg.classList.add('safe');
      }

      const percentage  = parseInt(legitimatePercent);
      $('#site_msg').text(isNaN(percentage) ? '...' : phishingMessage);
      $('#site_score').text(isNaN(percentage) ? '...' : `${parseInt(legitimatePercent) - 1}%`);
      $('#domain_url').text(domain);
    }
  });
});
