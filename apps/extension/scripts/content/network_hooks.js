// Runs in the page's MAIN world — network monitoring hooks
// Tách riêng từ features.js để tránh vi phạm CSP khi inject inline script
(function () {
  if (window.__antiscamNetHookInstalled) return;
  window.__antiscamNetHookInstalled = true;

  var host = location.hostname.replace(/^www\./, '');

  var send = function (host2, upload) {
    try {
      window.dispatchEvent(new CustomEvent('__antiscam_net', {
        detail: { host: host2, upload: upload }
      }));
    } catch (e) {}
  };

  // ── fetch hook ──
  try {
    var _fetch = window.fetch;
    if (_fetch && !_fetch.__antiscamWrapped) {
      window.fetch = function (input, opts) {
        try {
          var u = typeof input === 'string' ? input : (input && input.url);
          if (u) {
            var h = new URL(u, location.href).hostname.replace(/^www\./, '');
            if (h && h !== host) {
              var up = opts && opts.method && /post|put|patch/i.test(opts.method);
              if (opts && opts.body) up = true;
              send(h, !!up);
            }
          }
        } catch (e) {}
        return _fetch.apply(this, arguments);
      };
      window.fetch.__antiscamWrapped = true;
    }
  } catch (e) {}

  // ── XMLHttpRequest hook ──
  try {
    var _open = XMLHttpRequest.prototype.open;
    var _send = XMLHttpRequest.prototype.send;
    if (!_open.__antiscamWrapped) {
      XMLHttpRequest.prototype.open = function (m, u) {
        this.__ascm_m = m;
        this.__ascm_url = u;
        return _open.apply(this, arguments);
      };
      XMLHttpRequest.prototype.open.__antiscamWrapped = true;
    }
    if (!_send.__antiscamWrapped) {
      XMLHttpRequest.prototype.send = function (body) {
        try {
          if (this.__ascm_url) {
            var h = new URL(this.__ascm_url, location.href).hostname.replace(/^www\./, '');
            if (h && h !== host) send(h, !!body || /post|put|patch/i.test(this.__ascm_m || ''));
          }
        } catch (e) {}
        return _send.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send.__antiscamWrapped = true;
    }
  } catch (e) {}

  // ── sendBeacon hook ──
  try {
    if (navigator.sendBeacon && !navigator.sendBeacon.__antiscamWrapped) {
      var _beacon = navigator.sendBeacon.bind(navigator);
      navigator.sendBeacon = function (url) {
        try {
          var h = new URL(url, location.href).hostname.replace(/^www\./, '');
          if (h && h !== host) send(h, true);
        } catch (e) {}
        return _beacon.apply(navigator, arguments);
      };
      navigator.sendBeacon.__antiscamWrapped = true;
    }
  } catch (e) {}

  // ── WebSocket hook ──
  try {
    var _WS = window.WebSocket;
    if (_WS && !_WS.__antiscamWrapped) {
      var OrigWS = _WS;
      var WrappedWS = function (url, protocols) {
        try {
          var h = new URL(url, location.href).hostname.replace(/^www\./, '');
          if (h && h !== host) send(h, false);
        } catch (e) {}
        return protocols !== undefined
          ? new OrigWS(url, protocols)
          : new OrigWS(url);
      };
      WrappedWS.prototype = OrigWS.prototype;
      WrappedWS.__antiscamWrapped = true;
      try { Object.setPrototypeOf(WrappedWS, OrigWS); } catch (_) {}
      if (OrigWS.CONNECTING != null) WrappedWS.CONNECTING = OrigWS.CONNECTING;
      if (OrigWS.OPEN != null) WrappedWS.OPEN = OrigWS.OPEN;
      if (OrigWS.CLOSING != null) WrappedWS.CLOSING = OrigWS.CLOSING;
      if (OrigWS.CLOSED != null) WrappedWS.CLOSED = OrigWS.CLOSED;
      window.WebSocket = WrappedWS;
    }
  } catch (e) {}
})();
