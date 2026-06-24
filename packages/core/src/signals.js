// ============================================================
// @anti-scam/core — HTML signal parser (pure, no DOM/Chrome API)
// Extracted from background.js parseHtmlSignals()
// ============================================================
import { BRAND_KEYS_SCAN, BRAND_OFFICIAL_SCAN, VN_SCAM_PATTERNS } from './constants.js';
import { getRegistrableDomain, isTrustedHost, createUrlObject } from './url.js';

const ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;

const _normalizeText = (str) => {
  try { return (str||'').toString().normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase(); } catch(_) { return (str||'').toString().toLowerCase(); }
};

/**
 * Parse HTML signals — same format as features.js collect() but runs on fetched HTML string
 * Does NOT use document/window/DOM of any tab
 */
export const parseHtmlSignals = (urlString, html) => {
  const urlObj = createUrlObject(urlString);
  if (!urlObj) return { result: {}, dom: { scanned: true, fetchBased: true } };

  const domain = urlObj.hostname;
  const currentOnlyDomain = domain.replace(/^www\./, '');
  const result = {};
  const dom = { scanned: true, fetchBased: true };

  // URL-based ML features
  result['IP Address'] = ipRe.test(currentOnlyDomain) ? '1' : '-1';
  result['URL Length'] = urlString.length > 100 ? '0' : '-1';
  result['Tiny URL'] = (currentOnlyDomain.length < 5 && !ipRe.test(currentOnlyDomain)) ? '0' : '-1';
  result['@ Symbol'] = urlString.includes('@') ? '0' : '-1';
  result['Redirecting using //'] = (urlString.lastIndexOf('//') > 7 && /\/\/[^/]+@/.test(urlString)) ? '0' : '-1';
  result['(-) Prefix/Suffix in domain'] = ((currentOnlyDomain.match(/-/g) || []).length >= 3) ? '0' : '-1';
  result['No. of Sub Domains'] = ((currentOnlyDomain.match(/\./g) || []).length >= 4) ? '0' : '-1';
  result['HTTPS'] = urlObj.protocol === 'https:' ? '-1' : '0';
  result['HTTPS in URL\'s domain part'] = /https/i.test(currentOnlyDomain) ? '0' : '-1';
  result['Favicon'] = '-1';
  result['Port'] = '-1';
  const port = urlObj.port;
  if (port && !['80','443','8080','8000','3000','5000'].includes(port)) result['Port'] = '0';

  if (!html) return { result, dom };

  const maxHtml = html.slice(0, 2_000_000);
  const _stripTags = (s) => (s||'').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();

  // Extract elements via regex
  const allScripts = [...maxHtml.matchAll(/<script[^>]*>/gi)];
  const allScriptsWithSrc = allScripts.filter(m => /\ssrc\s*=/i.test(m[0]));
  const allLinks = [...maxHtml.matchAll(/<link[^>]*>/gi)];
  const allImgs = [...maxHtml.matchAll(/<img[^>]*>/gi)];
  const allAnchors = [...maxHtml.matchAll(/<a[^>]*>([\s\S]*?)<\/a>/gi)];
  const allForms = [...maxHtml.matchAll(/<form[^>]*>([\s\S]*?)<\/form>/gi)];
  const allIframes = [...maxHtml.matchAll(/<iframe[^>]*>/gi)];

  const _extractAttr = (tag, attr) => { const m = tag.match(new RegExp(`\\s${attr}\\s*=\\s*["']([^"']+)["']`, 'i')); return m ? m[1] : null; };
  const _hostOf = (href) => { if (!href || href.startsWith('data:') || href.startsWith('javascript:')) return null; try { return new URL(href, urlString).hostname.replace(/^www\./, ''); } catch { return null; } };
  const _isExternal = (host) => host && host !== currentOnlyDomain && !host.endsWith('.' + currentOnlyDomain) && !isTrustedHost(host);

  // Script & Link ratios
  let extRes = 0, totalRes = 0;
  const countRes = (getSrc) => { for (const m of getSrc) { const src = _extractAttr(m[0], 'src') || _extractAttr(m[0], 'href'); if (!src) continue; totalRes++; const h = _hostOf(src); if (_isExternal(h)) extRes++; } };
  countRes(allScriptsWithSrc); countRes(allLinks);
  const outPct = totalRes === 0 ? 0 : (extRes / totalRes) * 100;
  result['Script & Link'] = outPct > 80 ? '1' : (outPct > 50 ? '0' : '-1');

  // Request URL (image ratio)
  let imgExt = 0, imgTotal = 0;
  for (const m of allImgs) { const src = _extractAttr(m[0], 'src'); if (!src) continue; imgTotal++; if (_isExternal(_hostOf(src))) imgExt++; }
  const imgPct = imgTotal === 0 ? 0 : (imgExt / imgTotal) * 100;
  result['Request URL'] = imgPct > 60 ? '1' : (imgPct > 30 ? '0' : '-1');

  // Anchor analysis
  let aExt = 0, aTotal = 0;
  const pageLinks = [];
  const deceptiveLinks = [];
  for (const m of allAnchors) {
    const fullTag = m[0];
    const href = _extractAttr(fullTag, 'href');
    if (!href) continue;
    let abs = null; try { abs = new URL(href, urlString).href; } catch {}
    if (abs && /^https?:\/\//i.test(abs) && pageLinks.length < 160) pageLinks.push(abs);
    aTotal++;
    const h = _hostOf(href);
    if (_isExternal(h)) aExt++;
    const text = _stripTags(m[1]).toLowerCase();
    const textMatch = text.match(/(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i);
    if (textMatch && abs) {
      const shownHost = textMatch[1].replace(/^www\./, '');
      const hrefHost = _hostOf(abs) || '';
      if (shownHost && hrefHost && shownHost !== hrefHost && !shownHost.endsWith('.' + hrefHost)) {
        deceptiveLinks.push({ text: shownHost, href: hrefHost });
      }
    }
  }
  const aPct = aTotal === 0 ? 0 : (aExt / aTotal) * 100;
  result['Anchor'] = aPct > 75 ? '1' : (aPct > 40 ? '0' : '-1');
  dom.pageLinks = pageLinks.slice(0, 160);
  dom.deceptiveLinks = deceptiveLinks.slice(0, 10);
  dom.deceptiveLinkCount = deceptiveLinks.length;

  // Forms
  let sensitiveFound = false, hijackFound = false, pwField = false, otpField = false,
      cardField = false, bankField = false, hiddenFormFound = false, sensitiveFormCount = 0;
  const sensitiveNames = ['password','passcode','passwd','otp','pin','cvv','cvc','cardnumber','card-number','creditcard','cccd','cmnd','stk','sotk','so-tai-khoan','ngan-hang','internet-banking'];
  for (const m of allForms) {
    const formTag = m[0]; const formContent = m[1] || '';
    const formStyle = _extractAttr(formTag, 'style') || '';
    const hiddenByCss = /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/i.test(formStyle);
    let sensitive = /type\s*=\s*["']password["']/i.test(formContent) || /autocomplete\s*=\s*["']current-password["']/i.test(formContent);
    if (!sensitive) { for (const nm of sensitiveNames) { if (formContent.toLowerCase().includes(nm)) { sensitive = true; break; } } }
    if (sensitive) {
      sensitiveFound = true; sensitiveFormCount++;
      if (/type\s*=\s*["']password["']/i.test(formContent)) pwField = true;
      if (/otp|ma-xac-thuc|maxacthuc/i.test(formContent)) otpField = true;
      if (/card|credit|debit|cvv|so-the|sothe/i.test(formContent)) cardField = true;
      if (/stk|sotk|so-tai-khoan|ngan-hang|internet-banking/i.test(formContent)) bankField = true;
      if (hiddenByCss) hiddenFormFound = true;
      const action = _extractAttr(formTag, 'action') || '';
      if (action.startsWith('http')) { try { const ah = new URL(action, urlString).hostname.replace(/^www\./, ''); if (_isExternal(ah) && !isTrustedHost(ah)) hijackFound = true; } catch {} }
    }
  }
  dom.sensitiveForm = sensitiveFound; dom.formHijack = hijackFound;
  dom.passwordField = pwField; dom.otpField = otpField;
  dom.cardField = cardField; dom.bankAccountField = bankField;
  dom.hiddenForm = hiddenFormFound;
  result['Sensitive Form'] = sensitiveFound ? (cardField || bankField ? '2' : '0') : '-1';
  result['Form Hijacking'] = hijackFound ? '1' : '-1';
  result['Hidden Form'] = hiddenFormFound ? '2' : '-1';

  // SFH / mailto
  result['SFH'] = '-1';
  for (const m of allForms) {
    const action = _extractAttr(m[0], 'action') || '';
    if (!action || action === '' || action === '#') result['SFH'] = '0';
    else if (action.startsWith('http')) { try { const ah = new URL(action, urlString).hostname.replace(/^www\./, ''); if (_isExternal(ah)) result['SFH'] = '1'; } catch {} }
  }
  result['mailto'] = '-1';
  for (const m of allForms) { if ((_extractAttr(m[0], 'action') || '').startsWith('mailto')) { result['mailto'] = '0'; break; } }

  // iFrames
  dom.numIframes = allIframes.length; dom.hiddenIframe = false;
  let iframeRiskScore = 0;
  for (const m of allIframes) {
    const src = _extractAttr(m[0], 'src');
    const srcHost = _hostOf(src);
    const style = _extractAttr(m[0], 'style') || '';
    const w = parseInt(_extractAttr(m[0], 'width') || '0'); const h = parseInt(_extractAttr(m[0], 'height') || '0');
    const isHidden = /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/i.test(style) || (w > 0 && w <= 1) || (h > 0 && h <= 1);
    if (isHidden) { iframeRiskScore += 10; dom.hiddenIframe = true; }
    if (_isExternal(srcHost)) { iframeRiskScore += 15; }
  }
  dom.iframeRiskScore = iframeRiskScore;
  result['iFrames'] = iframeRiskScore >= 40 ? '1' : (iframeRiskScore >= 25 ? '2' : (iframeRiskScore >= 10 ? '0' : '-1'));

  // Brand detection
  const titleMatch = maxHtml.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? titleMatch[1].trim().toLowerCase() : '';
  const descMatch = maxHtml.match(/<meta[^>]+name\s*=\s*["']description["'][^>]+content\s*=\s*["']([^"']+)["']/i);
  const metaDesc = descMatch ? descMatch[1].trim().toLowerCase() : '';
  const h1Match = maxHtml.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i);
  const h1 = h1Match ? _stripTags(h1Match[1]).toLowerCase() : '';

  let brandInContent = false, matchedBrand = null, brandSurfaces = 0;
  for (const [key, name] of BRAND_KEYS_SCAN) {
    if (key.length < 3 && !['fpt','mb'].includes(key)) continue;
    const official = BRAND_OFFICIAL_SCAN[key] || [];
    const isOfficial = official.some(d => currentOnlyDomain === d || currentOnlyDomain.endsWith('.' + d));
    if (isOfficial) continue;
    let count = 0;
    if (title.includes(key)) count++;
    if (metaDesc.includes(key)) count++;
    if (h1.includes(key)) count++;
    if (count > 0) { brandInContent = true; if (count > brandSurfaces) { brandSurfaces = count; matchedBrand = name; } }
  }
  dom.brandInContent = brandInContent; dom.brandSurfaces = brandSurfaces; dom.matchedBrand = matchedBrand;

  // Scam content
  let bodyText = '';
  const bodyMatch = maxHtml.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  bodyText = _normalizeText(bodyMatch ? bodyMatch[1].slice(0, 60000) : maxHtml.slice(0, 60000));
  const scamHits = [];
  for (const p of VN_SCAM_PATTERNS) { if (p.re.test(bodyText)) scamHits.push(p.label); }
  dom.scamContentHits = scamHits; dom.scamContentRisk = scamHits.length;
  result['Scam Content'] = scamHits.length >= 2 ? '2' : (scamHits.length === 1 ? '0' : '-1');
  dom.contentRich = bodyText.length > 200;

  // Meta refresh redirect
  dom.metaRefreshRedirect = false;
  const metaRefresh = maxHtml.match(/<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]+content\s*=\s*["']([^"']+)["']/i);
  if (metaRefresh) {
    const urlPart = metaRefresh[1].match(/url\s*=\s*([^;]+)/i);
    if (urlPart) { try { const target = new URL(urlPart[1].trim().replace(/^['"]|['"]$/g,''), urlString); if (_isExternal(target.hostname.replace(/^www\./,''))) dom.metaRefreshRedirect = true; } catch {} }
  }

  // Obfuscation
  let maxConf = 0, hasObf = false;
  const inlineScripts = [...maxHtml.matchAll(/<script(?![^>]*\ssrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)];
  for (const m of inlineScripts) {
    const code = m[1]; if (!code || code.length < 80) continue;
    let conf = 0;
    const compactCode = code.replace(/\s+/g, '');
    if ((code.match(/\\x[0-9a-fA-F]{2}/g) || []).length > 15 || (code.match(/\\u[0-9a-fA-F]{4}/g) || []).length > 15) conf += 30;
    if (/unescape\s*\(|String\.fromCharCode\s*\(/i.test(code)) conf += 25;
    if (/atob\s*\(/i.test(code)) conf += code.length > 2000 ? 15 : 8;
    if (/eval\s*\(/i.test(code)) conf += conf > 0 ? 25 : 10;
    if (code.length > 1500 && (code.match(/\n/g) || []).length < 4) conf += 20;
    maxConf = Math.max(maxConf, conf);
    if (conf >= 60) hasObf = true;
  }
  dom.obfuscatedScript = hasObf; dom.jsRiskScore = maxConf;
  result['Obfuscated Script'] = hasObf ? '1' : (maxConf >= 40 ? '0' : '-1');
  result['JavaScript Risk'] = maxConf >= 60 ? '1' : (maxConf >= 35 ? '2' : '-1');

  // Dangerous download
  const htmlLower = maxHtml.toLowerCase();
  dom.downloadFile = /\.exe|\.scr|\.bat|\.apk|\.msi|\.dll/i.test(htmlLower) && /download|href/i.test(htmlLower);
  dom.archiveDownload = /\.zip|\.rar|\.7z/i.test(htmlLower) && /download|href/i.test(htmlLower);

  // Favicon
  result['Favicon'] = '-1';
  const faviconLink = maxHtml.match(/<link[^>]+rel\s*=\s*["'][^"']*icon[^"']*["'][^>]+href\s*=\s*["']([^"']+)["']/i);
  if (faviconLink) { const fHost = _hostOf(faviconLink[1]); if (_isExternal(fHost)) result['Favicon'] = '0'; }

  // Counts
  const linkWarnings = aExt;
  const scriptWarnings = extRes;
  const imageWarnings = imgExt;
  const iframeDanger = iframeRiskScore >= 40 ? 1 : 0;
  const iframeWarning = iframeRiskScore > 0 && iframeRiskScore < 40 ? 1 : 0;
  const formDanger = hijackFound ? 1 : 0;
  const formWarning = sensitiveFormCount;

  dom.counts = {
    hiddenIframes: dom.hiddenIframe ? 1 : 0, totalIframes: allIframes.length, iframeRiskScore,
    sensitiveForms: sensitiveFormCount, totalForms: allForms.length,
    externalAnchors: aExt, totalAnchors: aTotal,
    externalScripts: extRes, totalScripts: totalRes,
    externalImages: imgExt, totalImages: imgTotal,
    scamContentHits: scamHits.length, jsRiskScore: maxConf,
    hiddenForms: hiddenFormFound ? 1 : 0,
    suspiciousLinks: 0, deceptiveLinks: deceptiveLinks.length,
    permissionRequests: 0,
    links: { total: aTotal, safe: Math.max(0, aTotal - linkWarnings), warning: linkWarnings, dangerous: 0 },
    scripts: { total: totalRes, safe: Math.max(0, totalRes - scriptWarnings), warning: scriptWarnings, dangerous: 0 },
    images: { total: imgTotal, safe: Math.max(0, imgTotal - imageWarnings), warning: imageWarnings, dangerous: 0 },
    iframes: { total: allIframes.length, safe: Math.max(0, allIframes.length - iframeWarning - iframeDanger), warning: iframeWarning, dangerous: iframeDanger },
    forms: { total: allForms.length, safe: Math.max(0, allForms.length - formWarning - formDanger), warning: formWarning, dangerous: formDanger },
  };

  return { result, dom };
};