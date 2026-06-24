// ============================================================
// @anti-scam/core — URL utilities
// ============================================================
import { MULTI_PART_TLDS, BRANDS, TRUSTED_HOSTS } from './constants.js';

export const getRegistrableDomain = (host) => {
  if (!host) return '';
  let h = host.toLowerCase().replace(/^www\./, '');
  const psl = typeof self !== 'undefined' && self.psl ? self.psl : (typeof window !== 'undefined' && window.psl ? window.psl : null);
  if (psl && typeof psl.parse === 'function') {
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

export const getDomain = (url) => {
  try { return new URL(url).hostname; } catch (_) {
    const m = url.match(/^https?:\/\/([^/?#]+)(?:[/?#]|$)/i);
    return (m && m[1].split(':')[0]) || '';
  }
};

export const createUrlObject = (url) => {
  try { return new URL(url); } catch { return null; }
};

export const normalizeUrl = (raw) => {
  let u = (raw || '').trim();
  if (!u) return '';
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  try { return new URL(u).href; } catch { return ''; }
};

export const isTrustedHost = (host) => {
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

export const isOfficialBrandDomain = (host) => {
  if (!host) return null;
  const h = host.toLowerCase().replace(/^www\./, '');
  for (const b of BRANDS) {
    if (b.official.some(od => h === od || h.endsWith('.' + od))) return b;
  }
  return null;
};

export const normalizeDomainAge = (domainAgeInput) => {
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