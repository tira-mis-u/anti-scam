export const DomainParser = {
  getDomain: (url) => {
    try {
      return new URL(url).hostname;
    } catch (_) {
      const m = url.match(/^https?:\/\/([^/?#]+)/i);
      return (m && m[1].split(':')[0]) || '';
    }
  },

  createUrlObject: (url) => {
    try {
      return new URL(url);
    } catch {
      return null;
    }
  },

  getRegistrable: (domain) => {
    if (typeof getRegistrableDomain !== 'undefined') return getRegistrableDomain(domain);
    if (typeof self !== 'undefined' && self.getRegistrableDomain) return self.getRegistrableDomain(domain);
    let h = (domain || '').toLowerCase().replace(/^www\./, '');
    return h.split('.').slice(-2).join('.');
  }
};
