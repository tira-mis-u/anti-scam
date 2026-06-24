// Fetch HTML for RN — uses react-native's fetch (polyfilled globally)
export const fetchHtml = async (urlString, fetchImpl = global.fetch, timeoutMs = 15000) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(urlString, { signal: controller.signal, redirect: 'follow' });
    clearTimeout(timer);
    if (!res.ok) return null;
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    if (!ct.includes('text/html') && !ct.includes('application/xhtml') && !ct.includes('text/plain')) return null;
    return await res.text();
  } catch (err) {
    clearTimeout(timer);
    console.warn('[fetchHtml]', urlString, err.message);
    return null;
  }
};
