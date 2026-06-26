const tls = require('tls');
const dns = require('dns').promises;
const axios = require('axios');

const withTimeout = (promise, ms, fallback) => {
  let timer;
  return Promise.race([
    promise,
    new Promise(resolve => { timer = setTimeout(() => resolve(fallback), ms); })
  ]).finally(() => clearTimeout(timer));
};

/**
 * Lấy chứng chỉ số (SSL/TLS Certificate) của một tên miền.
 */
async function getCertificateInfo(domain, ip) {
  return new Promise((resolve) => {
    let resolved = false;
    // Dùng IP nếu có để tránh kẹt ở bước phân giải DNS của tls.connect
    const targetHost = ip || domain;
    const socket = tls.connect(443, targetHost, { servername: domain, rejectUnauthorized: false }, () => {
      if (resolved) return;
      resolved = true;
      try {
        const cert = socket.getPeerCertificate(true);
        socket.destroy();
        if (!cert || !Object.keys(cert).length) {
          return resolve({ status: 'no_cert' });
        }
        
        resolve({
          status: 'success',
          subject: cert.subject,
          issuer: cert.issuer,
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          san: cert.subjectaltname,
          organization: cert.subject?.O || null,
        });
      } catch (err) {
        resolve({ status: 'error', message: err.message });
      }
    });

    socket.on('error', (err) => {
      if (!resolved) {
        resolved = true;
        resolve({ status: 'error', message: err.message });
      }
      socket.destroy();
    });

    socket.setTimeout(2500, () => {
      if (!resolved) {
        resolved = true;
        resolve({ status: 'timeout' });
      }
      socket.destroy();
    });
  });
}

/**
 * Lấy Reverse DNS (PTR record) của một IP
 */
async function getReverseDns(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    return hostnames;
  } catch (err) {
    return [];
  }
}

/**
 * Lấy thông tin ASN & Organization thông qua API công khai (ip-api.com).
 */
async function getAsnInfo(ip) {
  try {
    const res = await axios.get(`http://ip-api.com/json/${ip}?fields=isp,org,as,asname`, { timeout: 2000 });
    if (res.data && res.data.as) {
      return {
        asn: res.data.as.split(' ')[0], // e.g., "AS15169"
        isp: res.data.isp,
        org: res.data.org,
        asname: res.data.asname
      };
    }
    return null;
  } catch (err) {
    return null;
  }
}

/**
 * Quét toàn bộ Identity Profile
 */
async function scanIdentityProfile(domain, ip) {
  const profile = {
    certificate: null,
    ptr: [],
    asn: null
  };

  const tasks = [];
  // Bọc thêm timeout cứng để chống kẹt ở mức syscall
  tasks.push(withTimeout(getCertificateInfo(domain, ip), 3000, { status: 'timeout' }).then(res => profile.certificate = res));
  
  if (ip) {
    tasks.push(withTimeout(getReverseDns(ip), 2000, []).then(res => profile.ptr = res));
    tasks.push(withTimeout(getAsnInfo(ip), 3000, null).then(res => profile.asn = res));
  }

  await Promise.allSettled(tasks);
  return profile;
}

module.exports = { scanIdentityProfile, getCertificateInfo, getReverseDns, getAsnInfo };
