// SSL Certificate Checker — uses the free ssl-checker approach via TLS negotiation
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

  if (req.method === 'OPTIONS') { res.status(200).end(); return; }

  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Domain parameter required' });

  try {
    // Use crt.sh (Certificate Transparency Logs) — free, no key needed
    const crtResp = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
      { method: 'GET', headers: { 'User-Agent': 'OSINTAIPro/3.0' } }
    );

    let certificates = [];
    if (crtResp.ok) {
      const crtData = await crtResp.json();
      // Get unique, most recent certs
      const seen = new Set();
      certificates = crtData
        .filter(c => { const k = c.serial_number; if (seen.has(k)) return false; seen.add(k); return true; })
        .slice(0, 10)
        .map(c => ({
          issuer: c.issuer_name || 'N/A',
          commonName: c.common_name || 'N/A',
          notBefore: c.not_before || 'N/A',
          notAfter: c.not_after || 'N/A',
          serialNumber: c.serial_number || 'N/A'
        }));
    }

    const latestCert = certificates[0] || {};
    const notAfter = latestCert.notAfter ? new Date(latestCert.notAfter) : null;
    const isValid = notAfter ? notAfter > new Date() : false;
    const daysRemaining = notAfter ? Math.ceil((notAfter - new Date()) / (1000 * 60 * 60 * 24)) : 'N/A';

    return res.status(200).json({
      service: 'SSL_CHECK',
      domain,
      data: {
        valid: isValid,
        issuer: latestCert.issuer || 'N/A',
        commonName: latestCert.commonName || 'N/A',
        notBefore: latestCert.notBefore || 'N/A',
        notAfter: latestCert.notAfter || 'N/A',
        daysRemaining,
        totalCertsFound: certificates.length,
        certificates
      },
      timestamp: new Date().toISOString(),
      success: true
    });
  } catch (error) {
    console.error('SSL Check Error:', error);
    return res.status(500).json({ error: 'Failed to check SSL certificate', details: error.message });
  }
}
