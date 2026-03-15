export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    if (req.method === 'OPTIONS') { res.status(200).end(); return; }

    const { action, domain, url } = req.query;

    if (action === 'ssl') {
        if (!domain) return res.status(400).json({ error: 'Domain parameter required' });
        try {
            const crtResp = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, { method: 'GET', headers: { 'User-Agent': 'OSINTAIPro/3.0' } });
            let certificates = [];
            if (crtResp.ok) {
                const crtData = await crtResp.json();
                const seen = new Set();
                certificates = crtData.filter(c => { const k = c.serial_number; if (seen.has(k)) return false; seen.add(k); return true; })
                    .slice(0, 10).map(c => ({
                        issuer: c.issuer_name || 'N/A', commonName: c.common_name || 'N/A',
                        notBefore: c.not_before || 'N/A', notAfter: c.not_after || 'N/A', serialNumber: c.serial_number || 'N/A'
                    }));
            }
            const latestCert = certificates[0] || {};
            const notAfter = latestCert.notAfter ? new Date(latestCert.notAfter) : null;
            const isValid = notAfter ? notAfter > new Date() : false;
            const daysRemaining = notAfter ? Math.ceil((notAfter - new Date()) / (1000 * 60 * 60 * 24)) : 'N/A';

            return res.status(200).json({
                service: 'SSL_CHECK', domain,
                data: { valid: isValid, issuer: latestCert.issuer || 'N/A', commonName: latestCert.commonName || 'N/A', notBefore: latestCert.notBefore || 'N/A', notAfter: latestCert.notAfter || 'N/A', daysRemaining, totalCertsFound: certificates.length, certificates },
                timestamp: new Date().toISOString(), success: true
            });
        } catch (error) {
            return res.status(500).json({ error: 'Failed to check SSL certificate', details: error.message });
        }
    } 
    else if (action === 'headers') {
        if (!url) return res.status(400).json({ error: 'URL parameter required' });
        let targetUrl = url;
        if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 10000);
            const response = await fetch(targetUrl, { method: 'HEAD', redirect: 'follow', signal: controller.signal, headers: { 'User-Agent': 'OSINTAIPro/3.0 SecurityScanner' } });
            clearTimeout(timeout);

            const headers = {};
            response.headers.forEach((value, key) => { headers[key] = value; });

            const securityHeaders = {
                'Strict-Transport-Security': headers['strict-transport-security'] || 'MISSING ⚠️',
                'Content-Security-Policy': headers['content-security-policy'] ? 'Present ✅' : 'MISSING ⚠️',
                'X-Frame-Options': headers['x-frame-options'] || 'MISSING ⚠️',
                'X-Content-Type-Options': headers['x-content-type-options'] || 'MISSING ⚠️',
                'X-XSS-Protection': headers['x-xss-protection'] || 'MISSING ⚠️',
                'Referrer-Policy': headers['referrer-policy'] || 'MISSING ⚠️',
                'Permissions-Policy': headers['permissions-policy'] ? 'Present ✅' : 'MISSING ⚠️'
            };

            const totalHeaders = Object.keys(securityHeaders).length;
            const presentHeaders = Object.values(securityHeaders).filter(v => !v.includes('MISSING')).length;
            const securityScore = Math.round((presentHeaders / totalHeaders) * 10);

            return res.status(200).json({
                service: 'HTTP_HEADERS', url: targetUrl,
                data: { statusCode: response.status, statusText: response.statusText, server: headers['server'] || 'Not disclosed', poweredBy: headers['x-powered-by'] || 'Not disclosed', contentType: headers['content-type'] || 'N/A', securityHeaders, securityScore: `${securityScore}/10`, allHeaders: headers },
                timestamp: new Date().toISOString(), success: true
            });
        } catch (error) {
            return res.status(500).json({ error: 'Failed to fetch HTTP headers', details: error.message });
        }
    }

    return res.status(400).json({ error: 'Invalid action parameter' });
}
