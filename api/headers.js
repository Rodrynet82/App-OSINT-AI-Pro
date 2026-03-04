// HTTP Headers Analyzer — fetches a URL and returns its response headers + security analysis
export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    if (req.method === 'OPTIONS') { res.status(200).end(); return; }

    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'URL parameter required' });

    let targetUrl = url;
    if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);

        const response = await fetch(targetUrl, {
            method: 'HEAD',
            redirect: 'follow',
            signal: controller.signal,
            headers: { 'User-Agent': 'OSINTAIPro/3.0 SecurityScanner' }
        });
        clearTimeout(timeout);

        const headers = {};
        response.headers.forEach((value, key) => { headers[key] = value; });

        // Security header analysis
        const securityHeaders = {
            'Strict-Transport-Security': headers['strict-transport-security'] || 'MISSING ⚠️',
            'Content-Security-Policy': headers['content-security-policy'] ? 'Present ✅' : 'MISSING ⚠️',
            'X-Frame-Options': headers['x-frame-options'] || 'MISSING ⚠️',
            'X-Content-Type-Options': headers['x-content-type-options'] || 'MISSING ⚠️',
            'X-XSS-Protection': headers['x-xss-protection'] || 'MISSING ⚠️',
            'Referrer-Policy': headers['referrer-policy'] || 'MISSING ⚠️',
            'Permissions-Policy': headers['permissions-policy'] ? 'Present ✅' : 'MISSING ⚠️'
        };

        // Calculate security score
        const totalHeaders = Object.keys(securityHeaders).length;
        const presentHeaders = Object.values(securityHeaders).filter(v => !v.includes('MISSING')).length;
        const securityScore = Math.round((presentHeaders / totalHeaders) * 10);

        return res.status(200).json({
            service: 'HTTP_HEADERS',
            url: targetUrl,
            data: {
                statusCode: response.status,
                statusText: response.statusText,
                server: headers['server'] || 'Not disclosed',
                poweredBy: headers['x-powered-by'] || 'Not disclosed',
                contentType: headers['content-type'] || 'N/A',
                securityHeaders,
                securityScore: `${securityScore}/10`,
                allHeaders: headers
            },
            timestamp: new Date().toISOString(),
            success: true
        });
    } catch (error) {
        console.error('Headers Error:', error);
        return res.status(500).json({ error: 'Failed to fetch HTTP headers', details: error.message });
    }
}
