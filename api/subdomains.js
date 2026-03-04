// Subdomain Finder — uses crt.sh Certificate Transparency logs (free, no API key)
export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    if (req.method === 'OPTIONS') { res.status(200).end(); return; }

    const { domain } = req.query;
    if (!domain) return res.status(400).json({ error: 'Domain parameter required' });

    try {
        // crt.sh with wildcard search for subdomains
        const crtResp = await fetch(
            `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
            { method: 'GET', headers: { 'User-Agent': 'OSINTAIPro/3.0' } }
        );

        let subdomains = [];
        if (crtResp.ok) {
            const crtData = await crtResp.json();
            const uniqueSubs = new Set();

            crtData.forEach(cert => {
                const names = (cert.name_value || '').split('\n');
                names.forEach(name => {
                    const clean = name.trim().toLowerCase().replace(/^\*\./, '');
                    if (clean && clean.endsWith(domain.toLowerCase()) && clean !== domain.toLowerCase()) {
                        uniqueSubs.add(clean);
                    }
                });
            });

            subdomains = [...uniqueSubs].sort().slice(0, 100);
        }

        return res.status(200).json({
            service: 'SUBDOMAIN_FINDER',
            domain,
            data: {
                found: subdomains.length,
                subdomains,
                source: 'Certificate Transparency (crt.sh)'
            },
            timestamp: new Date().toISOString(),
            success: true
        });
    } catch (error) {
        console.error('Subdomain Finder Error:', error);
        return res.status(500).json({ error: 'Failed to find subdomains', details: error.message });
    }
}
