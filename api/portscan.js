// Port Scanner — uses Shodan InternetDB (free, no key required)
// InternetDB provides open ports, vulns, hostnames for any IP
export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    if (req.method === 'OPTIONS') { res.status(200).end(); return; }

    const { target } = req.query;
    if (!target) return res.status(400).json({ error: 'Target (IP) parameter required' });

    try {
        // First, resolve domain to IP if necessary
        let ip = target;
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;

        if (!ipRegex.test(target)) {
            // It's a domain — resolve via DNS
            const dnsResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(target)}&type=A`);
            const dnsData = await dnsResp.json();
            if (dnsData.Answer && dnsData.Answer.length > 0) {
                ip = dnsData.Answer.find(a => a.type === 1)?.data || target;
            } else {
                return res.status(400).json({ error: `Cannot resolve domain ${target} to IP`, code: 'DNS_RESOLUTION_FAILED' });
            }
        }

        // Use Shodan InternetDB — completely free, no API key needed
        const shodanResp = await fetch(`https://internetdb.shodan.io/${ip}`, { method: 'GET' });

        if (!shodanResp.ok) {
            return res.status(200).json({
                service: 'PORT_SCAN',
                target,
                ip,
                data: { ports: [], vulns: [], hostnames: [], cpes: [], note: 'No data available for this IP in Shodan InternetDB' },
                timestamp: new Date().toISOString(),
                success: true
            });
        }

        const shodanData = await shodanResp.json();

        return res.status(200).json({
            service: 'PORT_SCAN',
            target,
            ip,
            data: {
                ports: (shodanData.ports || []).map(p => `${p}/tcp`),
                vulns: shodanData.vulns || [],
                hostnames: shodanData.hostnames || [],
                cpes: shodanData.cpes || [],
                tags: shodanData.tags || []
            },
            timestamp: new Date().toISOString(),
            success: true
        });
    } catch (error) {
        console.error('Port Scan Error:', error);
        return res.status(500).json({ error: 'Failed to scan ports', details: error.message });
    }
}
