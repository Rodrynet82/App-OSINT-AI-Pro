// SPF + DKIM + DMARC Checker — uses Google DNS to check email authentication records (free, no key needed)
export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    if (req.method === 'OPTIONS') { res.status(200).end(); return; }

    const { domain } = req.query;
    if (!domain) return res.status(400).json({ error: 'Domain parameter required' });

    try {
        // 1. SPF Record (TXT record on domain)
        const spfResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`);
        const spfData = await spfResp.json();
        const txtRecords = (spfData.Answer || []).filter(a => a.type === 16);
        const spfRecord = txtRecords.find(r => (r.data || '').toLowerCase().includes('v=spf1'));

        // 2. DKIM — check common selectors
        const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim', 's1', 's2'];
        let dkimResult = null;
        let dkimSelector = null;

        for (const selector of dkimSelectors) {
            const dkimResp = await fetch(`https://dns.google/resolve?name=${selector}._domainkey.${encodeURIComponent(domain)}&type=TXT`);
            const dkimData = await dkimResp.json();
            const dkimRecords = (dkimData.Answer || []).filter(a => a.type === 16);
            if (dkimRecords.length > 0) {
                dkimResult = dkimRecords[0].data;
                dkimSelector = selector;
                break;
            }
        }

        // 3. DMARC Record
        const dmarcResp = await fetch(`https://dns.google/resolve?name=_dmarc.${encodeURIComponent(domain)}&type=TXT`);
        const dmarcData = await dmarcResp.json();
        const dmarcRecords = (dmarcData.Answer || []).filter(a => a.type === 16);
        const dmarcRecord = dmarcRecords.find(r => (r.data || '').toLowerCase().includes('v=dmarc'));

        // Parse DMARC policy
        let dmarcPolicy = 'Not set';
        if (dmarcRecord) {
            const pMatch = dmarcRecord.data.match(/p=(\w+)/i);
            if (pMatch) dmarcPolicy = pMatch[1];
        }

        // Score
        let score = 0;
        const checks = [];
        if (spfRecord) { score += 3; checks.push('SPF: ✅ válido'); } else { checks.push('SPF: ❌ no encontrado'); }
        if (dkimResult) { score += 4; checks.push(`DKIM: ✅ selector "${dkimSelector}"`); } else { checks.push('DKIM: ❌ no encontrado (con selectores comunes)'); }
        if (dmarcRecord) { score += 3; checks.push(`DMARC: ✅ policy=${dmarcPolicy}`); } else { checks.push('DMARC: ❌ no encontrado'); }

        const grade = score >= 9 ? 'A+' : score >= 7 ? 'A' : score >= 5 ? 'B' : score >= 3 ? 'C' : 'F';

        return res.status(200).json({
            service: 'SPF_DKIM_CHECK',
            domain,
            data: {
                spf: spfRecord ? spfRecord.data : 'Not found',
                spf_valid: !!spfRecord,
                dkim: dkimResult || 'Not found (checked common selectors)',
                dkim_valid: !!dkimResult,
                dkim_selector: dkimSelector || 'N/A',
                dmarc: dmarcRecord ? dmarcRecord.data : 'Not found',
                dmarc_valid: !!dmarcRecord,
                dmarc_policy: dmarcPolicy,
                grade,
                checks
            },
            timestamp: new Date().toISOString(),
            success: true
        });
    } catch (error) {
        console.error('SPF/DKIM Error:', error);
        return res.status(500).json({ error: 'Failed to check email authentication', details: error.message });
    }
}
