export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    if (req.method === 'OPTIONS') { res.status(200).end(); return; }

    const { action, email, domain } = req.query;

    if (action === 'verify') {
        if (!email) return res.status(400).json({ error: 'Email parameter required' });
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) return res.status(400).json({ error: 'Invalid email format' });

        try {
            const dom = email.split('@')[1];
            const mxResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(dom)}&type=MX`);
            const mxData = await mxResp.json();
            const mxRecords = (mxData.Answer || []).filter(a => a.type === 15);

            const aResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(dom)}&type=A`);
            const aData = await aResp.json();
            const aRecords = (aData.Answer || []).filter(a => a.type === 1);

            const txtResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(dom)}&type=TXT`);
            const txtData = await txtResp.json();
            const txtRecords = (txtData.Answer || []).filter(a => a.type === 16);
            const spfRecord = txtRecords.find(r => (r.data || '').toLowerCase().includes('v=spf1'));

            const domainExists = aRecords.length > 0 || mxRecords.length > 0;
            const mxFound = mxRecords.length > 0;

            let score = 0;
            if (emailRegex.test(email)) score += 30;
            if (domainExists) score += 25;
            if (mxFound) score += 30;
            if (spfRecord) score += 15;

            return res.status(200).json({
                service: 'EMAIL_VERIFY', email,
                data: {
                    format_valid: emailRegex.test(email),
                    domain: dom, domain_exists: domainExists, mx_found: mxFound,
                    mx_records: mxRecords.map(r => r.data).slice(0, 5),
                    has_spf: !!spfRecord, spf_record: spfRecord ? spfRecord.data : 'Not found',
                    ip_addresses: aRecords.map(r => r.data).slice(0, 5),
                    deliverability_score: score,
                    verdict: score >= 85 ? 'Probablemente válido ✅' : score >= 50 ? 'Puede existir ⚠️' : 'Riesgo alto de no existir ❌'
                },
                timestamp: new Date().toISOString(), success: true
            });
        } catch (error) {
            return res.status(500).json({ error: 'Failed to verify email', details: error.message });
        }
    } 
    else if (action === 'spfdkim') {
        if (!domain) return res.status(400).json({ error: 'Domain parameter required' });
        try {
            const spfResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`);
            const spfData = await spfResp.json();
            const txtRecords = (spfData.Answer || []).filter(a => a.type === 16);
            const spfRecord = txtRecords.find(r => (r.data || '').toLowerCase().includes('v=spf1'));

            const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim', 's1', 's2'];
            let dkimResult = null; let dkimSelector = null;

            for (const selector of dkimSelectors) {
                const dkimResp = await fetch(`https://dns.google/resolve?name=${selector}._domainkey.${encodeURIComponent(domain)}&type=TXT`);
                const dkimData = await dkimResp.json();
                const dkimRecords = (dkimData.Answer || []).filter(a => a.type === 16);
                if (dkimRecords.length > 0) {
                    dkimResult = dkimRecords[0].data; dkimSelector = selector; break;
                }
            }

            const dmarcResp = await fetch(`https://dns.google/resolve?name=_dmarc.${encodeURIComponent(domain)}&type=TXT`);
            const dmarcData = await dmarcResp.json();
            const dmarcRecords = (dmarcData.Answer || []).filter(a => a.type === 16);
            const dmarcRecord = dmarcRecords.find(r => (r.data || '').toLowerCase().includes('v=dmarc'));

            let dmarcPolicy = 'Not set';
            if (dmarcRecord) {
                const pMatch = dmarcRecord.data.match(/p=(\w+)/i);
                if (pMatch) dmarcPolicy = pMatch[1];
            }

            let score = 0; const checks = [];
            if (spfRecord) { score += 3; checks.push('SPF: ✅ válido'); } else { checks.push('SPF: ❌ no encontrado'); }
            if (dkimResult) { score += 4; checks.push(`DKIM: ✅ selector "${dkimSelector}"`); } else { checks.push('DKIM: ❌ no encontrado (con selectores comunes)'); }
            if (dmarcRecord) { score += 3; checks.push(`DMARC: ✅ policy=${dmarcPolicy}`); } else { checks.push('DMARC: ❌ no encontrado'); }

            const grade = score >= 9 ? 'A+' : score >= 7 ? 'A' : score >= 5 ? 'B' : score >= 3 ? 'C' : 'F';

            return res.status(200).json({
                service: 'SPF_DKIM_CHECK', domain,
                data: {
                    spf: spfRecord ? spfRecord.data : 'Not found', spf_valid: !!spfRecord,
                    dkim: dkimResult || 'Not found', dkim_valid: !!dkimResult, dkim_selector: dkimSelector || 'N/A',
                    dmarc: dmarcRecord ? dmarcRecord.data : 'Not found', dmarc_valid: !!dmarcRecord, dmarc_policy: dmarcPolicy,
                    grade, checks
                },
                timestamp: new Date().toISOString(), success: true
            });
        } catch (error) {
            return res.status(500).json({ error: 'Failed to check email authentication', details: error.message });
        }
    }

    return res.status(400).json({ error: 'Invalid action parameter' });
}
