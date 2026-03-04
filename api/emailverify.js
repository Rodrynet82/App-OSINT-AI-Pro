// Email Verifier — checks format, domain DNS, MX records (no external API key needed)
export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    if (req.method === 'OPTIONS') { res.status(200).end(); return; }

    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email parameter required' });

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    try {
        const domain = email.split('@')[1];

        // Check MX records via Google DNS
        const mxResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`);
        const mxData = await mxResp.json();
        const mxRecords = (mxData.Answer || []).filter(a => a.type === 15);

        // Check A records for the domain
        const aResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`);
        const aData = await aResp.json();
        const aRecords = (aData.Answer || []).filter(a => a.type === 1);

        // Check SPF record
        const txtResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`);
        const txtData = await txtResp.json();
        const txtRecords = (txtData.Answer || []).filter(a => a.type === 16);
        const spfRecord = txtRecords.find(r => (r.data || '').toLowerCase().includes('v=spf1'));

        const domainExists = aRecords.length > 0 || mxRecords.length > 0;
        const mxFound = mxRecords.length > 0;

        // Build a score based on these checks
        let score = 0;
        if (emailRegex.test(email)) score += 30;    // valid format
        if (domainExists) score += 25;               // domain resolves
        if (mxFound) score += 30;                    // has MX records
        if (spfRecord) score += 15;                  // has SPF

        return res.status(200).json({
            service: 'EMAIL_VERIFY',
            email,
            data: {
                format_valid: emailRegex.test(email),
                domain,
                domain_exists: domainExists,
                mx_found: mxFound,
                mx_records: mxRecords.map(r => r.data).slice(0, 5),
                has_spf: !!spfRecord,
                spf_record: spfRecord ? spfRecord.data : 'Not found',
                ip_addresses: aRecords.map(r => r.data).slice(0, 5),
                deliverability_score: score,
                verdict: score >= 85 ? 'Probablemente válido ✅' : score >= 50 ? 'Puede existir ⚠️' : 'Riesgo alto de no existir ❌'
            },
            timestamp: new Date().toISOString(),
            success: true
        });
    } catch (error) {
        console.error('Email Verify Error:', error);
        return res.status(500).json({ error: 'Failed to verify email', details: error.message });
    }
}
