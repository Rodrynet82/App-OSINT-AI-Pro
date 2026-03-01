export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter required', code: 'MISSING_DOMAIN' });
  }

  // Validar dominio
  const domainRegex = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i;
  if (!domainRegex.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format', code: 'INVALID_DOMAIN' });
  }

  try {
    const apiKey = process.env.WHOIS_API_KEY || 'demo';
    
    const response = await fetch(
      `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${encodeURIComponent(domain)}&outputFormat=JSON&slFormat=1`,
      {
        method: 'GET',
        timeout: 10000
      }
    );

    if (!response.ok) {
      throw new Error(`WHOIS API error: ${response.status}`);
    }

    const data = await response.json();

    if (data.WhoisRecord) {
      return res.status(200).json({
        service: 'WHOIS',
        domain,
        data: {
          registrar: data.WhoisRecord.registrarName || 'N/A',
          registrationDate: data.WhoisRecord.createdDate || 'N/A',
          expirationDate: data.WhoisRecord.expiresDate || 'N/A',
          updatedDate: data.WhoisRecord.updatedDate || 'N/A',
          nameServers: data.WhoisRecord.nameServers || [],
          registrantName: data.WhoisRecord.registrantName || 'N/A',
          registrantEmail: data.WhoisRecord.registrantEmail || 'N/A',
          status: data.WhoisRecord.status || 'active',
          tld: data.WhoisRecord.tld || 'N/A'
        },
        timestamp: new Date().toISOString(),
        success: true
      });
    } else {
      return res.status(404).json({
        error: 'Domain not found',
        code: 'DOMAIN_NOT_FOUND',
        domain
      });
    }
  } catch (error) {
    console.error('WHOIS Error:', error);
    return res.status(500).json({
      error: 'Failed to fetch WHOIS data',
      code: 'API_ERROR',
      details: error.message
    });
  }
}
