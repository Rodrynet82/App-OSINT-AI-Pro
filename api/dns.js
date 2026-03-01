export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  const { domain, type = 'A' } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter required' });
  }

  try {
    // Usar Google DNS API (gratis)
    const response = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
      { method: 'GET' }
    );

    const data = await response.json();

    return res.status(200).json({
      service: 'DNS_LOOKUP',
      domain,
      type,
      data: {
        status: data.Status === 0 ? 'success' : 'failed',
        answer: data.Answer || [],
        authority: data.Authority || [],
        additional: data.Additional || [],
        recursionAvailable: data.RecursionAvailable || false,
        recursionDesired: data.RecursionDesired || false
      },
      timestamp: new Date().toISOString(),
      success: true
    });
  } catch (error) {
    console.error('DNS Error:', error);
    return res.status(500).json({
      error: 'Failed to fetch DNS records',
      details: error.message
    });
  }
}
