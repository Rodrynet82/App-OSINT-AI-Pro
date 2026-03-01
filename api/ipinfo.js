export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  const { ip } = req.query;

  if (!ip) {
    return res.status(400).json({ error: 'IP parameter required' });
  }

  // Validar IP
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i;
  if (!ipRegex.test(ip)) {
    return res.status(400).json({ error: 'Invalid IP format' });
  }

  try {
    const token = process.env.IPINFO_TOKEN || 'demo';
    
    const response = await fetch(
      `https://ipinfo.io/${ip}?token=${token}`,
      { method: 'GET' }
    );

    const data = await response.json();

    return res.status(200).json({
      service: 'IP_GEOLOCATION',
      ip,
      data: {
        country: data.country || 'N/A',
        region: data.region || 'N/A',
        city: data.city || 'N/A',
        timezone: data.timezone || 'N/A',
        latitude: data.loc ? data.loc.split(',')[0] : 'N/A',
        longitude: data.loc ? data.loc.split(',')[1] : 'N/A',
        isp: data.org || 'N/A',
        asn: data.asn || 'N/A',
        hostname: data.hostname || 'N/A',
        privacy: data.privacy || {}
      },
      timestamp: new Date().toISOString(),
      success: true
    });
  } catch (error) {
    console.error('IPInfo Error:', error);
    return res.status(500).json({
      error: 'Failed to fetch IP information',
      details: error.message
    });
  }
}
