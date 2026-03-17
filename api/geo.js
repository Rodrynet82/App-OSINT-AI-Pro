import { validateApiKey } from './_utils/validation.js';

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, x-antigravity-key');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // Pre-flight check / validation
  const clientKey = req.headers['x-antigravity-key'];
  const validation = validateApiKey(clientKey);

  if (!validation.isValid) {
    return res.status(401).json({
      success: false,
      error: 'Acceso denegado. Clave Antigravity inválida o ausente.',
      code: 'UNAUTHORIZED'
    });
  }

  const { action, ip, location, lat, lon, radius = 5 } = req.query;

  // ACTION: IP GEOLOCATION (ipinfo)
  if (action === 'ipinfo') {
    if (!ip) return res.status(400).json({ error: 'IP parameter required' });
    try {
      const token = process.env.IPINFO_TOKEN || 'demo';
      const response = await fetch(`https://ipinfo.io/${ip}?token=${token}`);
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
          hostname: data.hostname || 'N/A'
        },
        success: true
      });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // ACTION: GEOFENCE SEARCH (shodan)
  if (action === 'geosearch') {
    const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
    if (!SHODAN_API_KEY) return res.status(500).json({ error: 'Shodan API Key missing' });

    let query = '';
    if (lat && lon) query = `geo:${lat},${lon},${radius}`;
    else if (location) query = location.includes(',') ? `location:"${location}"` : `city:"${location}"`;
    else return res.status(400).json({ error: 'Location or Coords required' });

    try {
      const apiUrl = `https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=${encodeURIComponent(query)}&facets=city,org,port`;
      const response = await fetch(apiUrl);
      const data = await response.json();
      const results = (data.matches || []).map(item => ({
        ip: item.ip_str,
        port: item.port,
        org: item.org || 'N/A',
        city: item.location?.city || 'N/A',
        country: item.location?.country_name || 'N/A',
        os: item.os || 'N/A',
        vulnerability: item.vulns ? true : false
      }));
      return res.status(200).json({
        success: true,
        service: 'Shodan Geofence',
        query,
        total: data.total || 0,
        results: results.slice(0, 50)
      });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  return res.status(400).json({ error: 'Invalid action' });
}
