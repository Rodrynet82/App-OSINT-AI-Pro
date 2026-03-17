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

  // ACTION: GEOFENCE SEARCH / GENERAL SHODAN (shodan)
  if (action === 'geosearch' || action === 'shodan') {
    const SHODAN_API_KEY = process.env.SHODAN_API_KEY || process.env.SHODAN_KEY;
    if (!SHODAN_API_KEY || SHODAN_API_KEY === 'demo') {
      return res.status(500).json({
        success: false,
        error: 'Shodan API Key no configurada o es "demo".',
        details: 'Para usar esta herramienta en local, añade SHODAN_API_KEY=tu_clave en el archivo .env.'
      });
    }

    let query = req.query.query || '';

    // Si no hay query explícita, la construimos desde los parámetros de geofencing
    if (!query) {
      if (lat && lon) {
        // Formato geo:LAT,LONG,RADIUS (sin espacios, radio opcional en km)
        const rVal = radius ? (parseInt(radius) || 5) : 5;
        // Importante: Shodan prefiere geo:"lat,lon,radius" o geo:lat,lon en algunos casos
        query = `geo:${lat.trim()},${lon.trim()},${rVal}`;
      } else if (location) {
        const parts = location.split(',').map(p => p.trim());
        if (parts.length > 1) {
          // Si hay coma, asumimos City, Country Code (ej: Madrid, ES)
          // Shodan usa filtros city:"name" y country:"CC"
          query = `city:"${parts[0]}" country:"${parts[1].substring(0,2).toUpperCase()}"`;
        } else {
          // Búsqueda simple por ciudad
          query = `city:"${location}"`;
        }
      }
    }

    if (!query) return res.status(400).json({ error: 'Faltan parámetros de búsqueda (query, location o coords)', code: 'MISSING_PARAMS' });

    try {
      // Usamos el endpoint de búsqueda de Shodan
      const apiUrl = `https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=${encodeURIComponent(query)}&facets=city,org,port`;

      const response = await fetch(apiUrl);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || `Shodan API error: ${response.status}`);
      }

      const results = (data.matches || []).map(item => ({
        ip: item.ip_str,
        port: item.port,
        org: item.org || 'N/A',
        city: item.location?.city || 'N/A',
        country: item.location?.country_name || 'N/A',
        os: item.os || 'N/A',
        vulnerability: item.vulns ? true : false,
        hostnames: item.hostnames || []
      }));

      return res.status(200).json({
        success: true,
        service: 'Shodan OSINT',
        query,
        total: data.total || 0,
        results: results.slice(0, 50),
        timestamp: new Date().toISOString()
      });
    } catch (e) {
      console.error('Shodan Error:', e);
      return res.status(500).json({ success: false, error: e.message });
    }
  }

  return res.status(400).json({ error: 'Invalid action' });
}
