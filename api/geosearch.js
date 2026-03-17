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

  const { location, lat, lon, radius = 5 } = req.query;
  const SHODAN_API_KEY = process.env.SHODAN_API_KEY;

  if (!SHODAN_API_KEY) {
    return res.status(500).json({ 
      success: false,
      error: 'Shodan API Key no configurada en el servidor (Vercel ENV).',
      code: 'MISSING_API_KEY' 
    });
  }

  // Construir la Query de Shodan
  let query = '';
  if (lat && lon) {
    query = `geo:${lat},${lon},${radius}`;
  } else if (location) {
    // Si es una palabra simple, asumimos ciudad o país
    query = location.includes(',') ? `location:"${location}"` : `city:"${location}"`;
  } else {
    return res.status(400).json({ 
      success: false,
      error: 'Se requiere al menos una ubicación (Ciudad) o coordenadas (Lat/Lon).',
      code: 'MISSING_PARAMS' 
    });
  }

  try {
    const apiUrl = `https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=${encodeURIComponent(query)}&facets=city,org,port`;
    
    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'OSINTAIPro/3.0' }
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || `Shodan API error: ${response.status}`);
    }

    const data = await response.json();

    // Mapear resultados para el frontend
    const results = (data.matches || []).map(item => ({
      ip: item.ip_str,
      port: item.port,
      org: item.org || 'N/A',
      isp: item.isp || 'N/A',
      city: item.location?.city || 'N/A',
      country: item.location?.country_name || 'N/A',
      os: item.os || 'N/A',
      hostnames: item.hostnames || [],
      timestamp: item.timestamp,
      vulnerability: item.vulns ? true : false
    }));

    return res.status(200).json({
      success: true,
      service: 'Shodan Geofence',
      query,
      total: data.total || 0,
      results: results.slice(0, 50), // Limitamos por seguridad de transferencia
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Shodan Geosearch Error:', error);
    return res.status(500).json({
      success: false,
      error: 'Error al consultar la API de Shodan.',
      code: 'API_ERROR',
      details: error.message
    });
  }
}
