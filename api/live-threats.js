import { validateApiKey } from './_utils/validation.js';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // Permite llamadas locales o desde el frontend sin clave para la visual del mapa público,
  // pero mantendremos validación básica si se envía.
  const clientKey = req.headers['x-antigravity-key'];
  if (clientKey) {
     const validation = validateApiKey(clientKey);
     if (!validation.isValid) return res.status(401).json({ success: false, error: 'Acceso denegado.' });
  }

  try {
    // 1. Fetch REAL Live Threat Data from Abuse.ch (Feodo Tracker - Botnet C2s)
    const threatRes = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.json', { timeout: 8000 });
    const threatData = await threatRes.json();

    if (!Array.isArray(threatData)) {
       throw new Error("Invalid format from Threat Intel Feed");
    }

    // Filter only online C2 servers
    const onlineThreats = threatData.filter(t => t.status === 'online');
    
    // Pick 5-8 random live threats for this poll
    const numThreats = Math.floor(Math.random() * 4) + 5;
    const selected = [];
    for (let i = 0; i < numThreats; i++) {
       const randomIndex = Math.floor(Math.random() * onlineThreats.length);
       selected.push(onlineThreats[randomIndex]);
    }

    // 2. Batch GeoLocation request using ip-api.com for the selected IPs
    const ipsToLocate = selected.map(t => t.ip_address);
    const geoRes = await fetch('http://ip-api.com/batch', {
      method: 'POST',
      body: JSON.stringify(ipsToLocate),
      headers: { 'Content-Type': 'application/json' }
    });
    
    const geoData = await geoRes.json(); // Array of geo results corresponding to the IPs

    // 3. Map into the format our frontend expects
    const finalThreats = selected.map((t, index) => {
       const geo = geoData[index];
       if (geo.status !== 'success') return null;

       return {
          id: `${t.ip_address}-${Date.now()}`,
          ip: t.ip_address,
          type: t.malware || 'Botnet C2',
          city: geo.city || geo.country,
          country: geo.country,
          lat: geo.lat,
          lng: geo.lon,
          org: geo.isp || geo.org || t.as_name,
          first_seen: t.first_seen,
          severity: 'critical'
       };
    }).filter(t => t !== null);

    return res.status(200).json({
      success: true,
      timestamp: new Date().toISOString(),
      count: finalThreats.length,
      threats: finalThreats
    });

  } catch (error) {
    console.error('Live Threats Error:', error);
    return res.status(500).json({ error: 'Fallo al obtener Live Threats', details: error.message });
  }
}
