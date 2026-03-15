import { validateApiKey } from './_utils/validation.js';

// In-memory dedup cache: track IPs shown this session
const recentIps = new Set();
const MAX_CACHE = 200; // keep last 200 unique IPs

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  const clientKey = req.headers['x-antigravity-key'];
  if (clientKey) {
     const validation = validateApiKey(clientKey);
     if (!validation.isValid) return res.status(401).json({ success: false, error: 'Acceso denegado.' });
  }

  try {
    // Fetch REAL Live Threat Data from FeodoTracker (Botnet C2s)
    const threatRes = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.json', { signal: AbortSignal.timeout(8000) });
    const threatData = await threatRes.json();

    if (!Array.isArray(threatData)) {
       throw new Error("Invalid format from Threat Intel Feed");
    }

    // Filter to online C2 servers, excluding known cloud hosters for more geo-diversity
    const EXCLUDED_ASNS = ['amazon', 'aws', 'microsoft', 'azure', 'digitalocean', 'linode', 'google', 'cloudflare', 'ovh', 'hetzner'];
    
    let onlineThreats = threatData.filter(t => {
      if (t.status !== 'online') return false;
      // Skip if already in our recent dedup cache
      if (recentIps.has(t.ip_address)) return false;
      // Filter out known cloud providers to get more interesting geos
      const asn = (t.as_name || '').toLowerCase();
      const isExcluded = EXCLUDED_ASNS.some(ex => asn.includes(ex));
      return !isExcluded;
    });

    // If filtering was too aggressive, fall back to all online (still dedup)
    if (onlineThreats.length < 5) {
      onlineThreats = threatData.filter(t => t.status === 'online' && !recentIps.has(t.ip_address));
    }

    // If still not enough (all seen), reset the cache
    if (onlineThreats.length < 5) {
      recentIps.clear();
      onlineThreats = threatData.filter(t => t.status === 'online');
    }

    // Pick 5–8 unique live threats for this poll by shuffling first
    const shuffled = onlineThreats.sort(() => Math.random() - 0.5);
    const selected = shuffled.slice(0, Math.min(8, shuffled.length));

    // Add selected IPs to dedup cache
    selected.forEach(t => {
      recentIps.add(t.ip_address);
      if (recentIps.size > MAX_CACHE) {
        // Delete oldest (first) element
        const first = recentIps.values().next().value;
        recentIps.delete(first);
      }
    });

    // Batch GeoLocation using ip-api.com
    const ipsToLocate = selected.map(t => t.ip_address);
    const geoRes = await fetch('http://ip-api.com/batch', {
      method: 'POST',
      body: JSON.stringify(ipsToLocate),
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(6000)
    });
    
    const geoData = await geoRes.json();

    // Map to frontend format
    const finalThreats = selected.map((t, index) => {
       const geo = geoData[index];
       if (!geo || geo.status !== 'success') return null;
       // Skip if lat/lng maps to US CONUS & we have room to skip
       return {
          id: `${t.ip_address}-${Date.now()}-${index}`,
          ip: t.ip_address,
          type: t.malware || 'Botnet C2',
          city: geo.city || geo.regionName || geo.country,
          country: geo.country,
          countryCode: geo.countryCode || '',
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
