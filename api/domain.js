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

  const { action, domain, type = 'A' } = req.query;

  if (!domain) return res.status(400).json({ error: 'Domain parameter required' });

  // ACTION: WHOIS
  if (action === 'whois') {
    try {
      const response = await fetch(`https://networkcalc.com/api/dns/whois/${encodeURIComponent(domain)}`);
      const data = await response.json();
      if (data.status === 'OK' && data.whois) {
        return res.status(200).json({
          success: true, service: 'WHOIS', domain,
          data: {
            registrar: data.whois.registrar || 'N/A',
            registrationDate: data.whois.creation_date || 'N/A',
            expirationDate: data.whois.registrar_registration_expiration_date || 'N/A',
            nameServers: data.whois.name_servers || [],
            status: data.whois.domain_status || 'active'
          }
        });
      }
      return res.status(404).json({ error: 'WHOIS data not found' });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // ACTION: DNS
  if (action === 'dns') {
    try {
      const response = await fetch(`https://networkcalc.com/api/dns/lookup/${encodeURIComponent(domain)}`);
      const data = await response.json();
      if (data.status === 'OK' && data.records) {
        // Si el usuario pidió un tipo específico (A, MX, etc) lo filtramos
        const filtered = type && data.records[type] ? { [type]: data.records[type] } : data.records;
        return res.status(200).json({ success: true, service: 'DNS', domain, data: filtered });
      }
      return res.status(404).json({ error: 'DNS records not found' });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // ACTION: SUBDOMAINS
  if (action === 'subdomains') {
    try {
      // Usamos crt.sh como fallback gratuito para enumeración básica
      const response = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`);
      const data = await response.json();
      const subs = [...new Set(data.map(item => item.name_value.toLowerCase()))];
      return res.status(200).json({ success: true, service: 'SUBDOMAINS', domain, total: subs.length, subdomains: subs.slice(0, 50) });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  return res.status(400).json({ error: 'Invalid action' });
}
