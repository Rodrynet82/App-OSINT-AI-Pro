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
    const response = await fetch(
      `https://networkcalc.com/api/dns/whois/${encodeURIComponent(domain)}`,
      {
        method: 'GET',
        headers: { 'User-Agent': 'OSINTAIPro/3.0' },
        timeout: 10000
      }
    );

    if (!response.ok) {
      throw new Error(`WHOIS API error: ${response.status}`);
    }

    const data = await response.json();

    if (data.status === 'OK' && data.whois) {
      return res.status(200).json({
        service: 'WHOIS',
        domain,
        data: {
          registrar: data.whois.registrar || 'N/A',
          registrationDate: data.whois.creation_date || 'N/A',
          expirationDate: data.whois.registrar_registration_expiration_date || 'N/A',
          updatedDate: data.whois.updated_date || 'N/A',
          nameServers: data.whois.name_servers || [],
          registrantName: data.whois.registrant?.name || 'Redactado/Provacy',
          registrantEmail: data.whois.registrant?.email || 'N/A',
          status: data.whois.domain_status || 'active',
          tld: domain.split('.').pop()
        },
        timestamp: new Date().toISOString(),
        success: true
      });
    } else {
      return res.status(404).json({
        error: 'Domain not found or no WHOIS data',
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
