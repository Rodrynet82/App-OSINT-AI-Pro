export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  const { hash, url, ip } = req.query;
  const query = hash || url || ip;

  if (!query) {
    return res.status(400).json({ error: 'Hash, URL, or IP parameter required' });
  }

  try {
    const apiKey = process.env.VIRUSTOTAL_API_KEY || 'demo';
    let endpoint;

    if (hash) {
      endpoint = `https://www.virustotal.com/api/v3/files/${hash}`;
    } else if (url) {
      endpoint = `https://www.virustotal.com/api/v3/urls/${Buffer.from(url).toString('base64').replace(/=/g, '')}`;
    } else {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${ip}`;
    }

    const response = await fetch(endpoint, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey
      }
    });

    if (!response.ok) {
      throw new Error(`VirusTotal API error: ${response.status}`);
    }

    const data = await response.json();

    return res.status(200).json({
      service: 'VIRUSTOTAL',
      query,
      data: {
        lastAnalysisDate: data.attributes?.last_analysis_date || 'N/A',
        lastAnalysisStats: data.attributes?.last_analysis_stats || {},
        threatClassification: data.attributes?.threat_classification || 'undetected',
        tags: data.attributes?.tags || []
      },
      timestamp: new Date().toISOString(),
      success: true
    });
  } catch (error) {
    console.error('VirusTotal Error:', error);
    return res.status(500).json({
      error: 'Failed to fetch VirusTotal data',
      details: error.message
    });
  }
}
