// Have I Been Pwned (HIBP) Me han Engañado?
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: 'Email parameter required' });
  }

  // Validar email
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  try {
    const response = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`,
      {
        method: 'GET',
        headers: {
          'User-Agent': 'OSINTAIPro'
        }
      }
    );

    let breaches = [];
    if (response.status === 200) {
      breaches = await response.json();
    }

    return res.status(200).json({
      service: 'HIBP',
      email,
      data: {
        breached: breaches.length > 0,
        breachCount: breaches.length,
        breaches: breaches.map(b => ({
          title: b.Title,
          date: b.BreachDate,
          dataClasses: b.DataClasses,
          isVerified: b.IsVerified
        })) || []
      },
      timestamp: new Date().toISOString(),
      success: true
    });
  } catch (error) {
    if (error.message.includes('404')) {
      return res.status(200).json({
        service: 'HIBP',
        email,
        data: {
          breached: false,
          breachCount: 0,
          breaches: []
        },
        timestamp: new Date().toISOString(),
        success: true
      });
    }

    console.error('HIBP Error:', error);
    return res.status(500).json({
      error: 'Failed to fetch HIBP data',
      details: error.message
    });
  }
}

