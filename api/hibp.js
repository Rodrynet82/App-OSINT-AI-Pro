import crypto from 'crypto';
import { validateApiKey } from './_utils/validation.js';

// Have I Been Pwned (HIBP) - Threat Intelligence Engine
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, x-antigravity-key');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // Pre-flight check / validation (Escudo de Seguridad)
  const clientKey = req.headers['x-antigravity-key'];
  const validation = validateApiKey(clientKey);

  if (!validation.isValid) {
    return res.status(401).json({
      success: false,
      error: 'Acceso denegado. Clave Antigravity inválida o ausente.',
      code: 'UNAUTHORIZED'
    });
  }

  const { email, password, login_ip_country, assigned_roles } = req.query;

  // 1. REQUISITO 1: k-Anonymity (Verificación de Password)
  if (password) {
    try {
      const sha1Hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
      const prefix = sha1Hash.substring(0, 5);
      const suffix = sha1Hash.substring(5);

      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: {
          'User-Agent': 'App-OSINT-AI-Pro-Analyzer'
        }
      });

      if (!response.ok) {
        throw new Error(`HIBP Password API Error: ${response.status}`);
      }

      const hashData = await response.text();
      const hashes = hashData.split('\r\n');
      let isCompromised = false;
      let occurrences = 0;

      for (const line of hashes) {
        const [h, count] = line.split(':');
        if (h === suffix) {
          isCompromised = true;
          occurrences = parseInt(count, 10);
          break;
        }
      }

      return res.status(200).json({
        service: 'HIBP Password Check (k-Anonymity)',
        query: { prefix_sent: prefix },
        data: {
          compromised: isCompromised,
          occurrences: occurrences,
          risk_level: isCompromised ? 'ALTA' : 'SEGURO',
          verdict: isCompromised 
            ? 'Esta contraseña ha aparecido en bases de datos de credenciales expuestas.'
            : 'Contraseña no encontrada en brechas conocidas (es segura por ahora).'
        },
        timestamp: new Date().toISOString(),
        success: true
      });
    } catch (error) {
      console.error('HIBP Password Error:', error);
      return res.status(500).json({ error: 'Failed to verify password via HIBP', details: error.message });
    }
  }

  // 2. REQUISITO 2 & 3: Breach Analysis & Anomaly Detection
  if (!email) {
    return res.status(400).json({ error: 'Email or password parameter required' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  try {
    const hibpApiKey = process.env.HIBP_API_KEY; // Obtenida de las variables de entorno de Vercel/Local
    let breaches = [];
    let isMock = false;

    if (hibpApiKey && hibpApiKey !== 'PLACEHOLDER_KEY') {
      const response = await fetch(
        `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
        {
          method: 'GET',
          headers: {
            'User-Agent': 'App-OSINT-AI-Pro-Analyzer',
            'hibp-api-key': hibpApiKey
          }
        }
      );

      if (response.status === 200) {
        breaches = await response.json();
      } else if (response.status === 429) {
        throw new Error('Rate limit excedido en HIBP. Espera unos segundos.');
      } else if (response.status !== 404) {
        const errorText = await response.text();
        throw new Error(`HIBP API Error: ${response.status} - ${errorText}`);
      }
    } else {
      // MOCK DATA: Si no hay API KEY provista, devolvemos data estática para demostrar la Lógica Anti-Singapur
      console.warn('[HIBP Engine] HIBP_API_KEY no detectada. Usando datos simulados.');
      isMock = true;
      breaches = [
        { Name: "LinkedIn", BreachDate: "2012-05-05", DataClasses: ["Email addresses", "Passwords"], IsVerified: true },
        { Name: "Canva", BreachDate: "2019-05-24", DataClasses: ["Email addresses", "Geographic locations", "Names"], IsVerified: true }
      ];
      // Pequeño retardo para simular red
      await new Promise(r => setTimeout(r, 600));
    }

    // Estructurar Brechas
    const structuredBreaches = breaches.map(b => {
      const dataClasses = b.DataClasses || [];
      return {
        breach_name: b.Name,
        date: b.BreachDate,
        risk_level: dataClasses.includes('Passwords') ? 'Alta' : 'Media',
        is_verified: b.IsVerified,
        data_lost: dataClasses
      };
    });

    // 3. ANOMALY DETECTION ENGINE (Anti-Singapur / Insider Threat)
    let riskScore = 0;
    const alerts = [];
    const highRiskCountries = ["SG", "KP", "RU", "IR"]; // Singapur añadido a lista de alto riesgo
    const roles = assigned_roles ? assigned_roles.split(',').map(r => r.trim()) : [];

    // Chequeo Geográfico
    if (login_ip_country && highRiskCountries.includes(login_ip_country.toUpperCase())) {
      riskScore += 50;
      alerts.push(`[Geografía Anómala] Actividad detectada desde zona de riesgo: ${login_ip_country.toUpperCase()}`);
    }

    // Chequeo de Roles (Insiders)
    if (roles.includes('Recruiter') || roles.includes('Admin')) {
      riskScore += 30;
      alerts.push(`[Role Analytics] La cuenta posee privilegios elevados: ${roles.join(', ')}`);
    }

    // Correlación de Brechas
    const highRiskBreaches = structuredBreaches.filter(b => b.risk_level === 'Alta');
    if (highRiskBreaches.length > 0) {
      riskScore += 40;
      alerts.push(`[Breach Intel] Usuario expuesto en ${highRiskBreaches.length} filtraciones críticas (contraseñas comprometidas).`);
    } else if (structuredBreaches.length > 0) {
      riskScore += 15;
      alerts.push(`[Breach Intel] Usuario expuesto en filtraciones de bajo nivel (solo metadata).`);
    }

    let statusVerdict = "SEGURO";
    if (riskScore >= 80) statusVerdict = "BLOQUEO_RECOMENDADO (Zero Trust Constraint)";
    else if (riskScore >= 40) statusVerdict = "EN_MONITOREO (High Risk User)";

    return res.status(200).json({
      service: 'HIBP Threat Intelligence Engine',
      target: email,
      is_simulated_data: isMock,
      analysis: {
        total_risk_score: riskScore,
        status: statusVerdict,
        breach_history_count: structuredBreaches.length,
        anomalies_detected: alerts.length > 0 ? alerts : ['Ninguna. Comportamiento basal normal.']
      },
      breaches: structuredBreaches.length > 0 ? structuredBreaches : 'No se encontraron filtraciones',
      timestamp: new Date().toISOString(),
      success: true
    });

  } catch (error) {
    if (error.message.includes('404')) { // Este bloque es algo redundante ahora pero útil por si acaso
      return res.status(200).json({
        service: 'HIBP',
        target: email,
        analysis: { total_risk_score: 0, status: 'SEGURO', anomalies_detected: [] },
        breaches: 'No se encontraron filtraciones',
        success: true
      });
    }

    console.error('HIBP Threat Intel Error:', error);
    return res.status(500).json({
      error: 'Failed to run Threat Intelligence correlation',
      details: error.message
    });
  }
}

