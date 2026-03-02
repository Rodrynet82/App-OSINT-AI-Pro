// OSINT AI Pro Platform - Complete Implementation V3.0
// Sistema completo con login, dashboard, mapa Kaspersky, 19 pruebas, exportación PDF/JSON, y más

// Global application state
const OSINTApp = {
  currentSection: 'dashboard',
  currentLanguage: 'es',
  analysisInProgress: false,
  searchResults: null,
  userMode: 'premium',
  isLoggedIn: false,
  settings: {
    theme: 'auto',
    notifications: true,
    language: 'es',
    analysisTimeout: 30,
    autoSaveResults: true,
    realTimeUpdates: true
  },
  analysisConfig: {
    sensitivity: 7,
    correlation: 75,
    depth: 5
  },
  progressInterval: null,
  notifications: [],
  toolResults: [],
  reports: JSON.parse(localStorage.getItem('osint_reports') || '[]'),
  monitoring: JSON.parse(localStorage.getItem('osint_monitoring') || '[]'),
  apiConfigurations: [],
  threatMapInterval: null,
  threatFeedInterval: null
};

// Application data from JSON
const applicationData = {
  user_credentials: {
    email: "admin@osint-ai-pro.com",
    password: "OSINTPro2025!",
    role: "premium"
  },
  kaspersky_map_style: {
    background_color: "#0a0a0f",
    map_color: "#1a1a2e",
    connection_colors: {
      malware: "#ff006e",
      ddos: "#00f5ff",
      phishing: "#39ff14",
      apt: "#ff9500"
    },
    animation_speed: "2s",
    threat_types: [
      { name: "OAS", count: 26062, color: "#39ff14" },
      { name: "DDS", count: 64354, color: "#ff006e" },
      { name: "MAV", count: 19399, color: "#00f5ff" },
      { name: "NAV", count: 65383, color: "#9d00ff" },
      { name: "IDS", count: 9, color: "#ff9500" },
      { name: "VUL", count: 743, color: "#ffff00" },
      { name: "KAS", count: 29444, color: "#ff0040" },
      { name: "EMU", count: 222, color: "#40ff00" },
      { name: "RHM", count: 8, color: "#0040ff" }
    ]
  },
  detailed_explanations: {
    analisis_ia: {
      title: "Análisis de Inteligencia Artificial",
      description: "Sistema avanzado de análisis con IA que procesa más de 50 fuentes de datos simultáneamente",
      metrics: [
        { label: "Algoritmos Activos", value: "7" },
        { label: "Confianza Promedio", value: "87%" },
        { label: "Detecciones Hoy", value: "1,247" }
      ]
    },
    investigaciones: {
      title: "Investigaciones Activas",
      description: "Estado actual de investigaciones en curso con análisis automatizado",
      active_investigations: [
        { id: "INV-001", target: "suspicious-domain.com", status: "En Progreso", progress: 65, priority: "Alta" },
        { id: "INV-002", target: "192.168.100.50", status: "Completada", progress: 100, priority: "Media" }
      ]
    },
    score: {
      title: "Score de Riesgo Global",
      description: "Puntuación calculada basada en múltiples factores de amenaza",
      components: [
        { factor: "Exposición de Servicios", score: 85, weight: "30%" },
        { factor: "Vulnerabilidades Conocidas", score: 72, weight: "25%" },
        { factor: "Reputación de Dominio", score: 45, weight: "20%" },
        { factor: "Actividad Sospechosa", score: 58, weight: "25%" }
      ]
    },
    paises: {
      title: "Distribución Geográfica",
      description: "Análisis de amenazas por ubicación geográfica",
      countries: [
        { name: "Estados Unidos", threats: 2840, percentage: "32%" },
        { name: "China", threats: 1950, percentage: "22%" },
        { name: "Rusia", threats: 1200, percentage: "14%" },
        { name: "Brasil", threats: 890, percentage: "10%" },
        { name: "Otros", threats: 1945, percentage: "22%" }
      ]
    }
  },
  notification_settings: [
    { id: "email_alerts", name: "Alertas por Email", enabled: true, frequency: "Inmediato", description: "Notificaciones críticas por correo electrónico" },
    { id: "push_notifications", name: "Notificaciones Push", enabled: true, frequency: "Tiempo Real", description: "Alertas instantáneas en el navegador" },
    { id: "threat_alerts", name: "Alertas de Amenazas", enabled: true, frequency: "Inmediato", description: "Notificaciones de nuevas amenazas detectadas" },
    { id: "report_ready", name: "Reportes Listos", enabled: false, frequency: "Diario", description: "Cuando los reportes están listos para descarga" }
  ],
  api_configurations: [
    { name: "OpenAI GPT", endpoint: "https://api.openai.com/v1", status: "connected", calls_today: 47, limit: 1000, key: "sk-..." },
    { name: "VirusTotal", endpoint: "https://www.virustotal.com/vtapi/v2", status: "disconnected", calls_today: 0, limit: 500, key: "" },
    { name: "Shodan", endpoint: "https://api.shodan.io", status: "connected", calls_today: 156, limit: 1000, key: "xyz123..." },
    { name: "IPinfo", endpoint: "https://ipinfo.io", status: "connected", calls_today: 89, limit: 500, key: "abc456..." }
  ]
};

// Test definitions for 19 analysis tests
const analysisTests = [
  { name: "WHOIS Lookup", description: "Información de registro del dominio", category: "basic" },
  { name: "DNS Analysis", description: "Análisis de registros DNS", category: "basic" },
  { name: "IP Geolocation", description: "Localización geográfica", category: "basic" },
  { name: "Port Scanning", description: "Escaneo de puertos abiertos", category: "network" },
  { name: "SSL Certificate Check", description: "Verificación de certificados SSL", category: "security" },
  { name: "Web Technology Detection", description: "Detección de tecnologías web", category: "web" },
  { name: "Email Verification", description: "Verificación de direcciones email", category: "email" },
  { name: "Social Media Presence", description: "Presencia en redes sociales", category: "social" },
  { name: "Domain Reputation", description: "Reputación del dominio", category: "reputation" },
  { name: "Malware Detection", description: "Detección de malware", category: "security" },
  { name: "Phishing Analysis", description: "Análisis de phishing", category: "security" },
  { name: "Dark Web Monitoring", description: "Monitoreo en dark web", category: "intelligence" },
  { name: "Threat Intelligence", description: "Inteligencia de amenazas", category: "intelligence" },
  { name: "Data Breach Check", description: "Verificación de filtraciones", category: "security" },
  { name: "Subdomain Enumeration", description: "Enumeración de subdominios", category: "recon" },
  { name: "HTTP Headers Analysis", description: "Análisis de headers HTTP", category: "web" },
  { name: "Open Source Intelligence", description: "Inteligencia de fuentes abiertas", category: "intelligence" },
  { name: "Network Topology", description: "Topología de red", category: "network" },
  { name: "Behavioral Analysis", description: "Análisis de comportamiento", category: "advanced" }
];

// OSINT tools database — expanded catalog
const toolsDatabase = {
  'Análisis de Red e IP': {
    icon: 'fas fa-network-wired',
    color: '#3B82F6',
    gradient: 'linear-gradient(135deg, #1d4ed8, #3b82f6)',
    description: 'Herramientas de análisis de infraestructura y redes',
    tools: [
      {
        name: 'WHOIS',
        description: 'Obtén información completa de registro de un dominio: titular, registrador, fechas de creación/expiración y servidores de nombres. Esencial para identificar la propiedad de un activo online.',
        shortDesc: 'Información de registro del dominio',
        icon: 'fas fa-globe',
        endpoint: 'whois',
        form: {
          title: 'WHOIS Lookup',
          fields: [
            { name: 'domain', type: 'text', label: 'Dominio', placeholder: 'example.com', required: true }
          ]
        }
      },
      {
        name: 'DNS Lookup',
        description: 'Consulta todos los registros DNS de un dominio: A, AAAA, MX, NS, TXT, CNAME y SOA. Permite descubrir la infraestructura de email, servidores y políticas de seguridad (SPF/DKIM).',
        shortDesc: 'Análisis completo de registros DNS',
        icon: 'fas fa-server',
        endpoint: 'dns',
        form: {
          title: 'DNS Lookup',
          fields: [
            { name: 'domain', type: 'text', label: 'Dominio', placeholder: 'example.com', required: true },
            { name: 'type', type: 'select', label: 'Tipo de Registro', options: ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'], required: true }
          ]
        }
      },
      {
        name: 'IP Geolocation',
        description: 'Localiza geográficamente cualquier dirección IP y obtén información sobre el ISP, ASN, organización propietaria y coordenadas aproximadas. Útil para tracing y atribución de ataques.',
        shortDesc: 'Localización geográfica de IPs',
        icon: 'fas fa-map-marker-alt',
        endpoint: 'ipinfo',
        form: {
          title: 'IP Geolocation',
          fields: [
            { name: 'ip', type: 'text', label: 'Dirección IP', placeholder: '8.8.8.8', required: true }
          ]
        }
      },
      {
        name: 'Port Scanner',
        description: 'Detecta puertos abiertos y servicios expuestos en un host. Identifica servicios como SSH, HTTP, FTP o bases de datos que puedan representar vectores de ataque para un adversario.',
        shortDesc: 'Escaneo de puertos y servicios',
        icon: 'fas fa-search-plus',
        endpoint: null,
        form: {
          title: 'Port Scanner',
          fields: [
            { name: 'target', type: 'text', label: 'IP / Dominio', placeholder: '192.168.1.1 o example.com', required: true },
            { name: 'ports', type: 'text', label: 'Puertos', placeholder: '1-1000 ó 22,80,443', required: true }
          ]
        }
      },
      {
        name: 'SSL Checker',
        description: 'Analiza el certificado TLS/SSL de un dominio: emisor, validez, algoritmos de cifrado y vulnerabilidades conocidas (Heartbleed, POODLE). Fundamental para auditorías de seguridad web.',
        shortDesc: 'Análisis de certificados SSL/TLS',
        icon: 'fas fa-lock',
        endpoint: null,
        form: {
          title: 'SSL Checker',
          fields: [
            { name: 'domain', type: 'text', label: 'Dominio', placeholder: 'example.com', required: true }
          ]
        }
      },
      {
        name: 'Traceroute',
        description: 'Traza la ruta de red entre tu host y el objetivo, identificando cada salto de router. Permite detectar puntos de fallo, latencia y proveedores de tránsito utilizados en la infraestructura.',
        shortDesc: 'Trazado de ruta IP hop-by-hop',
        icon: 'fas fa-route',
        endpoint: null,
        form: {
          title: 'Traceroute',
          fields: [
            { name: 'target', type: 'text', label: 'IP / Dominio', placeholder: '8.8.8.8 o example.com', required: true }
          ]
        }
      },
      {
        name: 'Shodan Search',
        description: 'Busca dispositivos conectados indexados por Shodan: cámaras, routers, servidores industriales y más. Descubre activos expuestos involuntariamente a internet por una organización.',
        shortDesc: 'Búsqueda de dispositivos en Shodan',
        icon: 'fas fa-satellite-dish',
        endpoint: null,
        form: {
          title: 'Shodan Search',
          fields: [
            { name: 'query', type: 'text', label: 'Query Shodan', placeholder: 'org:"Google" port:8080', required: true }
          ]
        }
      }
    ]
  },
  'Email & Domain Intelligence': {
    icon: 'fas fa-envelope',
    color: '#10B981',
    gradient: 'linear-gradient(135deg, #065f46, #10b981)',
    description: 'Inteligencia avanzada sobre emails y dominios',
    tools: [
      {
        name: 'Email Verifier',
        description: 'Verifica si una dirección de email existe y es válida sin necesidad de enviar un mensaje. Comprueba formato, dominio activo, registro MX y si el buzón está activo en el servidor de correo.',
        shortDesc: 'Verificación de existencia del email',
        icon: 'fas fa-check-circle',
        endpoint: null,
        form: {
          title: 'Email Verifier',
          fields: [
            { name: 'email', type: 'email', label: 'Email', placeholder: 'usuario@domain.com', required: true }
          ]
        }
      },
      {
        name: 'Breach Hunter',
        description: 'Comprueba si un email ha sido comprometido en filtraciones de datos conocidas (HIBP, DeHashed). Muestra en qué brechas aparece, qué datos fueron expuestos y cuándo ocurrió la filtración.',
        shortDesc: 'Búsqueda en bases de datos filtradas',
        icon: 'fas fa-shield-alt',
        endpoint: 'hibp',
        form: {
          title: 'Breach Hunter',
          fields: [
            { name: 'email', type: 'email', label: 'Email', placeholder: 'test@example.com', required: true }
          ]
        }
      },
      {
        name: 'Domain Reputation',
        description: 'Evalúa la reputación de un dominio en múltiples motores antivirus y listas negras. Detecta si ha sido utilizado para phishing, malware o spam. Integrado con VirusTotal y otras fuentes.',
        shortDesc: 'Reputación y blacklists del dominio',
        icon: 'fas fa-globe-americas',
        endpoint: 'virustotal',
        form: {
          title: 'Domain Reputation',
          fields: [
            { name: 'domain', type: 'text', label: 'Dominio', placeholder: 'example.com', required: true }
          ]
        }
      },
      {
        name: 'MX Records',
        description: 'Consulta específicamente los registros MX para identificar el proveedor de correo (Google Workspace, Office 365, ProtonMail...). Revela si el dominio utiliza un relay de seguridad o filtro antispam.',
        shortDesc: 'Análisis de configuración de correo',
        icon: 'fas fa-at',
        endpoint: 'dns',
        form: {
          title: 'MX Records',
          fields: [
            { name: 'domain', type: 'text', label: 'Dominio', placeholder: 'example.com', required: true }
          ]
        }
      },
      {
        name: 'SPF/DKIM Check',
        description: 'Audita las políticas de autenticación de correo de un dominio: registros SPF (remitentes autorizados), DKIM (firma criptográfica) y DMARC (política ante fallos). Detecta configuraciones inseguras.',
        shortDesc: 'Auditoría de seguridad de email',
        icon: 'fas fa-key',
        endpoint: null,
        form: {
          title: 'SPF/DKIM Check',
          fields: [
            { name: 'domain', type: 'text', label: 'Dominio', placeholder: 'example.com', required: true }
          ]
        }
      },
      {
        name: 'Subdomain Finder',
        description: 'Enumera subdominios de un dominio objetivo usando técnicas pasivas (Certificate Transparency, DNS brute-force). Descubre paneles de administración, entornos de staging o servicios no documentados.',
        shortDesc: 'Enumeración de subdominios',
        icon: 'fas fa-sitemap',
        endpoint: null,
        form: {
          title: 'Subdomain Finder',
          fields: [
            { name: 'domain', type: 'text', label: 'Dominio Base', placeholder: 'example.com', required: true }
          ]
        }
      }
    ]
  },
  'Social Media & OSINT': {
    icon: 'fas fa-users',
    color: '#8B5CF6',
    gradient: 'linear-gradient(135deg, #4c1d95, #8b5cf6)',
    description: 'Inteligencia en redes sociales y fuentes abiertas',
    tools: [
      {
        name: 'Username Search',
        description: 'Busca un nombre de usuario en más de 300 plataformas simultáneamente: Twitter/X, Instagram, LinkedIn, GitHub, Reddit, TikTok y más. Construye el perfil digital y footprint de una persona u organización.',
        shortDesc: 'Búsqueda en 300+ plataformas',
        icon: 'fas fa-user-circle',
        endpoint: null,
        form: {
          title: 'Username Search',
          fields: [
            { name: 'username', type: 'text', label: 'Nombre de Usuario', placeholder: 'username123', required: true },
            { name: 'platforms', type: 'select', label: 'Plataformas', options: ['Todas', 'Twitter/X', 'Instagram', 'LinkedIn', 'GitHub', 'Reddit', 'TikTok'], required: true }
          ]
        }
      },
      {
        name: 'Phone Lookup',
        description: 'Investiga un número de teléfono para obtener el operador, país de origen, tipo de línea (móvil/fijo/VoIP), posible nombre del titular y si aparece en directorios públicos o bases de datos filtradas.',
        shortDesc: 'Investigación de números telefónicos',
        icon: 'fas fa-phone',
        endpoint: null,
        form: {
          title: 'Phone Lookup',
          fields: [
            { name: 'phone', type: 'tel', label: 'Teléfono', placeholder: '+34 600 000 000', required: true }
          ]
        }
      },
      {
        name: 'Image Reverse',
        description: 'Búsqueda inversa de imágenes usando Google Lens, Yandex y TinEye en paralelo. Localiza el origen de una imagen, detecta copias, deepfakes o el contexto real de una fotografía.',
        shortDesc: 'Búsqueda inversa de imágenes',
        icon: 'fas fa-image',
        endpoint: null,
        form: {
          title: 'Image Reverse Search',
          fields: [
            { name: 'imageUrl', type: 'url', label: 'URL de la Imagen', placeholder: 'https://example.com/foto.jpg', required: true }
          ]
        }
      },
      {
        name: 'Paste Search',
        description: 'Busca en Pastebin, GitHub Gists, Hastebin y otros servicios de pasta texto. Detecta credenciales, tokens API, código fuente o datos personales filtrados relacionados con tu objetivo.',
        shortDesc: 'Búsqueda en sitios de paste público',
        icon: 'fas fa-paste',
        endpoint: null,
        form: {
          title: 'Paste Search',
          fields: [
            { name: 'query', type: 'text', label: 'Término de Búsqueda', placeholder: 'email, dominio o keyword', required: true }
          ]
        }
      },
      {
        name: 'Profile Analyzer',
        description: 'Analiza un perfil de red social y extrae metadatos: horarios de actividad, análisis de sentimiento, relaciones, idioma, geolocalización implícita y posibles seudónimos o cuentas vinculadas.',
        shortDesc: 'Análisis profundo de perfiles sociales',
        icon: 'fas fa-user-secret',
        endpoint: null,
        form: {
          title: 'Profile Analyzer',
          fields: [
            { name: 'profileUrl', type: 'url', label: 'URL del Perfil', placeholder: 'https://twitter.com/usuario', required: true }
          ]
        }
      }
    ]
  },
  'Análisis Forense': {
    icon: 'fas fa-microscope',
    color: '#F59E0B',
    gradient: 'linear-gradient(135deg, #78350f, #f59e0b)',
    description: 'Herramientas de análisis forense digital',
    tools: [
      {
        name: 'Hash Analyzer',
        description: 'Analiza un hash MD5, SHA-1, SHA-256 o SHA-512 contra la base de datos de VirusTotal y Malware Bazaar. Determina si corresponde a un archivo malicioso conocido y obtén su historial de detecciones.',
        shortDesc: 'Verificación de hash en VirusTotal',
        icon: 'fas fa-fingerprint',
        endpoint: 'virustotal',
        form: {
          title: 'Hash Analyzer',
          fields: [
            { name: 'hash', type: 'text', label: 'Hash del Archivo', placeholder: 'MD5 / SHA-1 / SHA-256...', required: true }
          ]
        }
      },
      {
        name: 'URL Scanner',
        description: 'Analiza una URL en más de 70 motores antivirus y servicios de inteligencia de amenazas. Detecta phishing, malware drive-by, redirectores maliciosos y calcula una puntuación de riesgo global.',
        shortDesc: 'Análisis de URLs en 70+ motores',
        icon: 'fas fa-link',
        endpoint: 'virustotal',
        form: {
          title: 'URL Scanner',
          fields: [
            { name: 'url', type: 'url', label: 'URL a Analizar', placeholder: 'https://example.com', required: true }
          ]
        }
      },
      {
        name: 'Metadata Extractor',
        description: 'Extrae metadatos EXIF de imágenes JPEG/PNG: coordenadas GPS, cámara utilizada, fecha y hora, software de edición. También analiza metadatos ocultos en documentos PDF y Office.',
        shortDesc: 'Extracción de metadatos EXIF/PDF',
        icon: 'fas fa-info-circle',
        endpoint: null,
        form: {
          title: 'Metadata Extractor',
          fields: [
            { name: 'fileUrl', type: 'url', label: 'URL del Archivo', placeholder: 'https://example.com/imagen.jpg', required: true }
          ]
        }
      },
      {
        name: 'IP Blacklist Check',
        description: 'Comprueba si una IP está listada en más de 100 listas negras RBL/DNSBL (Spamhaus, Barracuda, SORBS...). Detecta si una IP está siendo usada para spam, ataques DDoS o botnets activas.',
        shortDesc: 'Verificación en 100+ blacklists',
        icon: 'fas fa-ban',
        endpoint: null,
        form: {
          title: 'IP Blacklist Check',
          fields: [
            { name: 'ip', type: 'text', label: 'Dirección IP', placeholder: '192.168.1.1', required: true }
          ]
        }
      },
      {
        name: 'HTTP Headers',
        description: 'Analiza las cabeceras HTTP de respuesta de un servidor web. Detecta tecnologías utilizadas (Server, X-Powered-By), presencia de cabeceras de seguridad (CSP, HSTS, X-Frame-Options) y posibles fugas de información.',
        shortDesc: 'Análisis de cabeceras HTTP del servidor',
        icon: 'fas fa-code',
        endpoint: null,
        form: {
          title: 'HTTP Headers',
          fields: [
            { name: 'url', type: 'url', label: 'URL', placeholder: 'https://example.com', required: true }
          ]
        }
      }
    ]
  }
};

// DOM initialization
document.addEventListener('DOMContentLoaded', function () {
  console.log('🚀 Initializing OSINT AI Pro Platform...');

  try {
    // Check login status
    const savedSession = localStorage.getItem('osint-session');
    if (savedSession) {
      const session = JSON.parse(savedSession);
      if (session.email === applicationData.user_credentials.email) {
        OSINTApp.isLoggedIn = true;
        showMainApp();
      }
    }

    // Initialize all components
    initializeLogin();
    initializeNavigation();
    initializeSidebar();
    initializeDashboard();
    initializeIntelligenceSearch();
    initializeToolsSection();
    initializeReportsSection();
    initializeMonitoringSection();
    initializeSettingsSection();
    initializeModals();
    initializeNotificationSystem();
    initializeAnalysisIA();
    initializeThemeToggle();
    initializeDashboardShortcuts();

    // Start real-time updates if logged in
    if (OSINTApp.isLoggedIn) {
      startRealTimeUpdates();
      setTimeout(() => initializeKasperskyMap(), 1000);
    }

    loadUserPreferences();

    console.log('✅ OSINT AI Pro Platform initialized successfully');
  } catch (error) {
    console.error('❌ Initialization error:', error);
    showNotification('⚠️ Plataforma iniciada en modo básico', 'warning', 3000);
  }
});

// LOGIN SYSTEM
function initializeLogin() {
  const loginBtn = document.getElementById('loginBtn');
  const loginEmail = document.getElementById('loginEmail');
  const loginPassword = document.getElementById('loginPassword');

  if (loginBtn) {
    loginBtn.addEventListener('click', function () {
      const email = loginEmail?.value.trim();
      const password = loginPassword?.value.trim();

      if (!email || !password) {
        showNotification('⚠️ Por favor ingresa email y contraseña', 'warning');
        return;
      }

      // Validate credentials
      if (email === applicationData.user_credentials.email && password === applicationData.user_credentials.password) {
        const btn = this;
        const icon = btn.querySelector('i');
        const span = btn.querySelector('span') || btn;
        icon.className = 'fas fa-spinner fa-spin';
        span.textContent = 'Verificando...';
        btn.disabled = true;

        showNotification('🔐 Verificando credenciales...', 'info');

        setTimeout(() => {
          // Save session
          const session = {
            email: email,
            role: applicationData.user_credentials.role,
            loginTime: new Date().toISOString()
          };
          localStorage.setItem('osint-session', JSON.stringify(session));

          OSINTApp.isLoggedIn = true;
          OSINTApp.userMode = 'premium';

          showNotification('✅ Acceso autorizado. Bienvenido a OSINT AI Pro', 'success');

          setTimeout(() => {
            showMainApp();
            startRealTimeUpdates();
            initializeKasperskyMap();
          }, 1000);
        }, 2000);
      } else {
        showNotification('❌ Credenciales incorrectas', 'error');
      }
    });
  }

  // Enter key support
  [loginEmail, loginPassword].forEach(input => {
    if (input) {
      input.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
          loginBtn?.click();
        }
      });
    }
  });
}

function showMainApp() {
  document.getElementById('loginScreen')?.classList.add('hidden');
  document.getElementById('mainApp')?.classList.remove('hidden');
}

function logout() {
  localStorage.removeItem('osint-session');
  OSINTApp.isLoggedIn = false;

  // Clear intervals
  if (OSINTApp.threatMapInterval) clearInterval(OSINTApp.threatMapInterval);
  if (OSINTApp.threatFeedInterval) clearInterval(OSINTApp.threatFeedInterval);

  document.getElementById('mainApp')?.classList.add('hidden');
  document.getElementById('loginScreen')?.classList.remove('hidden');
  showNotification('👋 Sesión cerrada correctamente', 'info');
}

// NAVIGATION SYSTEM
function initializeNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  const sections = document.querySelectorAll('.content-section');

  navItems.forEach((item) => {
    item.addEventListener('click', function (e) {
      e.preventDefault();
      const targetSection = this.getAttribute('data-section');

      navItems.forEach(nav => nav.classList.remove('active'));
      this.classList.add('active');

      sections.forEach(section => section.classList.remove('active'));
      const targetElement = document.getElementById(targetSection + '-section');

      if (targetElement) {
        targetElement.classList.add('active');
        OSINTApp.currentSection = targetSection;
        updatePageTitle(this.querySelector('span')?.textContent || targetSection);
        loadSectionData(targetSection);
      }
    });
  });
}

function updatePageTitle(title) {
  const pageTitle = document.getElementById('page-title');
  if (pageTitle) {
    pageTitle.textContent = title;
    document.title = `OSINT AI Pro - ${title}`;
  }
}

// SIDEBAR
function initializeSidebar() {
  const sidebarToggle = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  const logoutBtn = document.getElementById('logoutBtn');

  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', function () {
      sidebar.classList.toggle('collapsed');
    });
  }

  if (logoutBtn) {
    logoutBtn.addEventListener('click', logout);
  }

  // Idioma
  const langSelect = document.getElementById('languageSelect');
  if (langSelect) {
    langSelect.addEventListener('change', function (e) {
      const newLang = e.target.value;
      OSINTApp.currentLanguage = newLang;
      showNotification(newLang === 'es' ? '🇪🇸 Idioma cambiado a Español' : '🇺🇸 Language changed to English', 'info');
      // Update setting global variable
      OSINTApp.settings.language = newLang;
      localStorage.setItem('user-preferences', JSON.stringify(OSINTApp.settings));
    });
  }
}

// DASHBOARD
function initializeDashboard() {
  // Inicializar listeners en los botones del header
  initializeHeaderButtons();

  // Esperar a que el DOM esté 100% listo
  setTimeout(() => {
    initializeClickableMetrics();
    console.log('✅ Dashboard listeners initialized');
  }, 500);

  initializeThreatAlert();
  initializeNotificationsButton();

  setTimeout(() => {
    if (OSINTApp.isLoggedIn) {
      initializeKasperskyMap();
      startLiveMetrics(); // <- Iniciar métricas en vivo
    }
  }, 1000);
}

function initializeHeaderButtons() {
  const quickScanBtn = document.getElementById('quickScanBtn');
  if (quickScanBtn) {
    quickScanBtn.addEventListener('click', (e) => {
      e.preventDefault();

      const searchInput = document.getElementById('universalSearchInput'); // Changed to new ID
      if (searchInput) {
        // Asignar IP default para escaneo rápido si está vacío
        if (!searchInput.value) searchInput.value = '127.0.0.1';
      }

      // Ir directo a la sección de Inteligencia donde ocurre el análisis
      const intelligenceNav = document.querySelector('[data-section="intelligence"]');
      if (intelligenceNav) intelligenceNav.click();

      // Ejecutar la búsqueda directamente
      setTimeout(() => {
        const searchBtn = document.getElementById('startUniversalSearchBtn'); // Changed to new ID
        if (searchBtn) searchBtn.click();
      }, 500);
    });
  }
}

function startLiveMetrics() {
  // Actualización aleatoria de las métricas cada 5-10 segundos
  setInterval(() => {
    const metrics = document.querySelectorAll('.metric-value');
    if (metrics.length >= 4) {
      // Análisis IA
      const val1 = parseInt(metrics[0].textContent.replace(/,/g, ''));
      metrics[0].textContent = (val1 + Math.floor(Math.random() * 3)).toLocaleString();

      // Investigaciones
      const val2 = parseInt(metrics[1].textContent.replace(/,/g, ''));
      metrics[1].textContent = (val2 + Math.floor(Math.random() * 5)).toLocaleString();

      // Score (fluctua ligeramente)
      let val3 = parseInt(metrics[2].textContent);
      val3 += (Math.random() > 0.5 ? 1 : -1) * Math.floor(Math.random() * 3);
      if (val3 < 0) val3 = 0;
      if (val3 > 100) val3 = 100;
      metrics[2].textContent = val3;

      // Paises (ocasionalmente suma)
      if (Math.random() > 0.8) {
        const val4 = parseInt(metrics[3].textContent);
        metrics[3].textContent = val4 + 1;
      }
    }
  }, 8000);
}

function initializeClickableMetrics() {
  console.log('🔍 Inicializando métricas clickables...');

  setTimeout(() => {
    const metricsGrid = document.querySelector('.metrics-grid');
    if (!metricsGrid) {
      console.error('❌ NO SE ENCONTRÓ CONTENEDOR DE MÉTRICAS');
      return;
    }

    // Usar Event Delegation para evitar problemas con nodos clonados
    metricsGrid.addEventListener('click', function (e) {
      const metric = e.target.closest('.clickable-metric');
      if (!metric) return;

      e.preventDefault();
      e.stopPropagation();

      const modalId = metric.getAttribute('data-modal');
      if (!modalId) return; // FIX: If no modalId, do nothing (let other listeners handle it)

      console.log('🖱️ CLICK en métrica:', modalId);
      openModal(modalId);

      setTimeout(() => {
        populateDetailModal(modalId);
        console.log('📊 Gráficos cargados en modal:', modalId);
      }, 200);
    });

    console.log('✅ Listeners de delegación agregados a métricas');
  }, 1000);
}

// POPULATE DETAIL MODALS WITH CHARTS AND DATA - PHASE 1
function populateDetailModal(modalId) {
  const modalBody = document.getElementById(modalId.replace('Modal', 'ModalBody'));
  if (!modalBody) return;

  switch (modalId) {
    case 'analysisModal':
      populateAnalysisModal(modalBody);
      break;
    case 'investigationsModal':
      populateInvestigationsModal(modalBody);
      break;
    case 'scoreModal':
      populateScoreModal(modalBody);
      break;
    case 'countriesModal':
      populateCountriesModal(modalBody);
      break;
  }
}

// Análisis IA - Line Chart
function populateAnalysisModal(modalBody) {
  const analysisData = applicationData.detailed_explanations.analisis_ia;

  modalBody.innerHTML = `
    <div class="detail-modal-content">
      <p class="detail-description">${analysisData.description}</p>
      <div style="margin-top: 20px; position: relative; height: 300px;">
        <canvas id="analysisChart"></canvas>
      </div>
      <div style="margin-top: 20px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px;">
        ${analysisData.metrics.map(m => `
          <div style="background: rgba(56, 189, 248, 0.1); padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #38bdf8;">
            <div style="font-size: 12px; color: #94a3b8; margin-bottom: 5px;">${m.label}</div>
            <div style="font-size: 24px; font-weight: bold; color: #38bdf8;">${m.value}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  // Wait for DOM update, then create chart
  setTimeout(() => {
    const ctx = document.getElementById('analysisChart');
    if (ctx) {
      new Chart(ctx, {
        type: 'line',
        data: {
          labels: ['Sem 1', 'Sem 2', 'Sem 3', 'Sem 4', 'Sem 5'],
          datasets: [
            {
              label: 'Algoritmos Activos',
              data: [5, 6, 7, 7, 7],
              borderColor: '#38bdf8',
              backgroundColor: 'rgba(56, 189, 248, 0.1)',
              tension: 0.4,
              fill: true
            },
            {
              label: 'Confianza (%)',
              data: [82, 84, 85, 87, 87],
              borderColor: '#10b981',
              backgroundColor: 'rgba(16, 185, 129, 0.1)',
              tension: 0.4,
              fill: true
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: { color: '#cbd5e1' }
            }
          },
          scales: {
            y: {
              grid: { color: 'rgba(203, 213, 225, 0.1)' },
              ticks: { color: '#94a3b8' }
            },
            x: {
              grid: { color: 'rgba(203, 213, 225, 0.1)' },
              ticks: { color: '#94a3b8' }
            }
          }
        }
      });
    }
  }, 100);
}

// Investigaciones - Table
function populateInvestigationsModal(modalBody) {
  const invData = applicationData.detailed_explanations.investigaciones;

  modalBody.innerHTML = `
    <div class="detail-modal-content">
      <p class="detail-description">${invData.description}</p>
      <div style="margin-top: 20px; overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse;">
          <thead>
            <tr style="background: rgba(56, 189, 248, 0.1); border-bottom: 2px solid #38bdf8;">
              <th style="padding: 12px; text-align: left; color: #38bdf8; font-weight: bold;">ID</th>
              <th style="padding: 12px; text-align: left; color: #38bdf8; font-weight: bold;">Target</th>
              <th style="padding: 12px; text-align: left; color: #38bdf8; font-weight: bold;">Estado</th>
              <th style="padding: 12px; text-align: left; color: #38bdf8; font-weight: bold;">Progreso</th>
              <th style="padding: 12px; text-align: left; color: #38bdf8; font-weight: bold;">Prioridad</th>
            </tr>
          </thead>
          <tbody>
            ${invData.active_investigations.map(inv => `
              <tr style="border-bottom: 1px solid rgba(203, 213, 225, 0.2); cursor: pointer;" onmouseover="this.style.background='rgba(56, 189, 248, 0.05)'" onmouseout="this.style.background=''">
                <td style="padding: 12px; color: #cbd5e1; font-family: monospace; font-size: 12px;">${inv.id}</td>
                <td style="padding: 12px; color: #cbd5e1;">${inv.target}</td>
                <td style="padding: 12px; color: #cbd5e1;">
                  <span style="background: ${inv.status === 'Completada' ? '#10b981' : '#f59e0b'}; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px;">
                    ${inv.status}
                  </span>
                </td>
                <td style="padding: 12px;">
                  <div style="background: rgba(203, 213, 225, 0.1); height: 24px; border-radius: 12px; overflow: hidden;">
                    <div style="background: linear-gradient(90deg, #38bdf8, #0284c7); height: 100%; width: ${inv.progress}%; transition: width 0.3s;"></div>
                  </div>
                </td>
                <td style="padding: 12px;">
                  <span style="background: ${inv.priority === 'Alta' ? '#ff006e' : '#fbbf24'}; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px;">
                    ${inv.priority}
                  </span>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// Score de Riesgo - Donut Chart
function populateScoreModal(modalBody) {
  const scoreData = applicationData.detailed_explanations.score;

  modalBody.innerHTML = `
    <div class="detail-modal-content">
      <p class="detail-description">${scoreData.description}</p>
      <div style="margin-top: 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 30px; align-items: center;">
        <div style="position: relative; height: 300px;">
          <canvas id="scoreChart"></canvas>
        </div>
        <div>
          ${scoreData.components.map(comp => `
            <div style="margin-bottom: 15px;">
              <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                <span style="color: #cbd5e1; font-weight: 500;">${comp.factor}</span>
                <span style="color: #38bdf8; font-weight: bold;">${comp.score}/100</span>
              </div>
              <div style="background: rgba(203, 213, 225, 0.1); height: 8px; border-radius: 4px; overflow: hidden;">
                <div style="background: ${comp.score > 75 ? '#ff006e' : comp.score > 50 ? '#f59e0b' : '#10b981'}; height: 100%; width: ${comp.score}%; transition: width 0.5s;"></div>
              </div>
              <div style="font-size: 12px; color: #94a3b8; margin-top: 3px;">Peso: ${comp.weight}</div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;

  setTimeout(() => {
    const ctx = document.getElementById('scoreChart');
    if (ctx) {
      new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: scoreData.components.map(c => c.factor),
          datasets: [{
            data: scoreData.components.map(c => c.score),
            backgroundColor: [
              'rgba(255, 0, 110, 0.8)',
              'rgba(245, 158, 11, 0.8)',
              'rgba(59, 130, 246, 0.8)',
              'rgba(16, 185, 129, 0.8)'
            ],
            borderColor: '#1a1a2e',
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: { color: '#cbd5e1' }
            }
          }
        }
      });
    }
  }, 100);
}

// Países - Bar Chart
function populateCountriesModal(modalBody) {
  const countriesData = applicationData.detailed_explanations.paises;

  modalBody.innerHTML = `
    <div class="detail-modal-content">
      <p class="detail-description">${countriesData.description}</p>
      <div style="margin-top: 20px; position: relative; height: 300px;">
        <canvas id="countriesChart"></canvas>
      </div>
    </div>
  `;

  setTimeout(() => {
    const ctx = document.getElementById('countriesChart');
    if (ctx) {
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: countriesData.countries.map(c => c.name),
          datasets: [{
            label: 'Amenazas',
            data: countriesData.countries.map(c => c.threats),
            backgroundColor: [
              'rgba(255, 0, 110, 0.7)',
              'rgba(245, 158, 11, 0.7)',
              'rgba(59, 130, 246, 0.7)',
              'rgba(16, 185, 129, 0.7)',
              'rgba(139, 92, 246, 0.7)'
            ],
            borderRadius: 8,
            borderSkipped: false
          }]
        },
        options: {
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: { color: '#cbd5e1' }
            }
          },
          scales: {
            x: {
              grid: { color: 'rgba(203, 213, 225, 0.1)' },
              ticks: { color: '#94a3b8' }
            },
            y: {
              grid: { color: 'rgba(203, 213, 225, 0.1)' },
              ticks: { color: '#94a3b8' }
            }
          }
        }
      });
    }
  }, 100);
}

function initializeThreatAlert() {
  const threatAlert = document.getElementById('threatAlert');
  if (threatAlert) {
    threatAlert.addEventListener('click', function () {
      showNotification('🔍 Desplazando al Panel de Amenazas', 'info');
      // Scroll smoothly to the threat feed
      const mapSection = document.getElementById('threatMap').parentElement.parentElement;
      if (mapSection) {
        mapSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  }
}

function initializeNotificationsButton() {
  const notificationsBtn = document.getElementById('notificationsBtn');
  const markAllReadBtn = document.getElementById('markAllReadBtn');

  if (notificationsBtn) {
    notificationsBtn.addEventListener('click', function () {
      openModal('notificationsModal');
      populateNotificationsModal();
    });
  }

  if (markAllReadBtn) {
    markAllReadBtn.addEventListener('click', function () {
      showNotification('✅ Notificaciones marcadas como leídas', 'success');
      const badge = document.getElementById('notificationCount');
      if (badge) {
        badge.textContent = '0';
        badge.style.display = 'none';
      }
      populateNotificationsModal(true); // Pasar true param para limpiar
    });
  }

  updateNotificationBadge();
}

function updateNotificationBadge() {
  const badge = document.getElementById('notificationCount');
  if (badge) {
    badge.textContent = '3';
    badge.style.display = 'flex';
  }
}

function populateNotificationsModal(clear = false) {
  const modalBody = document.getElementById('notificationsModalBody');
  if (!modalBody) return;

  if (clear) {
    modalBody.innerHTML = `
        <div style="text-align: center; padding: 40px 20px;">
            <i class="fas fa-bell-slash" style="font-size: 40px; color: #334155; margin-bottom: 15px;"></i>
            <h4 style="color: #94a3b8;">No tienes nuevas notificaciones</h4>
        </div>
      `;
    return;
  }

  // Demo notifications data
  const notifs = [
    { id: 1, type: 'critical', title: 'Alerta Crítica: Filtración detectada', desc: 'Se ha comprometido una cuenta de administrador en un servicio conectado.', time: 'Hace 5 min', icon: 'fa-shield-alt', color: '#ef4444' },
    { id: 2, type: 'warning', title: 'Actualización pendiente', desc: 'La API de Shodan requiere renovación de token.', time: 'Hace 2 horas', icon: 'fa-exclamation-triangle', color: '#f59e0b' },
    { id: 3, type: 'success', title: 'Reporte generado', desc: 'El reporte ejecutivo de seguridad está listo para descarga.', time: 'Ayer', icon: 'fa-file-pdf', color: '#10b981' }
  ];

  modalBody.innerHTML = `
    <div class="notifications-list">
        ${notifs.map(n => `
            <div style="display: flex; align-items: start; padding: 15px; border-bottom: 1px solid rgba(203, 213, 225, 0.1); background: rgba(${n.type === 'critical' ? '239, 68, 68' : n.type === 'warning' ? '245, 158, 11' : '16, 185, 129'}, 0.05); border-left: 3px solid ${n.color}; margin-bottom: 10px; border-radius: 4px;">
                <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 50%; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; margin-right: 15px;">
                    <i class="fas ${n.icon}" style="color: ${n.color}; font-size: 16px;"></i>
                </div>
                <div style="flex: 1;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <h4 style="margin: 0; color: #f8fafc; font-size: 14px;">${n.title}</h4>
                        <span style="color: #94a3b8; font-size: 11px;">${n.time}</span>
                    </div>
                    <p style="margin: 0; color: #cbd5e1; font-size: 13px;">${n.desc}</p>
                </div>
            </div>
        `).join('')}
    </div>
  `;
}

// KASPERSKY-STYLE 3D THREAT MAP V4.0 (Globe.gl)
function initializeKasperskyMap() {
  try {
    const mapContainer = document.getElementById('threatMap');
    const threatFeed = document.getElementById('threatFeed');

    if (!mapContainer) {
      console.warn('⚠️ Map container not found');
      return;
    }

    // Limpiar contenedor por si existía el mapa anterior de Leaflet
    mapContainer.innerHTML = '';

    // Check si Globe.gl está disponible
    if (typeof Globe === 'undefined') {
      console.error('Globe.gl no está cargado');
      return;
    }

    // Configurar localizaciones base para conexiones
    const N = 20;
    const arcsData = [...Array(N).keys()].map(() => ({
      startLat: (Math.random() - 0.5) * 180,
      startLng: (Math.random() - 0.5) * 360,
      endLat: (Math.random() - 0.5) * 180,
      endLng: (Math.random() - 0.5) * 360,
      color: applicationData.kaspersky_map_style.threat_types[Math.floor(Math.random() * 4)].color
    }));

    // Localizaciones de anillos (impactos)
    const ringsData = [];
    const threatLocations = [
      { lat: 40.7128, lng: -74.0060, city: 'Nueva York', type: 'DDS' },
      { lat: 51.5074, lng: -0.1278, city: 'Londres', type: 'MAV' },
      { lat: 35.6762, lng: 139.6503, city: 'Tokio', type: 'OAS' },
      { lat: 55.7558, lng: 37.6176, city: 'Moscú', type: 'NAV' },
      { lat: 39.9042, lng: 116.4074, city: 'Beijing', type: 'IDS' },
      { lat: -23.5505, lng: -46.6333, city: 'São Paulo', type: 'DDS' },
      { lat: 52.5200, lng: 13.4050, city: 'Berlín', type: 'MAV' }
    ];

    threatLocations.forEach(loc => {
      const typeInfo = applicationData.kaspersky_map_style.threat_types.find(t => t.name === loc.type) || applicationData.kaspersky_map_style.threat_types[0];
      ringsData.push({
        lat: loc.lat,
        lng: loc.lng,
        maxR: Math.random() * 5 + 3,
        propagationSpeed: Math.random() * 2 + 1,
        repeatPeriod: Math.random() * 1000 + 500,
        color: typeInfo.color
      });
    });

    // Guardar referencia
    window.threatMapInstance = Globe()
      .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
      .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
      .backgroundColor('#0a0a0f') // Color de fondo del card
      .width(mapContainer.clientWidth)
      .height(mapContainer.clientHeight || 650) // Fijar altura dinámica al contenedor
      .arcLabel(() => 'Ataque Detectado')
      .arcStartLat(d => d.startLat)
      .arcStartLng(d => d.startLng)
      .arcEndLat(d => d.endLat)
      .arcEndLng(d => d.endLng)
      .arcColor('color')
      .arcDashLength(0.4)
      .arcDashGap(0.2)
      .arcDashAnimateTime(() => Math.random() * 4000 + 1000)
      .arcsData(arcsData)
      .ringColor('color')
      .ringMaxRadius('maxR')
      .ringPropagationSpeed('propagationSpeed')
      .ringRepeatPeriod('repeatPeriod')
      .ringsData(ringsData)
      (mapContainer);

    // Auto-rotación para darle ese feeling "Kaspersky"
    window.threatMapInstance.controls().autoRotate = true;
    window.threatMapInstance.controls().autoRotateSpeed = 1.0;

    // Zoom inicial para que no se vea tan lejos
    window.threatMapInstance.pointOfView({ altitude: 1.8 });

    // Handle clicks directos en el globo (onGlobeClick)
    window.threatMapInstance.onGlobeClick(({ lat, lng }) => {
      const fakeCountries = ['Rusia', 'Estados Unidos', 'China', 'Irán', 'Alemania', 'Brasil', 'India', 'Corea del Norte', 'Reino Unido', 'Francia'];
      const randomCountry = fakeCountries[Math.floor(Math.random() * fakeCountries.length)];

      const modalBody = document.getElementById('analysisModalBody');
      const modalTitle = document.querySelector('#analysisModal .modal-header h3');
      if (modalBody && modalTitle) {
        modalTitle.innerHTML = `<i class="fas fa-satellite" style="color: #39ff14"></i> Telemetría de Ubicación`;
        modalBody.innerHTML = `
                <div style="padding: 20px; text-align: center;">
                    <h2 style="color: #f8fafc; margin-bottom: 5px;">Origen Estimado: ${randomCountry}</h2>
                    <p style="color: #94a3b8; font-family: monospace; font-size: 14px; margin-bottom: 20px;">Lat: ${lat.toFixed(4)} | Lng: ${lng.toFixed(4)}</p>
                    <p style="color: #cbd5e1; font-size: 15px; margin-bottom: 15px;">Se ha detectado actividad inusual saliente desde este nodo geoespacial. El sistema OSINT AI está interceptando paquetes para determinar la naturaleza de la amenaza.</p>
                    <div style="margin-top: 15px; padding: 15px; background: rgba(57, 255, 20, 0.1); border-radius: 8px; border-left: 4px solid #39ff14;">
                        <i class="fas fa-radar" style="color: #39ff14;"></i> Iniciando análisis profundo de red...
                    </div>
                </div>
            `;
        openModal('analysisModal');

        // Pausar rotación si estaba activa y acercar cámara
        const playPauseBtn = document.getElementById('mapPlayPauseBtn');
        if (window.threatMapInstance.controls().autoRotate) {
          window.threatMapInstance.controls().autoRotate = false;
          if (playPauseBtn) playPauseBtn.innerHTML = '<i class="fas fa-play"></i>';
        }
        window.threatMapInstance.pointOfView({ lat, lng, altitude: 0.6 }, 1000);
      }
    });

    // Box de info objetivo en vivo
    const liveCountryEl = document.getElementById('liveTargetCountry');
    const liveThreatEl = document.getElementById('liveTargetThreat');
    if (liveCountryEl && liveThreatEl) {
      setInterval(() => {
        const countries = ['Rusia', 'EE.UU.', 'China', 'Brasil', 'India', 'Reino Unido', 'Alemania', 'Irán', 'Sudáfrica', 'Japón', 'Australia'];
        const threats = [
          'Ataque DDoS en puerto 443', 'Escaneo masivo de puertos TCP',
          'Infección Botnet detectada', 'Exfiltración de datos sospechosa',
          'Intento de Login por Fuerza Bruta', 'Tráfico C&C identificado'
        ];

        liveCountryEl.textContent = countries[Math.floor(Math.random() * countries.length)];
        liveThreatEl.textContent = threats[Math.floor(Math.random() * threats.length)];

        // Pequeño efecto flash en la caja
        const box = liveCountryEl.parentElement;
        box.style.borderColor = '#39ff14';
        setTimeout(() => { box.style.borderColor = 'rgba(57, 255, 20, 0.3)'; }, 400);
      }, 3500); // Actualizar cada 3.5s
    }

    // Handle window resize
    window.addEventListener('resize', () => {
      if (window.threatMapInstance && mapContainer.clientWidth) {
        window.threatMapInstance.width(mapContainer.clientWidth);
        window.threatMapInstance.height(mapContainer.clientHeight || 650);
      }
    });

    // Añadir ataques aleatorios continuamente
    OSINTApp.threatMapInterval = setInterval(() => {
      updateThreatCounts();

      // Lanzar un nuevo láser/arco
      const newArc = {
        startLat: (Math.random() - 0.5) * 180,
        startLng: (Math.random() - 0.5) * 360,
        endLat: (Math.random() - 0.5) * 180,
        endLng: (Math.random() - 0.5) * 360,
        color: applicationData.kaspersky_map_style.threat_types[Math.floor(Math.random() * 4)].color
      };
      const currentArcs = window.threatMapInstance.arcsData();
      window.threatMapInstance.arcsData([...currentArcs.slice(-20), newArc]);

    }, 2500);

    // Start threat feed
    if (threatFeed) {
      startThreatFeed();
      OSINTApp.threatFeedInterval = setInterval(() => {
        addRandomThreat();
      }, Math.random() * 5000 + 3000);
    }

    // MAP CONTROLS LOGIC
    const playPauseBtn = document.getElementById('mapPlayPauseBtn');
    if (playPauseBtn) {
      let isRotating = true; // Empieza en true
      playPauseBtn.addEventListener('click', () => {
        isRotating = !isRotating;
        if (window.threatMapInstance) {
          window.threatMapInstance.controls().autoRotate = isRotating;
        }
        playPauseBtn.innerHTML = isRotating ? '<i class="fas fa-pause"></i>' : '<i class="fas fa-play"></i>';
        showNotification(isRotating ? '▶️ Rotación del globo reanudada' : '⏸️ Rotación del globo pausada', 'info');
      });
    }

    const zoomGlobalBtn = document.getElementById('mapZoomGlobalBtn');
    if (zoomGlobalBtn) {
      zoomGlobalBtn.addEventListener('click', () => {
        // Globe.gl pointOfView transition
        if (window.threatMapInstance) {
          window.threatMapInstance.pointOfView({ altitude: 1.8 }, 1000);
        }
        showNotification('🌍 Vista global restaurada', 'info');
      });
    }

    // INTERACTIVE LEGENDS LOGIC
    const interactiveLegends = document.querySelectorAll('.interactive-legend');
    interactiveLegends.forEach(legend => {
      legend.addEventListener('click', () => {
        const type = legend.getAttribute('data-threat');
        const descriptions = {
          'OAS': { title: 'On-Access Scan (OAS)', desc: 'Detecta amenazas locales y escanea archivos en el momento en que son accedidos, modificados o guardados por el sistema.' },
          'DDS': { title: 'DDoS Attack (DDS)', desc: 'Intentos de denegación de servicio distribuido. Busca saturar los recursos de red o servidores con tráfico malicioso masivo.' },
          'MAV': { title: 'Mail Anti-Virus (MAV)', desc: 'Detecta y bloquea malware, phishing y enlaces maliciosos presentes en el tráfico de correo electrónico entrante y saliente.' },
          'NAV': { title: 'Network Attack Validator (NAV)', desc: 'Analiza el tráfico a nivel de red para detectar patrones anómalos o intentos de explotación de vulnerabilidades conocidas.' },
          'IDS': { title: 'Intrusion Detection System (IDS)', desc: 'Monitorea activamente la red en busca de actividades sospechosas, intentos de intrusión y violaciones de políticas.' }
        };

        if (type && descriptions[type]) {
          const info = descriptions[type];

          // Usar el modal "analysisModal" para mostrar el detalle de la amenaza legend
          const modalBody = document.getElementById('analysisModalBody');
          const modalTitle = document.querySelector('#analysisModal .modal-header h3');

          if (modalBody && modalTitle) {
            // Sacar el color visual de la leyenda para usarlo en el ícono del modal
            const colorBlob = legend.querySelector('.legend-color');
            const bgColor = colorBlob ? colorBlob.style.background : '#3b82f6';

            modalTitle.innerHTML = `<i class="fas fa-shield-alt" style="color: ${bgColor}"></i> Detalle de Amenaza: ${type}`;
            modalBody.innerHTML = `
                    <div style="padding: 20px; text-align: center;">
                        <h2 style="color: #f8fafc; margin-bottom: 15px;">${info.title}</h2>
                        <p style="color: #cbd5e1; font-size: 16px; line-height: 1.6;">${info.desc}</p>
                        <div style="margin-top: 20px; padding: 15px; background: rgba(59, 130, 246, 0.1); border-radius: 8px; border-left: 4px solid #3b82f6;">
                            <i class="fas fa-info-circle"></i> La telemetría en tiempo real clasifica estos eventos de seguridad a nivel global.
                        </div>
                    </div>
                `;
            openModal('analysisModal');
          } else {
            showNotification(`ℹ️ ${info.title}: ${info.desc}`, 'info');
          }

          // Opcional: enfocar de forma más sutil sin volverse loco
          if (window.threatMapInstance) {
            // Solo movemos el punto de vista sutilmente para interactividad, sin alejarnos o saltar violentamente
            const currentPOV = window.threatMapInstance.pointOfView();
            window.threatMapInstance.pointOfView({ lat: currentPOV.lat + (Math.random() * 10 - 5), lng: currentPOV.lng + (Math.random() * 20 - 10), altitude: currentPOV.altitude }, 1000);
          }
        }
      });
    });

    console.log('✅ Kaspersky 3D Map initialized (Globe.gl) with Modal prompts');

  } catch (error) {
    console.error('❌ Map initialization failed:', error);
  }
}

function showThreatDetails(threat, threatType) {
  // Reutilizaremos un modal genérico o el modal de "Detalles" si lo creamos.
  // Para simplificar, insertamos dinámicamente el contenido en el modal 'scoreModal' o similar,
  // o creamos uno dinámico usando SweetAlert/HTML. 
  // Usaremos una alerta personalizada tipo notificación grande:
  const threatMsg = `
        <div style="background: #1a1a2e; border-left: 4px solid ${threatType.color}; padding: 15px; border-radius: 5px;">
            <h3 style="color: ${threatType.color}; margin-bottom: 5px;">${threatType.name} Detectado</h3>
            <p style="color: #cbd5e1;"><strong>Ubicación:</strong> ${threat.city}</p>
            <p style="color: #cbd5e1;"><strong>Severidad:</strong> Alta</p>
            <p style="color: #94a3b8; font-size: 11px; margin-top: 5px;">Identificador Automático del Sistema de Defensa Activa.</p>
        </div>
    `;

  // Inyectarlo en un contenedor global de información si existe, o usar una notificación expandida
  const notificationContainer = document.querySelector('.notifications-container') || document.body;
  const alertBox = document.createElement('div');
  alertBox.style.position = 'fixed';
  alertBox.style.bottom = '20px';
  alertBox.style.right = '20px';
  alertBox.style.zIndex = '9999';
  alertBox.style.animation = 'slideInRight 0.3s ease forwards';
  alertBox.innerHTML = threatMsg + `<button onclick="this.parentElement.remove()" style="position:absolute; top:5px; right:5px; background:none; border:none; color:#fff; cursor:pointer;"><i class="fas fa-times"></i></button>`;

  notificationContainer.appendChild(alertBox);
  setTimeout(() => alertBox.remove(), 6000);
}

function startThreatFeed() {
  const threatFeed = document.getElementById('threatFeed');
  if (!threatFeed) return;

  // Add initial threats
  for (let i = 0; i < 5; i++) {
    setTimeout(() => addRandomThreat(), i * 500);
  }
}

function addRandomThreat() {
  const threatFeed = document.getElementById('threatFeed');
  if (!threatFeed) return;

  const threatTypes = applicationData.kaspersky_map_style.threat_types;
  const locations = ['Nueva York', 'Londres', 'Tokio', 'Moscú', 'Beijing', 'São Paulo', 'Berlín', 'París'];

  const randomThreat = threatTypes[Math.floor(Math.random() * threatTypes.length)];
  const randomLocation = locations[Math.floor(Math.random() * locations.length)];

  const threatItem = document.createElement('div');
  threatItem.className = `threat-feed-item threat-${randomThreat.name.toLowerCase()}`;
  threatItem.style.borderLeftColor = randomThreat.color;
  threatItem.style.cursor = 'pointer'; // Make it look clickable

  threatItem.innerHTML = `
    <div class="threat-feed-icon" style="color: ${randomThreat.color};">
      <i class="fas fa-shield-alt"></i>
    </div>
    <div class="threat-feed-content">
      <div class="threat-feed-type">${randomThreat.name} detectado</div>
      <div class="threat-feed-details">Origen: ${randomLocation} | Severidad: Alta</div>
      <div class="threat-feed-time">${new Date().toLocaleTimeString()}</div>
    </div>
  `;

  // Añadir evento click al item del feed
  threatItem.addEventListener('click', () => {
    showThreatDetails({ city: randomLocation, type: randomThreat.name }, randomThreat);
  });

  threatFeed.insertBefore(threatItem, threatFeed.firstChild);

  // Keep only last 10 items
  while (threatFeed.children.length > 10) {
    threatFeed.removeChild(threatFeed.lastChild);
  }
}

function updateThreatCounts() {
  applicationData.kaspersky_map_style.threat_types.forEach(threat => {
    const countElement = document.getElementById(threat.name.toLowerCase() + 'Count');
    if (countElement) {
      const currentCount = parseInt(countElement.textContent);
      const increment = Math.floor(Math.random() * 10) + 1;
      countElement.textContent = currentCount + increment;
    }
  });
}

// INTELLIGENCE & AI ANALYSIS UNIFIED SECTION
function initializeIntelligenceSearch() {
  const searchBtn = document.getElementById('startUniversalSearchBtn');
  const searchInput = document.getElementById('universalSearchInput');
  const loader = document.getElementById('aiScannerLoader');
  const resultsContainer = document.getElementById('intelligenceResults');

  if (searchBtn && searchInput) {
    searchBtn.addEventListener('click', () => {
      const target = searchInput.value.trim();

      if (!target) {
        showNotification('❌ Por favor, introduce un objetivo válido (IP, Dominio, Email...)', 'error');
        return;
      }

      // 1. Mostrar Loader
      loader.classList.remove('hidden');
      resultsContainer.classList.add('hidden');
      searchBtn.disabled = true;

      // Actualizar estado del loader
      const statusEl = document.getElementById('scannerStatus');
      const messages = [
        'Estableciendo túneles seguros y evadiendo firewalls...',
        'Interceptando paquetes en nodos de salida TOR...',
        'Cruzando bases de datos de Threat Intelligence globales...',
        'Analizando patrones mediante Red Neuronal Convulcional...'
      ];

      let step = 0;
      const statusInterval = setInterval(() => {
        if (step < messages.length) {
          if (statusEl) statusEl.textContent = messages[step];
          step++;
        }
      }, 800);

      // 2. Simular tiempo de carga (3.5 segundos)
      setTimeout(() => {
        clearInterval(statusInterval);
        loader.classList.add('hidden');
        searchBtn.disabled = false;

        populateIntelligenceResults(target);

        // Revelar contenedor de resultados
        resultsContainer.classList.remove('hidden');

        // Scroll suave hasta los resultados
        resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
        showNotification('✅ Análisis completado con éxito', 'success');

      }, 3500);
    });

    // Permitir "Enter" en el input
    searchInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') searchBtn.click();
    });
  }
}

function populateIntelligenceResults(target) {
  // Rellenamos el nombre del objetivo
  document.getElementById('reportTargetName').textContent = target;

  // Generamos datos aleatorios creíbles para The Threat
  const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);
  const riskScore = Math.floor(Math.random() * 60) + 40; // 40 a 100

  // UI Elements
  const scoreVal = document.getElementById('intelRiskScore');
  const riskCircle = document.getElementById('intelRiskCircle');
  const riskLevel = document.getElementById('intelRiskLevel');
  const riskDesc = document.getElementById('intelRiskDesc');

  // Animación de subida del score
  let currentScore = 0;
  const scoreInt = setInterval(() => {
    currentScore += 2;
    if (currentScore >= riskScore) {
      currentScore = riskScore;
      clearInterval(scoreInt);
    }
    scoreVal.textContent = currentScore;
  }, 20);

  let threatColor = '#10b981'; // Verde
  let levelTxt = 'BAJO';
  let verdict = `El objetivo analizado (${target}) no muestra indicadores de compromiso en las fuentes públicas. El tráfico asociado es benigno.`;

  if (riskScore >= 80) {
    threatColor = '#ef4444'; // Rojo
    levelTxt = 'CRÍTICO';
    riskCircle.style.borderColor = threatColor;
    riskCircle.style.boxShadow = `0 0 20px ${threatColor}`;
    riskDesc.textContent = "El objetivo está clasificado como una amenaza persistente avanzada (APT) o infraestructura maliciosa activa.";
    verdict = `⚠️ ALERTA GRAVE: El modelo neuronal ha detectado que ${target} está listado en 14 repositorios de malware y fue usado en una campaña de Ransomware recientemente. Aísle cualquier sistema conectado a este nodo inmediatamente.`;
    document.getElementById('dataDarkWeb').className = "dark-web-alert danger";
    document.getElementById('dataDarkWeb').innerHTML = "<i class='fas fa-skull'></i> 142 menciones encontradas en foros rusos (Exploit.in, XSS). Posible venta de credenciales.";
  } else if (riskScore >= 60) {
    threatColor = '#f59e0b'; // Naranja
    levelTxt = 'MEDIO / ALTO';
    riskCircle.style.borderColor = threatColor;
    riskCircle.style.boxShadow = `0 0 15px ${threatColor}`;
    riskDesc.textContent = "Actividad sospechosa detectada. El objetivo podría estar involucrado en escaneos masivos o distribución de Adware.";
    verdict = `El objetivo presenta un comportamiento inusual. Se recomienda añadir ${target} a la lista de monitoreo o listas grises preventivas.`;
    document.getElementById('dataDarkWeb').className = "dark-web-alert info";
    document.getElementById('dataDarkWeb').innerHTML = "3 menciones pasivas recuperadas. Sin riesgo inminente.";
  } else {
    riskCircle.style.borderColor = threatColor;
    riskCircle.style.boxShadow = `0 0 10px ${threatColor}`;
    riskDesc.textContent = "Sin indicios de actividad maliciosa. Reputación limpia según los principales vendors de seguridad.";
    document.getElementById('dataDarkWeb').className = "dark-web-alert info";
    document.getElementById('dataDarkWeb').innerHTML = "Sin rastro en repositorios Onion.";
  }

  riskLevel.textContent = levelTxt;
  riskLevel.style.color = threatColor;
  scoreVal.style.color = threatColor;
  document.getElementById('aiVerdictBox').textContent = verdict;
  document.getElementById('aiVerdictBox').style.borderColor = threatColor;

  // Info Geográfica Aleatorizada
  const countries = ['Rusia (RU)', 'Estados Unidos (US)', 'Irlanda (IE)', 'China (CN)', 'Brasil (BR)'];
  document.getElementById('geoCountry').textContent = countries[Math.floor(Math.random() * countries.length)];
  document.getElementById('geoIsp').textContent = isIp ? 'Desconocido Cloud Hosting LLC' : 'Cloudflare Inc. / AWS';
  document.getElementById('geoCoords').textContent = `${(Math.random() * 180 - 90).toFixed(4)}, ${(Math.random() * 360 - 180).toFixed(4)}`;

  // Show map pin
  document.getElementById('targetPin').classList.remove('hidden');

  // Llenar listas de datos (Huella Digital)
  document.getElementById('dataPorts').innerHTML = `
        <li><i class="fas fa-unlock" style="color:#ef4444"></i> 22/tcp (SSH) - OpenSSH 8.2p1</li>
        <li><i class="fas fa-lock" style="color:#10b981"></i> 80/tcp (HTTP) - Nginx 1.18.0</li>
        <li><i class="fas fa-lock" style="color:#10b981"></i> 443/tcp (HTTPS)</li>
    `;

  if (riskScore >= 60) {
    document.getElementById('dataCves').innerHTML = `
            <li><span style="color:#ef4444">CVE-2021-34527</span> (PrintNightmare) - CVSS 8.8</li>
            <li><span style="color:#f59e0b">CVE-2023-38039</span> (HTTP Denial of Service)</li>
        `;
  } else {
    document.getElementById('dataCves').innerHTML = `<li>No se reportaron vulnerabilidades conocidas.</li>`;
  }

  if (!isIp) {
    document.getElementById('dataNames').innerHTML = `
            <li>mail.${target} (A)</li>
            <li>vpn.${target} (CNAME)</li>
            <li>dev.${target} (A)</li>
        `;
  } else {
    document.getElementById('dataNames').innerHTML = `<li>No hay resolución DNS / CNAME pasiva.</li>`;
  }

  // Guardar resultados detallados en el estado global para los reportes
  OSINTApp.searchResults = {
    target: target,
    timestamp: new Date().toISOString(),
    riskScore: riskScore,
    riskLevel: levelTxt,
    verdict: verdict,
    geo: {
      country: document.getElementById('geoCountry').textContent,
      isp: document.getElementById('geoIsp').textContent,
      coords: document.getElementById('geoCoords').textContent
    },
    findings: [
      { tool: 'Port Scanner', result: '22/tcp, 80/tcp, 443/tcp abiertos', status: 'critical', raw: 'OpenSSH 8.2p1, Nginx 1.18.0 detected' },
      { tool: 'CVE Analysis', result: riskScore >= 60 ? 'CVE-2021-34527 detectado' : 'No se detectaron vulnerabilidades críticas', status: riskScore >= 60 ? 'danger' : 'success', raw: riskScore >= 60 ? 'CVSS 8.8 (PrintNightmare)' : 'Clean scan' },
      { tool: 'Dark Web Scan', result: riskScore >= 80 ? '142 menciones en foros' : 'Sin presencia detectada', status: riskScore >= 80 ? 'danger' : 'info', raw: riskScore >= 80 ? 'Exploit.in, XSS mentions found' : 'No onion records' },
      { tool: 'DNS/Whois', result: isIp ? 'Hosting desconocido' : 'Cloudflare/AWS detectado', status: 'info', raw: isIp ? 'Reverse DNS not available' : 'CNAME: vpn.' + target }
    ]
  };
}

// EXPORT RESULTS (PDF / JSON)
function initializeExportButtons() {
  const btnPdf = document.getElementById('btnExportPdf');
  const btnJson = document.getElementById('btnExportJson');

  const btnSave = document.getElementById('btnSaveReport');

  if (btnPdf) {
    btnPdf.addEventListener('click', () => {
      showNotification('📄 Generando PDF premium...', 'info');

      const element = document.getElementById('intelligenceResults');
      if (!element) return;

      setTimeout(async () => {
        try {
          const { jsPDF } = window.jspdf;
          const canvas = await html2canvas(element, {
            backgroundColor: '#0f172a',
            scale: 2,
            logging: false,
            useCORS: true
          });

          const imgData = canvas.toDataURL('image/png');
          const pdf = new jsPDF('p', 'mm', 'a4');
          const imgProps = pdf.getImageProperties(imgData);
          const pdfWidth = pdf.internal.pageSize.getWidth();
          const pdfHeight = (imgProps.height * pdfWidth) / imgProps.width;

          pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
          pdf.save(`osint_intel_${Date.now()}.pdf`);
          showNotification('✅ PDF generado con éxito', 'success');
        } catch (err) {
          console.error('Error generando PDF:', err);
          showNotification('❌ Error al generar PDF. Usando impresión nativa.', 'error');
          window.print();
        }
      }, 500);
    });
  }

  if (btnSave) {
    btnSave.addEventListener('click', () => {
      if (!OSINTApp.searchResults) {
        showNotification('⚠️ No hay resultados para guardar', 'warning');
        return;
      }

      const reportName = prompt('Nombre para el reporte:', `Investigación ${OSINTApp.searchResults.target}`);
      if (!reportName) return;

      const newReport = {
        id: Date.now(),
        name: reportName,
        type: 'inteligencia',
        created: new Date().toLocaleString(),
        data: OSINTApp.searchResults
      };

      OSINTApp.reports.unshift(newReport);
      localStorage.setItem('osint_reports', JSON.stringify(OSINTApp.reports));
      showNotification('✅ Reporte guardado correctamente en la sección Reportes', 'success');

      // Force update of the list
      if (typeof renderReportsList === 'function') {
        renderReportsList();
      }
    });
  }

  if (btnJson) {
    btnJson.addEventListener('click', () => {
      const target = document.getElementById('reportTargetName').textContent;
      const risk = document.getElementById('intelRiskScore').textContent;

      const mockData = {
        target: target,
        timestamp: new Date().toISOString(),
        risk_score: risk,
        threat_level: document.getElementById('intelRiskLevel').textContent,
        geo_location: {
          country: document.getElementById('geoCountry').textContent,
          isp: document.getElementById('geoIsp').textContent
        },
        verdict: document.getElementById('aiVerdictBox').textContent
      };

      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(mockData, null, 2));
      const downloadAnchorNode = document.createElement('a');
      downloadAnchorNode.setAttribute("href", dataStr);
      downloadAnchorNode.setAttribute("download", `OSINT_Report_${target}.json`);
      document.body.appendChild(downloadAnchorNode); // required for firefox
      downloadAnchorNode.click();
      downloadAnchorNode.remove();

      showNotification('Archivo JSON generado correctamente', 'success');
    });
  }
}

// Ensure exports are initialized
document.addEventListener('DOMContentLoaded', () => {
  // ... existings initializations
  initializeExportButtons();
});

function exportSearchResults(format) {
  if (!OSINTApp.searchResults) {
    showNotification('⚠️ No hay resultados para exportar', 'warning');
    return;
  }

  if (format === 'json') {
    const blob = new Blob([JSON.stringify(OSINTApp.searchResults, null, 2)], { type: 'application/json' });
    downloadFile(blob, `osint-analysis-${OSINTApp.searchResults.query}-${Date.now()}.json`);
    showNotification('✅ Resultados exportados en JSON', 'success');
  }
}

function downloadFile(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ANALYSIS IA
function initializeAnalysisIA() {
  const analyzeMyNetworkBtn = document.getElementById('analyzeMyNetworkBtn');
  const targetInput = document.getElementById('universalSearchInput');

  if (analyzeMyNetworkBtn && targetInput) {
    analyzeMyNetworkBtn.addEventListener('click', () => {
      executeNetworkAnalysis();
    });
  }
}

function executeNetworkAnalysis() {
  const targetInput = document.getElementById('universalSearchInput');
  const intelligenceNav = document.querySelector('[data-section="intelligence"]');

  // Navegar a inteligencia si no estamos ahí
  if (intelligenceNav) intelligenceNav.click();

  showNotification('🌐 Detectando IP pública...', 'info');

  fetch('https://api.ipify.org?format=json')
    .then(res => res.json())
    .then(data => {
      if (targetInput) {
        targetInput.value = data.ip;
        showNotification('🌐 IP Pública detectada: ' + data.ip, 'info');

        // Ejecutar búsqueda automáticamente
        const searchBtn = document.getElementById('startUniversalSearchBtn');
        if (searchBtn) {
          setTimeout(() => searchBtn.click(), 500);
        }
      }
    })
    .catch(() => {
      if (targetInput) {
        targetInput.value = '127.0.0.1';
        showNotification('🌐 Error detectando IP pública. Usando localhost.', 'warning');
        const searchBtn = document.getElementById('startUniversalSearchBtn');
        if (searchBtn) setTimeout(() => searchBtn.click(), 500);
      }
    });
}

function initializeDashboardShortcuts() {
  const networkCard = document.getElementById('networkAnalysisCard');
  if (networkCard) {
    networkCard.addEventListener('click', () => {
      executeNetworkAnalysis();
    });
  }
}

function initializeThemeToggle() {
  const themeBtn = document.getElementById('themeToggleBtn');
  if (!themeBtn) return;

  // Cargar modo guardado
  const currentTheme = localStorage.getItem('osint-theme') || 'dark';
  document.documentElement.setAttribute('data-color-scheme', currentTheme);
  updateThemeIcon(currentTheme);

  themeBtn.addEventListener('click', () => {
    const newTheme = document.documentElement.getAttribute('data-color-scheme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-color-scheme', newTheme);
    localStorage.setItem('osint-theme', newTheme);
    updateThemeIcon(newTheme);
    showNotification(`🌗 Modo ${newTheme === 'dark' ? 'Oscuro' : 'Claro'} activado`, 'info');
  });
}

function updateThemeIcon(theme) {
  const themeBtn = document.getElementById('themeToggleBtn');
  if (themeBtn) {
    themeBtn.innerHTML = theme === 'dark' ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
  }
}

// TOOLS SECTION — v2.0 (inline panel, toggles, search)

// Load enabled tools from localStorage or default all to enabled
function getEnabledTools() {
  const saved = localStorage.getItem('osint_enabled_tools');
  if (saved) return JSON.parse(saved);
  const defaults = {};
  Object.values(toolsDatabase).forEach(cat => {
    cat.tools.forEach(tool => { defaults[tool.name] = true; });
  });
  return defaults;
}

function saveEnabledTools(state) {
  localStorage.setItem('osint_enabled_tools', JSON.stringify(state));
}

function initializeToolsSection() {
  const toolsContainer = document.getElementById('toolsCategories');
  if (!toolsContainer) return;

  const enabledTools = getEnabledTools();
  OSINTApp.enabledTools = enabledTools;

  renderToolsGrid(toolsContainer, enabledTools);
  initToolsSearch(toolsContainer);
  updateToolsStats();
}

function renderToolsGrid(container, enabledTools, searchFilter = '') {
  const html = Object.entries(toolsDatabase).map(([categoryName, category]) => {
    const filteredTools = category.tools.filter(t =>
      searchFilter === '' ||
      t.name.toLowerCase().includes(searchFilter) ||
      t.shortDesc.toLowerCase().includes(searchFilter)
    );
    if (filteredTools.length === 0) return '';

    return `
      <div class="tool-category-panel" data-category="${categoryName}">
        <div class="category-panel-header" style="border-left: 4px solid ${category.color}; background: ${category.gradient};">
          <div class="category-panel-icon" style="color: ${category.color};">
            <i class="${category.icon}"></i>
          </div>
          <div class="category-panel-info">
            <h3>${categoryName}</h3>
            <p>${category.description}</p>
          </div>
          <div class="category-panel-badge" style="background: ${category.color}20; border: 1px solid ${category.color}40; color: ${category.color};">
            ${filteredTools.filter(t => enabledTools[t.name] !== false).length}/${filteredTools.length} activas
          </div>
        </div>
        <div class="tool-cards-grid">
          ${filteredTools.map(tool => {
      const isEnabled = enabledTools[tool.name] !== false;
      return `
              <div class="tool-card ${isEnabled ? 'tool-card--enabled' : 'tool-card--disabled'}" data-tool-name="${tool.name}" style="--tool-color: ${category.color};">
                <div class="tool-card-top">
                  <div class="tool-card-icon" style="background: ${category.color}15; color: ${category.color};">
                    <i class="${tool.icon}"></i>
                  </div>
                  <label class="tool-toggle" title="${isEnabled ? 'Desactivar herramienta' : 'Activar herramienta'}">
                    <input type="checkbox" class="tool-toggle-input" data-tool="${tool.name}" ${isEnabled ? 'checked' : ''}>
                    <span class="tool-toggle-track"></span>
                  </label>
                </div>
                <div class="tool-card-info">
                  <h4 class="tool-card-name">${tool.name}</h4>
                  <p class="tool-card-short">${tool.shortDesc}</p>
                  <p class="tool-card-desc">${tool.description}</p>
                </div>
                <div class="tool-card-actions">
                  <button class="tool-run-btn" data-tool='${JSON.stringify(tool).replace(/'/g, "&#39;")}' ${isEnabled ? '' : 'disabled'}
                    style="--btn-color: ${category.color};">
                    <i class="fas fa-play"></i>
                    Ejecutar
                  </button>
                </div>
              </div>
            `;
    }).join('')}
        </div>
      </div>
    `;
  }).join('');

  container.innerHTML = html || '<div class="tools-no-results"><i class="fas fa-search"></i><p>No se encontraron herramientas</p></div>';

  // Attach toggle event listeners
  container.querySelectorAll('.tool-toggle-input').forEach(input => {
    input.addEventListener('change', function () {
      const toolName = this.dataset.tool;
      OSINTApp.enabledTools[toolName] = this.checked;
      saveEnabledTools(OSINTApp.enabledTools);

      // Update card state
      const card = this.closest('.tool-card');
      if (card) {
        card.classList.toggle('tool-card--enabled', this.checked);
        card.classList.toggle('tool-card--disabled', !this.checked);
        const runBtn = card.querySelector('.tool-run-btn');
        if (runBtn) runBtn.disabled = !this.checked;
      }

      updateToolsStats();
      showNotification(
        this.checked ? `✅ ${toolName} activada` : `⚫ ${toolName} desactivada`,
        this.checked ? 'success' : 'info'
      );
    });
  });

  // Attach run button listeners
  container.querySelectorAll('.tool-run-btn:not([disabled])').forEach(btn => {
    btn.addEventListener('click', function () {
      const toolData = JSON.parse(this.getAttribute('data-tool').replace(/&#39;/g, "'"));
      openInlineToolPanel(toolData);
    });
  });
}

function initToolsSearch(container) {
  const searchInput = document.getElementById('toolsSearchInput');
  if (!searchInput) return;
  searchInput.addEventListener('input', function () {
    const enabledTools = OSINTApp.enabledTools || getEnabledTools();
    renderToolsGrid(container, enabledTools, this.value.toLowerCase().trim());
  });
}

function updateToolsStats() {
  const enabledTools = OSINTApp.enabledTools || getEnabledTools();
  let total = 0, active = 0;
  Object.values(toolsDatabase).forEach(cat => {
    cat.tools.forEach(tool => {
      total++;
      if (enabledTools[tool.name] !== false) active++;
    });
  });
  const statsEl = document.getElementById('toolsActiveCount');
  if (statsEl) statsEl.textContent = `${active} / ${total} herramientas activas`;
}

// ── INLINE EXECUTION PANEL ──
function openInlineToolPanel(toolData) {
  const panel = document.getElementById('toolInlinePanel');
  const panelTitle = document.getElementById('inlinePanelTitle');
  const panelIcon = document.getElementById('inlinePanelIcon');
  const formArea = document.getElementById('inlinePanelForm');
  const resultsArea = document.getElementById('inlinePanelResults');

  if (!panel) return;

  // Set header
  if (panelTitle) panelTitle.textContent = toolData.name;
  if (panelIcon) panelIcon.className = toolData.icon;

  // Reset results
  if (resultsArea) resultsArea.innerHTML = '<div class="inline-results-placeholder"><i class="fas fa-terminal"></i><p>Esperando parámetros...</p></div>';

  // Build form
  if (formArea && toolData.form) {
    let formHTML = `<form id="inlineToolForm" class="inline-tool-form">`;
    toolData.form.fields.forEach(field => {
      formHTML += `<div class="inline-form-group">`;
      formHTML += `<label class="inline-form-label">${field.label}${field.required ? ' <span class="req">*</span>' : ''}</label>`;
      if (field.type === 'select') {
        formHTML += `<select name="${field.name}" class="inline-form-control" ${field.required ? 'required' : ''}>`;
        field.options.forEach(opt => { formHTML += `<option value="${opt}">${opt}</option>`; });
        formHTML += `</select>`;
      } else {
        formHTML += `<input type="${field.type}" name="${field.name}" class="inline-form-control" placeholder="${field.placeholder || ''}" ${field.required ? 'required' : ''}>`;
      }
      formHTML += `</div>`;
    });
    formHTML += `</form>`;
    formArea.innerHTML = formHTML;
  }

  // Wire up Execute button
  const execBtn = document.getElementById('inlinePanelExecBtn');
  if (execBtn) {
    const newBtn = execBtn.cloneNode(true);
    execBtn.parentNode.replaceChild(newBtn, execBtn);
    newBtn.addEventListener('click', () => executeInlineTool(toolData));
  }

  // Show panel
  panel.classList.add('tool-panel--open');
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function closeInlineToolPanel() {
  const panel = document.getElementById('toolInlinePanel');
  if (panel) panel.classList.remove('tool-panel--open');
}

async function executeInlineTool(toolData) {
  const form = document.getElementById('inlineToolForm');
  const resultsArea = document.getElementById('inlinePanelResults');

  if (!form || !form.checkValidity()) {
    showNotification('⚠️ Completa los campos requeridos', 'warning');
    if (form) form.reportValidity();
    return;
  }

  const params = Object.fromEntries(new FormData(form).entries());

  resultsArea.innerHTML = `
    <div class="inline-results-loading">
      <div class="loading-spinner"></div>
      <p>Ejecutando <strong>${toolData.name}</strong>...</p>
    </div>`;

  const execBtn = document.getElementById('inlinePanelExecBtn');
  if (execBtn) { execBtn.disabled = true; execBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Ejecutando...'; }

  try {
    let result = null;
    let endpoint = '';

    switch (toolData.name) {
      case 'WHOIS':
        endpoint = `/api/whois?domain=${encodeURIComponent(params.domain)}`; break;
      case 'DNS Lookup':
      case 'MX Records':
        const dnsType = params.type || 'MX';
        endpoint = `/api/dns?domain=${encodeURIComponent(params.domain)}&type=${encodeURIComponent(dnsType)}`; break;
      case 'IP Geolocation':
      case 'IP Blacklist Check':
        endpoint = `/api/ipinfo?ip=${encodeURIComponent(params.ip)}`; break;
      case 'URL Scanner':
      case 'HTTP Headers':
        endpoint = `/api/virustotal?url=${encodeURIComponent(params.url)}`; break;
      case 'Domain Reputation':
        endpoint = `/api/virustotal?url=${encodeURIComponent(params.domain)}`; break;
      case 'Breach Hunter':
        endpoint = `/api/hibp?email=${encodeURIComponent(params.email)}`; break;
      case 'Hash Analyzer':
        endpoint = `/api/virustotal?hash=${encodeURIComponent(params.hash)}`; break;
      default:
        await new Promise(r => setTimeout(r, 1200 + Math.random() * 800));
        result = simulateToolResult(toolData, params);
    }

    if (endpoint) {
      try {
        const resp = await fetch(endpoint);
        const contentType = resp.headers.get('content-type') || '';

        if (!resp.ok || !contentType.includes('application/json')) {
          // API not available locally — use rich simulation
          console.info(`[OSINT] API endpoint ${endpoint} not available, using simulation for ${toolData.name}`);
          await new Promise(r => setTimeout(r, 800 + Math.random() * 600));
          result = simulateToolResult(toolData, params);
          result._note = '⚡ Modo simulación (API no disponible en local)';
        } else {
          result = await resp.json();
        }
      } catch (fetchErr) {
        // Network error (e.g. file:// protocol) — use simulation
        console.info(`[OSINT] Fetch failed for ${toolData.name}, falling back to simulation`);
        await new Promise(r => setTimeout(r, 600 + Math.random() * 600));
        result = simulateToolResult(toolData, params);
        result._note = '⚡ Modo simulación (sin conexión a APIs)';
      }
    }

    renderInlineResults(resultsArea, toolData, result, true);
    showNotification(`✅ ${toolData.name} completado`, 'success');
  } catch (err) {
    renderInlineResults(resultsArea, toolData, { error: err.message }, false);
    showNotification(`❌ ${err.message}`, 'error');
  } finally {
    if (execBtn) { execBtn.disabled = false; execBtn.innerHTML = '<i class="fas fa-play"></i> Ejecutar'; }
  }
}

function simulateToolResult(toolData, params) {
  const simulations = {
    'Port Scanner': { open_ports: ['22/tcp (SSH)', '80/tcp (HTTP)', '443/tcp (HTTPS)', '8080/tcp (HTTP-ALT)'], host: params.target, scan_time: '2.3s', total_scanned: 1000 },
    'SSL Checker': { valid: true, issuer: 'Let\'s Encrypt', expires: '2025-06-15', grade: 'A+', protocols: ['TLSv1.2', 'TLSv1.3'], vulnerabilities: 'None detected' },
    'Traceroute': { hops: [{ ttl: 1, ip: '192.168.1.1', rtt: '1ms' }, { ttl: 2, ip: '10.0.0.1', rtt: '5ms' }, { ttl: 8, ip: params.target, rtt: '32ms' }] },
    'Shodan Search': { total: 127, results: [{ ip: '45.33.32.156', port: 80, org: 'Linode', os: 'Linux' }, { ip: '172.217.14.110', port: 443, org: 'Google', os: 'Unknown' }] },
    'Email Verifier': { valid: true, format: 'correct', domain_exists: true, mx_found: true, smtp_check: 'deliverable', score: 95 },
    'Username Search': { found: 8, platforms: ['GitHub', 'Reddit', 'Twitter/X', 'LinkedIn', 'Steam', 'Twitch', 'HackerNews', 'GitLab'], query: params.username },
    'Phone Lookup': { valid: true, country: 'Spain', carrier: 'Vodafone', type: 'mobile', formatted: params.phone },
    'Image Reverse': { matches: 3, sources: ['Google Images (23 results)', 'Yandex Images (5 results)', 'TinEye (2 matches)'] },
    'Paste Search': { results: 2, pastes: [{ site: 'Pastebin', date: '2024-01-15', preview: 'Found in credential dump...', url: '#' }, { site: 'GitHub Gist', date: '2023-11-20', preview: 'Config file mention...', url: '#' }] },
    'Profile Analyzer': { activity_hours: '20:00-23:00 UTC+1', languages: ['es', 'en'], sentiment: 'neutral (62%)', estimated_age_range: '25-35', linked_accounts: [] },
    'Metadata Extractor': { format: 'JPEG', gps: 'Not embedded', camera: 'iPhone 15 Pro', software: 'Adobe Lightroom 6.0', created: '2024-08-22T14:30:00' },
    'IP Blacklist Check': { blacklisted: false, checked_lists: 112, clean_lists: 112, ip: params.ip },
    'HTTP Headers': { server: 'nginx/1.18.0', x_powered_by: 'Not exposed', hsts: true, csp: 'present', x_frame_options: 'SAMEORIGIN', security_score: '8/10' },
    'SPF/DKIM Check': { spf: 'pass (v=spf1 include:_spf.google.com ~all)', dkim: 'pass (2048-bit RSA)', dmarc: 'p=reject (strict)', score: 'A+' },
    'Subdomain Finder': { found: 7, subdomains: ['www', 'mail', 'api', 'cdn', 'staging', 'admin', 'status'].map(s => `${s}.${params.domain || 'example.com'}`) }
  };
  return simulations[toolData.name] || { simulated: true, tool: toolData.name, params };
}

function renderInlineResults(container, toolData, result, success) {
  if (!success) {
    container.innerHTML = `
      <div class="inline-result-error">
        <i class="fas fa-exclamation-triangle"></i>
        <div>
          <h5>Error de Ejecución</h5>
          <p>${result.error || 'Error desconocido'}</p>
        </div>
      </div>`;
    return;
  }

  // Build a pretty key-value table
  const rows = Object.entries(result).map(([k, v]) => {
    const val = Array.isArray(v)
      ? `<ul class="result-list">${v.map(i => typeof i === 'object' ? `<li><code>${JSON.stringify(i)}</code></li>` : `<li>${i}</li>`).join('')}</ul>`
      : typeof v === 'object'
        ? `<pre class="result-code">${JSON.stringify(v, null, 2)}</pre>`
        : `<span class="result-val">${v}</span>`;
    const keyLabel = k.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    return `<tr><td class="result-key">${keyLabel}</td><td class="result-value">${val}</td></tr>`;
  }).join('');

  container.innerHTML = `
    <div class="inline-result-success">
      <div class="inline-result-header">
        <i class="fas fa-check-circle"></i>
        <span>${toolData.name} — Resultado</span>
        <span class="inline-result-ts">${new Date().toLocaleTimeString()}</span>
        <button class="inline-copy-btn" onclick="copyResultToClipboard(this)" data-result='${JSON.stringify(result)}'>
          <i class="fas fa-copy"></i> Copiar
        </button>
      </div>
      <div class="inline-result-body">
        <table class="result-table">${rows}</table>
      </div>
    </div>`;
}

function copyResultToClipboard(btn) {
  const data = btn.getAttribute('data-result');
  navigator.clipboard.writeText(JSON.stringify(JSON.parse(data), null, 2)).then(() => {
    showNotification('📋 Resultado copiado al portapapeles', 'success');
  });
}

// REPORTS SECTION
function initializeReportsSection() {
  const createReportBtn = document.getElementById('createReportBtn');
  if (createReportBtn) {
    createReportBtn.addEventListener('click', () => openModal('reportModal'));
  }

  // Si existe un botón de "Generar Reporte" global (por ejemplo de Investigación Inteligente)
  const generateReportFromTestsBtn = document.getElementById('generateReportFromTests');
  if (generateReportFromTestsBtn) {
    generateReportFromTestsBtn.addEventListener('click', () => openModal('reportModal'));
  }
  const generateReportFromResultsBtn = document.getElementById('generateReportFromResults');
  if (generateReportFromResultsBtn) {
    generateReportFromResultsBtn.addEventListener('click', () => openModal('reportModal'));
  }

  // Generar reporte en el modal
  const generateReportBtn = document.getElementById('generateReportBtn');
  if (generateReportBtn) {
    const newBtn = generateReportBtn.cloneNode(true);
    generateReportBtn.parentNode.replaceChild(newBtn, generateReportBtn);

    newBtn.addEventListener('click', function () {
      const reportName = document.getElementById('reportName')?.value.trim();
      const reportType = document.getElementById('reportType')?.value || 'executive';

      if (!reportName) {
        showNotification('⚠️ Ingresa nombre del reporte', 'warning');
        return;
      }

      const newReport = {
        id: `RPT-${Date.now()}`,
        name: reportName,
        type: reportType,
        created: new Date().toLocaleDateString() + ' ' + new Date().toLocaleTimeString(),
        status: 'Completado',
        data: OSINTApp.searchResults || null
      };

      // Guardar en la variable local y en localStorage
      OSINTApp.reports.unshift(newReport);
      localStorage.setItem('osint_reports', JSON.stringify(OSINTApp.reports));

      showNotification(`✅ Reporte "${reportName}" generado y guardado localmente`, 'success');
      closeAllModals();
      renderReportsList(); // Refrescar lista

      // Limpiar input
      if (document.getElementById('reportName')) document.getElementById('reportName').value = '';
    });
  }

  // Cargar reportes del localStorage si existen
  const savedReports = localStorage.getItem('osint_reports');
  if (savedReports) {
    try {
      OSINTApp.reports = JSON.parse(savedReports);
    } catch (e) {
      console.error("Error cargando reportes", e);
      OSINTApp.reports = [];
    }
  }

  renderReportsList();
}

function renderReportsList() {
  const container = document.getElementById('existingReports');
  if (!container) return;

  if (OSINTApp.reports.length === 0) {
    container.innerHTML = '<p style="color: #94a3b8; grid-column: 1/-1;">No tienes reportes guardados todavía.</p>';
    return;
  }

  container.innerHTML = OSINTApp.reports.map((report, index) => `
        <div class="report-card" style="display: flex; flex-direction: column; justify-content: space-between; border-left: 4px solid var(--color-primary); background: rgba(30, 41, 59, 0.4); border-radius: 12px; padding: 18px; transition: all 0.3s ease;">
            <div class="report-header" style="margin-bottom: 15px;">
                <div>
                    <span class="report-type" style="font-size: 10px; padding: 2px 8px; border-radius: 10px; background: rgba(56, 189, 248, 0.1); color: #38bdf8; text-transform: uppercase;">${report.type}</span>
                    <h4 class="report-title" style="margin-top: 8px; font-size: 16px; color: #f8fafc;">${report.name}</h4>
                    <p style="font-size: 11px; color: #94a3b8; margin-top: 4px;"><i class="fas fa-calendar-alt"></i> ${report.created}</p>
                </div>
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                <button class="btn btn--primary btn--sm" onclick="viewReportDetails(${index})" style="flex: 1 1 100%; border-radius: 6px; padding: 10px; font-weight: 500;"><i class="fas fa-eye"></i> Ver Análisis</button>
                <button class="btn btn--outline btn--sm" onclick="exportReport(${index}, 'json')" style="flex: 1; min-width: 80px; font-size: 12px;"><i class="fas fa-file-code"></i> JSON</button>
                <button class="btn btn--outline btn--sm" onclick="exportReport(${index}, 'pdf')" style="flex: 1; min-width: 80px; font-size: 12px;"><i class="fas fa-file-pdf"></i> PDF</button>
                <button class="btn btn--outline btn--sm" onclick="deleteReport(${index})" style="color: #ef4444; border-color: rgba(239, 68, 68, 0.3);"><i class="fas fa-trash"></i></button>
            </div>
        </div>
    `).join('');
}

window.viewReportDetails = function (index) {
  const report = OSINTApp.reports[index];
  if (!report || !report.data) {
    showNotification('⚠️ Este reporte no contiene datos de análisis.', 'warning');
    return;
  }

  const data = report.data;
  const modalBody = document.getElementById('analysisModalBody');
  const modalTitle = document.querySelector('#analysisModal .modal-header h3');

  if (modalBody && modalTitle) {
    modalTitle.innerHTML = `<i class="fas fa-file-alt" style="color: #38bdf8"></i> Reporte: ${report.name}`;

    let findingsHtml = '';
    if (data.findings) {
      findingsHtml = `
            <div style="margin-top: 20px;">
                <h4 style="color: #38bdf8; margin-bottom: 10px; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;">Hallazgos por herramienta:</h4>
                <div style="display: grid; gap: 10px;">
                    ${data.findings.map(f => `
                        <div style="background: rgba(15, 23, 42, 0.6); border-left: 3px solid ${f.status === 'danger' || f.status === 'critical' ? '#ef4444' : f.status === 'warning' ? '#f59e0b' : '#10b981'}; padding: 12px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.05);">
                            <div style="font-weight: bold; color: #f8fafc; font-size: 13px; margin-bottom: 4px; display: flex; justify-content: space-between;">
                                <span>${f.tool}</span>
                                <span style="font-size: 10px; opacity: 0.7;">${f.status.toUpperCase()}</span>
                            </div>
                            <div style="color: #94a3b8; font-size: 11px; font-family: monospace; border-top: 1px solid rgba(255,255,255,0.05); margin-top: 5px; padding-top: 5px; opacity: 0.8;">${f.raw || ''}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
          `;
    }

    modalBody.innerHTML = `
          <div style="padding: 5px;">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; background: linear-gradient(135deg, rgba(56, 189, 248, 0.15) 0%, rgba(56, 189, 248, 0.05) 100%); padding: 18px; border-radius: 12px; border: 1px solid rgba(56, 189, 248, 0.3);">
                  <div>
                      <h4 style="color: #f8fafc; margin-bottom: 5px; font-size: 18px;">${data.target}</h4>
                      <p style="color: #94a3b8; font-size: 12px;"><i class="fas fa-calendar-alt"></i> Generado el ${report.created}</p>
                      <p style="color: #94a3b8; font-size: 12px;"><i class="fas fa-tag"></i> Tipo: ${report.type.toUpperCase()}</p>
                  </div>
                  <div style="text-align: right;">
                      <div style="font-size: 32px; font-weight: 800; color: ${data.riskLevel === 'CRÍTICO' ? '#ef4444' : data.riskLevel.includes('ALTO') ? '#f59e0b' : '#10b981'}; text-shadow: 0 0 15px rgba(0,0,0,0.5);">${data.riskScore}%</div>
                      <div style="font-size: 10px; color: #94a3b8; font-weight: bold; letter-spacing: 1px;">RISK SCORE</div>
                      <div style="font-size: 12px; margin-top: 5px; color: ${data.riskLevel === 'CRÍTICO' ? '#ef4444' : data.riskLevel.includes('ALTO') ? '#f59e0b' : '#10b981'}; font-weight: bold;">${data.riskLevel}</div>
                  </div>
              </div>
              
              <div style="margin-bottom: 15px; display: flex; gap: 10px;">
                  <button class="btn btn--primary btn--sm" onclick="exportReport(${index}, 'pdf')" style="flex: 1;"><i class="fas fa-download"></i> Descargar PDF</button>
                  <button class="btn btn--outline btn--sm" onclick="exportReport(${index}, 'json')" style="flex: 1;"><i class="fas fa-file-code"></i> Data JSON</button>
              </div>

              <div style="margin-bottom: 25px; padding: 15px; background: rgba(0,0,0,0.2); border-radius: 8px; border: 1px dashed rgba(255,255,255,0.1);">
                  <h4 style="color: #38bdf8; margin-bottom: 8px; font-size: 14px; text-transform: uppercase;">Conclusión de la IA:</h4>
                  <p style="color: #cbd5e1; font-size: 14px; line-height: 1.6; font-style: italic;">"${data.verdict}"</p>
              </div>

              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                  <div style="background: rgba(30, 41, 59, 0.4); padding: 12px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.05);">
                      <div style="color: #94a3b8; font-size: 10px; text-transform: uppercase; margin-bottom: 4px;">Ubicación Detectada</div>
                      <div style="color: #f8fafc; font-size: 14px; font-weight: 500;"><i class="fas fa-map-marker-alt" style="color: #38bdf8; margin-right: 5px;"></i> ${data.geo.country}</div>
                  </div>
                  <div style="background: rgba(30, 41, 59, 0.4); padding: 12px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.05);">
                      <div style="color: #94a3b8; font-size: 10px; text-transform: uppercase; margin-bottom: 4px;">Proveedor de Red</div>
                      <div style="color: #f8fafc; font-size: 14px; font-weight: 500;"><i class="fas fa-server" style="color: #38bdf8; margin-right: 5px;"></i> ${data.geo.isp}</div>
                  </div>
              </div>

              ${findingsHtml}
          </div>
      `;
    openModal('analysisModal');
  }
}

window.exportReport = async function (index, format) {
  const report = OSINTApp.reports[index];
  if (!report) return;

  if (format === 'json') {
    // Si exportas a JSON, ahora incluirá el campo aiAnalysis si existe
    const dataToExport = { ...report, exportedAt: new Date().toISOString() };
    const blob = new Blob([JSON.stringify(dataToExport, null, 2)], { type: 'application/json' });
    downloadFile(blob, `report-${report.id}.json`);
    showNotification(`✅ Reporte JSON exportado`, 'success');
  } else if (format === 'pdf') {
    showNotification('📄 Generando PDF con Inteligencia Forense...', 'info');

    // IMPORTANTE: Forzamos la vista de detalles para que el modal se actualice con la IA
    viewReportDetails(index);

    setTimeout(async () => {
      const element = document.getElementById('analysisModalBody');
      if (!element) return;

      try {
        const { jsPDF } = window.jspdf;
        // Capturamos el modal incluyendo la nueva sección de IA
        const canvas = await html2canvas(element, {
          backgroundColor: '#0a0a0f', // Color de tu fondo oscuro
          scale: 2,
          logging: false,
          useCORS: true
        });

        const imgData = canvas.toDataURL('image/png');
        const pdf = new jsPDF('p', 'mm', 'a4');
        const pdfWidth = pdf.internal.pageSize.getWidth();
        const pdfHeight = (canvas.height * pdfWidth) / canvas.width;

        pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
        pdf.save(`OSINT_AI_PRO_REPORT_${report.id}.pdf`);
        showNotification('✅ PDF generado con éxito', 'success');
      } catch (err) {
        console.error('Error generando PDF:', err);
        showNotification('❌ Error al generar PDF.', 'error');
      }
    }, 1000); // Damos un poco más de tiempo para que la IA se renderice bien
  }
};

window.deleteReport = function (index) {
  if (confirm('¿Seguro que deseas eliminar este reporte permanentemente?')) {
    OSINTApp.reports.splice(index, 1);
    localStorage.setItem('osint_reports', JSON.stringify(OSINTApp.reports));
    renderReportsList();
    showNotification('🗑️ Reporte eliminado', 'info');
  }
};

function closeAllModals() {
  document.querySelectorAll('.modal').forEach(m => {
    m.classList.remove('active');
    m.classList.add('hidden');
    m.style.display = 'none';
  });
  document.getElementById('modalOverlay')?.classList.add('hidden');
}

// MONITORING SECTION
function initializeMonitoringSection() {
  const addTargetBtn = document.getElementById('addTargetBtn');

  // Lista local de monitoreo en localStorage
  if (!localStorage.getItem('osint_monitoring')) {
    localStorage.setItem('osint_monitoring', JSON.stringify([
      { id: 1, target: 'midominio.com', type: 'Dominio', status: 'Activo', lastCheck: 'hace 5 min' },
      { id: 2, target: '192.168.1.100', type: 'IP', status: 'Pausado', lastCheck: 'hace 2 horas' }
    ]));
  }

  if (addTargetBtn) {
    addTargetBtn.addEventListener('click', () => {
      const domain = prompt('Introduce el dominio o IP a monitorear continuamente:');
      if (domain) {
        const current = JSON.parse(localStorage.getItem('osint_monitoring') || '[]');
        current.push({
          id: Date.now(),
          target: domain,
          type: domain.includes('.') && !domain.match(/\d+\.\d+\.\d+\.\d+/) ? 'Dominio' : 'IP',
          status: 'Activo',
          lastCheck: 'Recién añadido'
        });
        localStorage.setItem('osint_monitoring', JSON.stringify(current));
        showNotification(`✅ Objetivo ${domain} añadido al monitoreo`, 'success');
        renderMonitoringList();
      }
    });
  }

  // Exportar datos
  const exportMonitoringData = document.getElementById('exportMonitoringData');
  if (exportMonitoringData) {
    exportMonitoringData.addEventListener('click', () => {
      const data = localStorage.getItem('osint_monitoring');
      const blob = new Blob([data], { type: 'application/json' });
      downloadFile(blob, `monitoring-data-${Date.now()}.json`);
      showNotification('✅ Datos de monitoreo exportados en JSON', 'success');
    });
  }

  renderMonitoringList();

  // Iniciar simulación de alertas (cada 45 segundos)
  setInterval(() => {
    const alertsList = document.getElementById('recentAlertsList');
    if (!alertsList || document.getElementById('monitoring-section').classList.contains('hidden')) return;

    const activeTargets = JSON.parse(localStorage.getItem('osint_monitoring') || '[]').filter(t => t.status === 'Activo');
    if (activeTargets.length === 0) return;

    const randomTarget = activeTargets[Math.floor(Math.random() * activeTargets.length)];
    const alertHtml = `
            <div style="background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; padding: 10px; margin-bottom: 10px; font-size: 13px;">
                <strong style="color: #ef4444;">Alerta crítica: ${randomTarget.target}</strong>
                <p style="color: #cbd5e1; margin-top: 5px;">Se detectó un cambio inusual en los registros DNS / Puertos.</p>
                <small style="color: #94a3b8;">${new Date().toLocaleTimeString()}</small>
            </div>
        `;
    alertsList.insertAdjacentHTML('afterbegin', alertHtml);

    if (alertsList.children.length > 5) {
      alertsList.removeChild(alertsList.lastChild);
    }
  }, 45000);
}

function renderMonitoringList() {
  const list = document.getElementById('monitoringTargetsList');
  if (!list) return;

  const targets = JSON.parse(localStorage.getItem('osint_monitoring') || '[]');
  if (targets.length === 0) {
    list.innerHTML = '<p style="color: #94a3b8;">No hay objetivos monitoreados. Añade uno desde el Panel de Control.</p>';
    return;
  }

  list.innerHTML = targets.map((t, idx) => `
        <div style="display: flex; justify-content: space-between; align-items: center; background: #1a1a2e; padding: 15px; margin-bottom: 10px; border-radius: 5px; border: 1px solid #334155;">
            <div>
                <strong style="color: #f8fafc; font-size: 15px;">${t.target}</strong>
                <div style="font-size: 12px; color: #94a3b8; margin-top: 5px;">
                    Tipo: ${t.type} | Último chequeo: ${t.lastCheck}
                </div>
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <span style="background: ${t.status === 'Activo' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)'}; color: ${t.status === 'Activo' ? '#10b981' : '#f59e0b'}; padding: 4px 10px; border-radius: 12px; font-size: 11px;">
                    ${t.status}
                </span>
                <button onclick="toggleMonitoringStatus(${idx})" class="btn btn--outline btn--sm" style="padding: 4px 8px;"><i class="fas ${t.status === 'Activo' ? 'fa-pause' : 'fa-play'}"></i></button>
                <button onclick="deleteMonitoringTarget(${idx})" class="btn btn--outline btn--sm" style="padding: 4px 8px; color:#ef4444; border-color:#ef4444;"><i class="fas fa-trash"></i></button>
            </div>
        </div>
    `).join('');
}

window.toggleMonitoringStatus = function (index) {
  const targets = JSON.parse(localStorage.getItem('osint_monitoring') || '[]');
  if (targets[index]) {
    targets[index].status = targets[index].status === 'Activo' ? 'Pausado' : 'Activo';
    localStorage.setItem('osint_monitoring', JSON.stringify(targets));
    renderMonitoringList();
  }
};

window.deleteMonitoringTarget = function (index) {
  if (confirm('¿Eliminar objetivo del monitoreo?')) {
    const targets = JSON.parse(localStorage.getItem('osint_monitoring') || '[]');
    targets.splice(index, 1);
    localStorage.setItem('osint_monitoring', JSON.stringify(targets));
    renderMonitoringList();
  }
};

// SETTINGS SECTION
function initializeSettingsSection() {
  // Cargar configuraciones iniciales
  const prefs = JSON.parse(localStorage.getItem('osint_prefs')) || {
    lang: 'es',
    theme: 'dark',
    notifications: true,
    timeout: 30
  };

  const langSelect = document.getElementById('languageSettingSelect');
  const themeSelect = document.getElementById('themeSelect');
  const notifCheck = document.getElementById('notificationsEnabled');
  const timeoutInput = document.getElementById('analysisTimeout');

  if (langSelect) langSelect.value = prefs.lang;
  if (themeSelect) themeSelect.value = prefs.theme;
  if (notifCheck) notifCheck.checked = prefs.notifications;
  if (timeoutInput) timeoutInput.value = prefs.timeout;

  // Aplicar tema si es necesario
  applySavedTheme(prefs.theme);

  const saveSettingsBtn = document.getElementById('saveGeneralSettings');
  if (saveSettingsBtn) {
    saveSettingsBtn.addEventListener('click', () => {
      const newPrefs = {
        lang: langSelect ? langSelect.value : 'es',
        theme: themeSelect ? themeSelect.value : 'dark',
        notifications: notifCheck ? notifCheck.checked : true,
        timeout: timeoutInput ? parseInt(timeoutInput.value) : 30
      };

      localStorage.setItem('osint_prefs', JSON.stringify(newPrefs));
      applySavedTheme(newPrefs.theme);
      OSINTApp.notificationsEnabled = newPrefs.notifications;

      showNotification('✅ Preferencias generales guardadas localmente', 'success');
    });
  }
}

function applySavedTheme(themeValue) {
  if (themeValue === 'light') {
    // En una app real, esto cambiaría clases de CSS globales (ej. document.body.classList.add('light-theme'))
    showNotification('ℹ️ Tema Claro será aplicado en la próxima versión.', 'info');
  }
}

// MODALS
function initializeModals() {
  const modals = document.querySelectorAll('.modal');
  modals.forEach(modal => {
    // Fix: Class in HTML is modal-close
    const closeBtns = modal.querySelectorAll('.modal-close');
    closeBtns.forEach(btn => {
      btn.addEventListener('click', () => closeModal(modal.id));
    });

    // Make modals draggable by their header
    const header = modal.querySelector('.modal-header');
    if (header) {
      makeDraggable(modal, header);
    }
  });

  window.addEventListener('click', function (event) {
    if (event.target.classList.contains('modal-overlay')) {
      // Find the active modal to close
      const activeModal = document.querySelector('.modal:not(.hidden)');
      if (activeModal) closeModal(activeModal.id);
    }
  });
}

function openModal(modalId) {
  console.log('🔓 openModal() llamada para:', modalId);

  // Cerrar otros modales activos primero si los hay
  document.querySelectorAll('.modal:not(.hidden)').forEach(m => {
    if (m.id !== modalId) closeModal(m.id);
  });

  // Mostrar overlay
  const overlay = document.getElementById('modalOverlay');
  if (overlay) {
    overlay.classList.remove('hidden');
    // FIX: Add active class to show it with opacity
    overlay.classList.add('active');
    console.log('✅ Overlay visible');
  }

  const modal = document.getElementById(modalId);
  console.log('Modal encontrado:', modal ? 'SÍ' : 'NO');

  if (modal) {
    modal.classList.remove('hidden');
    modal.classList.add('active');
    modal.style.display = 'flex';
    modal.style.zIndex = '1001';

    console.log('✅ Modal completamente visible:', modalId);
  } else {
    console.error('❌ Modal NO encontrado:', modalId);
  }
}

function closeModal(modalId) {
  console.log('🔒 closeModal() llamada para:', modalId);

  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('active');
    modal.classList.add('hidden');
    modal.style.display = 'none'; // Ensure CSS display goes none 

    // Reset position if it was dragged
    if (typeof modal.resetPosition === 'function') {
      modal.resetPosition();
    }
  }

  // Ocultar overlay
  const overlay = document.getElementById('modalOverlay');
  if (overlay) {
    overlay.classList.remove('active');
    setTimeout(() => {
      // give it time to animate before displaying none
      overlay.classList.add('hidden');
    }, 300);
  }
}

// DRAGGABLE MODALS UTILITY
function makeDraggable(element, handle) {
  let isDragging = false;
  let currentX;
  let currentY;
  let initialX;
  let initialY;
  let xOffset = 0;
  let yOffset = 0;

  handle.addEventListener("mousedown", dragStart);
  document.addEventListener("mouseup", dragEnd);
  document.addEventListener("mousemove", drag);

  function dragStart(e) {
    if (e.target === handle || handle.contains(e.target)) {
      initialX = e.clientX - xOffset;
      initialY = e.clientY - yOffset;
      isDragging = true;
      handle.style.cursor = 'grabbing';
    }
  }

  function dragEnd() {
    initialX = currentX;
    initialY = currentY;
    isDragging = false;
    handle.style.cursor = 'grab';
  }

  function drag(e) {
    if (isDragging) {
      e.preventDefault();
      currentX = e.clientX - initialX;
      currentY = e.clientY - initialY;
      xOffset = currentX;
      yOffset = currentY;
      setTranslate(currentX, currentY, element);
    }
  }

  function setTranslate(xPos, yPos, el) {
    el.style.transform = `translate3d(${xPos}px, ${yPos}px, 0) scale(1)`;
  }

  // Reset position function to be called when modal closes
  element.resetPosition = function () {
    xOffset = 0;
    yOffset = 0;
    currentX = 0;
    currentY = 0;
    setTranslate(0, 0, element);
  };
}


// NOTIFICATIONS
function initializeNotificationSystem() {
  // Notification system initialized
}

function showNotification(message, type = 'info', duration = 3000) {
  const container = document.getElementById('notificationContainer') || createNotificationContainer();

  const notification = document.createElement('div');
  notification.className = `notification notification-${type}`;
  notification.innerHTML = `
    <span>${message}</span>
    <button class="close-notification">&times;</button>
  `;

  notification.querySelector('.close-notification').addEventListener('click', () => {
    notification.remove();
  });

  container.appendChild(notification);

  if (duration > 0) {
    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease-out';
      setTimeout(() => notification.remove(), 300);
    }, duration);
  }
}

function createNotificationContainer() {
  const container = document.createElement('div');
  container.id = 'notificationContainer';
  container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999; max-width: 400px;';
  document.body.appendChild(container);
  return container;
}

// UTILS
function loadSectionData(section) {
  console.log(`📂 Cargando datos para sección: ${section}`);
  switch (section) {
    case 'dashboard':
      // Initialize charts or dynamic data
      break;
    case 'reports':
      renderReportsList();
      break;
  }
}

function startRealTimeUpdates() {
  console.log('Real-time updates started');
}

function loadUserPreferences() {
  const preferences = localStorage.getItem('user-preferences');
  if (preferences) {
    OSINTA

// --- FUNCIÓN DE DETALLES DEL REPORTE (CON IA) ---
window.viewReportDetails = function (index) {
    const report = OSINTApp.reports[index];
    if (!report || (!report.data && !report.results)) {
        showNotification('⚠️ Este report no contiene datos.', 'warning');
        return;
    }

    const modalBody = document.getElementById('analysisModalBody');
    const modalTitle = document.querySelector('#analysisModal .modal-header h3');
    modalTitle.innerText = `Detalles: ${report.tool.toUpperCase()}`;

    const technicalData = report.data || report.results;
    let htmlContent = renderReportData(technicalData);

    const aiSection = `
        <div class="ai-analysis-card" style="margin-top: 20px; border: 1px dashed var(--color-primary); border-radius: 12px; padding: 15px; background: rgba(0, 255, 129, 0.05);">
            <h4 style="color: var(--color-primary); margin-bottom: 10px;"><i class="fas fa-robot"></i> Gemini AI Insight</h4>
            <div id="ai-content-${index}">
                ${report.aiAnalysis ? formatMarkdown(report.aiAnalysis) : `
                    <button class="btn btn--primary btn--sm" onclick="generateAIAnalysis(${index})" id="btn-ai-${index}">
                        Analizar con IA
                    </button>`}
            </div>
        </div>`;

    modalBody.innerHTML = htmlContent + aiSection;
    openModal('analysisModal');
};

// --- MOTOR DE IA ---
window.generateAIAnalysis = async function(index) {
    const report = OSINTApp.reports[index];
    const btn = document.getElementById('btn-ai-' + index);
    const contentArea = document.getElementById('ai-content-' + index);
    if (!btn || !contentArea) return;

    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Procesando...';
    btn.disabled = true;

    try {
        await new Promise(r => setTimeout(r, 2000));
        const aiResponse = "**Análisis:** Riesgo detectado. Se recomienda revisión de credenciales.";
        report.aiAnalysis = aiResponse;
        localStorage.setItem('osint_reports', JSON.stringify(OSINTApp.reports));
        contentArea.innerHTML = formatMarkdown(aiResponse);
        btn.style.display = 'none';
        showNotification('✨ Análisis completado', 'success');
    } catch (e) {
        showNotification('❌ Error IA', 'error');
        btn.disabled = false;
    }
};

// --- FORMATEADOR ---
function formatMarkdown(text) {
    if (!text) return "";
    return text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br>');
}

// ÚLTIMA LÍNEA DEL ARCHIVO: Asegúrate de que no haya nada abierto después de esto.
console.log("OSINT AI Pro: Sistema Cargado Correctamente.");
