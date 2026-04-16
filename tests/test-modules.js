// Tests unitaires pour PentestHAR
// Usage: node tests/test-modules.js

const fs = require('fs');
const path = require('path');

// Mock browser environment
global.window = {};
global.localStorage = {
  store: {},
  getItem(k) { return this.store[k] || null; },
  setItem(k, v) { this.store[k] = v; },
  removeItem(k) { delete this.store[k]; }
};

// Charger les modules
function loadModule(filename) {
  const filepath = path.join(__dirname, '..', 'devtools', 'security', filename);
  const code = fs.readFileSync(filepath, 'utf8');
  // Exécuter dans le contexte global pour que les classes soient accessibles
  const vm = require('vm');
  vm.runInThisContext(code, { filename: filepath });
}

// Compteurs de tests
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

function assertEqual(actual, expected, msg = '') {
  if (actual !== expected) {
    throw new Error(`${msg} Expected "${expected}", got "${actual}"`);
  }
}

function assertTrue(condition, msg = '') {
  if (!condition) {
    throw new Error(msg || 'Assertion failed');
  }
}

// ========== Tests SecretDetector ==========
console.log('\n📍 SecretDetector');
loadModule('SecretDetector.js');

const detector = new SecretDetector();

test('Détecte JWT valide', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
  const secrets = detector.detectInText(jwt, 'test');
  assertTrue(secrets.length === 1, 'Devrait trouver 1 secret');
  assertEqual(secrets[0].type, 'jwt');
});

test('Décode JWT payload', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A';
  const secrets = detector.detectInText(jwt, 'test');
  assertTrue(secrets[0].decoded !== undefined, 'JWT devrait être décodé');
  assertEqual(secrets[0].decoded.payload.sub, '1234567890');
});

test('Détecte AWS Access Key', () => {
  const awsKey = 'AKIAIOSFODNN7EXAMPLE';
  const secrets = detector.detectInText(awsKey, 'test');
  assertTrue(secrets.length === 1, 'Devrait trouver AWS key');
  assertEqual(secrets[0].type, 'awsAccessKey');
  assertEqual(secrets[0].severity, 'critical');
});

test('Détecte GitHub token', () => {
  const ghToken = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
  const secrets = detector.detectInText(ghToken, 'test');
  assertTrue(secrets.length === 1, 'Devrait trouver GitHub token');
  assertEqual(secrets[0].type, 'githubToken');
});

test('Détecte Stripe secret key', () => {
  // Clé test factice (pattern valide mais non-fonctionnelle)
  const stripeKey = 'sk_test_FAKEFAKEFAKEFAKEFAKEFAKE1234';
  const secrets = detector.detectInText(stripeKey, 'test');
  assertTrue(secrets.length === 1, 'Devrait trouver Stripe key');
  assertEqual(secrets[0].type, 'stripeSecret');
  assertEqual(secrets[0].severity, 'critical');
});

test('Pas de faux positif sur texte normal', () => {
  const normalText = 'Hello world, this is a normal text without secrets.';
  const secrets = detector.detectInText(normalText, 'test');
  assertTrue(secrets.length === 0, 'Ne devrait pas trouver de secrets');
});

test('Masque correctement les secrets', () => {
  const awsKey = 'AKIAIOSFODNN7EXAMPLE';
  const secrets = detector.detectInText(awsKey, 'test');
  assertTrue(secrets[0].masked.includes('...'), 'Secret devrait être masqué');
  assertTrue(!secrets[0].masked.includes('IOSFODNN7'), 'Partie centrale masquée');
});

// ========== Tests EndpointExtractor ==========
console.log('\n📍 EndpointExtractor');
loadModule('EndpointExtractor.js');

const extractor = new EndpointExtractor();

test('Normalise les IDs numériques', () => {
  assertEqual(extractor.normalizePath('/users/123'), '/users/{id}');
  assertEqual(extractor.normalizePath('/api/v1/orders/456/items/789'), '/api/v1/orders/{id}/items/{id}');
});

test('Normalise les UUIDs', () => {
  assertEqual(
    extractor.normalizePath('/items/550e8400-e29b-41d4-a716-446655440000'),
    '/items/{uuid}'
  );
});

test('Normalise les ObjectIds MongoDB', () => {
  assertEqual(
    extractor.normalizePath('/documents/507f1f77bcf86cd799439011'),
    '/documents/{objectId}'
  );
});

test('Infère le type integer', () => {
  assertEqual(extractor.inferType('12345'), 'integer');
  assertEqual(extractor.inferType('0'), 'integer');
});

test('Infère le type email', () => {
  assertEqual(extractor.inferType('test@example.com'), 'email');
});

test('Infère le type UUID', () => {
  assertEqual(extractor.inferType('550e8400-e29b-41d4-a716-446655440000'), 'uuid');
});

test('Infère le type URL', () => {
  assertEqual(extractor.inferType('https://example.com/path'), 'url');
});

test('Détecte IDOR sur /users/{id}', () => {
  const entry = {
    request: {
      url: 'https://api.example.com/users/1234',
      method: 'GET',
      headers: []
    },
    response: { status: 200, content: { size: 100 } }
  };
  const indicators = extractor.detectIDOR(entry);
  assertTrue(indicators.length > 0, 'Devrait détecter IDOR');
  assertTrue(indicators[0].confidence >= 0.5, 'Confidence >= 0.5');
});

test('IDOR confidence augmentée avec auth', () => {
  const entry = {
    request: {
      url: 'https://api.example.com/users/1234',
      method: 'GET',
      headers: [{ name: 'Authorization', value: 'Bearer xxx' }]
    },
    response: { status: 200, content: { size: 100 } }
  };
  const indicators = extractor.detectIDOR(entry);
  assertTrue(indicators[0].confidence >= 0.8, 'Confidence >= 0.8 avec auth');
});

test('Parse endpoints depuis JS', () => {
  const jsCode = `
    fetch('/api/v1/users');
    axios.get('/api/v2/orders');
    const endpoint = '/api/secret/hidden';
  `;
  const endpoints = extractor.parseJSForEndpoints(jsCode, 'test.js');
  assertTrue(endpoints.length >= 3, 'Devrait trouver >= 3 endpoints');
});

// ========== Tests SecurityHeaderChecker ==========
console.log('\n📍 SecurityHeaderChecker');
loadModule('SecurityHeaderChecker.js');

const headerChecker = new SecurityHeaderChecker();

test('Détecte headers de sécurité manquants', () => {
  const entry = {
    request: { url: 'https://example.com', headers: [] },
    response: {
      headers: [{ name: 'Content-Type', value: 'text/html' }]
    }
  };
  const issues = headerChecker.checkMissingHeaders(entry);
  assertTrue(issues.length > 0, 'Devrait détecter headers manquants');
  assertTrue(issues.some(i => i.header === 'content-security-policy'), 'CSP manquant');
  assertTrue(issues.some(i => i.header === 'strict-transport-security'), 'HSTS manquant');
});

test('Détecte cookies non sécurisés', () => {
  const entry = {
    request: { url: 'https://example.com', headers: [] },
    response: {
      headers: [{ name: 'Set-Cookie', value: 'session=abc123' }]
    }
  };
  const issues = headerChecker.checkCookies(entry);
  assertTrue(issues.length > 0, 'Devrait détecter cookie non sécurisé');
  assertTrue(issues[0].type === 'insecure_cookie', 'Type insecure_cookie');
});

test('Détecte CORS wildcard', () => {
  const entry = {
    request: { url: 'https://example.com', headers: [] },
    response: {
      headers: [{ name: 'Access-Control-Allow-Origin', value: '*' }]
    }
  };
  const issues = headerChecker.checkCORS(entry);
  assertTrue(issues.length > 0, 'Devrait détecter CORS wildcard');
  assertEqual(issues[0].type, 'cors_wildcard');
});

test('Détecte CORS avec credentials dangereux', () => {
  const entry = {
    request: {
      url: 'https://example.com',
      headers: [{ name: 'Origin', value: 'https://evil.com' }]
    },
    response: {
      headers: [
        { name: 'Access-Control-Allow-Origin', value: 'https://evil.com' },
        { name: 'Access-Control-Allow-Credentials', value: 'true' }
      ]
    }
  };
  const issues = headerChecker.checkCORS(entry);
  assertTrue(issues.some(i => i.type === 'cors_origin_reflection'), 'CORS origin reflection');
});

// ========== Tests PromptTemplateStore ==========
console.log('\n📍 PromptTemplateStore');
global.localStorage.store = {}; // Reset
loadModule('PromptTemplateStore.js');

const store = new PromptTemplateStore();

test('Charge les prompts par défaut', () => {
  const prompts = store.getAll();
  assertTrue(prompts.length >= 8, 'Devrait avoir >= 8 prompts par défaut');
});

test('Prompts ont les champs requis', () => {
  const prompts = store.getAll();
  for (const p of prompts) {
    assertTrue(p.id !== undefined, 'id requis');
    assertTrue(p.name !== undefined, 'name requis');
    assertTrue(p.prompt !== undefined, 'prompt requis');
    assertTrue(p.category !== undefined, 'category requis');
  }
});

test('Filtre par catégorie', () => {
  const recon = store.getByCategory('recon');
  assertTrue(recon.length >= 1, 'Au moins 1 prompt recon');
  assertTrue(recon.every(p => p.category === 'recon'), 'Tous catégorie recon');
});

test('Valide prompt invalide', () => {
  const result = store.validate({ name: '', prompt: '' });
  assertTrue(!result.valid, 'Devrait être invalide');
  assertTrue(result.errors.length > 0, 'Devrait avoir des erreurs');
});

test('Valide prompt valide', () => {
  const result = store.validate({
    name: 'Test Prompt',
    prompt: 'Ceci est un prompt de test {{target}}',
    category: 'custom'
  });
  assertTrue(result.valid, 'Devrait être valide');
});

test('Ajoute un prompt custom', () => {
  const before = store.getAll().length;
  const newPrompt = store.add({
    name: 'Mon Prompt',
    prompt: 'Test {{endpoints}}',
    category: 'custom',
    description: 'Description test'
  });
  const after = store.getAll().length;
  assertEqual(after, before + 1, 'Devrait avoir +1 prompt');
  assertTrue(newPrompt.id.startsWith('custom-'), 'ID commence par custom-');
  assertTrue(!newPrompt.isDefault, 'isDefault = false');
});

test('Supprime un prompt custom', () => {
  const custom = store.getAll().find(p => !p.isDefault);
  assertTrue(custom !== undefined, 'Devrait avoir un prompt custom');
  const result = store.delete(custom.id);
  assertTrue(result, 'Suppression devrait réussir');
});

test('Ne peut pas supprimer prompt par défaut', () => {
  const defaultPrompt = store.getAll().find(p => p.isDefault);
  const result = store.delete(defaultPrompt.id);
  assertTrue(!result, 'Suppression devrait échouer');
});

test('Recherche dans les prompts', () => {
  const results = store.search('JWT');
  assertTrue(results.length >= 1, 'Devrait trouver prompt JWT');
});

// ========== Tests SmartFilters ==========
console.log('\n📍 SmartFilters');
loadModule('SmartFilters.js');

const filters = new SmartFilters({ ignoreStatic: true });

test('Filtre les fichiers statiques', () => {
  const staticEntry = {
    request: { url: 'https://example.com/style.css', method: 'GET' },
    response: { headers: [{ name: 'Content-Type', value: 'text/css' }] }
  };
  assertTrue(!filters.shouldProcess(staticEntry), 'CSS devrait être filtré');
});

test('Laisse passer les API', () => {
  const apiEntry = {
    request: { url: 'https://api.example.com/v1/users', method: 'GET' },
    response: { headers: [{ name: 'Content-Type', value: 'application/json' }] }
  };
  assertTrue(filters.shouldProcess(apiEntry), 'API devrait passer');
});

test('Filtre les images', () => {
  const imgEntry = {
    request: { url: 'https://example.com/logo.png', method: 'GET' },
    response: { headers: [{ name: 'Content-Type', value: 'image/png' }] }
  };
  assertTrue(!filters.shouldProcess(imgEntry), 'Image devrait être filtrée');
});

// ========== Tests RequestDeduplicator ==========
console.log('\n📍 RequestDeduplicator');
loadModule('RequestDeduplicator.js');

const dedup = new RequestDeduplicator();

test('Détecte les requêtes dupliquées', () => {
  const entry1 = {
    request: {
      method: 'GET',
      url: 'https://api.example.com/users?page=1',
      headers: [],
      postData: null
    }
  };
  const result1 = dedup.add(entry1);
  assertTrue(!result1.isDuplicate, 'Première requête pas dupliquée');

  const result2 = dedup.add(entry1);
  assertTrue(result2.isDuplicate, 'Deuxième requête dupliquée');
  assertEqual(result2.count, 2);
});

test('Requêtes différentes non dupliquées', () => {
  const entry1 = {
    request: { method: 'GET', url: 'https://api.example.com/users', headers: [], postData: null }
  };
  const entry2 = {
    request: { method: 'GET', url: 'https://api.example.com/orders', headers: [], postData: null }
  };
  dedup.add(entry1);
  const result = dedup.add(entry2);
  assertTrue(!result.isDuplicate, 'Requêtes différentes pas dupliquées');
});

// ========== Tests RequestTagger ==========
console.log('\n📍 RequestTagger');
loadModule('RequestTagger.js');

const tagger = new RequestTagger();

test('Tag auth pour endpoint login', () => {
  const entry = {
    request: {
      url: 'https://example.com/api/login',
      method: 'POST',
      headers: []
    },
    response: { status: 200, headers: [] }
  };
  const tags = tagger.autoTag(entry);
  assertTrue(tags.has('auth'), 'Devrait avoir tag auth');
});

test('Tag auth pour header Authorization', () => {
  const entry = {
    request: {
      url: 'https://example.com/api/data',
      method: 'GET',
      headers: [{ name: 'Authorization', value: 'Bearer xxx' }]
    },
    response: { status: 200, headers: [] }
  };
  const tags = tagger.autoTag(entry);
  assertTrue(tags.has('auth'), 'Devrait avoir tag auth');
});

test('Tag api pour /api/ endpoint', () => {
  const entry = {
    request: {
      url: 'https://example.com/api/v1/users',
      method: 'GET',
      headers: []
    },
    response: { status: 200, headers: [] }
  };
  const tags = tagger.autoTag(entry);
  assertTrue(tags.has('api'), 'Devrait avoir tag api');
});

test('Tag sensitive pour endpoint password', () => {
  const entry = {
    request: {
      url: 'https://example.com/api/password/reset',
      method: 'POST',
      headers: []
    },
    response: { status: 200, headers: [] }
  };
  const tags = tagger.autoTag(entry);
  assertTrue(tags.has('sensitive'), 'Devrait avoir tag sensitive');
});

test('Tag admin pour endpoint dashboard', () => {
  const entry = {
    request: {
      url: 'https://example.com/admin/dashboard',
      method: 'GET',
      headers: []
    },
    response: { status: 200, headers: [] }
  };
  const tags = tagger.autoTag(entry);
  assertTrue(tags.has('admin'), 'Devrait avoir tag admin');
});

test('Tag upload pour multipart', () => {
  const entry = {
    request: {
      url: 'https://example.com/upload',
      method: 'POST',
      headers: [{ name: 'Content-Type', value: 'multipart/form-data' }]
    },
    response: { status: 200, headers: [] }
  };
  const tags = tagger.autoTag(entry);
  assertTrue(tags.has('upload'), 'Devrait avoir tag upload');
});

test('Tag error pour status 4xx/5xx', () => {
  const entry = {
    request: { url: 'https://example.com/api/test', method: 'GET', headers: [] },
    response: { status: 404, headers: [] }
  };
  const tags = tagger.autoTag(entry);
  assertTrue(tags.has('error'), 'Devrait avoir tag error');
});

test('Tags multiples sur même requête', () => {
  const entry = {
    request: {
      url: 'https://example.com/api/admin/users',
      method: 'GET',
      headers: [{ name: 'Authorization', value: 'Bearer xxx' }]
    },
    response: { status: 200, headers: [] }
  };
  const tags = tagger.autoTag(entry);
  assertTrue(tags.has('api'), 'Devrait avoir tag api');
  assertTrue(tags.has('admin'), 'Devrait avoir tag admin');
  assertTrue(tags.has('auth'), 'Devrait avoir tag auth');
});

// ========== Tests HelpSystem (Logique) ==========
console.log('\n📍 HelpSystem');

// Charger HelpSystem depuis le dossier help
function loadHelpModule(filename) {
  const filepath = path.join(__dirname, '..', 'devtools', 'help', filename);
  const code = fs.readFileSync(filepath, 'utf8');
  const vm = require('vm');
  vm.runInThisContext(code, { filename: filepath });
}

// Mock DOM et window complet pour HelpSystem
global.window = {
  addEventListener: () => {},
  innerWidth: 1024,
  innerHeight: 768
};

global.document = {
  createElement: () => ({
    className: '',
    innerHTML: '',
    style: {},
    classList: { add: () => {}, remove: () => {} },
    appendChild: () => {},
    addEventListener: () => {},
    querySelector: () => null,
    querySelectorAll: () => []
  }),
  body: {
    appendChild: () => {}
  },
  getElementById: () => null,
  querySelector: () => null,
  querySelectorAll: () => [],
  addEventListener: () => {}
};

loadHelpModule('HelpSystem.js');

test('HelpSystem est défini', () => {
  assertTrue(typeof HelpSystem === 'function', 'HelpSystem devrait être une classe');
});

test('HelpSystem a les méthodes attendues', () => {
  const methods = ['showToast', 'openDrawer', 'closeDrawer', 'startOnboarding'];
  for (const method of methods) {
    assertTrue(
      typeof HelpSystem.prototype[method] === 'function',
      `Méthode ${method} devrait exister`
    );
  }
});

test('Glossaire contient les termes essentiels', () => {
  const help = new HelpSystem();
  const terms = Object.keys(help.glossary);
  const required = ['HAR', 'IDOR', 'CORS', 'JWT', 'CSP', 'XSS'];
  for (const term of required) {
    assertTrue(terms.includes(term), `Glossaire devrait contenir ${term}`);
  }
});

test('Tooltips sont définis pour éléments clés', () => {
  const help = new HelpSystem();
  const keys = Object.keys(help.tooltips);
  assertTrue(keys.includes('btnToggle'), 'Tooltip pour btnToggle');
  assertTrue(keys.includes('filterStatic'), 'Tooltip pour filterStatic');
  assertTrue(keys.includes('filterApiOnly'), 'Tooltip pour filterApiOnly');
});

test('Onboarding a les étapes requises', () => {
  const help = new HelpSystem();
  assertTrue(help.onboardingSteps.length >= 6, 'Au moins 6 étapes d\'onboarding');
  assertTrue(
    help.onboardingSteps[0].title.includes('Bienvenue'),
    'Première étape de bienvenue'
  );
});

test('Contenu d\'aide contient les sections', () => {
  const help = new HelpSystem();
  assertTrue(help.helpContent.quickStart !== undefined, 'Section quickStart');
  assertTrue(help.helpContent.workflows !== undefined, 'Section workflows');
  assertTrue(help.helpContent.shortcuts !== undefined, 'Section shortcuts');
  assertTrue(help.helpContent.faq !== undefined, 'Section faq');
});

test('RenderMarkdown transforme correctement', () => {
  const help = new HelpSystem();
  const result = help.renderMarkdown('## Titre\n**bold** et `code`');
  assertTrue(result.includes('<h4>Titre</h4>'), 'H2 -> H4');
  assertTrue(result.includes('<strong>bold</strong>'), 'Bold');
  assertTrue(result.includes('<code>code</code>'), 'Code');
});

// ========== Tests ExportManager ==========
console.log('\n📍 ExportManager');
loadModule('ExportManager.js');

const exportManager = new ExportManager();

test('Export ffuf wordlist', () => {
  const endpoints = [
    { host: 'api.example.com', originalPath: '/users', normalizedPath: '/users', method: 'GET' },
    { host: 'api.example.com', originalPath: '/orders', normalizedPath: '/orders', method: 'POST' }
  ];
  const result = exportManager.toFfuf(endpoints);
  assertTrue(result.includes('/users'), 'Contient /users');
  assertTrue(result.includes('/orders'), 'Contient /orders');
});

test('Export curl commands', () => {
  const entries = [{
    request: {
      url: 'https://api.example.com/users',
      method: 'GET',
      headers: [{ name: 'Authorization', value: 'Bearer token123' }]
    }
  }];
  const result = exportManager.toCurl(entries);
  assertTrue(result.includes('curl'), 'Contient curl');
  assertTrue(result.includes('-H'), 'Contient header flag');
  assertTrue(result.includes('Authorization'), 'Contient header Authorization');
});

test('Export Postman collection structure', () => {
  const endpoints = [{
    host: 'api.example.com',
    fullUrl: 'https://api.example.com/users',
    originalPath: '/users',
    normalizedPath: '/users',
    method: 'GET',
    parameters: { query: [], body: [], header: [] },
    request: { headers: [] }
  }];
  const result = exportManager.toPostman(endpoints, { name: 'Test Collection' });
  const parsed = JSON.parse(result);
  assertTrue(parsed.info !== undefined, 'Contient info');
  assertTrue(parsed.info.name === 'Test Collection', 'Nom correct');
  assertTrue(Array.isArray(parsed.item), 'Contient items');
});

test('Export param wordlist', () => {
  const endpoints = [
    { parameters: { query: [{ name: 'page' }, { name: 'limit' }], body: [] } },
    { parameters: { query: [{ name: 'id' }], body: [{ name: 'username' }] } }
  ];
  const result = exportManager.toParamWordlist(endpoints);
  assertTrue(result.includes('page'), 'Contient page');
  assertTrue(result.includes('limit'), 'Contient limit');
  assertTrue(result.includes('username'), 'Contient username');
});

test('Export Burp Suite XML structure', () => {
  const entries = [{
    request: {
      url: 'https://api.example.com/users',
      method: 'GET',
      headers: [{ name: 'Authorization', value: 'Bearer token123' }],
      cookies: []
    },
    response: {
      status: 200,
      headers: [{ name: 'Content-Type', value: 'application/json' }],
      content: { text: '{"users":[]}', size: 14 }
    },
    startedDateTime: '2024-01-01T00:00:00Z'
  }];
  const result = exportManager.toBurp(entries);
  assertTrue(result.includes('<?xml'), 'Commence par XML declaration');
  assertTrue(result.includes('<items'), 'Contient balise items');
  assertTrue(result.includes('<url>'), 'Contient balise url');
  assertTrue(result.includes('<method>GET</method>'), 'Contient méthode');
  assertTrue(result.includes('base64="true"'), 'Request encodée en base64');
});

test('Export CSV structure', () => {
  const data = {
    secrets: [{ severity: 'critical', description: 'AWS Key', location: 'header', masked: 'AKIA...' }],
    findings: [{ type: 'missing_header', severity: 'medium', description: 'CSP missing' }],
    endpoints: []
  };
  const result = exportManager.toCSV(data);
  assertTrue(result.includes('Type,Severity,Description'), 'Contient en-têtes');
  assertTrue(result.includes('Secret'), 'Contient type Secret');
  assertTrue(result.includes('critical'), 'Contient sévérité');
});

test('Export wfuzz wordlists', () => {
  const endpoints = [{
    host: 'api.example.com',
    normalizedPath: '/users',
    parameters: { query: [{ name: 'page' }, { name: 'id' }], body: [] }
  }];
  const result = exportManager.toWfuzz(endpoints);
  assertTrue(result.pathWordlist.includes('/users'), 'Wordlist contient path');
  assertTrue(result.paramWordlist.includes('page'), 'Params contient page');
  assertTrue(result.commands.includes('wfuzz'), 'Commandes contient wfuzz');
});

// ========== Tests InjectionDetector ==========
console.log('\n📍 InjectionDetector');
loadModule('InjectionDetector.js');

const injectionDetector = new InjectionDetector();

test('Détecte erreur SQL MySQL', () => {
  const entry = {
    request: { url: 'https://example.com/search?q=test', method: 'GET' },
    response: { status: 500 }
  };
  const responseContent = 'Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version';
  const findings = injectionDetector.analyze(entry, responseContent);
  assertTrue(findings.length >= 1, 'Devrait détecter erreur SQL');
  assertTrue(findings.some(f => f.type === 'sql_injection_indicator'), 'Type sql_injection_indicator');
});

test('Détecte erreur SQL PostgreSQL', () => {
  const entry = {
    request: { url: 'https://example.com/api', method: 'POST' },
    response: { status: 500 }
  };
  const responseContent = 'ERROR: syntax error at or near "SELECT"';
  const findings = injectionDetector.analyze(entry, responseContent);
  assertTrue(findings.some(f => f.type === 'sql_injection_indicator'), 'Devrait détecter erreur PostgreSQL');
});

test('Détecte erreur NoSQL MongoDB', () => {
  const entry = {
    request: { url: 'https://example.com/api', method: 'POST' },
    response: { status: 500 }
  };
  const responseContent = 'MongoError: bad query: BadValue';
  const findings = injectionDetector.analyze(entry, responseContent);
  assertTrue(findings.some(f => f.type === 'nosql_injection_indicator'), 'Devrait détecter erreur MongoDB');
});

test('Détecte indicateur XXE', () => {
  const entry = {
    request: { url: 'https://example.com/xml', method: 'POST' },
    response: { status: 200 }
  };
  const responseContent = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>';
  const findings = injectionDetector.analyze(entry, responseContent);
  assertTrue(findings.some(f => f.type === 'xxe_indicator'), 'Devrait détecter XXE');
});

test('Détecte indicateur Command Injection', () => {
  const entry = {
    request: { url: 'https://example.com/ping', method: 'GET' },
    response: { status: 200 }
  };
  const responseContent = 'uid=0(root) gid=0(root) groups=0(root)';
  const findings = injectionDetector.analyze(entry, responseContent);
  assertTrue(findings.some(f => f.type === 'command_injection_indicator'), 'Devrait détecter Command Injection');
});

test('Détecte indicateur Path Traversal dans réponse', () => {
  const entry = {
    request: { url: 'https://example.com/file', method: 'GET' },
    response: { status: 200 }
  };
  // Pattern détecté: contenu /etc/passwd
  const responseContent = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin';
  const findings = injectionDetector.analyze(entry, responseContent);
  assertTrue(findings.some(f => f.type === 'command_injection_indicator'), 'Devrait détecter passwd leak');
});

test('Détecte paramètres suspects avec payload SQL', () => {
  const entry = {
    request: {
      url: "https://example.com/search?query=' OR '1'='1",
      method: 'GET'
    },
    response: { status: 200 }
  };
  const findings = injectionDetector.analyze(entry, '');
  assertTrue(findings.some(f => f.type === 'suspicious_parameter'), 'Devrait détecter paramètre suspect');
});

test('Génère payloads de test', () => {
  const entry = {
    request: {
      url: 'https://example.com/search?id=1',
      method: 'GET',
      queryString: [{ name: 'id', value: '1' }]
    }
  };
  const payloads = injectionDetector.generateTestPayloads(entry);
  assertTrue(payloads.sql !== undefined, 'Payloads SQL générés');
  assertTrue(payloads.sql.length > 0, 'Au moins 1 payload SQL');
  assertTrue(payloads.nosql !== undefined, 'Payloads NoSQL générés');
  assertTrue(payloads.xss !== undefined, 'Payloads XSS générés');
});

test('Pas de faux positif sur réponse normale', () => {
  const entry = {
    request: { url: 'https://example.com/api/users', method: 'GET' },
    response: { status: 200 }
  };
  const responseContent = '{"users": [{"id": 1, "name": "John"}]}';
  const findings = injectionDetector.analyze(entry, responseContent);
  const injectionFindings = findings.filter(f =>
    f.type.includes('error') || f.type.includes('indicator')
  );
  assertTrue(injectionFindings.length === 0, 'Pas de faux positif');
});

// ========== Tests JWTAnalyzer ==========
console.log('\n📍 JWTAnalyzer');
loadModule('JWTAnalyzer.js');

const jwtAnalyzer = new JWTAnalyzer();

test('Décode JWT valide', () => {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const analysis = jwtAnalyzer.analyze(token);
  assertTrue(analysis.decoded !== null, 'JWT décodé');
  assertEqual(analysis.decoded.payload.sub, '1234567890');
  assertEqual(analysis.decoded.payload.name, 'John Doe');
});

test('Détecte alg=none vulnérable', () => {
  // JWT avec alg=none (header: {"alg":"none","typ":"JWT"})
  const token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.';
  const analysis = jwtAnalyzer.analyze(token);
  assertTrue(analysis.vulnerabilities.length >= 1, 'Devrait avoir vulnérabilité');
  assertTrue(
    analysis.vulnerabilities.some(v => v.type === 'alg_none'),
    'Devrait détecter alg=none'
  );
  assertEqual(analysis.vulnerabilities.find(v => v.type === 'alg_none').severity, 'critical');
});

test('Détecte JWT sans expiration', () => {
  // JWT sans claim exp
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A';
  const analysis = jwtAnalyzer.analyze(token);
  // no_expiration est une vulnérabilité, pas un warning
  assertTrue(
    analysis.vulnerabilities.some(v => v.type === 'no_expiration'),
    'Devrait détecter absence expiration'
  );
});

test('Détecte claims sensibles dans payload', () => {
  // JWT avec données sensibles (password)
  // header: {"alg":"HS256","typ":"JWT"}
  // payload: {"sub":"1234","password":"secret123"}
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwicGFzc3dvcmQiOiJzZWNyZXQxMjMifQ.XXXXX';
  const analysis = jwtAnalyzer.analyze(token);
  // sensitive_claim est une vulnérabilité
  assertTrue(
    analysis.vulnerabilities.some(v => v.type === 'sensitive_claim'),
    'Devrait détecter données sensibles'
  );
});

test('Génère variantes d\'attaque', () => {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
  const analysis = jwtAnalyzer.analyze(token);
  assertTrue(analysis.attackVariants.length >= 1, 'Devrait avoir variantes');
  // Les variantes ont un champ 'name', pas 'type'
  assertTrue(
    analysis.attackVariants.some(v => v.name === 'Algorithm None'),
    'Variante Algorithm None générée'
  );
});

test('Détecte algorithme symétrique', () => {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
  const analysis = jwtAnalyzer.analyze(token);
  assertTrue(
    analysis.warnings.some(w => w.type === 'symmetric_algorithm'),
    'Devrait indiquer algorithme symétrique'
  );
});

test('Token invalide retourne warning decode_error', () => {
  const invalidToken = 'not.a.valid.jwt';
  const analysis = jwtAnalyzer.analyze(invalidToken);
  assertTrue(analysis.decoded === null, 'Decoded devrait être null');
  assertTrue(
    analysis.warnings.some(w => w.type === 'decode_error'),
    'Devrait avoir warning decode_error'
  );
});

test('Détecte claims d\'identité', () => {
  // JWT avec user_id
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwidXNlcl9pZCI6NDIsImFkbWluIjpmYWxzZX0.XXXXX';
  const analysis = jwtAnalyzer.analyze(token);
  // Les claims d'identité sont dans info
  assertTrue(
    analysis.info.some(i => i.type === 'identity_claim' && i.claim === 'user_id'),
    'Devrait détecter claim user_id'
  );
});

// ========== Tests RiskScorer ==========
console.log('\n📊 Tests RiskScorer');
loadModule('RiskScorer.js');
const riskScorer = new RiskScorer();

test('calculateCompositeScore retourne un score valide', () => {
  const finding = {
    type: 'secret',
    severity: 'critical',
    description: 'API Key exposée',
    location: 'Response body'
  };

  const result = riskScorer.calculateCompositeScore(finding, {});

  assertTrue(result.score >= 0 && result.score <= 10, 'Score doit être entre 0 et 10');
  assertTrue(result.level !== undefined, 'Level doit être défini');
  assertTrue(result.priority !== undefined, 'Priority doit être définie');
  assertTrue(result.cvss !== undefined, 'CVSS doit être défini');
  assertTrue(result.enrichment !== undefined, 'Enrichment doit être défini');
});

test('Secrets critiques ont score élevé', () => {
  const secret = {
    type: 'api_key',
    severity: 'critical',
    description: 'Stripe API Key',
    location: 'response'
  };

  const result = riskScorer.calculateCompositeScore(secret, {});

  assertTrue(result.score >= 8, `Secret critique devrait avoir score >= 8, got ${result.score}`);
  assertTrue(result.priority === 'P0' || result.priority === 'P1', 'Secret critique devrait être P0 ou P1');
});

test('Enrichissement CWE fonctionne', () => {
  const finding = {
    type: 'sql_injection',
    severity: 'high'
  };

  const result = riskScorer.calculateCompositeScore(finding, {});

  assertTrue(result.enrichment.cwe.id === 'CWE-89', `CWE devrait être CWE-89, got ${result.enrichment.cwe.id}`);
  assertTrue(result.enrichment.cwe.name === 'SQL Injection', 'CWE name devrait être SQL Injection');
});

test('Enrichissement OWASP fonctionne', () => {
  const finding = {
    type: 'xss',
    severity: 'medium'
  };

  const result = riskScorer.calculateCompositeScore(finding, {});

  assertTrue(result.enrichment.owasp.includes('Injection'), 'OWASP devrait contenir Injection');
});

test('IDOR haute confiance a score élevé', () => {
  const idor = {
    type: 'idor',
    severity: 'high',
    normalizedPath: '/api/users/{id}',
    idorIndicators: [{ confidence: 0.9, pattern: 'sequential_id' }]
  };

  const result = riskScorer.calculateCompositeScore(idor, {});

  assertTrue(result.score >= 6, `IDOR haute confiance devrait avoir score >= 6, got ${result.score}`);
  assertTrue(result.priority === 'P1' || result.priority === 'P2', 'IDOR devrait être P1 ou P2');
});

test('calculateOverallRisk avec plusieurs findings', () => {
  const findings = [
    { type: 'secret', severity: 'critical' },
    { type: 'xss', severity: 'medium' },
    { type: 'missing_header', severity: 'low' }
  ];

  const result = riskScorer.calculateOverallRisk(findings);

  assertTrue(result.score > 0, 'Score global devrait être > 0');
  assertTrue(result.level !== 'AUCUN', 'Level ne devrait pas être AUCUN');
  assertTrue(result.criticalCount === 1, `Critical count devrait être 1, got ${result.criticalCount}`);
});

test('Skill level est correctement inféré', () => {
  const beginner = { type: 'secret', severity: 'high' };
  const intermediate = { type: 'xss', severity: 'medium' };
  const expert = { type: 'xxe', severity: 'high' };

  const r1 = riskScorer.calculateCompositeScore(beginner, {});
  const r2 = riskScorer.calculateCompositeScore(intermediate, {});
  const r3 = riskScorer.calculateCompositeScore(expert, {});

  assertEqual(r1.enrichment.skillLevel, 'beginner', 'Secret devrait être beginner');
  assertEqual(r2.enrichment.skillLevel, 'intermediate', 'XSS devrait être intermediate');
  assertEqual(r3.enrichment.skillLevel, 'expert', 'XXE devrait être expert');
});

test('Temps d\'exploitation est cohérent', () => {
  const easy = { type: 'secret', severity: 'critical' };
  const hard = { type: 'xxe', severity: 'high' };

  const r1 = riskScorer.calculateCompositeScore(easy, {});
  const r2 = riskScorer.calculateCompositeScore(hard, {});

  assertTrue(r1.timeToExploit.includes('5 min') || r1.timeToExploit.includes('30 min'), 'Secret devrait être rapide');
  assertTrue(
    r2.timeToExploit.includes('heure') || r2.timeToExploit.includes('jour'),
    'XXE devrait prendre plus de temps'
  );
});

test('Contexte affecte le score', () => {
  const finding = { type: 'xss', severity: 'medium' };

  const publicContext = { isPublic: true, requiresAuth: false };
  const privateContext = { isPublic: false, requiresAuth: true, hasRateLimit: true };

  const r1 = riskScorer.calculateCompositeScore(finding, publicContext);
  const r2 = riskScorer.calculateCompositeScore(finding, privateContext);

  assertTrue(r1.score > r2.score, 'Score public devrait être supérieur au score privé');
});

test('Références CWE sont générées', () => {
  const finding = { type: 'sql_injection', severity: 'high' };
  const result = riskScorer.calculateCompositeScore(finding, {});

  assertTrue(result.enrichment.references.length > 0, 'References devrait contenir des URLs');
  assertTrue(
    result.enrichment.references[0].includes('cwe.mitre.org'),
    'Première référence devrait être CWE'
  );
});

// ========== Résumé ==========
console.log('\n' + '='.repeat(50));
console.log(`Résultats: ${passed} passés, ${failed} échoués`);
console.log('='.repeat(50));

process.exit(failed > 0 ? 1 : 0);
