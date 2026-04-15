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

// ========== Résumé ==========
console.log('\n' + '='.repeat(50));
console.log(`Résultats: ${passed} passés, ${failed} échoués`);
console.log('='.repeat(50));

process.exit(failed > 0 ? 1 : 0);
