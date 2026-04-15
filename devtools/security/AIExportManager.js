// AIExportManager.js - Export optimisé pour analyse IA
// PentestHAR - Génération de contexte AI-ready

class AIExportManager {
  constructor(securityAnalyzer) {
    this.analyzer = securityAnalyzer;
    this.promptStore = new PromptTemplateStore();
    this.sessionStart = Date.now();
    this.target = null;
  }

  // Définir la cible principale
  setTarget(url) {
    try {
      this.target = new URL(url).host;
    } catch (e) {
      this.target = url;
    }
  }

  // Collecter toutes les données de contexte
  collectContext() {
    const endpoints = this.analyzer.getEndpoints();
    const secrets = this.analyzer.getSecrets();
    const issues = this.analyzer.getIssues();
    const idorCandidates = this.analyzer.getIDORCandidates();
    const jsEndpoints = this.analyzer.getJSEndpoints();
    const params = this.analyzer.getAllParameters();
    const summary = this.analyzer.getSummary();

    return {
      target: this.target || 'Unknown',
      sessionDuration: this.formatDuration(Date.now() - this.sessionStart),
      requestCount: summary.deduplication?.totalProcessed || 0,
      endpoints,
      endpointsCount: endpoints.length,
      secrets,
      issues,
      idorCandidates,
      jsEndpoints,
      parameters: params,
      summary
    };
  }

  // Substituer les variables dans un prompt
  renderPrompt(template, context = null) {
    context = context || this.collectContext();

    let rendered = template;

    // Substitutions
    const substitutions = {
      '{{target}}': context.target,
      '{{session_duration}}': context.sessionDuration,
      '{{request_count}}': String(context.requestCount),
      '{{endpoints_count}}': String(context.endpointsCount),
      '{{endpoints}}': this.formatEndpoints(context.endpoints),
      '{{secrets}}': this.formatSecrets(context.secrets, true),
      '{{secrets_full}}': this.formatSecrets(context.secrets, false),
      '{{jwt_decoded}}': this.formatJWTs(context.secrets),
      '{{idor_candidates}}': this.formatIDORCandidates(context.idorCandidates),
      '{{security_issues}}': this.formatIssues(context.issues),
      '{{parameters}}': this.formatParameters(context.parameters),
      '{{auth_endpoints}}': this.formatAuthEndpoints(context.endpoints),
      '{{methods_summary}}': this.formatMethodsSummary(context.endpoints),
      '{{headers_issues}}': this.formatHeadersIssues(context.issues),
      '{{cookies_issues}}': this.formatCookiesIssues(context.issues),
      '{{cors_issues}}': this.formatCORSIssues(context.issues),
      '{{tech_stack}}': this.detectTechStack(context),
      '{{api_version}}': this.detectAPIVersions(context.endpoints)
    };

    for (const [variable, value] of Object.entries(substitutions)) {
      rendered = rendered.split(variable).join(value);
    }

    return rendered;
  }

  // === Formateurs ===

  formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    }
    return `${seconds}s`;
  }

  formatEndpoints(endpoints) {
    if (!endpoints.length) return 'Aucun endpoint découvert';

    const byMethod = {};
    for (const ep of endpoints) {
      byMethod[ep.method] = byMethod[ep.method] || [];
      byMethod[ep.method].push(ep.normalizedPath);
    }

    let output = '';
    for (const [method, paths] of Object.entries(byMethod)) {
      output += `\n### ${method}\n`;
      for (const path of [...new Set(paths)].slice(0, 30)) {
        output += `- ${path}\n`;
      }
      if (paths.length > 30) {
        output += `- ... et ${paths.length - 30} autres\n`;
      }
    }

    return output;
  }

  formatSecrets(secrets, masked = true) {
    if (!secrets.length) return 'Aucun secret détecté';

    let output = '';
    for (const secret of secrets.slice(0, 20)) {
      const value = masked ? secret.masked : secret.value;
      output += `- **${secret.type}** [${secret.severity}]: \`${value}\`\n`;
      output += `  - Location: ${secret.location}\n`;
    }

    if (secrets.length > 20) {
      output += `\n*... et ${secrets.length - 20} autres secrets*\n`;
    }

    return output;
  }

  formatJWTs(secrets) {
    const jwts = secrets.filter(s => s.type === 'jwt' && s.decoded);
    if (!jwts.length) return 'Aucun JWT détecté';

    let output = '';
    for (const jwt of jwts) {
      output += `\n#### JWT trouvé dans ${jwt.location}\n`;
      output += '```json\n';
      output += `// Header\n${JSON.stringify(jwt.decoded.header, null, 2)}\n\n`;
      output += `// Payload\n${JSON.stringify(jwt.decoded.payload, null, 2)}\n`;
      output += '```\n';

      if (jwt.decoded.payload.exp) {
        const expDate = new Date(jwt.decoded.payload.exp * 1000);
        const expired = expDate < new Date();
        output += `- Expiration: ${expDate.toISOString()} ${expired ? '(EXPIRÉ)' : ''}\n`;
      }

      if (jwt.decoded.payload.iat) {
        output += `- Émis le: ${new Date(jwt.decoded.payload.iat * 1000).toISOString()}\n`;
      }
    }

    return output;
  }

  formatIDORCandidates(candidates) {
    if (!candidates.length) return 'Aucun candidat IDOR détecté';

    let output = '| Endpoint | Méthode | Confiance | Pattern |\n';
    output += '|----------|---------|-----------|--------|\n';

    for (const ep of candidates.slice(0, 20)) {
      const maxIndicator = ep.idorIndicators.reduce((a, b) =>
        a.confidence > b.confidence ? a : b
      );
      const confidence = (maxIndicator.confidence * 100).toFixed(0);
      output += `| \`${ep.normalizedPath}\` | ${ep.method} | ${confidence}% | ${maxIndicator.pattern} |\n`;
    }

    if (candidates.length > 20) {
      output += `\n*... et ${candidates.length - 20} autres candidats*\n`;
    }

    return output;
  }

  formatIssues(issues) {
    if (!issues.length) return 'Aucun problème de sécurité détecté';

    const byType = {};
    for (const issue of issues) {
      byType[issue.type] = byType[issue.type] || [];
      byType[issue.type].push(issue);
    }

    let output = '';
    for (const [type, typeIssues] of Object.entries(byType)) {
      output += `\n### ${this.formatIssueType(type)} (${typeIssues.length})\n`;
      for (const issue of typeIssues.slice(0, 5)) {
        output += `- [${issue.severity.toUpperCase()}] ${issue.description}\n`;
      }
      if (typeIssues.length > 5) {
        output += `  *... et ${typeIssues.length - 5} autres*\n`;
      }
    }

    return output;
  }

  formatIssueType(type) {
    const names = {
      'missing_header': 'Headers manquants',
      'weak_header': 'Headers faibles',
      'insecure_cookie': 'Cookies non sécurisés',
      'cors_wildcard': 'CORS Wildcard',
      'cors_origin_reflection': 'CORS Réflexion Origin',
      'information_leakage': 'Fuite d\'information'
    };
    return names[type] || type;
  }

  formatParameters(params) {
    const allParams = [...params.query, ...params.body];
    if (!allParams.length) return 'Aucun paramètre découvert';

    let output = '**Query parameters:**\n';
    for (const p of params.query.slice(0, 30)) {
      output += `- ${p}\n`;
    }

    output += '\n**Body parameters:**\n';
    for (const p of params.body.slice(0, 30)) {
      output += `- ${p}\n`;
    }

    return output;
  }

  formatAuthEndpoints(endpoints) {
    const authKeywords = ['auth', 'login', 'logout', 'signin', 'signup', 'register', 'password', 'token', 'oauth', 'session'];
    const authEndpoints = endpoints.filter(ep =>
      authKeywords.some(kw => ep.normalizedPath.toLowerCase().includes(kw))
    );

    if (!authEndpoints.length) return 'Aucun endpoint d\'authentification détecté';

    let output = '';
    for (const ep of authEndpoints) {
      output += `- ${ep.method} ${ep.normalizedPath}\n`;
    }

    return output;
  }

  formatMethodsSummary(endpoints) {
    const methods = {};
    for (const ep of endpoints) {
      methods[ep.method] = (methods[ep.method] || 0) + 1;
    }

    let output = '';
    for (const [method, count] of Object.entries(methods).sort((a, b) => b[1] - a[1])) {
      output += `- ${method}: ${count} endpoints\n`;
    }

    return output || 'Aucune donnée';
  }

  formatHeadersIssues(issues) {
    const headerIssues = issues.filter(i =>
      i.type === 'missing_header' || i.type === 'weak_header'
    );

    if (!headerIssues.length) return 'Aucun problème de headers détecté';

    let output = '';
    const grouped = {};
    for (const issue of headerIssues) {
      grouped[issue.header] = grouped[issue.header] || [];
      grouped[issue.header].push(issue);
    }

    for (const [header, issues] of Object.entries(grouped)) {
      output += `- **${header}**: ${issues[0].description}\n`;
    }

    return output;
  }

  formatCookiesIssues(issues) {
    const cookieIssues = issues.filter(i => i.type === 'insecure_cookie');
    if (!cookieIssues.length) return 'Aucun problème de cookies détecté';

    let output = '';
    for (const issue of cookieIssues.slice(0, 10)) {
      output += `- **${issue.cookieName}**: `;
      output += issue.issues.map(i => i.flag).join(', ') + ' manquant(s)\n';
    }

    return output;
  }

  formatCORSIssues(issues) {
    const corsIssues = issues.filter(i => i.type.startsWith('cors_'));
    if (!corsIssues.length) return 'Aucun problème CORS détecté';

    let output = '';
    for (const issue of corsIssues) {
      output += `- [${issue.severity.toUpperCase()}] ${issue.description}\n`;
    }

    return output;
  }

  detectTechStack(context) {
    const stack = new Set();

    // Analyser les issues pour détecter la stack
    for (const issue of context.issues) {
      if (issue.header === 'x-powered-by') {
        stack.add(issue.value);
      }
      if (issue.header === 'server') {
        stack.add(issue.value);
      }
    }

    // Analyser les endpoints
    for (const ep of context.endpoints) {
      if (ep.normalizedPath.includes('/api/')) stack.add('REST API');
      if (ep.normalizedPath.includes('/graphql')) stack.add('GraphQL');
      if (ep.normalizedPath.includes('/wp-')) stack.add('WordPress');
      if (ep.normalizedPath.includes('/.well-known/')) stack.add('OIDC/OAuth');
    }

    return stack.size > 0 ? Array.from(stack).join(', ') : 'Non détecté';
  }

  detectAPIVersions(endpoints) {
    const versions = new Set();
    const versionRegex = /\/v(\d+)/gi;

    for (const ep of endpoints) {
      let match;
      while ((match = versionRegex.exec(ep.normalizedPath)) !== null) {
        versions.add(`v${match[1]}`);
      }
    }

    return versions.size > 0 ? Array.from(versions).sort().join(', ') : 'Non détecté';
  }

  // === Exports spécialisés ===

  // Générer un AI Brief complet
  generateAIBrief() {
    const context = this.collectContext();

    return `# AI Security Brief - ${context.target}

## Métadonnées Session
| Propriété | Valeur |
|-----------|--------|
| Cible | ${context.target} |
| Durée | ${context.sessionDuration} |
| Requêtes | ${context.requestCount} |
| Endpoints uniques | ${context.endpointsCount} |
| Secrets détectés | ${context.secrets.length} |
| Issues sécurité | ${context.issues.length} |
| Candidats IDOR | ${context.idorCandidates.length} |

## Résumé Exécutif

### Criticité Globale
${this.assessOverallRisk(context)}

### Findings Prioritaires
${this.getTopFindings(context)}

## Surface d'Attaque
${this.formatEndpoints(context.endpoints)}

## Authentification
${this.formatAuthEndpoints(context.endpoints)}

## Secrets Détectés
${this.formatSecrets(context.secrets, true)}

## JWT Analysis
${this.formatJWTs(context.secrets)}

## IDOR Candidates
${this.formatIDORCandidates(context.idorCandidates)}

## Security Issues
${this.formatIssues(context.issues)}

## Paramètres Découverts
${this.formatParameters(context.parameters)}

## Stack Technique
${this.detectTechStack(context)}

---
*Généré par PentestHAR - ${new Date().toISOString()}*
`;
  }

  assessOverallRisk(context) {
    let risk = 'LOW';
    let reasons = [];

    const criticalSecrets = context.secrets.filter(s => s.severity === 'critical');
    const highSecrets = context.secrets.filter(s => s.severity === 'high');
    const criticalIssues = context.issues.filter(i => i.severity === 'critical');

    if (criticalSecrets.length > 0) {
      risk = 'CRITICAL';
      reasons.push(`${criticalSecrets.length} secret(s) critique(s) exposé(s)`);
    } else if (highSecrets.length > 0 || criticalIssues.length > 0) {
      risk = 'HIGH';
      if (highSecrets.length) reasons.push(`${highSecrets.length} secret(s) haute sévérité`);
      if (criticalIssues.length) reasons.push(`${criticalIssues.length} issue(s) critique(s)`);
    } else if (context.idorCandidates.length > 0) {
      risk = 'MEDIUM';
      reasons.push(`${context.idorCandidates.length} candidat(s) IDOR à tester`);
    }

    const emoji = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };

    return `${emoji[risk]} **${risk}**\n${reasons.length > 0 ? reasons.map(r => `- ${r}`).join('\n') : '- Aucun finding critique'}`;
  }

  getTopFindings(context) {
    const findings = [];

    // Secrets critiques
    for (const s of context.secrets.filter(s => s.severity === 'critical').slice(0, 3)) {
      findings.push({ severity: 'CRITICAL', text: `Secret exposé: ${s.type}`, source: 'secrets' });
    }

    // Issues critiques
    for (const i of context.issues.filter(i => i.severity === 'critical').slice(0, 3)) {
      findings.push({ severity: 'CRITICAL', text: i.description, source: 'issues' });
    }

    // IDOR haute confiance
    for (const ep of context.idorCandidates.filter(e =>
      e.idorIndicators.some(i => i.confidence >= 0.8)
    ).slice(0, 3)) {
      findings.push({ severity: 'HIGH', text: `IDOR potentiel: ${ep.normalizedPath}`, source: 'idor' });
    }

    if (findings.length === 0) {
      return 'Aucun finding critique détecté automatiquement.';
    }

    return findings.slice(0, 5).map(f =>
      `- [${f.severity}] ${f.text}`
    ).join('\n');
  }

  // Générer des scénarios d'attaque
  generateAttackScenarios() {
    const context = this.collectContext();
    const scenarios = [];

    // Scénario IDOR
    if (context.idorCandidates.length > 0) {
      const topIDOR = context.idorCandidates[0];
      scenarios.push({
        id: 1,
        name: 'IDOR sur ressource utilisateur',
        severity: 'HIGH',
        target: topIDOR.normalizedPath,
        method: topIDOR.method,
        description: `L'endpoint ${topIDOR.normalizedPath} utilise des IDs séquentiels`,
        steps: [
          'Identifier votre propre ID utilisateur',
          'Capturer la requête vers cet endpoint',
          'Modifier l\'ID pour accéder à une autre ressource',
          'Vérifier si les données d\'un autre utilisateur sont retournées'
        ],
        payloads: ['id-1', 'id+1', '1', '0', '-1', '999999'],
        successIndicators: ['Status 200 avec données différentes', 'Données d\'un autre utilisateur']
      });
    }

    // Scénario JWT
    const jwtSecrets = context.secrets.filter(s => s.type === 'jwt' && s.decoded);
    if (jwtSecrets.length > 0) {
      const jwt = jwtSecrets[0];
      scenarios.push({
        id: 2,
        name: 'Manipulation JWT',
        severity: 'HIGH',
        target: 'Header Authorization',
        description: 'Token JWT capturé pouvant être manipulé',
        steps: [
          'Décoder le JWT actuel',
          'Identifier les claims sensibles (role, permissions, sub)',
          'Tester algorithm=none',
          'Tester modification des claims',
          'Tester avec signature invalide'
        ],
        payloads: [
          'Changer "role": "user" en "role": "admin"',
          'Changer "alg": "HS256" en "alg": "none"',
          'Modifier "sub" pour un autre utilisateur'
        ],
        successIndicators: ['Accès à des fonctionnalités admin', 'Données d\'un autre utilisateur']
      });
    }

    // Scénario secrets exposés
    const criticalSecrets = context.secrets.filter(s => s.severity === 'critical');
    if (criticalSecrets.length > 0) {
      scenarios.push({
        id: 3,
        name: 'Exploitation de secrets exposés',
        severity: 'CRITICAL',
        target: 'Secrets dans réponses HTTP',
        description: `${criticalSecrets.length} secret(s) critique(s) détecté(s)`,
        steps: [
          'Identifier le type de chaque secret',
          'Vérifier la validité du secret',
          'Tester l\'accès aux services associés',
          'Documenter l\'impact potentiel'
        ],
        secrets: criticalSecrets.map(s => ({ type: s.type, masked: s.masked })),
        successIndicators: ['Accès au service externe', 'Exfiltration de données']
      });
    }

    // Scénario injection via paramètres
    if (context.parameters.query.length > 0 || context.parameters.body.length > 0) {
      scenarios.push({
        id: 4,
        name: 'Test d\'injection sur paramètres',
        severity: 'MEDIUM',
        target: 'Paramètres détectés',
        description: `${context.parameters.query.length + context.parameters.body.length} paramètres à tester`,
        steps: [
          'Lister tous les paramètres découverts',
          'Tester SQLi: \' OR 1=1--',
          'Tester XSS: <script>alert(1)</script>',
          'Tester SSRF: http://localhost/',
          'Tester Path Traversal: ../../../etc/passwd'
        ],
        parameters: {
          query: context.parameters.query.slice(0, 10),
          body: context.parameters.body.slice(0, 10)
        },
        successIndicators: ['Erreur SQL', 'Exécution JavaScript', 'Contenu fichier système']
      });
    }

    // Formatter en YAML-like
    let output = `# Scénarios d'Attaque - ${context.target}\n`;
    output += `# Générés le ${new Date().toISOString()}\n\n`;

    for (const scenario of scenarios) {
      output += `## Scénario ${scenario.id}: ${scenario.name}\n\n`;
      output += `**Sévérité:** ${scenario.severity}\n`;
      output += `**Cible:** ${scenario.target}\n`;
      output += `**Description:** ${scenario.description}\n\n`;

      output += `### Étapes\n`;
      scenario.steps.forEach((step, i) => {
        output += `${i + 1}. ${step}\n`;
      });

      if (scenario.payloads) {
        output += `\n### Payloads\n`;
        output += '```\n';
        scenario.payloads.forEach(p => output += `${p}\n`);
        output += '```\n';
      }

      output += `\n### Indicateurs de succès\n`;
      scenario.successIndicators.forEach(ind => {
        output += `- ${ind}\n`;
      });

      output += '\n---\n\n';
    }

    return output;
  }

  // Générer un export chunké pour les gros contextes
  generateChunkedExport(maxTokensPerChunk = 4000) {
    const context = this.collectContext();
    const chunks = [];

    // Estimation grossière: 1 token ~= 4 caractères
    const charsPerChunk = maxTokensPerChunk * 4;

    // Chunk 1: Métadonnées et résumé
    chunks.push({
      index: 1,
      title: 'Métadonnées et Résumé',
      content: `# Analyse PentestHAR - Partie 1/N

## Cible: ${context.target}
## Session: ${context.sessionDuration}, ${context.requestCount} requêtes

## Résumé
- Endpoints: ${context.endpointsCount}
- Secrets: ${context.secrets.length}
- Issues: ${context.issues.length}
- IDOR: ${context.idorCandidates.length}

## Criticité
${this.assessOverallRisk(context)}

## Top Findings
${this.getTopFindings(context)}
`
    });

    // Chunk 2: Endpoints
    const endpointsContent = this.formatEndpoints(context.endpoints);
    if (endpointsContent.length > charsPerChunk) {
      // Découper les endpoints en plusieurs chunks
      const methods = {};
      for (const ep of context.endpoints) {
        methods[ep.method] = methods[ep.method] || [];
        methods[ep.method].push(ep.normalizedPath);
      }

      for (const [method, paths] of Object.entries(methods)) {
        chunks.push({
          index: chunks.length + 1,
          title: `Endpoints ${method}`,
          content: `# Endpoints ${method} (${paths.length})\n\n${[...new Set(paths)].map(p => `- ${p}`).join('\n')}`
        });
      }
    } else {
      chunks.push({
        index: chunks.length + 1,
        title: 'Endpoints',
        content: `# Endpoints découverts\n\n${endpointsContent}`
      });
    }

    // Chunk 3: Secrets
    if (context.secrets.length > 0) {
      chunks.push({
        index: chunks.length + 1,
        title: 'Secrets',
        content: `# Secrets détectés\n\n${this.formatSecrets(context.secrets, true)}\n\n## JWT Decoded\n${this.formatJWTs(context.secrets)}`
      });
    }

    // Chunk 4: IDOR
    if (context.idorCandidates.length > 0) {
      chunks.push({
        index: chunks.length + 1,
        title: 'IDOR Candidates',
        content: `# Candidats IDOR\n\n${this.formatIDORCandidates(context.idorCandidates)}`
      });
    }

    // Chunk 5: Issues
    if (context.issues.length > 0) {
      chunks.push({
        index: chunks.length + 1,
        title: 'Security Issues',
        content: `# Problèmes de sécurité\n\n${this.formatIssues(context.issues)}`
      });
    }

    // Mettre à jour le total
    const total = chunks.length;
    chunks.forEach(chunk => {
      chunk.content = chunk.content.replace('/N', `/${total}`);
      chunk.total = total;
    });

    return chunks;
  }

  // Obtenir un prompt rendu par ID
  getRenderedPrompt(templateId) {
    const template = this.promptStore.getById(templateId);
    if (!template) return null;

    return {
      ...template,
      renderedPrompt: this.renderPrompt(template.prompt)
    };
  }

  // Obtenir tous les prompts avec preview
  getAllPromptsWithPreview() {
    const templates = this.promptStore.getAll();
    return templates.map(t => ({
      ...t,
      preview: this.renderPrompt(t.prompt).substring(0, 500) + '...'
    }));
  }

  // Copier un prompt rendu dans le presse-papier
  async copyPromptToClipboard(templateId) {
    const rendered = this.getRenderedPrompt(templateId);
    if (!rendered) return false;

    try {
      await navigator.clipboard.writeText(rendered.renderedPrompt);
      return true;
    } catch (e) {
      // Fallback
      const textarea = document.createElement('textarea');
      textarea.value = rendered.renderedPrompt;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      return true;
    }
  }

  // Export tout-en-un pour IA
  generateFullAIPackage() {
    const context = this.collectContext();

    return {
      brief: this.generateAIBrief(),
      scenarios: this.generateAttackScenarios(),
      chunks: this.generateChunkedExport(),
      rawData: {
        target: context.target,
        session: {
          duration: context.sessionDuration,
          requests: context.requestCount
        },
        endpoints: context.endpoints.map(ep => ({
          method: ep.method,
          path: ep.normalizedPath,
          params: ep.parameters,
          idor: ep.idorIndicators
        })),
        secrets: context.secrets.map(s => ({
          type: s.type,
          severity: s.severity,
          location: s.location,
          masked: s.masked
        })),
        issues: context.issues.map(i => ({
          type: i.type,
          severity: i.severity,
          description: i.description
        }))
      },
      meta: {
        generatedAt: new Date().toISOString(),
        generator: 'PentestHAR v2.0.0'
      }
    };
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.AIExportManager = AIExportManager;
}
