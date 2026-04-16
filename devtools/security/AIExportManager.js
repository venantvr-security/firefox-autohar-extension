// AIExportManager.js - Export optimisé pour analyse IA
// PentestHAR - Génération de contexte AI-ready

class AIExportManager {
  constructor(securityAnalyzer) {
    this.analyzer = securityAnalyzer;
    this.promptStore = new PromptTemplateStore();
    this.riskScorer = new RiskScorer();
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

  // === Scoring et Enrichissement ===

  /**
   * Enrichir tous les findings avec scoring
   */
  enrichFindings(context) {
    const allFindings = [
      ...context.secrets.map(s => ({ ...s, findingType: 'secret' })),
      ...context.issues.map(i => ({ ...i, findingType: 'issue' })),
      ...context.idorCandidates.map(c => ({ ...c, findingType: 'idor', severity: 'high', type: 'idor' }))
    ];

    return allFindings.map(finding => {
      const scored = this.riskScorer.calculateCompositeScore(finding, {
        requiresAuth: true, // TODO: détecter depuis le contexte
        isPublic: true
      });

      return {
        ...finding,
        riskScore: scored.score,
        riskLevel: scored.level,
        priority: scored.priority,
        cvss: scored.cvss,
        timeToExploit: scored.timeToExploit,
        recommendation: scored.recommendation,
        enrichment: scored.enrichment
      };
    }).sort((a, b) => b.riskScore - a.riskScore); // Trier par score décroissant
  }

  /**
   * Obtenir les findings critiques (score >= 8.5)
   */
  getCriticalFindings(context) {
    const enriched = this.enrichFindings(context);
    return enriched.filter(f => f.riskScore >= 8.5);
  }

  /**
   * Calculer le score de risque global
   */
  calculateOverallRiskScore(context) {
    const allFindings = [
      ...context.secrets,
      ...context.issues,
      ...context.idorCandidates.map(c => ({ ...c, severity: 'high', type: 'idor' }))
    ];

    if (allFindings.length === 0) {
      return {
        score: 0,
        level: 'AUCUN',
        emoji: '🟢',
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        recommendation: 'Aucune vulnérabilité détectée'
      };
    }

    const overallRisk = this.riskScorer.calculateOverallRisk(allFindings);

    return {
      ...overallRisk,
      emoji: this.getRiskEmoji(overallRisk.level),
      summary: this.formatRiskSummary(overallRisk)
    };
  }

  /**
   * Obtenir l'emoji pour un niveau de risque
   */
  getRiskEmoji(level) {
    const emojis = {
      'CRITIQUE': '🔴',
      'ÉLEVÉ': '🟠',
      'MOYEN': '🟡',
      'FAIBLE': '🟢',
      'AUCUN': '⚪'
    };
    return emojis[level] || '⚪';
  }

  /**
   * Formater le résumé de risque
   */
  formatRiskSummary(overallRisk) {
    let summary = `**${overallRisk.level}** (Score: ${overallRisk.score.toFixed(1)}/10)\n`;

    if (overallRisk.criticalCount > 0) {
      summary += `- ${overallRisk.criticalCount} finding(s) critique(s)\n`;
    }
    if (overallRisk.highCount > 0) {
      summary += `- ${overallRisk.highCount} finding(s) de haute sévérité\n`;
    }

    summary += `\n**Action recommandée**: ${overallRisk.recommendation}`;

    return summary;
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

  // === Formateurs Enrichis (avec scoring) ===

  formatCriticalFindings(criticalFindings) {
    if (criticalFindings.length === 0) {
      return '✅ **Aucun finding critique détecté** (score < 8.5)\n\nCependant, veuillez examiner les findings de priorité haute ci-dessous.';
    }

    let output = `**${criticalFindings.length} finding(s) critique(s) nécessitant une action immédiate:**\n\n`;

    for (const [index, finding] of criticalFindings.entries()) {
      const num = index + 1;
      output += `### #${num} - ${finding.description || finding.type || 'Finding'} [${finding.riskLevel}]\n\n`;
      output += `- **Score de Risque**: ${finding.riskScore.toFixed(1)}/10\n`;
      output += `- **Priorité**: ${finding.priority}\n`;
      output += `- **CVSS v3**: ${finding.cvss}\n`;
      output += `- **Temps d'exploitation estimé**: ${finding.timeToExploit}\n`;

      if (finding.enrichment) {
        output += `- **CWE**: ${finding.enrichment.cwe.id} - ${finding.enrichment.cwe.name}\n`;
        output += `- **OWASP**: ${finding.enrichment.owasp}\n`;
        output += `- **Niveau requis**: ${finding.enrichment.skillLevel}\n`;
      }

      if (finding.findingType === 'secret') {
        output += `- **Valeur**: \`${finding.masked}\`\n`;
        output += `- **Location**: ${finding.location}\n`;
      } else if (finding.findingType === 'idor') {
        const maxConfidence = Math.max(...finding.idorIndicators.map(i => i.confidence));
        output += `- **Endpoint**: ${finding.method} ${finding.normalizedPath}\n`;
        output += `- **Confiance IDOR**: ${(maxConfidence * 100).toFixed(0)}%\n`;
      } else if (finding.findingType === 'issue') {
        output += `- **Détails**: ${finding.description}\n`;
      }

      output += `\n**📋 Recommandation**:\n`;
      output += `- **Action**: ${finding.recommendation.action}\n`;
      output += `- **Timeline**: ${finding.recommendation.timeline}\n`;
      if (finding.recommendation.notification.length > 0) {
        output += `- **Notifier**: ${finding.recommendation.notification.join(', ')}\n`;
      }

      output += '\n---\n\n';
    }

    return output;
  }

  formatTopFindings(topFindings) {
    if (topFindings.length === 0) {
      return 'Aucun finding détecté.';
    }

    let output = '';

    for (const [index, finding] of topFindings.entries()) {
      const num = index + 1;
      const emoji = finding.riskScore >= 8.5 ? '🔴' : finding.riskScore >= 7 ? '🟠' : '🟡';

      output += `**${num}. ${emoji} ${finding.description || finding.type}** - Score: ${finding.riskScore.toFixed(1)}/10 [${finding.priority}]\n`;

      if (finding.enrichment) {
        output += `   - ${finding.enrichment.cwe.id} | ${finding.enrichment.owasp}\n`;
      }

      output += `   - Exploitation: ${finding.timeToExploit} | Skill: ${finding.enrichment?.skillLevel || 'N/A'}\n`;

      if (finding.findingType === 'secret') {
        output += `   - Secret: \`${finding.masked}\` dans ${finding.location}\n`;
      } else if (finding.findingType === 'idor') {
        output += `   - Endpoint: ${finding.method} ${finding.normalizedPath}\n`;
      }

      output += '\n';
    }

    return output;
  }

  formatSecretsEnriched(secrets, enrichedFindings) {
    if (!secrets.length) return 'Aucun secret détecté';

    const enrichedSecrets = enrichedFindings.filter(f => f.findingType === 'secret');

    let output = '';
    for (const secret of enrichedSecrets.slice(0, 20)) {
      output += `### ${secret.type.toUpperCase()} [${secret.riskLevel}]\n\n`;
      output += `- **Score**: ${secret.riskScore.toFixed(1)}/10 | **CVSS**: ${secret.cvss}\n`;
      output += `- **Valeur**: \`${secret.masked}\`\n`;
      output += `- **Location**: ${secret.location}\n`;

      if (secret.enrichment) {
        output += `- **CWE**: ${secret.enrichment.cwe.id} - ${secret.enrichment.cwe.name}\n`;
        output += `- **OWASP**: ${secret.enrichment.owasp}\n`;
        output += `- **Exploitation**: ${secret.timeToExploit}\n`;

        if (secret.enrichment.references && secret.enrichment.references.length > 0) {
          output += `- **Références**: [CWE](${secret.enrichment.references[0]})\n`;
        }
      }

      output += `\n**Recommandation**: ${secret.recommendation.action} (${secret.recommendation.timeline})\n\n`;
    }

    if (enrichedSecrets.length > 20) {
      output += `\n*... et ${enrichedSecrets.length - 20} autres secrets*\n`;
    }

    return output;
  }

  formatIDORCandidatesEnriched(candidates, enrichedFindings) {
    if (!candidates.length) return 'Aucun candidat IDOR détecté';

    const enrichedIDORs = enrichedFindings.filter(f => f.findingType === 'idor');

    let output = '| Endpoint | Score | CVSS | Confiance | Temps Exploit |\n';
    output += '|----------|-------|------|-----------|---------------|\n';

    for (const idor of enrichedIDORs.slice(0, 20)) {
      const maxConfidence = Math.max(...idor.idorIndicators.map(i => i.confidence));
      output += `| \`${idor.method} ${idor.normalizedPath}\` | ${idor.riskScore.toFixed(1)}/10 | ${idor.cvss} | ${(maxConfidence * 100).toFixed(0)}% | ${idor.timeToExploit} |\n`;
    }

    if (enrichedIDORs.length > 20) {
      output += `\n*... et ${enrichedIDORs.length - 20} autres candidats*\n`;
    }

    return output;
  }

  formatIssuesEnriched(issues, enrichedFindings) {
    if (!issues.length) return 'Aucun problème de sécurité détecté';

    const enrichedIssues = enrichedFindings.filter(f => f.findingType === 'issue');

    const byType = {};
    for (const issue of enrichedIssues) {
      byType[issue.type] = byType[issue.type] || [];
      byType[issue.type].push(issue);
    }

    let output = '';
    for (const [type, typeIssues] of Object.entries(byType)) {
      output += `\n### ${this.formatIssueType(type)} (${typeIssues.length})\n\n`;

      for (const issue of typeIssues.slice(0, 5)) {
        output += `- **[${issue.riskLevel}]** ${issue.description}\n`;
        output += `  - Score: ${issue.riskScore.toFixed(1)}/10 | CVSS: ${issue.cvss}\n`;

        if (issue.enrichment) {
          output += `  - ${issue.enrichment.cwe.id} | ${issue.enrichment.owasp}\n`;
        }
      }

      if (typeIssues.length > 5) {
        output += `  *... et ${typeIssues.length - 5} autres*\n`;
      }
    }

    return output;
  }

  generateRecommendations(enrichedFindings, overallRisk) {
    let output = `### Action Immédiate\n\n`;

    // Findings P0
    const p0Findings = enrichedFindings.filter(f => f.priority === 'P0');
    if (p0Findings.length > 0) {
      output += `**${p0Findings.length} vulnérabilité(s) critique(s) à corriger dans les 24 heures:**\n\n`;
      for (const f of p0Findings) {
        output += `1. ${f.description || f.type} - ${f.recommendation.action}\n`;
      }
      output += '\n';
    }

    // Findings P1
    const p1Findings = enrichedFindings.filter(f => f.priority === 'P1');
    if (p1Findings.length > 0) {
      output += `### Corrections Urgentes (< 7 jours)\n\n`;
      output += `**${p1Findings.length} vulnérabilité(s) à corriger:**\n\n`;
      for (const f of p1Findings.slice(0, 5)) {
        output += `- ${f.description || f.type}\n`;
      }
      if (p1Findings.length > 5) {
        output += `- ... et ${p1Findings.length - 5} autres\n`;
      }
      output += '\n';
    }

    // Recommandations générales
    output += `### Recommandations Générales\n\n`;
    output += `1. **Monitoring**: Activer la surveillance des endpoints critiques\n`;
    output += `2. **Tests**: Effectuer des tests d'intrusion complets\n`;
    output += `3. **Formation**: Sensibiliser l'équipe dev aux vulnérabilités détectées\n`;
    output += `4. **Audit**: Planifier un audit de sécurité approfondi\n`;

    return output;
  }

  // === Formateurs originaux (rétro-compatibilité) ===

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

  // Générer un AI Brief complet (OPTIMISÉ - Pyramide Inversée)
  generateAIBrief() {
    const context = this.collectContext();
    const overallRisk = this.calculateOverallRiskScore(context);
    const criticalFindings = this.getCriticalFindings(context);
    const enrichedFindings = this.enrichFindings(context);

    return `# 🚨 ANALYSE SÉCURITÉ - ${context.target}

## ⚠️ ACTION IMMÉDIATE REQUISE

${this.formatCriticalFindings(criticalFindings)}

## 📊 SCORE DE RISQUE GLOBAL

${overallRisk.emoji} **${overallRisk.level}** - Score: **${overallRisk.score.toFixed(1)}/10**

${overallRisk.summary}

**Priorisation des corrections**:
- P0 (Critique): ${overallRisk.breakdown.p0} finding(s)
- P1 (Haute): ${overallRisk.breakdown.p1} finding(s)
- P2 (Moyenne): ${overallRisk.breakdown.p2} finding(s)
- P3 (Basse): ${overallRisk.breakdown.p3} finding(s)

---

## 🎯 FINDINGS PRIORITAIRES (Top ${Math.min(5, enrichedFindings.length)})

${this.formatTopFindings(enrichedFindings.slice(0, 5))}

---

## 📋 VUE D'ENSEMBLE SESSION

| Métrique | Valeur |
|----------|--------|
| 🎯 **Cible** | ${context.target} |
| ⏱️ **Durée** | ${context.sessionDuration} |
| 📡 **Requêtes** | ${context.requestCount} |
| 🌐 **Endpoints** | ${context.endpointsCount} |
| 🔑 **Secrets** | ${context.secrets.length} |
| ⚠️ **Issues** | ${context.issues.length} |
| 🎯 **IDOR candidats** | ${context.idorCandidates.length} |
| 🏗️ **Stack** | ${this.detectTechStack(context)} |
| 🔢 **API Version** | ${this.detectAPIVersions(context.endpoints)} |

---

## 📖 DÉTAILS TECHNIQUES

### 🔐 Secrets Détectés
${this.formatSecretsEnriched(context.secrets, enrichedFindings)}

### 🎯 Candidats IDOR
${this.formatIDORCandidatesEnriched(context.idorCandidates, enrichedFindings)}

### ⚠️ Problèmes de Sécurité
${this.formatIssuesEnriched(context.issues, enrichedFindings)}

### 🔍 JWT Analysis
${this.formatJWTs(context.secrets)}

### 🌐 Surface d'Attaque
${this.formatEndpoints(context.endpoints)}

### 🔑 Endpoints d'Authentification
${this.formatAuthEndpoints(context.endpoints)}

### 📝 Paramètres Découverts
${this.formatParameters(context.parameters)}

---

## 💡 RECOMMANDATIONS

${this.generateRecommendations(enrichedFindings, overallRisk)}

---

*🤖 Généré par PentestHAR v2.0 - ${new Date().toISOString()}*
*📊 Analysé avec RiskScorer - ${enrichedFindings.length} findings enrichis*
`;
  }

  // Générer un brief structuré (format JSON + Markdown hybride)
  generateStructuredBrief() {
    const context = this.collectContext();
    const overallRisk = this.calculateOverallRiskScore(context);
    const enrichedFindings = this.enrichFindings(context);
    const criticalFindings = enrichedFindings.filter(f => f.riskScore >= 8.5);
    const highFindings = enrichedFindings.filter(f => f.riskScore >= 7 && f.riskScore < 8.5);

    // Métadonnées en JSON
    const metadata = {
      target: context.target,
      sessionDuration: context.sessionDuration,
      sessionStart: new Date(this.sessionStart).toISOString(),
      requestCount: context.requestCount,
      endpointsCount: context.endpointsCount,
      riskScore: overallRisk.score,
      riskLevel: overallRisk.level,
      priority: {
        p0: overallRisk.breakdown.p0,
        p1: overallRisk.breakdown.p1,
        p2: overallRisk.breakdown.p2,
        p3: overallRisk.breakdown.p3
      },
      techStack: this.detectTechStack(context),
      apiVersions: this.detectAPIVersions(context.endpoints),
      generatedAt: new Date().toISOString(),
      generator: 'PentestHAR v2.0'
    };

    // Findings structurés en JSON
    const structuredFindings = enrichedFindings.map(f => ({
      id: `F${enrichedFindings.indexOf(f) + 1}`,
      type: f.type,
      findingType: f.findingType,
      description: f.description,
      severity: f.severity,
      riskScore: f.riskScore,
      riskLevel: f.riskLevel,
      priority: f.priority,
      cvss: f.cvss,
      timeToExploit: f.timeToExploit,
      cwe: f.enrichment?.cwe,
      owasp: f.enrichment?.owasp,
      skillLevel: f.enrichment?.skillLevel,
      location: f.location || f.normalizedPath || 'N/A',
      recommendation: f.recommendation,
      references: f.enrichment?.references || []
    }));

    return `# 🔐 Rapport Sécurité Structuré - ${context.target}

## 📦 Métadonnées (Machine-Readable)

\`\`\`json
${JSON.stringify(metadata, null, 2)}
\`\`\`

## 🚨 Findings (Structured Data)

\`\`\`json
${JSON.stringify(structuredFindings, null, 2)}
\`\`\`

---

## 📊 Analyse Narrative

### Vue d'Ensemble

${overallRisk.emoji} **Niveau de Risque**: ${overallRisk.level} (${overallRisk.score.toFixed(1)}/10)

Le scan a identifié **${enrichedFindings.length} findings** dont:
- **${criticalFindings.length}** critiques (P0)
- **${highFindings.length}** hautes (P1)
- **${overallRisk.breakdown.p2}** moyennes (P2)
- **${overallRisk.breakdown.p3}** basses (P3)

### Top 3 Findings Critiques

${this.formatTop3ForNarrative(criticalFindings)}

### Recommandations Immédiates

${this.generateImmediateActions(criticalFindings)}

---

## 🎯 Exploitation Guide

### Quick Wins (Facile + Impact Élevé)

${this.identifyQuickWins(enrichedFindings)}

### Attack Chains Détectés

${this.detectAttackChains(enrichedFindings)}

---

## 📚 Références et Ressources

- **CWE Database**: https://cwe.mitre.org/
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **PortSwigger KB**: https://portswigger.net/kb/issues/

---

*Généré le ${new Date().toISOString()}*
*Format: JSON + Markdown Hybride pour optimisation LLM*
`;
  }

  formatTop3ForNarrative(criticalFindings) {
    if (criticalFindings.length === 0) {
      return '✅ Aucun finding critique détecté.';
    }

    return criticalFindings.slice(0, 3).map((f, i) => {
      return `**${i + 1}. ${f.description || f.type}**
   - Score: ${f.riskScore.toFixed(1)}/10 | CVSS: ${f.cvss}
   - ${f.enrichment?.cwe.id} - ${f.enrichment?.cwe.name}
   - Exploitation: ${f.timeToExploit}
   - Action: ${f.recommendation.action} (${f.recommendation.timeline})`;
    }).join('\n\n');
  }

  generateImmediateActions(criticalFindings) {
    if (criticalFindings.length === 0) {
      return 'Aucune action critique immédiate requise.';
    }

    let output = '**À faire dans les 24h:**\n\n';
    for (const [i, f] of criticalFindings.entries()) {
      output += `${i + 1}. ${f.recommendation.action} pour "${f.description || f.type}"\n`;
    }

    return output;
  }

  identifyQuickWins(enrichedFindings) {
    // Quick wins = score élevé + temps d'exploit court
    const quickWins = enrichedFindings.filter(f =>
      f.riskScore >= 7 &&
      (f.timeToExploit.includes('< 5 min') || f.timeToExploit.includes('< 30 min'))
    ).slice(0, 5);

    if (quickWins.length === 0) {
      return 'Aucun quick win évident détecté.';
    }

    let output = '';
    for (const f of quickWins) {
      output += `- **${f.description || f.type}** (${f.timeToExploit})\n`;
      output += `  - Score: ${f.riskScore.toFixed(1)}/10 | Skill: ${f.enrichment?.skillLevel}\n`;
    }

    return output;
  }

  detectAttackChains(enrichedFindings) {
    // Logique simplifiée : détection de chaînes basée sur types
    const secrets = enrichedFindings.filter(f => f.findingType === 'secret');
    const idors = enrichedFindings.filter(f => f.findingType === 'idor');
    const jwts = secrets.filter(f => f.type?.includes('jwt'));

    const chains = [];

    // Chain 1: Secret + IDOR = Account Takeover
    if (secrets.length > 0 && idors.length > 0) {
      chains.push({
        name: 'Account Takeover Chain',
        impact: 'HIGH',
        steps: [
          `1. Exploiter secret: ${secrets[0].type}`,
          `2. Utiliser IDOR: ${idors[0].normalizedPath || idors[0].description}`,
          `3. Résultat: Accès complet aux comptes utilisateurs`
        ]
      });
    }

    // Chain 2: JWT + IDOR
    if (jwts.length > 0 && idors.length > 0) {
      chains.push({
        name: 'JWT Manipulation + IDOR',
        impact: 'CRITICAL',
        steps: [
          `1. Manipuler JWT: ${jwts[0].type}`,
          `2. Exploiter IDOR: ${idors[0].normalizedPath || idors[0].description}`,
          `3. Résultat: Privilege escalation + accès données`
        ]
      });
    }

    if (chains.length === 0) {
      return 'Aucune chaîne d\'attaque évidente détectée entre les findings.';
    }

    let output = '';
    for (const chain of chains) {
      output += `**${chain.name}** [Impact: ${chain.impact}]\n\n`;
      for (const step of chain.steps) {
        output += `${step}\n`;
      }
      output += '\n';
    }

    return output;
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
