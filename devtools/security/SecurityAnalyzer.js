// SecurityAnalyzer.js - Orchestrateur principal de l'analyse de securite
// AutoHAR Pentest Edition

class SecurityAnalyzer {
  constructor(options = {}) {
    // Modules d'analyse
    this.filters = new SmartFilters(options.filters || {});
    this.deduplicator = new RequestDeduplicator(options.deduplication || {});
    this.tagger = new RequestTagger();
    this.secretDetector = new SecretDetector();
    this.headerChecker = new SecurityHeaderChecker();
    this.endpointExtractor = new EndpointExtractor();
    this.exportManager = new ExportManager();

    // Nouveaux modules de détection avancée
    this.injectionDetector = typeof InjectionDetector !== 'undefined'
      ? new InjectionDetector()
      : null;
    this.jwtAnalyzer = typeof JWTAnalyzer !== 'undefined'
      ? new JWTAnalyzer()
      : null;

    // Stockage des resultats
    this.findings = {
      secrets: [],
      issues: [],
      endpoints: [],
      jsEndpoints: [],
      injections: [],      // Indicateurs d'injection détectés
      jwtVulnerabilities: [] // Vulnérabilités JWT
    };

    // Configuration
    this.enabled = true;
    this.options = {
      detectSecrets: true,
      checkHeaders: true,
      extractEndpoints: true,
      parseJS: true,
      deduplicate: true,
      detectInjections: true,  // Nouveau
      analyzeJWT: true,        // Nouveau
      ...options
    };

    // Callbacks pour UI
    this.onFinding = null;
    this.onUpdate = null;
  }

  // Point d'entree principal - appele depuis handleRequest()
  async analyze(harEntry, responseContent = '') {
    if (!this.enabled) return null;

    // Appliquer les filtres intelligents
    if (!this.filters.shouldProcess(harEntry)) {
      return { filtered: true };
    }

    // Deduplication
    if (this.options.deduplicate) {
      const dedupResult = this.deduplicator.add(harEntry);
      if (dedupResult.isDuplicate) {
        return { deduplicated: true, count: dedupResult.count };
      }
    }

    const results = {
      filtered: false,
      deduplicated: false,
      secrets: [],
      issues: [],
      injections: [],
      jwtVulnerabilities: [],
      endpoint: null,
      tags: new Set()
    };

    // Detection de secrets
    if (this.options.detectSecrets) {
      try {
        const secrets = await this.secretDetector.scan(harEntry, responseContent);
        if (secrets.length > 0) {
          results.secrets = secrets;
          this.findings.secrets.push(...secrets);
          this.notifyFinding('secret', secrets);
        }
      } catch (e) {
        console.error('Secret detection error:', e);
      }
    }

    // Verification des headers de securite
    if (this.options.checkHeaders) {
      try {
        const issues = this.headerChecker.check(harEntry);
        if (issues.length > 0) {
          results.issues = issues;
          this.findings.issues.push(...issues);
          this.notifyFinding('issue', issues);
        }
      } catch (e) {
        console.error('Header check error:', e);
      }
    }

    // Détection passive d'injections (SQL, NoSQL, XXE, Command, etc.)
    if (this.options.detectInjections && this.injectionDetector) {
      try {
        const injectionFindings = this.injectionDetector.analyze(harEntry, responseContent);
        if (injectionFindings.length > 0) {
          results.injections = injectionFindings;
          this.findings.injections.push(...injectionFindings);
          this.notifyFinding('injection', injectionFindings);
        }
      } catch (e) {
        console.error('Injection detection error:', e);
      }
    }

    // Analyse JWT avancée
    if (this.options.analyzeJWT && this.jwtAnalyzer) {
      try {
        const jwtResults = this.analyzeJWTInEntry(harEntry);
        if (jwtResults.length > 0) {
          results.jwtVulnerabilities = jwtResults;
          this.findings.jwtVulnerabilities.push(...jwtResults);
          this.notifyFinding('jwt', jwtResults);
        }
      } catch (e) {
        console.error('JWT analysis error:', e);
      }
    }

    // Extraction d'endpoints
    if (this.options.extractEndpoints) {
      try {
        results.endpoint = this.endpointExtractor.extract(harEntry);
      } catch (e) {
        console.error('Endpoint extraction error:', e);
      }
    }

    // Parsing JS pour endpoints caches
    if (this.options.parseJS && responseContent) {
      const contentType = this.getHeader(harEntry.response.headers, 'content-type');
      if (contentType?.includes('javascript') || harEntry.request.url.endsWith('.js')) {
        try {
          const jsEndpoints = this.endpointExtractor.parseJSForEndpoints(
            responseContent,
            harEntry.request.url
          );
          if (jsEndpoints.length > 0) {
            this.findings.jsEndpoints.push(...jsEndpoints);
          }
        } catch (e) {
          console.error('JS parsing error:', e);
        }
      }
    }

    // Auto-tagging
    results.tags = this.tagger.autoTag(harEntry);

    // Notifier l'UI
    this.notifyUpdate();

    return results;
  }

  getHeader(headers, name) {
    const header = headers?.find(h => h.name.toLowerCase() === name.toLowerCase());
    return header?.value;
  }

  // Analyser les JWT dans une entrée HAR
  analyzeJWTInEntry(harEntry) {
    if (!this.jwtAnalyzer) return [];

    const jwtResults = [];
    const jwtPattern = /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g;

    // Chercher dans les headers Authorization
    const authHeader = this.getHeader(harEntry.request.headers, 'authorization');
    if (authHeader) {
      const match = authHeader.match(jwtPattern);
      if (match) {
        for (const token of match) {
          const analysis = this.jwtAnalyzer.analyze(token);
          if (analysis.vulnerabilities.length > 0 || analysis.warnings.length > 0) {
            jwtResults.push({
              ...analysis,
              url: harEntry.request.url,
              location: 'Authorization header',
              token: token.substring(0, 50) + '...'
            });
          }
        }
      }
    }

    // Chercher dans les cookies
    for (const cookie of harEntry.request.cookies || []) {
      const match = cookie.value.match(jwtPattern);
      if (match) {
        for (const token of match) {
          const analysis = this.jwtAnalyzer.analyze(token);
          if (analysis.vulnerabilities.length > 0 || analysis.warnings.length > 0) {
            jwtResults.push({
              ...analysis,
              url: harEntry.request.url,
              location: `Cookie: ${cookie.name}`,
              token: token.substring(0, 50) + '...'
            });
          }
        }
      }
    }

    // Chercher dans le body de la requête
    if (harEntry.request.postData?.text) {
      const matches = harEntry.request.postData.text.match(jwtPattern);
      if (matches) {
        for (const token of matches) {
          const analysis = this.jwtAnalyzer.analyze(token);
          if (analysis.vulnerabilities.length > 0 || analysis.warnings.length > 0) {
            jwtResults.push({
              ...analysis,
              url: harEntry.request.url,
              location: 'Request body',
              token: token.substring(0, 50) + '...'
            });
          }
        }
      }
    }

    // Chercher dans la réponse
    if (harEntry.response.content?.text) {
      const matches = harEntry.response.content.text.match(jwtPattern);
      if (matches) {
        for (const token of matches) {
          const analysis = this.jwtAnalyzer.analyze(token);
          if (analysis.vulnerabilities.length > 0 || analysis.warnings.length > 0) {
            jwtResults.push({
              ...analysis,
              url: harEntry.request.url,
              location: 'Response body',
              token: token.substring(0, 50) + '...'
            });
          }
        }
      }
    }

    return jwtResults;
  }

  notifyFinding(type, data) {
    if (this.onFinding) {
      this.onFinding(type, data);
    }
  }

  notifyUpdate() {
    if (this.onUpdate) {
      this.onUpdate(this.getSummary());
    }
  }

  // Obtenir un resume pour l'UI
  getSummary() {
    const endpoints = this.endpointExtractor.getUniqueEndpoints();
    const idorCandidates = this.endpointExtractor.getIDORCandidates();
    const dedupStats = this.deduplicator.getStats();

    return {
      secrets: {
        total: this.findings.secrets.length,
        bySeverity: this.countBySeverity(this.findings.secrets),
        byType: this.countByType(this.findings.secrets)
      },
      issues: {
        total: this.findings.issues.length,
        bySeverity: this.countBySeverity(this.findings.issues),
        byType: this.countByType(this.findings.issues)
      },
      injections: {
        total: this.findings.injections.length,
        bySeverity: this.countBySeverity(this.findings.injections),
        byType: this.countByType(this.findings.injections)
      },
      jwtVulnerabilities: {
        total: this.findings.jwtVulnerabilities.length,
        bySeverity: this.countJWTBySeverity(this.findings.jwtVulnerabilities)
      },
      endpoints: {
        total: endpoints.length,
        byMethod: this.endpointExtractor.getStats().byMethod,
        idorCandidates: idorCandidates.length
      },
      jsEndpoints: this.findings.jsEndpoints.length,
      deduplication: dedupStats
    };
  }

  // Compter les vulnérabilités JWT par sévérité
  countJWTBySeverity(jwtResults) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const result of jwtResults) {
      for (const vuln of result.vulnerabilities || []) {
        if (vuln.severity && counts.hasOwnProperty(vuln.severity)) {
          counts[vuln.severity]++;
        }
      }
    }
    return counts;
  }

  countBySeverity(items) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const item of items) {
      if (item.severity && counts.hasOwnProperty(item.severity)) {
        counts[item.severity]++;
      }
    }
    return counts;
  }

  countByType(items) {
    const counts = {};
    for (const item of items) {
      const type = item.type || 'unknown';
      counts[type] = (counts[type] || 0) + 1;
    }
    return counts;
  }

  // Getters pour les resultats
  getSecrets() { return this.findings.secrets; }
  getIssues() { return this.findings.issues; }
  getInjections() { return this.findings.injections; }
  getJWTVulnerabilities() { return this.findings.jwtVulnerabilities; }
  getEndpoints() { return this.endpointExtractor.getUniqueEndpoints(); }
  getIDORCandidates() { return this.endpointExtractor.getIDORCandidates(); }
  getJSEndpoints() { return this.findings.jsEndpoints; }
  getDeduplicationStats() { return this.deduplicator.getStats(); }
  getAllParameters() { return this.endpointExtractor.getAllParameters(); }
  getTagStats(entries) { return this.tagger.getTagStats(entries); }

  // Générer des payloads de test pour les injections détectées
  generateInjectionPayloads(harEntry) {
    if (!this.injectionDetector) return {};
    return this.injectionDetector.generateTestPayloads(harEntry);
  }

  // Générer des variantes d'attaque JWT
  generateJWTAttackVariants(token) {
    if (!this.jwtAnalyzer) return [];
    const analysis = this.jwtAnalyzer.analyze(token);
    return analysis.attackVariants || [];
  }

  // Exports
  exportForFfuf(options) {
    return this.exportManager.toFfuf(this.getEndpoints(), options);
  }

  exportToCurl(harEntries) {
    return this.exportManager.toCurl(harEntries);
  }

  exportToPostman(options) {
    return this.exportManager.toPostman(this.getEndpoints(), options);
  }

  exportParamWordlist() {
    return this.exportManager.toParamWordlist(this.getEndpoints());
  }

  exportToMarkdown() {
    return this.exportManager.toMarkdown({
      endpoints: this.getEndpoints(),
      secrets: this.getSecrets(),
      issues: this.getIssues(),
      stats: {
        endpoints: this.getEndpoints().length,
        secrets: this.findings.secrets.length,
        issues: this.findings.issues.length,
        idor: this.getIDORCandidates().length
      }
    });
  }

  exportToJSON() {
    return this.exportManager.toJSON({
      summary: this.getSummary(),
      secrets: this.getSecrets(),
      issues: this.getIssues(),
      endpoints: this.getEndpoints(),
      jsEndpoints: this.getJSEndpoints(),
      parameters: this.getAllParameters()
    });
  }

  exportNucleiTemplates() {
    return this.exportManager.toNucleiTemplates(this.getIDORCandidates());
  }

  // Export Burp Suite XML
  exportToBurp(harEntries, options = {}) {
    return this.exportManager.toBurp(harEntries, options);
  }

  // Export SQLmap
  exportToSqlmap(harEntries, options = {}) {
    return this.exportManager.toSqlmap(harEntries, options);
  }

  // Export CSV
  exportToCSV(options = {}) {
    return this.exportManager.toCSV({
      findings: [...this.getIssues(), ...this.getInjections()],
      endpoints: this.getEndpoints(),
      secrets: this.getSecrets()
    }, options);
  }

  // Export wfuzz
  exportToWfuzz(options = {}) {
    return this.exportManager.toWfuzz(this.getEndpoints(), options);
  }

  // Obtenir tous les findings combinés (pour rapport complet)
  getAllFindings() {
    return {
      secrets: this.getSecrets(),
      issues: this.getIssues(),
      injections: this.getInjections(),
      jwtVulnerabilities: this.getJWTVulnerabilities(),
      endpoints: this.getEndpoints(),
      idorCandidates: this.getIDORCandidates(),
      jsEndpoints: this.getJSEndpoints()
    };
  }

  // Utilitaires
  download(content, filename, mimeType) {
    this.exportManager.download(content, filename, mimeType);
  }

  async copyToClipboard(content) {
    return this.exportManager.copyToClipboard(content);
  }

  // Configuration
  updateFilters(config) {
    this.filters.updateConfig(config);
  }

  setEnabled(enabled) {
    this.enabled = enabled;
  }

  setOptions(options) {
    this.options = { ...this.options, ...options };
  }

  // Reset
  clear() {
    this.findings = {
      secrets: [],
      issues: [],
      endpoints: [],
      jsEndpoints: [],
      injections: [],
      jwtVulnerabilities: []
    };
    this.deduplicator.clear();
    this.endpointExtractor.clear();
    this.notifyUpdate();
  }

  // Statistiques de filtrage
  getFilterStats(harEntries) {
    return this.filters.getFilterStats(harEntries);
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.SecurityAnalyzer = SecurityAnalyzer;
}
