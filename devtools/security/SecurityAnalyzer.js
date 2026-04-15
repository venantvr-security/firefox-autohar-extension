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

    // Stockage des resultats
    this.findings = {
      secrets: [],
      issues: [],
      endpoints: [],
      jsEndpoints: []
    };

    // Configuration
    this.enabled = true;
    this.options = {
      detectSecrets: true,
      checkHeaders: true,
      extractEndpoints: true,
      parseJS: true,
      deduplicate: true,
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
      endpoints: {
        total: endpoints.length,
        byMethod: this.endpointExtractor.getStats().byMethod,
        idorCandidates: idorCandidates.length
      },
      jsEndpoints: this.findings.jsEndpoints.length,
      deduplication: dedupStats
    };
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
  getEndpoints() { return this.endpointExtractor.getUniqueEndpoints(); }
  getIDORCandidates() { return this.endpointExtractor.getIDORCandidates(); }
  getJSEndpoints() { return this.findings.jsEndpoints; }
  getDeduplicationStats() { return this.deduplicator.getStats(); }
  getAllParameters() { return this.endpointExtractor.getAllParameters(); }
  getTagStats(entries) { return this.tagger.getTagStats(entries); }

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
      jsEndpoints: []
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
