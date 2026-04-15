// SmartFilters.js - Filtrage intelligent des requetes
// AutoHAR Pentest Edition

class SmartFilters {
  constructor(config = {}) {
    this.config = {
      ignoreStatic: true,
      staticExtensions: [
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
        '.woff', '.woff2', '.ttf', '.eot', '.ico', '.map', '.webp'
      ],
      apiOnlyMode: false,
      apiPatterns: ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/_api/'],
      methodFilter: [], // vide = tous
      excludeThirdParty: false,
      primaryDomain: '',
      excludePatterns: [],
      includePatterns: [],
      excludeDomains: [
        'google-analytics.com', 'googletagmanager.com', 'facebook.com',
        'doubleclick.net', 'hotjar.com', 'segment.com', 'mixpanel.com',
        'sentry.io', 'newrelic.com', 'datadoghq.com'
      ],
      ...config
    };
  }

  shouldProcess(harEntry) {
    const url = this.parseUrl(harEntry.request.url);
    if (!url) return false;

    // Filtre domaines exclus (analytics, tracking)
    if (this.isExcludedDomain(url.hostname)) {
      return false;
    }

    // Filtre assets statiques
    if (this.config.ignoreStatic) {
      const ext = this.getExtension(url.pathname);
      if (this.config.staticExtensions.includes(ext)) {
        return false;
      }
    }

    // Mode API-only
    if (this.config.apiOnlyMode) {
      if (!this.config.apiPatterns.some(p => url.pathname.includes(p))) {
        return false;
      }
    }

    // Filtre par methode HTTP
    if (this.config.methodFilter.length > 0) {
      if (!this.config.methodFilter.includes(harEntry.request.method)) {
        return false;
      }
    }

    // Exclusion third-party
    if (this.config.excludeThirdParty && this.config.primaryDomain) {
      if (!url.hostname.includes(this.config.primaryDomain)) {
        return false;
      }
    }

    // Patterns d'exclusion (regex)
    for (const pattern of this.config.excludePatterns) {
      try {
        if (new RegExp(pattern).test(harEntry.request.url)) {
          return false;
        }
      } catch (e) {
        console.warn('Invalid exclude pattern:', pattern);
      }
    }

    // Patterns d'inclusion (si specifies, doit matcher au moins un)
    if (this.config.includePatterns.length > 0) {
      const matches = this.config.includePatterns.some(p => {
        try {
          return new RegExp(p).test(harEntry.request.url);
        } catch (e) {
          return false;
        }
      });
      if (!matches) {
        return false;
      }
    }

    return true;
  }

  isExcludedDomain(hostname) {
    return this.config.excludeDomains.some(d => hostname.includes(d));
  }

  parseUrl(urlString) {
    try {
      return new URL(urlString);
    } catch (e) {
      return null;
    }
  }

  getExtension(pathname) {
    const match = pathname.match(/\.([^.?#]+)(?:\?|#|$)/);
    return match ? '.' + match[1].toLowerCase() : '';
  }

  // Detection automatique du domaine principal
  detectPrimaryDomain(harEntries) {
    const domains = {};
    for (const entry of harEntries) {
      const url = this.parseUrl(entry.request.url);
      if (url && !this.isExcludedDomain(url.hostname)) {
        domains[url.hostname] = (domains[url.hostname] || 0) + 1;
      }
    }

    // Retourner le domaine le plus frequent
    let maxCount = 0;
    let primaryDomain = '';
    for (const [domain, count] of Object.entries(domains)) {
      if (count > maxCount) {
        maxCount = count;
        primaryDomain = domain;
      }
    }

    return primaryDomain;
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
  }

  getConfig() {
    return { ...this.config };
  }

  // Stats sur les requetes filtrees
  getFilterStats(harEntries) {
    let passed = 0;
    let filtered = 0;
    const reasons = {
      static: 0,
      apiOnly: 0,
      method: 0,
      thirdParty: 0,
      excludePattern: 0,
      excludeDomain: 0
    };

    for (const entry of harEntries) {
      if (this.shouldProcess(entry)) {
        passed++;
      } else {
        filtered++;
        // Determiner la raison
        const url = this.parseUrl(entry.request.url);
        if (url) {
          if (this.isExcludedDomain(url.hostname)) reasons.excludeDomain++;
          else if (this.config.ignoreStatic && this.config.staticExtensions.includes(this.getExtension(url.pathname))) reasons.static++;
          else if (this.config.apiOnlyMode) reasons.apiOnly++;
          else if (this.config.methodFilter.length > 0) reasons.method++;
          else if (this.config.excludeThirdParty) reasons.thirdParty++;
          else reasons.excludePattern++;
        }
      }
    }

    return { passed, filtered, reasons };
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.SmartFilters = SmartFilters;
}
