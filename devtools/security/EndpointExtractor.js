// EndpointExtractor.js - Extraction et analyse des endpoints
// AutoHAR Pentest Edition

class EndpointExtractor {
  constructor() {
    this.endpoints = new Map(); // key -> endpoint data

    // Patterns IDOR
    this.idorPatterns = [
      { regex: /\/users?\/(\d+)/, param: 'user_id', confidence: 0.8 },
      { regex: /\/accounts?\/(\d+)/, param: 'account_id', confidence: 0.9 },
      { regex: /\/orders?\/(\d+)/, param: 'order_id', confidence: 0.8 },
      { regex: /\/profiles?\/(\d+)/, param: 'profile_id', confidence: 0.8 },
      { regex: /\/documents?\/(\d+)/, param: 'document_id', confidence: 0.7 },
      { regex: /\/files?\/(\d+)/, param: 'file_id', confidence: 0.7 },
      { regex: /\/invoices?\/(\d+)/, param: 'invoice_id', confidence: 0.8 },
      { regex: /\/payments?\/(\d+)/, param: 'payment_id', confidence: 0.9 },
      { regex: /\/messages?\/(\d+)/, param: 'message_id', confidence: 0.6 },
      { regex: /\/comments?\/(\d+)/, param: 'comment_id', confidence: 0.5 },
      { regex: /\/posts?\/(\d+)/, param: 'post_id', confidence: 0.5 },
      { regex: /\/items?\/(\d+)/, param: 'item_id', confidence: 0.6 },
      { regex: /[?&](id|user_id|account_id|order_id|doc_id|file_id)=(\d+)/, param: 'id', confidence: 0.7 },
      { regex: /\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i, param: 'uuid', confidence: 0.5 }
    ];

    // Patterns pour extraire des endpoints depuis le JS
    this.jsEndpointPatterns = [
      /["'](\/api\/[^"']+)["']/g,
      /["'](\/v\d+\/[^"']+)["']/g,
      /fetch\s*\(\s*["']([^"']+)["']/g,
      /\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']/g,
      /axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']/gi,
      /url:\s*["']([^"']+)["']/g,
      /endpoint:\s*["']([^"']+)["']/g,
      /path:\s*["']([^"']+)["']/g
    ];
  }

  // Extraire et enregistrer un endpoint
  extract(harEntry) {
    let url;
    try {
      url = new URL(harEntry.request.url);
    } catch (e) {
      return null;
    }

    const normalizedPath = this.normalizePath(url.pathname);
    const key = `${url.host}|${normalizedPath}|${harEntry.request.method}`;

    const endpoint = {
      originalPath: url.pathname,
      normalizedPath,
      method: harEntry.request.method,
      host: url.host,
      fullUrl: `${url.origin}${url.pathname}`,
      parameters: this.extractParameters(harEntry),
      idorIndicators: this.detectIDOR(harEntry),
      timestamp: Date.now()
    };

    // Mettre a jour ou creer l'endpoint
    if (this.endpoints.has(key)) {
      const existing = this.endpoints.get(key);
      existing.requestCount++;
      existing.lastSeen = Date.now();
      this.mergeParameters(existing.parameters, endpoint.parameters);
      // Garder le meilleur score IDOR
      if (endpoint.idorIndicators.length > 0) {
        existing.idorIndicators = this.mergeIdorIndicators(
          existing.idorIndicators,
          endpoint.idorIndicators
        );
      }
    } else {
      this.endpoints.set(key, {
        ...endpoint,
        requestCount: 1,
        firstSeen: Date.now(),
        lastSeen: Date.now()
      });
    }

    return endpoint;
  }

  normalizePath(path) {
    return path
      // UUIDs (must run BEFORE numeric IDs)
      .replace(/\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi, '/{uuid}')
      // MongoDB ObjectIds (24 hex chars, must run BEFORE numeric IDs)
      .replace(/\/[a-f0-9]{24}/gi, '/{objectId}')
      // Hashes MD5 (32 hex chars)
      .replace(/\/[a-f0-9]{32}/gi, '/{hash}')
      // IDs numeriques (run AFTER longer patterns)
      .replace(/\/\d+/g, '/{id}')
      // Slugs avec IDs
      .replace(/-\d+-/g, '-{id}-')
      // Trailing slashes
      .replace(/\/+$/, '');
  }

  extractParameters(harEntry) {
    const params = {
      path: [],
      query: [],
      body: [],
      header: []
    };

    // Parametres de path (detectes via normalisation)
    const pathParams = harEntry.request.url.match(/\/(\d+)|\/{uuid}|\/{objectId}/g);
    if (pathParams) {
      params.path = pathParams.map((p, i) => ({
        name: `path_param_${i}`,
        value: p.replace('/', ''),
        type: this.inferType(p.replace('/', ''))
      }));
    }

    // Parametres de query
    try {
      const url = new URL(harEntry.request.url);
      for (const [name, value] of url.searchParams) {
        params.query.push({
          name,
          value,
          type: this.inferType(value)
        });
      }
    } catch (e) { }

    // Parametres du body
    if (harEntry.request.postData?.text) {
      const bodyParams = this.extractBodyParams(
        harEntry.request.postData.text,
        harEntry.request.postData.mimeType
      );
      params.body = bodyParams;
    }

    // Headers interessants
    const interestingHeaders = [
      'authorization', 'x-api-key', 'x-auth-token', 'x-csrf-token',
      'x-request-id', 'x-correlation-id'
    ];
    for (const header of harEntry.request.headers || []) {
      if (interestingHeaders.includes(header.name.toLowerCase())) {
        params.header.push({
          name: header.name,
          value: '[REDACTED]',
          type: 'auth'
        });
      }
    }

    return params;
  }

  extractBodyParams(bodyText, mimeType) {
    const params = [];

    // JSON
    if (mimeType?.includes('json')) {
      try {
        const body = JSON.parse(bodyText);
        return this.flattenObject(body);
      } catch (e) { }
    }

    // Form data
    if (mimeType?.includes('form-urlencoded')) {
      try {
        const formData = new URLSearchParams(bodyText);
        for (const [name, value] of formData) {
          params.push({
            name,
            value,
            type: this.inferType(value)
          });
        }
      } catch (e) { }
    }

    return params;
  }

  flattenObject(obj, prefix = '', depth = 0) {
    if (depth > 5) return [];
    const params = [];

    for (const [key, value] of Object.entries(obj || {})) {
      const fullKey = prefix ? `${prefix}.${key}` : key;

      if (value && typeof value === 'object' && !Array.isArray(value)) {
        params.push(...this.flattenObject(value, fullKey, depth + 1));
      } else if (Array.isArray(value)) {
        params.push({
          name: `${fullKey}[]`,
          value: `[array:${value.length}]`,
          type: 'array'
        });
      } else {
        params.push({
          name: fullKey,
          value: String(value),
          type: this.inferType(String(value))
        });
      }
    }

    return params;
  }

  inferType(value) {
    if (/^\d+$/.test(value)) return 'integer';
    if (/^\d+\.\d+$/.test(value)) return 'float';
    if (/^(true|false)$/i.test(value)) return 'boolean';
    if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value)) return 'uuid';
    if (/^[a-f0-9]{24}$/i.test(value)) return 'objectId';
    if (/^[\w.-]+@[\w.-]+\.\w+$/.test(value)) return 'email';
    if (/^https?:\/\//.test(value)) return 'url';
    return 'string';
  }

  detectIDOR(harEntry) {
    const indicators = [];
    const url = harEntry.request.url;

    for (const pattern of this.idorPatterns) {
      const match = url.match(pattern.regex);
      if (match) {
        let confidence = pattern.confidence;

        // Augmenter la confiance si requete authentifiee
        const hasAuth = harEntry.request.headers.some(h =>
          h.name.toLowerCase() === 'authorization' ||
          h.name.toLowerCase() === 'cookie'
        );
        if (hasAuth) confidence += 0.1;

        // Augmenter pour methodes non-GET
        if (harEntry.request.method !== 'GET') confidence += 0.1;

        // Augmenter pour status 200 avec contenu
        if (harEntry.response.status === 200 &&
          harEntry.response.content?.size > 0) {
          confidence += 0.1;
        }

        indicators.push({
          pattern: pattern.param,
          value: match[1] || match[0],
          confidence: Math.min(confidence, 1)
        });
      }
    }

    return indicators;
  }

  mergeParameters(existing, newParams) {
    for (const type of ['query', 'body', 'header']) {
      const existingNames = new Set(existing[type].map(p => p.name));
      for (const param of newParams[type]) {
        if (!existingNames.has(param.name)) {
          existing[type].push(param);
        }
      }
    }
  }

  mergeIdorIndicators(existing, newIndicators) {
    const merged = [...existing];
    for (const indicator of newIndicators) {
      const existingIdx = merged.findIndex(i => i.pattern === indicator.pattern);
      if (existingIdx >= 0) {
        merged[existingIdx].confidence = Math.max(
          merged[existingIdx].confidence,
          indicator.confidence
        );
      } else {
        merged.push(indicator);
      }
    }
    return merged;
  }

  // Parser le JS pour trouver des endpoints caches
  parseJSForEndpoints(jsContent, sourceUrl) {
    const endpoints = [];

    for (const pattern of this.jsEndpointPatterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(jsContent)) !== null) {
        const endpoint = match[1];
        if (endpoint && endpoint.startsWith('/') && !endpoint.includes('${')) {
          endpoints.push({
            path: endpoint,
            source: sourceUrl,
            type: 'js_extracted'
          });
        }
      }
    }

    // Dedupliquer
    const unique = [...new Set(endpoints.map(e => e.path))];
    return unique.map(path => ({
      path,
      normalizedPath: this.normalizePath(path),
      source: sourceUrl,
      type: 'js_extracted'
    }));
  }

  // Obtenir tous les endpoints uniques
  getUniqueEndpoints() {
    return Array.from(this.endpoints.values());
  }

  // Obtenir les endpoints avec IDOR potentiel
  getIDORCandidates(minConfidence = 0.5) {
    return this.getUniqueEndpoints()
      .filter(ep => ep.idorIndicators.some(i => i.confidence >= minConfidence))
      .sort((a, b) => {
        const maxA = Math.max(...a.idorIndicators.map(i => i.confidence));
        const maxB = Math.max(...b.idorIndicators.map(i => i.confidence));
        return maxB - maxA;
      });
  }

  // Obtenir les stats
  getStats() {
    const endpoints = this.getUniqueEndpoints();
    const methods = {};
    let totalParams = 0;
    let idorCount = 0;

    for (const ep of endpoints) {
      methods[ep.method] = (methods[ep.method] || 0) + 1;
      totalParams += ep.parameters.query.length + ep.parameters.body.length;
      if (ep.idorIndicators.length > 0) idorCount++;
    }

    return {
      total: endpoints.length,
      byMethod: methods,
      totalParameters: totalParams,
      idorCandidates: idorCount
    };
  }

  // Obtenir tous les parametres uniques
  getAllParameters() {
    const params = {
      query: new Set(),
      body: new Set()
    };

    for (const ep of this.endpoints.values()) {
      for (const p of ep.parameters.query) params.query.add(p.name);
      for (const p of ep.parameters.body) params.body.add(p.name);
    }

    return {
      query: Array.from(params.query).sort(),
      body: Array.from(params.body).sort()
    };
  }

  clear() {
    this.endpoints.clear();
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.EndpointExtractor = EndpointExtractor;
}
