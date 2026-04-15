// RequestDeduplicator.js - Deduplication intelligente des requetes
// AutoHAR Pentest Edition

class RequestDeduplicator {
  constructor(options = {}) {
    this.seen = new Map(); // hash -> { count, first, last, entry }
    this.options = {
      ignoreTimestamps: true,
      ignoreRandomParams: true,
      normalizeIds: true,
      ...options
    };

    // Patterns de parametres aleatoires a ignorer
    this.randomParamPatterns = [
      /^_=\d+$/,           // jQuery cache buster
      /^t=\d+$/,           // Timestamp
      /^ts=\d+$/,
      /^timestamp=\d+$/,
      /^nocache=[\d.]+$/,
      /^rand=[\d.]+$/,
      /^cb=\d+$/,          // Cache buster
      /^v=\d+$/,           // Version
      /^_dc=\d+$/,         // ExtJS
      /^_=[\da-f-]+$/i     // UUID cache buster
    ];
  }

  isDuplicate(harEntry) {
    const hash = this.computeHash(harEntry);
    return this.seen.has(hash);
  }

  add(harEntry) {
    const hash = this.computeHash(harEntry);

    if (this.seen.has(hash)) {
      const entry = this.seen.get(hash);
      entry.count++;
      entry.last = Date.now();
      return { isDuplicate: true, count: entry.count, hash };
    }

    this.seen.set(hash, {
      count: 1,
      first: Date.now(),
      last: Date.now(),
      entry: harEntry,
      hash
    });

    return { isDuplicate: false, count: 1, hash };
  }

  computeHash(harEntry) {
    const components = [];

    // 1. Methode HTTP
    components.push(harEntry.request.method);

    // 2. URL normalisee
    try {
      const url = new URL(harEntry.request.url);
      let path = url.pathname;

      // Normaliser les IDs dans le path
      if (this.options.normalizeIds) {
        path = this.normalizePath(path);
      }

      components.push(url.host + path);

      // 3. Parametres de query (tries, sans randoms)
      const params = [];
      for (const [key, value] of url.searchParams.entries()) {
        if (!this.isRandomParam(key, value)) {
          params.push(key);
        }
      }
      params.sort();
      components.push(params.join('&'));
    } catch (e) {
      components.push(harEntry.request.url);
    }

    // 4. Structure du body (pour POST/PUT)
    if (harEntry.request.postData?.text) {
      const bodyStructure = this.getBodyStructure(harEntry.request.postData.text, harEntry.request.postData.mimeType);
      components.push(bodyStructure);
    }

    return components.join('|');
  }

  normalizePath(path) {
    return path
      // IDs numeriques
      .replace(/\/\d+/g, '/{id}')
      // UUIDs
      .replace(/\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi, '/{uuid}')
      // MongoDB ObjectIds
      .replace(/\/[a-f0-9]{24}/gi, '/{objectId}')
      // Hashes courts (MD5-like)
      .replace(/\/[a-f0-9]{32}/gi, '/{hash}')
      // Slugs avec IDs
      .replace(/\/-?\d+-/g, '/{id}-');
  }

  isRandomParam(key, value) {
    const combined = `${key}=${value}`;
    return this.randomParamPatterns.some(p => p.test(combined));
  }

  getBodyStructure(bodyText, mimeType) {
    // JSON body - extraire la structure des cles
    if (mimeType?.includes('json')) {
      try {
        const body = JSON.parse(bodyText);
        return 'json:' + this.getObjectStructure(body);
      } catch (e) {
        return 'json:invalid';
      }
    }

    // Form data
    if (mimeType?.includes('form-urlencoded')) {
      try {
        const params = new URLSearchParams(bodyText);
        const keys = Array.from(params.keys()).sort();
        return 'form:' + keys.join(',');
      } catch (e) {
        return 'form:invalid';
      }
    }

    // Multipart - juste indiquer le type
    if (mimeType?.includes('multipart')) {
      return 'multipart';
    }

    // Autres - hash de la taille
    return `raw:${bodyText?.length || 0}`;
  }

  getObjectStructure(obj, depth = 0) {
    if (depth > 3) return 'deep';
    if (obj === null) return 'null';
    if (Array.isArray(obj)) {
      if (obj.length === 0) return '[]';
      return `[${this.getObjectStructure(obj[0], depth + 1)}]`;
    }
    if (typeof obj === 'object') {
      const keys = Object.keys(obj).sort();
      return '{' + keys.join(',') + '}';
    }
    return typeof obj;
  }

  getStats() {
    const entries = Array.from(this.seen.values());
    const totalRequests = entries.reduce((sum, e) => sum + e.count, 0);

    return {
      unique: this.seen.size,
      total: totalRequests,
      duplicatesIgnored: totalRequests - this.seen.size,
      deduplicationRate: this.seen.size > 0
        ? ((totalRequests - this.seen.size) / totalRequests * 100).toFixed(1) + '%'
        : '0%'
    };
  }

  getUniqueEntries() {
    return Array.from(this.seen.values()).map(e => ({
      entry: e.entry,
      count: e.count,
      firstSeen: e.first,
      lastSeen: e.last,
      hash: e.hash
    }));
  }

  // Obtenir les requetes les plus repetees
  getMostDuplicated(limit = 10) {
    return Array.from(this.seen.values())
      .filter(e => e.count > 1)
      .sort((a, b) => b.count - a.count)
      .slice(0, limit)
      .map(e => ({
        url: e.entry.request.url,
        method: e.entry.request.method,
        count: e.count,
        hash: e.hash
      }));
  }

  clear() {
    this.seen.clear();
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.RequestDeduplicator = RequestDeduplicator;
}
