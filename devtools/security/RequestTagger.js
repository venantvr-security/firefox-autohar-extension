// RequestTagger.js - Auto-tagging des requetes
// AutoHAR Pentest Edition

class RequestTagger {
  constructor() {
    // Regles d'auto-tagging
    this.tagRules = [
      {
        tag: 'auth',
        color: '#8b5cf6',
        condition: (entry) => {
          const url = entry.request.url.toLowerCase();
          const hasAuthHeader = entry.request.headers.some(h =>
            h.name.toLowerCase() === 'authorization'
          );
          const authKeywords = ['login', 'logout', 'signin', 'signout', 'signup',
            'auth', 'oauth', 'token', 'session', 'password', 'register', 'forgot'];
          return hasAuthHeader || authKeywords.some(k => url.includes(k));
        }
      },
      {
        tag: 'api',
        color: '#3b82f6',
        condition: (entry) => {
          const url = entry.request.url.toLowerCase();
          const contentType = this.getHeader(entry.response.headers, 'content-type') || '';
          return url.includes('/api/') ||
            url.includes('/v1/') ||
            url.includes('/v2/') ||
            url.includes('/v3/') ||
            url.includes('/graphql') ||
            url.includes('/rest/') ||
            contentType.includes('application/json');
        }
      },
      {
        tag: 'sensitive',
        color: '#ef4444',
        condition: (entry) => {
          const url = entry.request.url.toLowerCase();
          const body = entry.request.postData?.text?.toLowerCase() || '';
          const sensitiveKeywords = ['password', 'passwd', 'secret', 'credit', 'card',
            'ssn', 'cvv', 'pin', 'private', 'payment', 'bank', 'billing', 'salary'];
          return sensitiveKeywords.some(k => url.includes(k) || body.includes(k));
        }
      },
      {
        tag: 'upload',
        color: '#22c55e',
        condition: (entry) => {
          const contentType = this.getHeader(entry.request.headers, 'content-type') || '';
          return contentType.includes('multipart/form-data');
        }
      },
      {
        tag: 'redirect',
        color: '#f59e0b',
        condition: (entry) => {
          return entry.response.status >= 300 && entry.response.status < 400;
        }
      },
      {
        tag: 'error',
        color: '#dc3545',
        condition: (entry) => {
          return entry.response.status >= 400;
        }
      },
      {
        tag: 'admin',
        color: '#ec4899',
        condition: (entry) => {
          const url = entry.request.url.toLowerCase();
          const adminKeywords = ['/admin', '/dashboard', '/manage', '/control',
            '/settings', '/config', '/internal', '/backoffice', '/cms'];
          return adminKeywords.some(k => url.includes(k));
        }
      },
      {
        tag: 'user-data',
        color: '#06b6d4',
        condition: (entry) => {
          const url = entry.request.url.toLowerCase();
          const userKeywords = ['/user', '/profile', '/account', '/me', '/self',
            '/member', '/customer'];
          return userKeywords.some(k => url.includes(k));
        }
      },
      {
        tag: 'file',
        color: '#84cc16',
        condition: (entry) => {
          const url = entry.request.url.toLowerCase();
          const fileKeywords = ['/download', '/upload', '/file', '/document',
            '/attachment', '/media', '/asset', '/export', '/import'];
          return fileKeywords.some(k => url.includes(k));
        }
      },
      {
        tag: 'websocket',
        color: '#a855f7',
        condition: (entry) => {
          const url = entry.request.url.toLowerCase();
          return url.startsWith('wss://') || url.startsWith('ws://') ||
            url.includes('/socket') || url.includes('/ws');
        }
      }
    ];

    // Tags manuels ajoutes par l'utilisateur
    this.manualTags = new Map(); // requestId -> Set<tags>

    // Tags disponibles pour ajout manuel
    this.availableTags = [
      { tag: 'interesting', color: '#fbbf24' },
      { tag: 'vuln', color: '#ef4444' },
      { tag: 'todo', color: '#6366f1' },
      { tag: 'tested', color: '#10b981' },
      { tag: 'idor', color: '#f97316' }
    ];
  }

  getHeader(headers, name) {
    const header = headers?.find(h => h.name.toLowerCase() === name.toLowerCase());
    return header?.value;
  }

  // Auto-tag une entree HAR
  autoTag(harEntry) {
    const tags = new Set();

    for (const rule of this.tagRules) {
      try {
        if (rule.condition(harEntry)) {
          tags.add(rule.tag);
        }
      } catch (e) {
        // Ignorer les erreurs de condition
      }
    }

    return tags;
  }

  // Obtenir tous les tags (auto + manuels)
  getAllTags(harEntry, requestId) {
    const autoTags = this.autoTag(harEntry);
    const manual = this.manualTags.get(requestId) || new Set();
    return new Set([...autoTags, ...manual]);
  }

  // Ajouter un tag manuel
  addManualTag(requestId, tag) {
    if (!this.manualTags.has(requestId)) {
      this.manualTags.set(requestId, new Set());
    }
    this.manualTags.get(requestId).add(tag);
  }

  // Retirer un tag manuel
  removeManualTag(requestId, tag) {
    this.manualTags.get(requestId)?.delete(tag);
  }

  // Obtenir la couleur d'un tag
  getTagColor(tag) {
    const rule = this.tagRules.find(r => r.tag === tag);
    if (rule) return rule.color;

    const available = this.availableTags.find(t => t.tag === tag);
    if (available) return available.color;

    return '#6b7280'; // Gris par defaut
  }

  // Filtrer les entrees par tag
  filterByTag(entries, tag) {
    return entries.filter((entry, index) => {
      const tags = this.getAllTags(entry, index);
      return tags.has(tag);
    });
  }

  // Obtenir les stats par tag
  getTagStats(entries) {
    const stats = {};

    entries.forEach((entry, index) => {
      const tags = this.getAllTags(entry, index);
      for (const tag of tags) {
        stats[tag] = (stats[tag] || 0) + 1;
      }
    });

    return Object.entries(stats)
      .map(([tag, count]) => ({ tag, count, color: this.getTagColor(tag) }))
      .sort((a, b) => b.count - a.count);
  }

  // Generer le HTML pour les tags
  renderTags(tags) {
    return Array.from(tags).map(tag => {
      const color = this.getTagColor(tag);
      return `<span class="tag" style="background: ${color}20; color: ${color};">${tag}</span>`;
    }).join('');
  }

  // Obtenir tous les tags disponibles
  getAvailableTagsList() {
    const autoTags = this.tagRules.map(r => ({ tag: r.tag, color: r.color, type: 'auto' }));
    const manualTags = this.availableTags.map(t => ({ ...t, type: 'manual' }));
    return [...autoTags, ...manualTags];
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.RequestTagger = RequestTagger;
}
