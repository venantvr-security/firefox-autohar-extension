// ExportManager.js - Export multi-format pour outils pentest
// AutoHAR Pentest Edition

class ExportManager {
  constructor() { }

  // Export pour ffuf (wordlist d'endpoints)
  toFfuf(endpoints, options = {}) {
    const lines = [];
    const seen = new Set();

    for (const ep of endpoints) {
      const path = options.normalized ? ep.normalizedPath : ep.originalPath;

      if (options.includeHost) {
        const fullUrl = `${ep.host}${path}`;
        if (!seen.has(fullUrl)) {
          seen.add(fullUrl);
          lines.push(fullUrl);
        }
      } else {
        if (!seen.has(path)) {
          seen.add(path);
          lines.push(path);
        }
      }

      // Ajouter les variations avec FUZZ
      if (options.withFuzz) {
        for (const param of ep.parameters.query) {
          const fuzzUrl = `${ep.fullUrl}?${param.name}=FUZZ`;
          if (!seen.has(fuzzUrl)) {
            seen.add(fuzzUrl);
            lines.push(fuzzUrl);
          }
        }
      }
    }

    return lines.join('\n');
  }

  // Export en commandes curl
  toCurl(harEntries) {
    return harEntries.map(entry => this.harToCurl(entry)).join('\n\n');
  }

  harToCurl(entry) {
    const parts = ['curl'];

    // Methode
    if (entry.request.method !== 'GET') {
      parts.push(`-X ${entry.request.method}`);
    }

    // Headers (filtrer les headers auto-generes)
    const skipHeaders = [
      'host', 'content-length', 'connection', 'accept-encoding',
      'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest'
    ];

    for (const header of entry.request.headers || []) {
      if (!skipHeaders.includes(header.name.toLowerCase())) {
        const escapedValue = header.value.replace(/'/g, "'\\''");
        parts.push(`-H '${header.name}: ${escapedValue}'`);
      }
    }

    // Body
    if (entry.request.postData?.text) {
      const escaped = entry.request.postData.text.replace(/'/g, "'\\''");
      parts.push(`-d '${escaped}'`);
    }

    // URL
    parts.push(`'${entry.request.url}'`);

    return parts.join(' \\\n  ');
  }

  // Export en collection Postman
  toPostman(endpoints, options = {}) {
    const collection = {
      info: {
        name: options.name || 'AutoHAR Export',
        description: 'Exported from AutoHAR Pentest Edition',
        schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
      },
      item: [],
      variable: [
        { key: 'baseUrl', value: options.baseUrl || '', type: 'string' },
        { key: 'authToken', value: '', type: 'string' }
      ]
    };

    // Grouper par host
    const byHost = new Map();
    for (const ep of endpoints) {
      if (!byHost.has(ep.host)) {
        byHost.set(ep.host, []);
      }
      byHost.get(ep.host).push(ep);
    }

    // Creer les folders
    for (const [host, eps] of byHost) {
      const folder = {
        name: host,
        item: eps.map(ep => this.endpointToPostmanItem(ep))
      };
      collection.item.push(folder);
    }

    return JSON.stringify(collection, null, 2);
  }

  endpointToPostmanItem(endpoint) {
    let url;
    try {
      url = new URL(endpoint.fullUrl);
    } catch (e) {
      url = { protocol: 'https:', hostname: endpoint.host, pathname: endpoint.normalizedPath };
    }

    return {
      name: `${endpoint.method} ${endpoint.normalizedPath}`,
      request: {
        method: endpoint.method,
        header: endpoint.parameters.header.map(h => ({
          key: h.name,
          value: '{{authToken}}',
          type: 'text'
        })),
        url: {
          raw: endpoint.fullUrl,
          protocol: url.protocol?.replace(':', '') || 'https',
          host: (url.hostname || endpoint.host).split('.'),
          path: endpoint.normalizedPath.split('/').filter(Boolean),
          query: endpoint.parameters.query.map(p => ({
            key: p.name,
            value: p.value,
            description: `Type: ${p.type}`
          }))
        },
        body: endpoint.parameters.body.length > 0 ? {
          mode: 'raw',
          raw: JSON.stringify(
            Object.fromEntries(endpoint.parameters.body.map(p => [p.name, p.value])),
            null, 2
          ),
          options: { raw: { language: 'json' } }
        } : undefined
      }
    };
  }

  // Export wordlist de parametres
  toParamWordlist(endpoints) {
    const params = new Set();

    for (const ep of endpoints) {
      for (const p of ep.parameters.query) params.add(p.name);
      for (const p of ep.parameters.body) {
        // Garder seulement le top-level pour les objets imbriques
        const topLevel = p.name.split('.')[0].replace('[]', '');
        params.add(topLevel);
      }
    }

    return Array.from(params).sort().join('\n');
  }

  // Export rapport Markdown
  toMarkdown(data) {
    const { endpoints, secrets, issues, stats } = data;
    let md = '# AutoHAR Security Analysis Report\n\n';
    md += `**Generated:** ${new Date().toISOString()}\n\n`;

    // Resume
    md += '## Summary\n\n';
    md += `| Metric | Value |\n`;
    md += `|--------|-------|\n`;
    md += `| Total Endpoints | ${stats.endpoints || 0} |\n`;
    md += `| Secrets Found | ${stats.secrets || 0} |\n`;
    md += `| Security Issues | ${stats.issues || 0} |\n`;
    md += `| IDOR Candidates | ${stats.idor || 0} |\n\n`;

    // Secrets
    if (secrets && secrets.length > 0) {
      md += '## Secrets Detected\n\n';
      md += '| Type | Severity | Location | Masked Value |\n';
      md += '|------|----------|----------|-------------|\n';

      for (const secret of secrets.slice(0, 50)) {
        md += `| ${secret.description} | ${secret.severity} | ${secret.location} | \`${secret.masked}\` |\n`;
      }

      if (secrets.length > 50) {
        md += `\n*... and ${secrets.length - 50} more*\n`;
      }
      md += '\n';
    }

    // Issues
    if (issues && issues.length > 0) {
      md += '## Security Issues\n\n';

      const byType = {};
      for (const issue of issues) {
        byType[issue.type] = byType[issue.type] || [];
        byType[issue.type].push(issue);
      }

      for (const [type, typeIssues] of Object.entries(byType)) {
        md += `### ${this.formatIssueType(type)}\n\n`;
        for (const issue of typeIssues.slice(0, 10)) {
          md += `- **${issue.severity}**: ${issue.description}`;
          if (issue.url) {
            const shortUrl = issue.url.length > 80 ? issue.url.substring(0, 80) + '...' : issue.url;
            md += ` - \`${shortUrl}\``;
          }
          md += '\n';
        }
        if (typeIssues.length > 10) {
          md += `  *... and ${typeIssues.length - 10} more*\n`;
        }
        md += '\n';
      }
    }

    // IDOR Candidates
    const idorEndpoints = endpoints?.filter(ep =>
      ep.idorIndicators && ep.idorIndicators.length > 0
    ) || [];

    if (idorEndpoints.length > 0) {
      md += '## Potential IDOR Endpoints\n\n';
      md += '| Endpoint | Method | Confidence | Pattern |\n';
      md += '|----------|--------|------------|--------|\n';

      for (const ep of idorEndpoints.slice(0, 20)) {
        const maxIndicator = ep.idorIndicators.reduce((a, b) =>
          a.confidence > b.confidence ? a : b
        );
        md += `| \`${ep.normalizedPath}\` | ${ep.method} | ${(maxIndicator.confidence * 100).toFixed(0)}% | ${maxIndicator.pattern} |\n`;
      }
      md += '\n';
    }

    // Endpoints (sample)
    if (endpoints && endpoints.length > 0) {
      md += '## Discovered Endpoints\n\n';
      md += '<details><summary>Click to expand</summary>\n\n';
      md += '```\n';

      const byMethod = {};
      for (const ep of endpoints) {
        byMethod[ep.method] = byMethod[ep.method] || [];
        byMethod[ep.method].push(ep.normalizedPath);
      }

      for (const [method, paths] of Object.entries(byMethod)) {
        md += `# ${method}\n`;
        for (const path of [...new Set(paths)].slice(0, 50)) {
          md += `${path}\n`;
        }
        md += '\n';
      }

      md += '```\n\n</details>\n\n';
    }

    // Footer
    md += '---\n';
    md += '*Generated by AutoHAR Pentest Edition*\n';

    return md;
  }

  formatIssueType(type) {
    const names = {
      'missing_header': 'Missing Security Headers',
      'weak_header': 'Weak Header Configuration',
      'insecure_cookie': 'Insecure Cookies',
      'cors_wildcard': 'CORS Wildcard',
      'cors_origin_reflection': 'CORS Origin Reflection',
      'cors_wildcard_credentials': 'CORS Wildcard with Credentials',
      'mixed_content_redirect': 'Mixed Content Redirect',
      'information_leakage': 'Information Disclosure'
    };
    return names[type] || type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }

  // Export JSON structure
  toJSON(data) {
    return JSON.stringify(data, null, 2);
  }

  // Export pour nuclei (templates basiques)
  toNucleiTemplates(endpoints, options = {}) {
    const templates = [];

    for (const ep of endpoints) {
      if (ep.idorIndicators && ep.idorIndicators.length > 0) {
        templates.push(this.createNucleiIDORTemplate(ep, options));
      }
    }

    return templates.join('\n---\n');
  }

  createNucleiIDORTemplate(endpoint, options = {}) {
    const templateId = `idor-${endpoint.normalizedPath.replace(/[^a-z0-9]/gi, '-')}`;

    return `id: ${templateId}

info:
  name: Potential IDOR - ${endpoint.normalizedPath}
  author: autohar
  severity: medium
  description: Potential Insecure Direct Object Reference detected
  tags: idor,pentest

http:
  - method: ${endpoint.method}
    path:
      - "{{BaseURL}}${endpoint.normalizedPath.replace(/{id}/g, '{{id}}')}"

    payloads:
      id:
        - "1"
        - "2"
        - "100"
        - "999999"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "id"
          - "user"
        condition: or
`;
  }

  // Telecharger un fichier
  download(content, filename, mimeType = 'text/plain') {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Copier dans le presse-papier
  async copyToClipboard(content) {
    try {
      await navigator.clipboard.writeText(content);
      return true;
    } catch (e) {
      // Fallback
      const textarea = document.createElement('textarea');
      textarea.value = content;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      return true;
    }
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.ExportManager = ExportManager;
}
