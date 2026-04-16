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

  // Export pour Burp Suite (XML)
  toBurp(harEntries, options = {}) {
    const items = harEntries.map(entry => this.harToBurpItem(entry, options));

    let xml = '<?xml version="1.0"?>\n';
    xml += '<!DOCTYPE items [\n';
    xml += '<!ELEMENT items (item*)>\n';
    xml += '<!ATTLIST items burpVersion CDATA "">\n';
    xml += '<!ELEMENT item (time,url,host,port,protocol,method,path,extension,request,status,responselength,mimetype,response,comment)>\n';
    xml += '<!ELEMENT time (#PCDATA)>\n';
    xml += '<!ELEMENT url (#PCDATA)>\n';
    xml += '<!ELEMENT host (#PCDATA)>\n';
    xml += '<!ATTLIST host ip CDATA "">\n';
    xml += '<!ELEMENT port (#PCDATA)>\n';
    xml += '<!ELEMENT protocol (#PCDATA)>\n';
    xml += '<!ELEMENT method (#PCDATA)>\n';
    xml += '<!ELEMENT path (#PCDATA)>\n';
    xml += '<!ELEMENT extension (#PCDATA)>\n';
    xml += '<!ELEMENT request (#PCDATA)>\n';
    xml += '<!ATTLIST request base64 (true|false) "true">\n';
    xml += '<!ELEMENT status (#PCDATA)>\n';
    xml += '<!ELEMENT responselength (#PCDATA)>\n';
    xml += '<!ELEMENT mimetype (#PCDATA)>\n';
    xml += '<!ELEMENT response (#PCDATA)>\n';
    xml += '<!ATTLIST response base64 (true|false) "true">\n';
    xml += '<!ELEMENT comment (#PCDATA)>\n';
    xml += ']>\n';
    xml += '<items burpVersion="2024.1">\n';
    xml += items.join('\n');
    xml += '\n</items>';

    return xml;
  }

  harToBurpItem(entry, options = {}) {
    let url;
    try {
      url = new URL(entry.request.url);
    } catch (e) {
      url = { hostname: 'unknown', port: '', protocol: 'https:', pathname: '/' };
    }

    const host = url.hostname;
    const port = url.port || (url.protocol === 'https:' ? '443' : '80');
    const protocol = url.protocol.replace(':', '');
    const path = url.pathname + url.search;
    const extension = this.getExtensionFromPath(path);

    // Construire la requête HTTP brute
    const rawRequest = this.buildRawRequest(entry);
    const requestBase64 = this.toBase64(rawRequest);

    // Construire la réponse HTTP brute
    const rawResponse = this.buildRawResponse(entry);
    const responseBase64 = this.toBase64(rawResponse);

    // Obtenir le Content-Type de la réponse
    const contentType = this.getHeaderValue(entry.response.headers, 'content-type') || 'text/html';
    const mimeType = contentType.split(';')[0].trim();

    // Timestamp
    const timestamp = entry.startedDateTime
      ? new Date(entry.startedDateTime).toUTCString()
      : new Date().toUTCString();

    // Commentaire avec tags si disponibles
    const comment = options.includeComment
      ? this.escapeXml(options.comment || 'Exported from AutoHAR Pentest Edition')
      : '';

    return `  <item>
    <time>${this.escapeXml(timestamp)}</time>
    <url>${this.escapeXml(entry.request.url)}</url>
    <host ip="">${this.escapeXml(host)}</host>
    <port>${port}</port>
    <protocol>${protocol}</protocol>
    <method>${this.escapeXml(entry.request.method)}</method>
    <path>${this.escapeXml(path)}</path>
    <extension>${this.escapeXml(extension)}</extension>
    <request base64="true">${requestBase64}</request>
    <status>${entry.response.status || 0}</status>
    <responselength>${entry.response.content?.size || 0}</responselength>
    <mimetype>${this.escapeXml(mimeType)}</mimetype>
    <response base64="true">${responseBase64}</response>
    <comment>${comment}</comment>
  </item>`;
  }

  // Construire une requête HTTP brute depuis une entrée HAR
  buildRawRequest(entry) {
    let url;
    try {
      url = new URL(entry.request.url);
    } catch (e) {
      url = { pathname: '/', search: '', hostname: 'unknown' };
    }

    const path = url.pathname + url.search;
    let raw = `${entry.request.method} ${path} HTTP/1.1\r\n`;
    raw += `Host: ${url.hostname}\r\n`;

    // Ajouter les headers (en évitant Host qui est déjà ajouté)
    for (const header of entry.request.headers || []) {
      if (header.name.toLowerCase() !== 'host') {
        raw += `${header.name}: ${header.value}\r\n`;
      }
    }

    // Ajouter les cookies
    if (entry.request.cookies && entry.request.cookies.length > 0) {
      const cookieHeader = entry.request.cookies
        .map(c => `${c.name}=${c.value}`)
        .join('; ');
      // Vérifier si Cookie header existe déjà
      const hasCookieHeader = (entry.request.headers || [])
        .some(h => h.name.toLowerCase() === 'cookie');
      if (!hasCookieHeader) {
        raw += `Cookie: ${cookieHeader}\r\n`;
      }
    }

    raw += '\r\n';

    // Body
    if (entry.request.postData?.text) {
      raw += entry.request.postData.text;
    }

    return raw;
  }

  // Construire une réponse HTTP brute depuis une entrée HAR
  buildRawResponse(entry) {
    const statusText = this.getStatusText(entry.response.status);
    let raw = `HTTP/1.1 ${entry.response.status} ${statusText}\r\n`;

    // Headers de réponse
    for (const header of entry.response.headers || []) {
      raw += `${header.name}: ${header.value}\r\n`;
    }

    raw += '\r\n';

    // Body de réponse
    if (entry.response.content?.text) {
      raw += entry.response.content.text;
    }

    return raw;
  }

  // Obtenir l'extension de fichier depuis le path
  getExtensionFromPath(path) {
    const match = path.match(/\.([a-zA-Z0-9]+)(?:\?|$)/);
    return match ? match[1] : '';
  }

  // Obtenir la valeur d'un header
  getHeaderValue(headers, name) {
    const header = (headers || []).find(h =>
      h.name.toLowerCase() === name.toLowerCase()
    );
    return header?.value;
  }

  // Encoder en Base64 (compatible navigateur)
  toBase64(str) {
    try {
      // Encoder en UTF-8 puis en base64
      const bytes = new TextEncoder().encode(str);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    } catch (e) {
      // Fallback pour caractères simples
      try {
        return btoa(str);
      } catch (e2) {
        return btoa(unescape(encodeURIComponent(str)));
      }
    }
  }

  // Échapper les caractères spéciaux XML
  escapeXml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  // Obtenir le texte de statut HTTP
  getStatusText(status) {
    const statusTexts = {
      200: 'OK',
      201: 'Created',
      204: 'No Content',
      301: 'Moved Permanently',
      302: 'Found',
      304: 'Not Modified',
      400: 'Bad Request',
      401: 'Unauthorized',
      403: 'Forbidden',
      404: 'Not Found',
      405: 'Method Not Allowed',
      500: 'Internal Server Error',
      502: 'Bad Gateway',
      503: 'Service Unavailable'
    };
    return statusTexts[status] || 'Unknown';
  }

  // Export pour SQLmap (fichier de requête)
  toSqlmap(harEntries, options = {}) {
    const exports = [];

    for (const entry of harEntries) {
      // Filtrer les requêtes avec paramètres
      const hasParams = entry.request.queryString?.length > 0 ||
                        entry.request.postData?.text;

      if (!hasParams && !options.includeAll) continue;

      const rawRequest = this.buildRawRequest(entry);
      const filename = this.sanitizeFilename(
        `${entry.request.method}_${new URL(entry.request.url).pathname}`
      );

      exports.push({
        filename: `${filename}.txt`,
        content: rawRequest,
        command: this.generateSqlmapCommand(entry, filename, options)
      });
    }

    return exports;
  }

  // Générer la commande SQLmap
  generateSqlmapCommand(entry, filename, options = {}) {
    const parts = ['sqlmap', `-r ${filename}.txt`];

    // Options de base
    if (options.level) parts.push(`--level=${options.level}`);
    if (options.risk) parts.push(`--risk=${options.risk}`);
    if (options.threads) parts.push(`--threads=${options.threads}`);

    // Techniques
    if (options.techniques) parts.push(`--technique=${options.techniques}`);

    // DBMS spécifique
    if (options.dbms) parts.push(`--dbms=${options.dbms}`);

    // Tamper scripts
    if (options.tamper) parts.push(`--tamper=${options.tamper}`);

    // Batch mode (non-interactif)
    parts.push('--batch');

    return parts.join(' ');
  }

  // Export CSV pour analyse
  toCSV(data, options = {}) {
    const { findings, endpoints, secrets } = data;
    const rows = [];
    const delimiter = options.delimiter || ',';

    // En-tête
    rows.push([
      'Type', 'Severity', 'Description', 'URL', 'Location',
      'Value', 'Recommendation', 'Timestamp'
    ].join(delimiter));

    // Secrets
    if (secrets) {
      for (const secret of secrets) {
        rows.push([
          'Secret',
          this.csvEscape(secret.severity),
          this.csvEscape(secret.description),
          this.csvEscape(secret.url || ''),
          this.csvEscape(secret.location),
          this.csvEscape(secret.masked),
          this.csvEscape('Remove from response or use secure storage'),
          this.csvEscape(new Date().toISOString())
        ].join(delimiter));
      }
    }

    // Findings (issues)
    if (findings) {
      for (const finding of findings) {
        rows.push([
          this.csvEscape(finding.type),
          this.csvEscape(finding.severity),
          this.csvEscape(finding.description),
          this.csvEscape(finding.url || ''),
          this.csvEscape(finding.header || finding.location || ''),
          this.csvEscape(finding.value || ''),
          this.csvEscape(finding.recommendation || ''),
          this.csvEscape(new Date().toISOString())
        ].join(delimiter));
      }
    }

    // Endpoints IDOR
    if (endpoints) {
      for (const ep of endpoints) {
        if (ep.idorIndicators && ep.idorIndicators.length > 0) {
          for (const idor of ep.idorIndicators) {
            rows.push([
              'IDOR Candidate',
              'Medium',
              this.csvEscape(`${idor.pattern} in ${idor.location}`),
              this.csvEscape(ep.fullUrl || ''),
              this.csvEscape(idor.location),
              this.csvEscape(idor.value || ''),
              this.csvEscape('Test with different user IDs'),
              this.csvEscape(new Date().toISOString())
            ].join(delimiter));
          }
        }
      }
    }

    return rows.join('\n');
  }

  // Échapper pour CSV
  csvEscape(value) {
    if (!value) return '';
    const str = String(value);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  }

  // Sanitizer les noms de fichiers
  sanitizeFilename(name) {
    return name
      .replace(/[^a-zA-Z0-9_-]/g, '_')
      .replace(/_+/g, '_')
      .substring(0, 50);
  }

  // Export wfuzz (wordlist + commandes)
  toWfuzz(endpoints, options = {}) {
    const paths = new Set();
    const params = new Set();
    const commands = [];

    for (const ep of endpoints) {
      // Collecter les paths
      paths.add(ep.normalizedPath);

      // Collecter les paramètres
      for (const p of ep.parameters?.query || []) {
        params.add(p.name);
      }
      for (const p of ep.parameters?.body || []) {
        params.add(p.name.split('.')[0]);
      }

      // Générer des commandes wfuzz
      if (ep.parameters?.query?.length > 0) {
        const baseUrl = `${ep.host}${ep.normalizedPath}`;
        for (const param of ep.parameters.query) {
          commands.push(
            `wfuzz -c -z file,wordlist.txt --hc 404 "${baseUrl}?${param.name}=FUZZ"`
          );
        }
      }
    }

    return {
      pathWordlist: Array.from(paths).join('\n'),
      paramWordlist: Array.from(params).join('\n'),
      commands: commands.slice(0, 20).join('\n')
    };
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
