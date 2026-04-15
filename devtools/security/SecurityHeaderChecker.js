// SecurityHeaderChecker.js - Verification des headers de securite
// AutoHAR Pentest Edition

class SecurityHeaderChecker {
  constructor() {
    // Headers de securite requis
    this.requiredHeaders = {
      'content-security-policy': {
        severity: 'high',
        description: 'Content Security Policy (CSP)',
        recommendation: 'Add CSP header to prevent XSS attacks'
      },
      'strict-transport-security': {
        severity: 'high',
        description: 'HTTP Strict Transport Security (HSTS)',
        recommendation: 'Add HSTS header with max-age >= 31536000'
      },
      'x-content-type-options': {
        severity: 'medium',
        description: 'X-Content-Type-Options',
        recommendation: 'Add "X-Content-Type-Options: nosniff"'
      },
      'x-frame-options': {
        severity: 'medium',
        description: 'X-Frame-Options',
        recommendation: 'Add "X-Frame-Options: DENY" or "SAMEORIGIN"'
      },
      'x-xss-protection': {
        severity: 'low',
        description: 'X-XSS-Protection (legacy)',
        recommendation: 'Consider using CSP instead'
      },
      'referrer-policy': {
        severity: 'low',
        description: 'Referrer-Policy',
        recommendation: 'Add "Referrer-Policy: strict-origin-when-cross-origin"'
      },
      'permissions-policy': {
        severity: 'low',
        description: 'Permissions-Policy',
        recommendation: 'Add Permissions-Policy to control browser features'
      }
    };

    // Flags de cookies securises
    this.cookieFlags = {
      httponly: {
        severity: 'high',
        description: 'HttpOnly flag missing',
        recommendation: 'Add HttpOnly flag to prevent XSS cookie theft'
      },
      secure: {
        severity: 'high',
        description: 'Secure flag missing',
        recommendation: 'Add Secure flag for HTTPS-only transmission'
      },
      samesite: {
        severity: 'medium',
        description: 'SameSite attribute missing',
        recommendation: 'Add SameSite=Strict or SameSite=Lax'
      }
    };
  }

  // Verifier une entree HAR
  check(harEntry) {
    const issues = [];

    // Verifier les headers uniquement sur les reponses HTML
    const contentType = this.getHeader(harEntry.response.headers, 'content-type');
    const isHtml = contentType?.includes('text/html');

    if (isHtml) {
      issues.push(...this.checkMissingHeaders(harEntry));
    }

    // Toujours verifier les cookies
    issues.push(...this.checkCookies(harEntry));

    // Verifier CORS
    issues.push(...this.checkCORS(harEntry));

    // Verifier mixed content
    issues.push(...this.checkMixedContent(harEntry));

    // Verifier les headers d'information sensibles
    issues.push(...this.checkInformationLeakage(harEntry));

    return issues;
  }

  checkMissingHeaders(harEntry) {
    const issues = [];
    const responseHeaders = new Map(
      harEntry.response.headers.map(h => [h.name.toLowerCase(), h.value])
    );

    for (const [header, info] of Object.entries(this.requiredHeaders)) {
      if (!responseHeaders.has(header)) {
        issues.push({
          type: 'missing_header',
          header,
          severity: info.severity,
          description: info.description,
          recommendation: info.recommendation,
          url: harEntry.request.url
        });
      } else {
        // Verifier la valeur du header
        const value = responseHeaders.get(header);
        const valueIssue = this.checkHeaderValue(header, value);
        if (valueIssue) {
          issues.push({
            type: 'weak_header',
            header,
            value,
            ...valueIssue,
            url: harEntry.request.url
          });
        }
      }
    }

    return issues;
  }

  checkHeaderValue(header, value) {
    switch (header) {
      case 'strict-transport-security':
        const maxAge = value.match(/max-age=(\d+)/i);
        if (maxAge && parseInt(maxAge[1]) < 31536000) {
          return {
            severity: 'medium',
            description: 'HSTS max-age too short',
            recommendation: 'Set max-age to at least 31536000 (1 year)'
          };
        }
        if (!value.includes('includeSubDomains')) {
          return {
            severity: 'low',
            description: 'HSTS missing includeSubDomains',
            recommendation: 'Consider adding includeSubDomains directive'
          };
        }
        break;

      case 'x-frame-options':
        if (value.toLowerCase() === 'allowall') {
          return {
            severity: 'high',
            description: 'X-Frame-Options set to ALLOWALL',
            recommendation: 'Use DENY or SAMEORIGIN instead'
          };
        }
        break;

      case 'content-security-policy':
        if (value.includes("'unsafe-inline'") || value.includes("'unsafe-eval'")) {
          return {
            severity: 'medium',
            description: 'CSP contains unsafe directives',
            recommendation: 'Remove unsafe-inline and unsafe-eval if possible'
          };
        }
        if (value.includes('*')) {
          return {
            severity: 'medium',
            description: 'CSP contains wildcard source',
            recommendation: 'Specify explicit sources instead of wildcards'
          };
        }
        break;
    }
    return null;
  }

  checkCookies(harEntry) {
    const issues = [];
    const isHttps = harEntry.request.url.startsWith('https://');

    const setCookies = harEntry.response.headers
      .filter(h => h.name.toLowerCase() === 'set-cookie');

    for (const cookie of setCookies) {
      const cookieIssues = [];
      const value = cookie.value.toLowerCase();
      const cookieName = cookie.value.split('=')[0].trim();

      // Verifier HttpOnly
      if (!value.includes('httponly')) {
        cookieIssues.push({
          flag: 'httponly',
          ...this.cookieFlags.httponly
        });
      }

      // Verifier Secure (seulement sur HTTPS)
      if (isHttps && !value.includes('secure')) {
        cookieIssues.push({
          flag: 'secure',
          ...this.cookieFlags.secure
        });
      }

      // Verifier SameSite
      if (!value.includes('samesite')) {
        cookieIssues.push({
          flag: 'samesite',
          ...this.cookieFlags.samesite
        });
      }

      // Verifier SameSite=None sans Secure
      if (value.includes('samesite=none') && !value.includes('secure')) {
        cookieIssues.push({
          flag: 'samesite-none-insecure',
          severity: 'high',
          description: 'SameSite=None without Secure flag',
          recommendation: 'SameSite=None requires Secure flag'
        });
      }

      if (cookieIssues.length > 0) {
        issues.push({
          type: 'insecure_cookie',
          cookieName,
          issues: cookieIssues,
          severity: this.getHighestSeverity(cookieIssues),
          url: harEntry.request.url,
          rawValue: cookie.value
        });
      }
    }

    return issues;
  }

  checkCORS(harEntry) {
    const issues = [];
    const responseHeaders = new Map(
      harEntry.response.headers.map(h => [h.name.toLowerCase(), h.value])
    );

    const acao = responseHeaders.get('access-control-allow-origin');
    const acac = responseHeaders.get('access-control-allow-credentials');
    const requestOrigin = this.getHeader(harEntry.request.headers, 'origin');

    // CORS wildcard
    if (acao === '*') {
      issues.push({
        type: 'cors_wildcard',
        severity: 'low',
        description: 'CORS allows all origins',
        recommendation: 'Specify explicit allowed origins if possible',
        url: harEntry.request.url
      });
    }

    // CORS avec credentials et origin reflete
    if (acac === 'true' && acao && acao !== '*') {
      if (requestOrigin && acao === requestOrigin) {
        issues.push({
          type: 'cors_origin_reflection',
          severity: 'high',
          description: 'CORS reflects Origin header with credentials',
          recommendation: 'Validate Origin against whitelist, do not reflect directly',
          url: harEntry.request.url,
          origin: requestOrigin
        });
      }
    }

    // CORS wildcard avec credentials (invalide mais parfois mal configure)
    if (acao === '*' && acac === 'true') {
      issues.push({
        type: 'cors_wildcard_credentials',
        severity: 'critical',
        description: 'CORS wildcard with credentials (browser will block)',
        recommendation: 'Specify explicit origin when using credentials',
        url: harEntry.request.url
      });
    }

    return issues;
  }

  checkMixedContent(harEntry) {
    const issues = [];

    // Detecter si une page HTTPS charge des ressources HTTP
    // Note: necessiterait d'analyser le body HTML pour etre complet
    if (harEntry.request.url.startsWith('https://')) {
      // Verifier les redirections vers HTTP
      const location = this.getHeader(harEntry.response.headers, 'location');
      if (location && location.startsWith('http://')) {
        issues.push({
          type: 'mixed_content_redirect',
          severity: 'high',
          description: 'HTTPS redirects to HTTP',
          recommendation: 'Ensure all redirects use HTTPS',
          url: harEntry.request.url,
          redirectTo: location
        });
      }
    }

    return issues;
  }

  checkInformationLeakage(harEntry) {
    const issues = [];
    const sensitiveHeaders = {
      'server': { severity: 'low', description: 'Server version disclosed' },
      'x-powered-by': { severity: 'low', description: 'Technology stack disclosed' },
      'x-aspnet-version': { severity: 'low', description: 'ASP.NET version disclosed' },
      'x-aspnetmvc-version': { severity: 'low', description: 'ASP.NET MVC version disclosed' }
    };

    for (const [header, info] of Object.entries(sensitiveHeaders)) {
      const value = this.getHeader(harEntry.response.headers, header);
      if (value) {
        issues.push({
          type: 'information_leakage',
          header,
          value,
          severity: info.severity,
          description: info.description,
          recommendation: 'Remove or obscure version information',
          url: harEntry.request.url
        });
      }
    }

    return issues;
  }

  getHeader(headers, name) {
    const header = headers?.find(h => h.name.toLowerCase() === name.toLowerCase());
    return header?.value;
  }

  getHighestSeverity(issues) {
    const order = ['critical', 'high', 'medium', 'low'];
    for (const severity of order) {
      if (issues.some(i => i.severity === severity)) {
        return severity;
      }
    }
    return 'low';
  }

  // Obtenir la couleur de severite
  getSeverityColor(severity) {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#f59e0b',
      low: '#3b82f6'
    };
    return colors[severity] || '#6b7280';
  }

  // Generer le HTML pour un issue
  renderIssue(issue) {
    const color = this.getSeverityColor(issue.severity);
    return `
      <div class="finding-item" style="border-left-color: ${color};">
        <div class="finding-header">
          <span class="finding-type">${issue.description}</span>
          <span class="finding-severity" style="color: ${color};">${issue.severity.toUpperCase()}</span>
        </div>
        <div class="finding-detail">
          ${issue.header ? `<span class="finding-header-name">${issue.header}</span>` : ''}
          ${issue.cookieName ? `<span class="finding-cookie">Cookie: ${issue.cookieName}</span>` : ''}
        </div>
        <div class="finding-recommendation">${issue.recommendation}</div>
      </div>
    `;
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.SecurityHeaderChecker = SecurityHeaderChecker;
}
