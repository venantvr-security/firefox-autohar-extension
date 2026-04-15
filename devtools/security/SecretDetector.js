// SecretDetector.js - Detection de secrets et tokens
// AutoHAR Pentest Edition

class SecretDetector {
  constructor() {
    // Patterns de detection de secrets
    this.patterns = {
      // JWT Tokens
      jwt: {
        regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
        severity: 'high',
        description: 'JSON Web Token'
      },

      // AWS
      awsAccessKey: {
        regex: /AKIA[0-9A-Z]{16}/g,
        severity: 'critical',
        description: 'AWS Access Key ID'
      },
      awsSecretKey: {
        regex: /(?<![A-Za-z0-9\/+=])[A-Za-z0-9\/+=]{40}(?![A-Za-z0-9\/+=])/g,
        severity: 'critical',
        description: 'Potential AWS Secret Key',
        contextRequired: true // Necessite contexte AWS
      },

      // Google Cloud
      gcpApiKey: {
        regex: /AIza[0-9A-Za-z_-]{35}/g,
        severity: 'high',
        description: 'Google Cloud API Key'
      },

      // Stripe
      stripePublishable: {
        regex: /pk_(test|live)_[0-9a-zA-Z]{24,}/g,
        severity: 'medium',
        description: 'Stripe Publishable Key'
      },
      stripeSecret: {
        regex: /sk_(test|live)_[0-9a-zA-Z]{24,}/g,
        severity: 'critical',
        description: 'Stripe Secret Key'
      },

      // GitHub
      githubToken: {
        regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
        severity: 'critical',
        description: 'GitHub Personal Access Token'
      },
      githubOAuth: {
        regex: /gho_[A-Za-z0-9]{36}/g,
        severity: 'high',
        description: 'GitHub OAuth Token'
      },

      // Generic Auth
      bearerToken: {
        regex: /Bearer\s+([A-Za-z0-9_-]+\.?){2,}/gi,
        severity: 'high',
        description: 'Bearer Token'
      },
      basicAuth: {
        regex: /Basic\s+[A-Za-z0-9+\/=]{10,}/gi,
        severity: 'high',
        description: 'Basic Authentication'
      },
      apiKey: {
        regex: /['"](api[_-]?key|apikey|api_secret)['"]\s*[:=]\s*['"]([A-Za-z0-9_-]{16,})['"]/gi,
        severity: 'high',
        description: 'API Key'
      },

      // Private Keys
      privateKey: {
        regex: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
        severity: 'critical',
        description: 'Private Key'
      },

      // Slack
      slackToken: {
        regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
        severity: 'high',
        description: 'Slack Token'
      },
      slackWebhook: {
        regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
        severity: 'medium',
        description: 'Slack Webhook URL'
      },

      // Firebase
      firebaseKey: {
        regex: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,
        severity: 'high',
        description: 'Firebase Cloud Messaging Key'
      },

      // Twilio
      twilioSid: {
        regex: /AC[a-f0-9]{32}/g,
        severity: 'medium',
        description: 'Twilio Account SID'
      },
      twilioToken: {
        regex: /SK[a-f0-9]{32}/g,
        severity: 'high',
        description: 'Twilio API Key'
      },

      // SendGrid
      sendgridKey: {
        regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
        severity: 'high',
        description: 'SendGrid API Key'
      },

      // Generic secrets in URLs
      secretInUrl: {
        regex: /[?&](secret|token|key|password|pwd|pass|api_key|apikey|auth|access_token)=([^&\s]{8,})/gi,
        severity: 'high',
        description: 'Secret in URL Parameter'
      },

      // Session IDs (generic)
      sessionId: {
        regex: /(session[_-]?id|sess[_-]?id|PHPSESSID|JSESSIONID|ASP\.NET_SessionId)=([A-Za-z0-9_-]{16,})/gi,
        severity: 'medium',
        description: 'Session ID'
      }
    };
  }

  // Scanner une entree HAR complete
  async scan(harEntry, responseContent = '') {
    const findings = [];

    // Scanner les headers de requete
    for (const header of harEntry.request.headers || []) {
      const headerFindings = this.scanValue(header.value, 'request_header', header.name);
      findings.push(...headerFindings);
    }

    // Scanner l'URL (query params)
    const urlFindings = this.scanValue(harEntry.request.url, 'url');
    findings.push(...urlFindings);

    // Scanner le body de requete
    if (harEntry.request.postData?.text) {
      const bodyFindings = this.scanValue(harEntry.request.postData.text, 'request_body');
      findings.push(...bodyFindings);
    }

    // Scanner les headers de reponse
    for (const header of harEntry.response.headers || []) {
      const headerFindings = this.scanValue(header.value, 'response_header', header.name);
      findings.push(...headerFindings);
    }

    // Scanner le contenu de reponse
    if (responseContent) {
      const responseFindings = this.scanValue(responseContent, 'response_body');
      findings.push(...responseFindings);
    }

    // Ajouter les metadonnees de la requete
    return findings.map(f => ({
      ...f,
      request: {
        url: harEntry.request.url,
        method: harEntry.request.method
      },
      timestamp: Date.now()
    }));
  }

  // Scanner une valeur pour tous les patterns
  scanValue(value, location, context = '') {
    if (!value || typeof value !== 'string') return [];

    const findings = [];

    for (const [type, config] of Object.entries(this.patterns)) {
      // Reset regex lastIndex pour les regex globales
      config.regex.lastIndex = 0;

      let match;
      while ((match = config.regex.exec(value)) !== null) {
        // Verifier le contexte si requis
        if (config.contextRequired && !this.hasValidContext(value, match, type)) {
          continue;
        }

        findings.push({
          type,
          severity: config.severity,
          description: config.description,
          value: match[0],
          masked: this.maskSecret(match[0]),
          location,
          context,
          decoded: type === 'jwt' ? this.decodeJWT(match[0]) : null,
          position: match.index
        });
      }
    }

    return findings;
  }

  // Verifier si le contexte est valide pour certains patterns
  hasValidContext(value, match, type) {
    if (type === 'awsSecretKey') {
      // Verifier qu'il y a un contexte AWS proche
      const contextWindow = value.substring(Math.max(0, match.index - 100), match.index + 100);
      return /aws|amazon|s3|ec2|lambda|iam/i.test(contextWindow);
    }
    return true;
  }

  // Decoder un JWT
  decodeJWT(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const header = JSON.parse(this.base64UrlDecode(parts[0]));
      const payload = JSON.parse(this.base64UrlDecode(parts[1]));

      // Calculer expiration
      let expiration = null;
      if (payload.exp) {
        const expDate = new Date(payload.exp * 1000);
        expiration = {
          timestamp: payload.exp,
          date: expDate.toISOString(),
          expired: expDate < new Date()
        };
      }

      return {
        header,
        payload,
        expiration,
        issuer: payload.iss || null,
        subject: payload.sub || null,
        audience: payload.aud || null
      };
    } catch (e) {
      return { error: 'Invalid JWT format' };
    }
  }

  base64UrlDecode(str) {
    // Remplacer les caracteres URL-safe
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    // Ajouter le padding si necessaire
    while (str.length % 4) {
      str += '=';
    }
    return atob(str);
  }

  // Masquer un secret pour l'affichage
  maskSecret(value) {
    if (!value) return '';
    if (value.length <= 8) return '*'.repeat(value.length);
    if (value.length <= 16) return value.substring(0, 4) + '...' + value.substring(value.length - 2);
    return value.substring(0, 6) + '...' + value.substring(value.length - 4);
  }

  // Obtenir un resume des findings
  getSummary(findings) {
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    const byType = {};

    for (const finding of findings) {
      bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
      byType[finding.type] = (byType[finding.type] || 0) + 1;
    }

    return {
      total: findings.length,
      bySeverity,
      byType,
      hasCritical: bySeverity.critical > 0
    };
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

  // Generer le HTML pour un finding
  renderFinding(finding) {
    const color = this.getSeverityColor(finding.severity);
    return `
      <div class="finding-item" style="border-left-color: ${color};">
        <div class="finding-header">
          <span class="finding-type">${finding.description}</span>
          <span class="finding-severity" style="color: ${color};">${finding.severity.toUpperCase()}</span>
        </div>
        <div class="finding-detail">
          <span class="finding-location">${finding.location}${finding.context ? ` (${finding.context})` : ''}</span>
          <code class="finding-value">${finding.masked}</code>
        </div>
        ${finding.decoded ? this.renderJWTInfo(finding.decoded) : ''}
      </div>
    `;
  }

  renderJWTInfo(decoded) {
    if (decoded.error) return '';

    const expiredClass = decoded.expiration?.expired ? 'expired' : '';
    return `
      <div class="jwt-info">
        <div class="jwt-row"><strong>Algorithm:</strong> ${decoded.header?.alg || 'N/A'}</div>
        ${decoded.issuer ? `<div class="jwt-row"><strong>Issuer:</strong> ${decoded.issuer}</div>` : ''}
        ${decoded.subject ? `<div class="jwt-row"><strong>Subject:</strong> ${decoded.subject}</div>` : ''}
        ${decoded.expiration ? `<div class="jwt-row ${expiredClass}"><strong>Expires:</strong> ${decoded.expiration.date} ${decoded.expiration.expired ? '(EXPIRED)' : ''}</div>` : ''}
      </div>
    `;
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.SecretDetector = SecretDetector;
}
