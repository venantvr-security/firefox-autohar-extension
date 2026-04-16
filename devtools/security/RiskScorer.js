// RiskScorer.js - Calcul de score de risque composite
// PentestHAR - Priorisation intelligente des findings

class RiskScorer {
  constructor() {
    // Poids des facteurs dans le score composite
    this.weights = {
      severity: 0.40,      // 40% - Criticité intrinsèque
      exploitability: 0.30, // 30% - Facilité d'exploitation
      businessImpact: 0.20, // 20% - Impact métier
      context: 0.10        // 10% - Contexte applicatif
    };

    // Mapping CWE pour enrichissement
    this.cweMapping = {
      'secret': { id: 'CWE-200', name: 'Information Exposure', category: 'disclosure' },
      'api_key': { id: 'CWE-798', name: 'Use of Hard-coded Credentials', category: 'authentication' },
      'jwt': { id: 'CWE-345', name: 'Insufficient Verification of Data Authenticity', category: 'authentication' },
      'idor': { id: 'CWE-639', name: 'Authorization Bypass Through User-Controlled Key', category: 'access-control' },
      'sql_injection': { id: 'CWE-89', name: 'SQL Injection', category: 'injection' },
      'xss': { id: 'CWE-79', name: 'Cross-site Scripting', category: 'injection' },
      'xxe': { id: 'CWE-611', name: 'XML External Entity', category: 'injection' },
      'ssrf': { id: 'CWE-918', name: 'Server-Side Request Forgery', category: 'ssrf' },
      'path_traversal': { id: 'CWE-22', name: 'Path Traversal', category: 'path' },
      'missing_header': { id: 'CWE-693', name: 'Protection Mechanism Failure', category: 'configuration' },
      'insecure_cookie': { id: 'CWE-614', name: 'Sensitive Cookie Without Secure Flag', category: 'configuration' },
      'cors_wildcard': { id: 'CWE-942', name: 'CORS Misconfiguration', category: 'cors' },
      'weak_crypto': { id: 'CWE-326', name: 'Inadequate Encryption Strength', category: 'crypto' }
    };

    // Mapping OWASP Top 10 2021
    this.owaspMapping = {
      'secret': 'A01:2021 – Broken Access Control',
      'api_key': 'A07:2021 – Identification and Authentication Failures',
      'jwt': 'A07:2021 – Identification and Authentication Failures',
      'idor': 'A01:2021 – Broken Access Control',
      'sql_injection': 'A03:2021 – Injection',
      'xss': 'A03:2021 – Injection',
      'xxe': 'A03:2021 – Injection',
      'ssrf': 'A10:2021 – Server-Side Request Forgery',
      'path_traversal': 'A01:2021 – Broken Access Control',
      'missing_header': 'A05:2021 – Security Misconfiguration',
      'insecure_cookie': 'A05:2021 – Security Misconfiguration',
      'cors_wildcard': 'A05:2021 – Security Misconfiguration',
      'weak_crypto': 'A02:2021 – Cryptographic Failures'
    };
  }

  /**
   * Calcule le score de risque composite pour un finding
   * @param {Object} finding - Le finding à scorer
   * @param {Object} context - Contexte applicatif
   * @returns {Object} Score composite et métadonnées
   */
  calculateCompositeScore(finding, context = {}) {
    const factors = {
      severity: this.severityScore(finding.severity),
      exploitability: this.exploitabilityScore(finding, context),
      businessImpact: this.businessImpactScore(finding, context),
      context: this.contextScore(context)
    };

    // Score composite pondéré
    const compositeScore =
      factors.severity * this.weights.severity +
      factors.exploitability * this.weights.exploitability +
      factors.businessImpact * this.weights.businessImpact +
      factors.context * this.weights.context;

    return {
      score: parseFloat(compositeScore.toFixed(2)),
      factors,
      level: this.scoreToLevel(compositeScore),
      priority: this.scoreToPriority(compositeScore),
      cvss: this.approximateCVSS(factors),
      timeToExploit: this.estimateExploitTime(factors),
      recommendation: this.getRecommendation(compositeScore),
      enrichment: this.enrichFinding(finding)
    };
  }

  /**
   * Score de sévérité (0-10)
   */
  severityScore(severity) {
    const scores = {
      critical: 10,
      high: 7.5,
      medium: 5,
      low: 2.5,
      info: 1
    };
    return scores[severity?.toLowerCase()] || 5;
  }

  /**
   * Score d'exploitabilité (0-10)
   * Plus le score est élevé, plus c'est facile à exploiter
   */
  exploitabilityScore(finding, context) {
    let score = 10;

    // Complexité d'exploitation
    const complexity = this.inferComplexity(finding);
    if (complexity === 'high') score -= 3;
    if (complexity === 'medium') score -= 1.5;

    // Prérequis nécessaires
    const prerequisites = this.inferPrerequisites(finding, context);
    score -= prerequisites.length * 1.5;

    // Compétence requise
    const skillRequired = this.inferSkillLevel(finding);
    if (skillRequired === 'expert') score -= 2.5;
    if (skillRequired === 'intermediate') score -= 1;

    // Exploit public disponible
    if (this.hasKnownExploit(finding)) score += 1.5;

    // Authentification requise
    if (context.requiresAuth === false) score += 1;

    return Math.max(0, Math.min(10, score));
  }

  /**
   * Score d'impact business (0-10)
   */
  businessImpactScore(finding, context) {
    let score = 0;

    // Type de données exposées
    const dataType = this.inferDataType(finding);
    if (dataType === 'pii') score += 3;
    if (dataType === 'financial') score += 4;
    if (dataType === 'credentials') score += 5;
    if (dataType === 'api_keys') score += 4;

    // Risque financier
    if (finding.type?.includes('payment') || finding.type?.includes('stripe')) score += 3;

    // Risque réputation
    if (finding.severity === 'critical') score += 2;

    // Compliance (RGPD, PCI-DSS, etc.)
    const compliance = this.inferComplianceImpact(finding);
    score += compliance.length * 1.5;

    // Volume de données potentiellement exposées
    if (context.affectedRecords === 'high') score += 2;

    return Math.min(10, score);
  }

  /**
   * Score de contexte (0-10)
   * Contexte de l'application qui aggrave ou atténue le risque
   */
  contextScore(context) {
    let score = 5; // Score neutre par défaut

    // Accessible publiquement
    if (context.isPublic) score += 2;

    // Pas d'authentification
    if (context.requiresAuth === false) score += 2;

    // Pas de rate limiting
    if (context.hasRateLimit === false) score += 1;

    // Pas de monitoring
    if (context.hasMonitoring === false) score += 1;

    // En production
    if (context.environment === 'production') score += 1;

    // API externe (vs interne)
    if (context.exposure === 'external') score += 1.5;

    return Math.min(10, score);
  }

  /**
   * Inférer la complexité d'exploitation
   */
  inferComplexity(finding) {
    // Secrets exposés = très facile
    if (finding.type?.includes('secret') || finding.type?.includes('api_key')) {
      return 'low';
    }

    // IDOR = facile
    if (finding.type === 'idor' || finding.idorIndicators?.length > 0) {
      return 'low';
    }

    // JWT avec algorithm=none = facile
    if (finding.type?.includes('jwt') && finding.decoded?.header?.alg === 'none') {
      return 'low';
    }

    // Injections = moyen (besoin de payloads)
    if (finding.type?.includes('injection') || finding.type?.includes('xss')) {
      return 'medium';
    }

    // XXE, Deserialization = complexe
    if (finding.type?.includes('xxe') || finding.type?.includes('deserialization')) {
      return 'high';
    }

    // Headers manquants = moyen (pas d'exploit direct)
    if (finding.type?.includes('header') || finding.type?.includes('cookie')) {
      return 'medium';
    }

    return 'medium';
  }

  /**
   * Inférer les prérequis nécessaires
   */
  inferPrerequisites(finding, context) {
    const prerequisites = [];

    // Authentification requise
    if (context.requiresAuth !== false) {
      prerequisites.push('valid_account');
    }

    // Besoin d'un autre finding
    if (finding.type === 'csrf') {
      prerequisites.push('xss_or_social_engineering');
    }

    // Besoin de timing/race condition
    if (finding.type?.includes('race_condition')) {
      prerequisites.push('precise_timing');
    }

    return prerequisites;
  }

  /**
   * Inférer le niveau de compétence requis
   */
  inferSkillLevel(finding) {
    const beginnerTypes = ['secret', 'api_key', 'idor', 'missing_header', 'insecure_cookie'];
    const intermediateTypes = ['xss', 'sql_injection', 'csrf', 'jwt', 'cors_wildcard'];
    const expertTypes = ['xxe', 'ssrf', 'deserialization', 'race_condition', 'prototype_pollution'];

    const type = finding.type?.toLowerCase() || '';

    if (beginnerTypes.some(t => type.includes(t))) return 'beginner';
    if (expertTypes.some(t => type.includes(t))) return 'expert';
    return 'intermediate';
  }

  /**
   * Vérifier si un exploit public existe
   */
  hasKnownExploit(finding) {
    // Pour les secrets exposés, c'est toujours exploitable
    if (finding.type?.includes('secret') || finding.type?.includes('api_key')) {
      return true;
    }

    // JWT none algorithm = exploit bien connu
    if (finding.decoded?.header?.alg === 'none') {
      return true;
    }

    // IDOR = concept bien connu
    if (finding.idorIndicators?.length > 0) {
      return true;
    }

    return false;
  }

  /**
   * Inférer le type de données exposées
   */
  inferDataType(finding) {
    const location = finding.location?.toLowerCase() || '';
    const description = finding.description?.toLowerCase() || '';
    const type = finding.type?.toLowerCase() || '';

    if (type.includes('stripe') || type.includes('payment')) return 'financial';
    if (type.includes('password') || type.includes('token')) return 'credentials';
    if (type.includes('api_key') || type.includes('secret')) return 'api_keys';
    if (location.includes('user') || description.includes('email')) return 'pii';

    return 'unknown';
  }

  /**
   * Inférer l'impact sur la compliance
   */
  inferComplianceImpact(finding) {
    const compliance = [];

    const dataType = this.inferDataType(finding);
    if (dataType === 'pii') compliance.push('RGPD');
    if (dataType === 'financial') compliance.push('PCI-DSS');
    if (dataType === 'credentials') compliance.push('ISO 27001');

    // Cookies non sécurisés
    if (finding.type?.includes('cookie')) compliance.push('RGPD');

    return compliance;
  }

  /**
   * Convertir score en niveau de risque
   */
  scoreToLevel(score) {
    if (score >= 8.5) return 'CRITIQUE';
    if (score >= 7) return 'ÉLEVÉ';
    if (score >= 5) return 'MOYEN';
    if (score >= 3) return 'FAIBLE';
    return 'INFORMATIONNEL';
  }

  /**
   * Convertir score en priorité
   */
  scoreToPriority(score) {
    if (score >= 8.5) return 'P0';
    if (score >= 7) return 'P1';
    if (score >= 5) return 'P2';
    return 'P3';
  }

  /**
   * Approximer le score CVSS v3
   */
  approximateCVSS(factors) {
    // Formule simplifiée basée sur les facteurs
    const cvss = (
      (factors.severity / 10) * 4 +      // Impact (max 4)
      (factors.exploitability / 10) * 4 + // Exploitability (max 4)
      (factors.context / 10) * 2          // Scope (max 2)
    );

    return parseFloat(cvss.toFixed(1));
  }

  /**
   * Estimer le temps d'exploitation
   */
  estimateExploitTime(factors) {
    const complexity = 10 - factors.exploitability; // Inverser

    if (complexity <= 2) return '< 5 minutes';
    if (complexity <= 4) return '< 30 minutes';
    if (complexity <= 6) return '< 2 heures';
    if (complexity <= 8) return '< 1 jour';
    return '> 1 jour';
  }

  /**
   * Obtenir la recommandation d'action
   */
  getRecommendation(score) {
    if (score >= 8.5) {
      return {
        action: 'PATCH_IMMÉDIAT',
        timeline: '< 24 heures',
        priority: 'P0',
        notification: ['RSSI', 'DevSecOps', 'On-call'],
        escalation: true
      };
    }

    if (score >= 7) {
      return {
        action: 'CORRECTIF_URGENT',
        timeline: '< 7 jours',
        priority: 'P1',
        notification: ['Équipe Sécurité', 'Dev Team'],
        escalation: false
      };
    }

    if (score >= 5) {
      return {
        action: 'CORRECTIF_PLANIFIÉ',
        timeline: '< 30 jours',
        priority: 'P2',
        notification: ['Équipe Sécurité'],
        escalation: false
      };
    }

    return {
      action: 'BACKLOG',
      timeline: 'Prochain sprint',
      priority: 'P3',
      notification: [],
      escalation: false
    };
  }

  /**
   * Enrichir le finding avec métadonnées
   */
  enrichFinding(finding) {
    const type = this.normalizeType(finding.type);

    return {
      cwe: this.cweMapping[type] || { id: 'CWE-Other', name: 'Unknown', category: 'other' },
      owasp: this.owaspMapping[type] || 'N/A',
      category: this.categorize(finding),
      skillLevel: this.inferSkillLevel(finding),
      dataType: this.inferDataType(finding),
      compliance: this.inferComplianceImpact(finding),
      references: this.generateReferences(type)
    };
  }

  /**
   * Normaliser le type de finding pour mapping
   */
  normalizeType(type) {
    if (!type) return 'unknown';

    const typeStr = type.toLowerCase();

    // Secrets
    if (typeStr.includes('api') && typeStr.includes('key')) return 'api_key';
    if (typeStr.includes('secret') || typeStr.includes('token')) return 'secret';
    if (typeStr.includes('jwt')) return 'jwt';

    // Access Control
    if (typeStr.includes('idor')) return 'idor';

    // Injection
    if (typeStr.includes('sql')) return 'sql_injection';
    if (typeStr.includes('xss')) return 'xss';
    if (typeStr.includes('xxe')) return 'xxe';

    // SSRF
    if (typeStr.includes('ssrf')) return 'ssrf';

    // Path
    if (typeStr.includes('path') || typeStr.includes('traversal')) return 'path_traversal';

    // Configuration
    if (typeStr.includes('header')) return 'missing_header';
    if (typeStr.includes('cookie')) return 'insecure_cookie';
    if (typeStr.includes('cors')) return 'cors_wildcard';
    if (typeStr.includes('crypto')) return 'weak_crypto';

    return 'unknown';
  }

  /**
   * Catégoriser le finding
   */
  categorize(finding) {
    const type = this.normalizeType(finding.type);
    const cwe = this.cweMapping[type];
    return cwe?.category || 'other';
  }

  /**
   * Générer des références utiles
   */
  generateReferences(type) {
    const cwe = this.cweMapping[type];
    if (!cwe) return [];

    return [
      `https://cwe.mitre.org/data/definitions/${cwe.id.replace('CWE-', '')}.html`,
      `https://owasp.org/www-community/vulnerabilities/${type}`,
      `https://portswigger.net/kb/issues/${type.replace(/_/g, '-')}`
    ];
  }

  /**
   * Calculer le score de risque global d'une session
   */
  calculateOverallRisk(findings) {
    if (findings.length === 0) {
      return {
        score: 0,
        level: 'AUCUN',
        criticalCount: 0,
        highCount: 0,
        recommendation: 'Aucune vulnérabilité détectée'
      };
    }

    const scoredFindings = findings.map(f => this.calculateCompositeScore(f, {}));

    // Score maximum comme score global
    const maxScore = Math.max(...scoredFindings.map(s => s.score));

    // Compter par sévérité
    const criticalCount = scoredFindings.filter(s => s.score >= 8.5).length;
    const highCount = scoredFindings.filter(s => s.score >= 7 && s.score < 8.5).length;

    return {
      score: maxScore,
      level: this.scoreToLevel(maxScore),
      criticalCount,
      highCount,
      averageScore: scoredFindings.reduce((sum, s) => sum + s.score, 0) / scoredFindings.length,
      recommendation: this.getRecommendation(maxScore).action,
      breakdown: {
        p0: scoredFindings.filter(s => s.priority === 'P0').length,
        p1: scoredFindings.filter(s => s.priority === 'P1').length,
        p2: scoredFindings.filter(s => s.priority === 'P2').length,
        p3: scoredFindings.filter(s => s.priority === 'P3').length
      }
    };
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.RiskScorer = RiskScorer;
}
