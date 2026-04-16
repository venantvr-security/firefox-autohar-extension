// PromptTemplateStore.js - Gestion des templates de prompts IA
// PentestHAR - Stockage LocalStorage extensible

class PromptTemplateStore {
  constructor() {
    this.STORAGE_KEY = 'pentesthar_prompts';
    this.VERSION = 1;

    // Variables disponibles pour substitution
    this.availableVariables = {
      '{{target}}': 'Domaine principal ciblé',
      '{{endpoints}}': 'Liste des endpoints découverts',
      '{{endpoints_count}}': 'Nombre d\'endpoints',
      '{{secrets}}': 'Secrets détectés (masqués)',
      '{{secrets_full}}': 'Secrets détectés (complets)',
      '{{jwt_decoded}}': 'JWT décodés avec claims',
      '{{idor_candidates}}': 'Endpoints candidats IDOR',
      '{{security_issues}}': 'Problèmes de sécurité détectés',
      '{{parameters}}': 'Liste des paramètres uniques',
      '{{auth_endpoints}}': 'Endpoints d\'authentification',
      '{{methods_summary}}': 'Résumé par méthode HTTP',
      '{{session_duration}}': 'Durée de la session',
      '{{request_count}}': 'Nombre de requêtes capturées',
      '{{headers_issues}}': 'Problèmes de headers de sécurité',
      '{{cookies_issues}}': 'Problèmes de cookies',
      '{{cors_issues}}': 'Problèmes CORS détectés',
      '{{tech_stack}}': 'Stack technique détectée',
      '{{api_version}}': 'Versions d\'API détectées'
    };

    // Templates par défaut
    this.defaultTemplates = [
      {
        id: 'recon-summary',
        name: 'Résumé Reconnaissance',
        category: 'recon',
        description: 'Génère un résumé de la reconnaissance pour briefing',
        prompt: `# Analyse de Reconnaissance - {{target}}

## Contexte
- Cible: {{target}}
- Durée session: {{session_duration}}
- Requêtes capturées: {{request_count}}

## Surface d'attaque découverte

### Endpoints ({{endpoints_count}})
{{endpoints}}

### Méthodes HTTP
{{methods_summary}}

### Paramètres découverts
{{parameters}}

## Demande
Analyse cette surface d'attaque et identifie:
1. Les endpoints les plus critiques à tester
2. Les vecteurs d'attaque potentiels
3. Une priorisation des tests à effectuer
4. Les informations manquantes pour compléter la reconnaissance`,
        isDefault: true,
        createdAt: Date.now()
      },
      {
        id: 'idor-analysis',
        name: 'Analyse IDOR',
        category: 'idor',
        description: 'Analyse les candidats IDOR détectés',
        prompt: `# Analyse IDOR - {{target}}

## Endpoints avec IDs séquentiels détectés
{{idor_candidates}}

## Contexte d'authentification
{{auth_endpoints}}

## Demande
Pour chaque endpoint candidat IDOR:
1. Évalue la probabilité de vulnérabilité (haute/moyenne/basse)
2. Propose une méthodologie de test spécifique
3. Suggère les payloads à tester (IDs adjacents, négatifs, très grands)
4. Identifie les contrôles d'accès à vérifier
5. Propose des scénarios de contournement si l'accès est refusé`,
        isDefault: true,
        createdAt: Date.now()
      },
      {
        id: 'jwt-audit',
        name: 'Audit JWT',
        category: 'auth',
        description: 'Analyse approfondie des tokens JWT capturés',
        prompt: `# Audit JWT - {{target}}

## Tokens JWT décodés
{{jwt_decoded}}

## Demande
Analyse ces JWT et réponds:
1. **Algorithme**: Est-il sécurisé? (none, HS256 faible, RS256 OK)
2. **Claims sensibles**: Quelles données exposées? (rôles, permissions, PII)
3. **Expiration**: Les tokens expirent-ils? Durée raisonnable?
4. **Attaques possibles**:
   - Algorithm confusion (RS256 -> HS256)
   - Clé faible/prévisible
   - Modification de claims (role, sub, permissions)
   - Token reuse après logout
5. **Recommandations**: Comment améliorer la sécurité?`,
        isDefault: true,
        createdAt: Date.now()
      },
      {
        id: 'secrets-triage',
        name: 'Triage Secrets',
        category: 'secrets',
        description: 'Triage et évaluation des secrets découverts',
        prompt: `# Triage Secrets - {{target}}

## Secrets détectés
{{secrets}}

## Localisation
Les secrets ont été trouvés dans les réponses HTTP de {{target}}.

## Demande
Pour chaque secret:
1. **Classification**: Type de secret (API key, token, credential)
2. **Criticité**: Impact si exposé (critique/haute/moyenne/basse)
3. **Validité**: Le secret semble-t-il actif? (format, préfixe)
4. **Exploitation**: Comment un attaquant pourrait l'utiliser?
5. **Recommandation**: Action immédiate à prendre
6. **Vérification**: Comment tester si le secret est valide sans causer de dommages?`,
        isDefault: true,
        createdAt: Date.now()
      },
      {
        id: 'api-security-review',
        name: 'Revue Sécurité API',
        category: 'api',
        description: 'Revue complète de la sécurité de l\'API',
        prompt: `# Revue Sécurité API - {{target}}

## Endpoints découverts
{{endpoints}}

## Headers de sécurité
{{headers_issues}}

## Cookies
{{cookies_issues}}

## CORS
{{cors_issues}}

## Stack technique
{{tech_stack}}

## Demande
Effectue une revue de sécurité complète:

### 1. Authentification/Autorisation
- Mécanismes détectés
- Faiblesses potentielles
- Tests recommandés

### 2. Input Validation
- Paramètres à tester pour injection
- Types de payloads recommandés

### 3. Configuration
- Headers manquants/faibles
- Cookies non sécurisés
- Problèmes CORS

### 4. Business Logic
- Flux critiques identifiés
- Tests de logique métier à effectuer

### 5. Priorisation
Liste ordonnée des 10 tests les plus importants à réaliser`,
        isDefault: true,
        createdAt: Date.now()
      },
      {
        id: 'attack-scenarios',
        name: 'Scénarios d\'Attaque',
        category: 'offensive',
        description: 'Génère des scénarios d\'attaque basés sur les findings',
        prompt: `# Scénarios d'Attaque - {{target}}

## Données collectées
- Endpoints: {{endpoints_count}}
- Secrets: {{secrets}}
- IDOR candidats: {{idor_candidates}}
- Issues: {{security_issues}}

## Demande
Génère 5 scénarios d'attaque réalistes:

Pour chaque scénario:
1. **Nom**: Titre descriptif
2. **Objectif**: Ce que l'attaquant cherche à obtenir
3. **Prérequis**: Accès/informations nécessaires
4. **Étapes**: Séquence d'actions détaillée
5. **Endpoints ciblés**: Quels endpoints utiliser
6. **Payloads**: Exemples concrets
7. **Indicateurs de succès**: Comment savoir si ça marche
8. **Impact**: Conséquences si réussi

Priorise par: facilité d'exploitation × impact`,
        isDefault: true,
        createdAt: Date.now()
      },
      {
        id: 'bug-bounty-report',
        name: 'Template Rapport Bug Bounty',
        category: 'reporting',
        description: 'Structure pour rapport de vulnérabilité',
        prompt: `# Rapport de Vulnérabilité - {{target}}

## Informations collectées
{{security_issues}}
{{secrets}}
{{idor_candidates}}

## Demande
Génère un template de rapport bug bounty professionnel:

### Structure demandée:
1. **Titre**: Concis et descriptif
2. **Sévérité**: Critique/Haute/Moyenne/Basse avec justification CVSS
3. **Résumé**: 2-3 phrases
4. **Endpoint vulnérable**: URL exacte
5. **Étapes de reproduction**: Numérotées, reproductibles
6. **Preuve de concept**: Commande curl ou script
7. **Impact**: Business impact concret
8. **Recommandation**: Fix suggéré
9. **Références**: CWE, OWASP, CVE similaires

Adapte le rapport au programme bug bounty standard (HackerOne/Bugcrowd).`,
        isDefault: true,
        createdAt: Date.now()
      },
      {
        id: 'quick-wins',
        name: 'Quick Wins',
        category: 'prioritization',
        description: 'Identifie les vulnérabilités faciles à exploiter',
        prompt: `# Quick Wins - {{target}}

## Données
- Issues: {{security_issues}}
- Secrets: {{secrets}}
- IDOR: {{idor_candidates}}
- Headers: {{headers_issues}}

## Demande
Identifie les "quick wins" - vulnérabilités:
- Faciles à exploiter (< 5 minutes)
- Forte probabilité de succès
- Impact démontrable

Pour chaque quick win:
1. **Vulnérabilité**: Description courte
2. **Exploitation**: Commande/action exacte
3. **Temps estimé**: En minutes
4. **Probabilité**: %
5. **Impact**: Ce qu'on obtient

Ordonne par ratio effort/impact (meilleur en premier).`,
        isDefault: true,
        createdAt: Date.now()
      },
      {
        id: 'structured-analysis',
        name: 'Analyse Structurée (JSON+MD)',
        category: 'recon',
        description: 'Analyse avec données structurées JSON pour parsing facile',
        prompt: `# Analyse Structurée - {{target}}

## Métadonnées
\`\`\`json
{
  "target": "{{target}}",
  "duration": "{{session_duration}}",
  "requests": {{request_count}},
  "endpoints": {{endpoints_count}},
  "riskLevel": "À déterminer"
}
\`\`\`

## Surface d'Attaque
{{endpoints}}

## Findings
- Secrets: {{secrets}}
- IDOR: {{idor_candidates}}
- Issues: {{security_issues}}

## Demande

Analyse ces données et génère un rapport JSON structuré avec:

\`\`\`json
{
  "riskScore": 0-10,
  "criticalFindings": [],
  "attackVectors": [],
  "recommendations": [],
  "exploitability": "low|medium|high"
}
\`\`\`

Ensuite, explique en français chaque élément du JSON.`,
        isDefault: true,
        createdAt: Date.now()
      },
      {
        id: 'conversational-deep-dive',
        name: 'Deep Dive Conversationnel',
        category: 'offensive',
        description: 'Format question-réponse pour analyse approfondie',
        prompt: `# 🤖 Session d'Analyse Sécurité - {{target}}

## 👤 Ton Rôle
Tu es un expert OSCP/OSWE avec 10 ans d'expérience en pentest web.
Tu analyses le trafic capturé pour identifier des vulnérabilités exploitables.

## 📦 Données Capturées
- **Durée**: {{session_duration}}
- **Requêtes**: {{request_count}}
- **Endpoints**: {{endpoints_count}}
- **Secrets**: Détectés (voir ci-dessous)
- **IDOR**: Candidats identifiés

### Findings Automatiques
{{security_issues}}
{{secrets}}
{{idor_candidates}}

## ❓ Questions pour Toi

### Q1: Priorisation Intelligente
Parmi TOUS les findings détectés, lesquels dois-je exploiter en PREMIER ?
Crée un classement par **ratio impact/effort** :
- Impact: 0-10 (données exposées, business impact)
- Effort: 0-10 (compétence requise, prérequis, temps)
- Ratio: Impact/Effort (plus élevé = meilleur)

Format: Tableau markdown avec colonnes [Finding, Impact, Effort, Ratio, Ordre]

### Q2: Attack Chain
Peux-tu **construire un scénario d'attaque complet** en enchaînant plusieurs vulnérabilités ?

Format attendu:
1. **Étape 1**: Action précise → Résultat obtenu
2. **Étape 2**: Action suivante → Nouveau résultat
3. **Étape 3**: ...
4. **Impact final**: Ce qu'un attaquant obtient

### Q3: Exploitation Technique
Pour les 3 findings les plus critiques, donne-moi:
1. **Commande curl/script exact** pour exploiter
2. **Indicateurs de succès** (status code, contenu réponse)
3. **Post-exploitation** (que faire avec l'accès obtenu)

### Q4: Blind Spots
Quelles vulnérabilités **NE PEUVENT PAS** être détectées par analyse passive ?
Liste ce que je devrais tester manuellement ensuite.

### Q5: Rapport Professionnel
Rédige un **rapport HackerOne** pour la vulnérabilité #1 (la plus critique).
Format:
- **Titre**: Concis et descriptif
- **Sévérité**: CVSS score avec justification
- **Description**: 2-3 phrases
- **Steps to Reproduce**: Numérotées, détaillées
- **Impact**: Business impact concret
- **Remediation**: Fix suggéré
- **References**: CWE, OWASP

---

## 📊 Données Brutes

<details>
<summary>Endpoints Complets</summary>

{{endpoints}}
</details>

<details>
<summary>Paramètres</summary>

{{parameters}}
</details>`,
        isDefault: true,
        createdAt: Date.now()
      },
      {
        id: 'exploit-ready',
        name: 'Exploitation Ready',
        category: 'offensive',
        description: 'Focus sur l\'exploitation immédiate avec commandes',
        prompt: `# ⚔️ Exploitation Guide - {{target}}

## 🎯 Cible
- **Domain**: {{target}}
- **Session**: {{session_duration}}
- **Findings détectés**: Voir ci-dessous

## 🔍 Findings

### Secrets Exposés
{{secrets}}

### IDOR Candidates
{{idor_candidates}}

### JWT Tokens
{{jwt_decoded}}

### Issues
{{security_issues}}

## 🚀 Demande: Génère un Guide d'Exploitation

Pour CHAQUE finding, fournis:

### Format:
\`\`\`
Finding: [Nom du finding]
Sévérité: [Critical/High/Medium]
Temps: [< 5min | < 30min | < 2h]

# Étape 1: Vérification
curl [commande exacte]
# Résultat attendu: [ce qu'on doit voir]

# Étape 2: Exploitation
[Commande ou script exact]
# Résultat attendu: [données exfiltrées, accès obtenu]

# Étape 3: Post-Exploitation
[Que faire avec l'accès]

# Défense/Mitigation
[Comment l'équipe dev devrait corriger]
\`\`\`

**IMPORTANT**: Toutes les commandes doivent être **copy-paste ready** (pas de placeholder, utilise les vraies URLs/endpoints détectés).`,
        isDefault: true,
        createdAt: Date.now()
      },
      {
        id: 'risk-scoring',
        name: 'Scoring CVSS Automatique',
        category: 'prioritization',
        description: 'Calcul de scores CVSS v3 pour priorisation',
        prompt: `# 📊 Scoring CVSS - {{target}}

## Findings Détectés

### Secrets
{{secrets}}

### IDOR
{{idor_candidates}}

### Issues Sécurité
{{security_issues}}

## Demande: Calcule les Scores CVSS v3.1

Pour CHAQUE finding, calcule le score CVSS v3.1 en détaillant:

### Format:
\`\`\`
Finding: [Nom]

CVSS Vector: CVSS:3.1/AV:[N/A/L/P]/AC:[L/H]/PR:[N/L/H]/UI:[N/R]/S:[U/C]/C:[N/L/H]/I:[N/L/H]/A:[N/L/H]

Justification:
- AV (Attack Vector): [Justification]
- AC (Attack Complexity): [Justification]
- PR (Privileges Required): [Justification]
- UI (User Interaction): [Justification]
- S (Scope): [Justification]
- C (Confidentiality): [Justification]
- I (Integrity): [Justification]
- A (Availability): [Justification]

Score Base: X.X (Critical/High/Medium/Low)
Score Temporel: X.X
Score Environnemental: X.X

Priorité: P0/P1/P2/P3
Timeline: < 24h | < 7j | < 30j
\`\`\`

Ensuite, classe tous les findings par score décroissant.`,
        isDefault: true,
        createdAt: Date.now()
      },
      {
        id: 'compliance-check',
        name: 'Audit Compliance (RGPD/PCI)',
        category: 'reporting',
        description: 'Vérification conformité RGPD, PCI-DSS, ISO 27001',
        prompt: `# ⚖️ Audit Compliance - {{target}}

## Données Analysées
- **Secrets**: {{secrets}}
- **Cookies**: {{cookies_issues}}
- **Headers**: {{headers_issues}}
- **Endpoints**: {{endpoints}}

## Demande: Audit de Conformité

Analyse la conformité par rapport à:

### 1. RGPD (Règlement Général sur la Protection des Données)
- [ ] Cookies sécurisés (Secure, HttpOnly, SameSite)
- [ ] Chiffrement des données en transit (HTTPS)
- [ ] Pas de fuite de PII dans les logs/responses
- [ ] Consentement cookies (si applicable)

**Findings RGPD**:
[Liste les violations détectées]

### 2. PCI-DSS (Payment Card Industry Data Security Standard)
- [ ] Pas de secrets/clés API en clair
- [ ] Headers de sécurité (CSP, HSTS)
- [ ] Chiffrement fort (TLS 1.2+)
- [ ] Pas de données bancaires en logs

**Findings PCI-DSS**:
[Liste les violations]

### 3. ISO 27001 (Security Management)
- [ ] Gestion des secrets appropriée
- [ ] Contrôle d'accès (pas d'IDOR)
- [ ] Logging et monitoring
- [ ] Authentification sécurisée

**Findings ISO 27001**:
[Liste les violations]

## Rapport de Conformité

Génère un tableau:

| Standard | Conforme | Findings | Sévérité | Action |
|----------|----------|----------|----------|--------|
| RGPD | ✅/❌ | [N] | Critical/High/Medium | [Action] |
| PCI-DSS | ✅/❌ | [N] | Critical/High/Medium | [Action] |
| ISO 27001 | ✅/❌ | [N] | Critical/High/Medium | [Action] |

**Score Global de Conformité**: X/100`,
        isDefault: true,
        createdAt: Date.now()
      }
    ];

    // Charger les templates au démarrage
    this.templates = this.load();
  }

  // Charger depuis LocalStorage
  load() {
    try {
      const stored = localStorage.getItem(this.STORAGE_KEY);
      if (stored) {
        const data = JSON.parse(stored);
        // Migration si nécessaire
        if (data.version !== this.VERSION) {
          return this.migrate(data);
        }
        return data.templates;
      }
    } catch (e) {
      console.error('Error loading prompts:', e);
    }

    // Premier lancement - retourner les défauts
    const defaults = [...this.defaultTemplates];
    this.save(defaults);
    return defaults;
  }

  // Sauvegarder dans LocalStorage
  save(templates = this.templates) {
    try {
      const data = {
        version: this.VERSION,
        templates,
        lastModified: Date.now()
      };
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(data));
      this.templates = templates;
      return true;
    } catch (e) {
      console.error('Error saving prompts:', e);
      return false;
    }
  }

  // Migration de version
  migrate(oldData) {
    // Pour l'instant, reset aux défauts
    console.log('Migrating prompts from version', oldData.version);
    const merged = [...this.defaultTemplates];

    // Garder les prompts custom de l'utilisateur
    if (oldData.templates) {
      for (const t of oldData.templates) {
        if (!t.isDefault) {
          merged.push(t);
        }
      }
    }

    this.save(merged);
    return merged;
  }

  // Obtenir tous les templates
  getAll() {
    return this.templates;
  }

  // Obtenir par catégorie
  getByCategory(category) {
    return this.templates.filter(t => t.category === category);
  }

  // Obtenir un template par ID
  getById(id) {
    return this.templates.find(t => t.id === id);
  }

  // Obtenir les catégories disponibles
  getCategories() {
    const categories = new Set(this.templates.map(t => t.category));
    return Array.from(categories).sort();
  }

  // Ajouter un nouveau template
  add(template) {
    const newTemplate = {
      id: `custom-${Date.now()}`,
      isDefault: false,
      createdAt: Date.now(),
      ...template
    };

    this.templates.push(newTemplate);
    this.save();
    return newTemplate;
  }

  // Mettre à jour un template
  update(id, updates) {
    const index = this.templates.findIndex(t => t.id === id);
    if (index === -1) return null;

    // Ne pas modifier les champs protégés des templates par défaut
    if (this.templates[index].isDefault) {
      // Créer une copie personnalisée
      const customCopy = {
        ...this.templates[index],
        ...updates,
        id: `custom-${Date.now()}`,
        isDefault: false,
        basedOn: id,
        createdAt: Date.now()
      };
      this.templates.push(customCopy);
      this.save();
      return customCopy;
    }

    this.templates[index] = {
      ...this.templates[index],
      ...updates,
      updatedAt: Date.now()
    };
    this.save();
    return this.templates[index];
  }

  // Supprimer un template (seulement les custom)
  delete(id) {
    const template = this.getById(id);
    if (!template || template.isDefault) return false;

    this.templates = this.templates.filter(t => t.id !== id);
    this.save();
    return true;
  }

  // Dupliquer un template
  duplicate(id) {
    const original = this.getById(id);
    if (!original) return null;

    return this.add({
      name: `${original.name} (copie)`,
      category: original.category,
      description: original.description,
      prompt: original.prompt,
      basedOn: id
    });
  }

  // Réinitialiser aux valeurs par défaut
  reset() {
    this.templates = [...this.defaultTemplates];
    this.save();
    return this.templates;
  }

  // Exporter tous les templates (pour backup)
  export() {
    return JSON.stringify({
      version: this.VERSION,
      exportedAt: new Date().toISOString(),
      templates: this.templates.filter(t => !t.isDefault)
    }, null, 2);
  }

  // Importer des templates
  import(jsonString) {
    try {
      const data = JSON.parse(jsonString);
      let imported = 0;

      for (const template of data.templates || []) {
        // Éviter les doublons
        if (!this.templates.find(t => t.id === template.id)) {
          this.templates.push({
            ...template,
            importedAt: Date.now()
          });
          imported++;
        }
      }

      this.save();
      return { success: true, imported };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  // Obtenir la liste des variables disponibles
  getAvailableVariables() {
    return this.availableVariables;
  }

  // Valider un template
  validate(template) {
    const errors = [];

    if (!template.name || template.name.trim().length < 2) {
      errors.push('Le nom doit contenir au moins 2 caractères');
    }

    if (!template.prompt || template.prompt.trim().length < 10) {
      errors.push('Le prompt doit contenir au moins 10 caractères');
    }

    if (!template.category) {
      errors.push('La catégorie est requise');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  // Rechercher dans les templates
  search(query) {
    const q = query.toLowerCase();
    return this.templates.filter(t =>
      t.name.toLowerCase().includes(q) ||
      t.description?.toLowerCase().includes(q) ||
      t.prompt.toLowerCase().includes(q) ||
      t.category.toLowerCase().includes(q)
    );
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.PromptTemplateStore = PromptTemplateStore;
}
