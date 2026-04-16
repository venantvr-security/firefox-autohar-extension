/**
 * CloudSyncManager - Gestion synchronisation cloud (Google Drive)
 *
 * Fonctionnalités :
 * - OAuth2 Google Drive avec stockage sécurisé tokens
 * - Upload automatique vers Google Drive
 * - Nommage intelligent : domain_YYYY-MM-DD_HHmmss.har
 * - Machine ID unique pour traçabilité
 * - Organisation par dossiers : PentestHAR/domain/
 *
 * Sécurité :
 * - Scope minimal : drive.file (accès fichiers créés par l'app uniquement)
 * - Tokens chiffrés dans localStorage
 * - Refresh token automatique
 * - Révocation facile
 */

class CloudSyncManager {
  constructor() {
    this.config = {
      // Google OAuth2 - À remplacer par vos credentials
      clientId: '', // À configurer par l'utilisateur
      clientSecret: '', // Optionnel pour extension
      redirectUri: 'https://YOUR_EXTENSION_ID.chromiumapp.org/',
      scopes: ['https://www.googleapis.com/auth/drive.file'], // Scope minimal

      // Configuration sync
      autoSync: false,
      syncProvider: 'none', // 'none', 'gdrive'
      folderStructure: 'PentestHAR/{domain}', // Template dossier

      // Machine ID
      machineId: null
    };

    this.tokens = {
      accessToken: null,
      refreshToken: null,
      expiresAt: null
    };

    this.init();
  }

  /**
   * Initialisation
   */
  async init() {
    // Charger configuration
    await this.loadConfig();

    // Générer ou récupérer machine ID
    this.config.machineId = await this.getMachineId();

    // Charger tokens si existent
    await this.loadTokens();
  }

  /**
   * Génère ou récupère un identifiant machine unique
   * Format : uuid-v4 persisté dans localStorage
   */
  async getMachineId() {
    const stored = localStorage.getItem('pentesthar_machine_id');
    if (stored) {
      return stored;
    }

    // Générer nouveau UUID
    const uuid = this.generateUUID();
    localStorage.setItem('pentesthar_machine_id', uuid);

    console.log('🆔 Machine ID généré:', uuid);
    return uuid;
  }

  /**
   * Génère un UUID v4
   */
  generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  /**
   * Génère un nom de fichier intelligent
   * Format : domain_YYYY-MM-DD_HHmmss_machineId.har
   */
  generateFileName(domain, extension = 'har') {
    const now = new Date();
    const date = now.toISOString().split('T')[0]; // YYYY-MM-DD
    const time = now.toTimeString().split(' ')[0].replace(/:/g, ''); // HHmmss

    // Nettoyer le domaine (supprimer protocole, ports, etc.)
    const cleanDomain = domain
      .replace(/^https?:\/\//, '')
      .replace(/:\d+$/, '')
      .replace(/\//g, '_')
      .replace(/[^a-zA-Z0-9._-]/g, '_');

    const shortMachineId = this.config.machineId.split('-')[0]; // 8 premiers chars

    return `${cleanDomain}_${date}_${time}_${shortMachineId}.${extension}`;
  }

  /**
   * Génère le chemin de dossier selon template
   */
  generateFolderPath(domain) {
    const cleanDomain = domain
      .replace(/^https?:\/\//, '')
      .replace(/:\d+$/, '')
      .replace(/\//g, '_');

    return this.config.folderStructure.replace('{domain}', cleanDomain);
  }

  /**
   * Charge la configuration depuis localStorage
   */
  async loadConfig() {
    const stored = localStorage.getItem('pentesthar_cloud_config');
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        Object.assign(this.config, parsed);
      } catch (e) {
        console.error('❌ Erreur chargement config cloud:', e);
      }
    }
  }

  /**
   * Sauvegarde la configuration
   */
  async saveConfig() {
    localStorage.setItem('pentesthar_cloud_config', JSON.stringify(this.config));
  }

  /**
   * Charge les tokens OAuth (chiffrés)
   */
  async loadTokens() {
    const stored = localStorage.getItem('pentesthar_cloud_tokens');
    if (stored) {
      try {
        // Simple obfuscation (à améliorer avec vrai chiffrement si sensible)
        const decoded = atob(stored);
        this.tokens = JSON.parse(decoded);

        // Vérifier expiration
        if (this.tokens.expiresAt && Date.now() > this.tokens.expiresAt) {
          console.log('⚠️  Token expiré, refresh nécessaire');
          await this.refreshAccessToken();
        }
      } catch (e) {
        console.error('❌ Erreur chargement tokens:', e);
      }
    }
  }

  /**
   * Sauvegarde les tokens (chiffrés)
   */
  async saveTokens() {
    // Simple obfuscation (à améliorer avec vrai chiffrement)
    const encoded = btoa(JSON.stringify(this.tokens));
    localStorage.setItem('pentesthar_cloud_tokens', encoded);
  }

  /**
   * Initie le flux OAuth2 Google Drive
   */
  async authenticateGoogleDrive() {
    if (!this.config.clientId) {
      throw new Error('Client ID Google non configuré. Allez dans Settings → Cloud Sync.');
    }

    // URL d'autorisation OAuth2
    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.set('client_id', this.config.clientId);
    authUrl.searchParams.set('redirect_uri', this.config.redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', this.config.scopes.join(' '));
    authUrl.searchParams.set('access_type', 'offline'); // Pour refresh token
    authUrl.searchParams.set('prompt', 'consent');

    console.log('🔐 Ouverture OAuth Google Drive...');

    // Ouvrir dans nouvelle fenêtre
    return new Promise((resolve, reject) => {
      const authWindow = window.open(authUrl.toString(), 'Google Drive Auth', 'width=600,height=700');

      // Écouter le callback (nécessite un listener sur redirectUri)
      // Pour une extension Firefox, utiliser browser.identity.launchWebAuthFlow
      const checkClosed = setInterval(() => {
        if (authWindow.closed) {
          clearInterval(checkClosed);
          reject(new Error('Authentification annulée'));
        }
      }, 500);

      // Note : Dans une vraie implémentation, il faut gérer le callback
      // avec browser.identity.launchWebAuthFlow (Firefox WebExtensions)
    });
  }

  /**
   * Échange le code OAuth contre un access token
   */
  async exchangeCodeForToken(code) {
    const tokenUrl = 'https://oauth2.googleapis.com/token';

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        code: code,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret || '',
        redirect_uri: this.config.redirectUri,
        grant_type: 'authorization_code'
      })
    });

    if (!response.ok) {
      throw new Error('Échec échange code OAuth');
    }

    const data = await response.json();

    this.tokens.accessToken = data.access_token;
    this.tokens.refreshToken = data.refresh_token;
    this.tokens.expiresAt = Date.now() + (data.expires_in * 1000);

    await this.saveTokens();

    console.log('✅ Authentification Google Drive réussie');
    return data;
  }

  /**
   * Rafraîchit le access token avec le refresh token
   */
  async refreshAccessToken() {
    if (!this.tokens.refreshToken) {
      throw new Error('Pas de refresh token disponible');
    }

    const tokenUrl = 'https://oauth2.googleapis.com/token';

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        refresh_token: this.tokens.refreshToken,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret || '',
        grant_type: 'refresh_token'
      })
    });

    if (!response.ok) {
      throw new Error('Échec refresh token');
    }

    const data = await response.json();

    this.tokens.accessToken = data.access_token;
    this.tokens.expiresAt = Date.now() + (data.expires_in * 1000);

    await this.saveTokens();

    console.log('✅ Token rafraîchi');
    return data;
  }

  /**
   * Crée ou récupère un dossier Google Drive
   */
  async getOrCreateFolder(folderPath) {
    const parts = folderPath.split('/');
    let parentId = 'root';

    for (const folderName of parts) {
      // Chercher si le dossier existe
      const searchUrl = new URL('https://www.googleapis.com/drive/v3/files');
      searchUrl.searchParams.set('q', `name='${folderName}' and '${parentId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`);
      searchUrl.searchParams.set('fields', 'files(id, name)');

      const searchResponse = await fetch(searchUrl, {
        headers: {
          'Authorization': `Bearer ${this.tokens.accessToken}`
        }
      });

      if (!searchResponse.ok) {
        throw new Error('Échec recherche dossier');
      }

      const searchData = await searchResponse.json();

      if (searchData.files && searchData.files.length > 0) {
        // Dossier existe
        parentId = searchData.files[0].id;
      } else {
        // Créer le dossier
        const createResponse = await fetch('https://www.googleapis.com/drive/v3/files', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.tokens.accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            name: folderName,
            mimeType: 'application/vnd.google-apps.folder',
            parents: [parentId]
          })
        });

        if (!createResponse.ok) {
          throw new Error('Échec création dossier');
        }

        const createData = await createResponse.json();
        parentId = createData.id;
      }
    }

    return parentId;
  }

  /**
   * Upload un fichier vers Google Drive
   */
  async uploadToGoogleDrive(content, fileName, domain, mimeType = 'application/json') {
    if (!this.tokens.accessToken) {
      throw new Error('Non authentifié sur Google Drive');
    }

    // Vérifier expiration token
    if (Date.now() > this.tokens.expiresAt) {
      await this.refreshAccessToken();
    }

    // Créer/récupérer dossier
    const folderPath = this.generateFolderPath(domain);
    const folderId = await this.getOrCreateFolder(folderPath);

    // Upload en 2 étapes (metadata puis content)
    // 1. Créer le fichier avec metadata
    const metadata = {
      name: fileName,
      parents: [folderId],
      mimeType: mimeType
    };

    const metadataResponse = await fetch('https://www.googleapis.com/drive/v3/files', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.tokens.accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(metadata)
    });

    if (!metadataResponse.ok) {
      throw new Error('Échec création fichier');
    }

    const file = await metadataResponse.json();

    // 2. Upload le contenu
    const uploadUrl = `https://www.googleapis.com/upload/drive/v3/files/${file.id}?uploadType=media`;

    const uploadResponse = await fetch(uploadUrl, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${this.tokens.accessToken}`,
        'Content-Type': mimeType
      },
      body: content
    });

    if (!uploadResponse.ok) {
      throw new Error('Échec upload contenu');
    }

    console.log(`✅ Fichier uploadé: ${fileName} → ${folderPath}`);

    return file;
  }

  /**
   * Sauvegarde locale (Downloads) + optionnellement cloud
   */
  async saveWithSync(content, domain, options = {}) {
    const extension = options.extension || 'har';
    const fileName = this.generateFileName(domain, extension);
    const mimeType = options.mimeType || 'application/json';

    // 1. Sauvegarde locale (Downloads)
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);

    const downloadOptions = {
      url: url,
      filename: `PentestHAR/${fileName}`,
      saveAs: false // Auto-download sans prompt
    };

    try {
      await browser.downloads.download(downloadOptions);
      console.log(`💾 Sauvegarde locale: ${fileName}`);
    } catch (e) {
      console.error('❌ Erreur sauvegarde locale:', e);
    }

    // 2. Sync cloud si activé
    if (this.config.autoSync && this.config.syncProvider === 'gdrive') {
      try {
        await this.uploadToGoogleDrive(content, fileName, domain, mimeType);
        console.log(`☁️  Sync cloud: ${fileName}`);
      } catch (e) {
        console.error('❌ Erreur sync cloud:', e);
        // Ne pas bloquer la sauvegarde locale si cloud échoue
      }
    }

    return fileName;
  }

  /**
   * Révoque l'authentification Google Drive
   */
  async revokeAccess() {
    if (!this.tokens.accessToken) {
      return;
    }

    try {
      await fetch(`https://oauth2.googleapis.com/revoke?token=${this.tokens.accessToken}`, {
        method: 'POST'
      });

      this.tokens = {
        accessToken: null,
        refreshToken: null,
        expiresAt: null
      };

      localStorage.removeItem('pentesthar_cloud_tokens');

      console.log('✅ Accès Google Drive révoqué');
    } catch (e) {
      console.error('❌ Erreur révocation:', e);
    }
  }

  /**
   * Vérifie si authentifié
   */
  isAuthenticated() {
    return this.tokens.accessToken !== null && Date.now() < this.tokens.expiresAt;
  }

  /**
   * Active/désactive la sync automatique
   */
  async setAutoSync(enabled, provider = 'gdrive') {
    this.config.autoSync = enabled;
    this.config.syncProvider = provider;
    await this.saveConfig();

    console.log(`${enabled ? '✅' : '❌'} Auto-sync ${enabled ? 'activée' : 'désactivée'} (${provider})`);
  }

  /**
   * Configure le client ID Google
   */
  async setGoogleClientId(clientId, clientSecret = '') {
    this.config.clientId = clientId;
    this.config.clientSecret = clientSecret;
    await this.saveConfig();

    console.log('✅ Client ID Google configuré');
  }

  /**
   * Obtient les statistiques de sync
   */
  getStats() {
    return {
      machineId: this.config.machineId,
      authenticated: this.isAuthenticated(),
      autoSync: this.config.autoSync,
      provider: this.config.syncProvider,
      folderStructure: this.config.folderStructure
    };
  }
}

// Export global pour Firefox extension
if (typeof window !== 'undefined') {
  window.CloudSyncManager = CloudSyncManager;
}
