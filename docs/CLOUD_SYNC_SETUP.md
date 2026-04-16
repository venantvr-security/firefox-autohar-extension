# ☁️ Configuration Cloud Sync - Guide Complet

**PentestHAR v2.2.0** - Synchronisation automatique Google Drive

---

## 🎯 Objectif

Centraliser automatiquement les résultats d'audits de sécurité de plusieurs applications vers Google Drive pour :
- **Agrégation organisationnelle** : Vue d'ensemble multi-applications
- **Traçabilité** : Machine ID unique par poste
- **Archivage automatique** : Sauvegarde locale + cloud
- **Collaboration** : Partage facile avec l'équipe sécurité

---

## 📋 Prérequis

### 1. Compte Google

- Compte Google avec accès Google Drive
- Espace de stockage suffisant (15 GB gratuit)

### 2. Google Cloud Console

Création d'un projet OAuth2 :

1. **Aller sur** : https://console.cloud.google.com/
2. **Créer un projet** : "PentestHAR Sync" (ou nom de votre choix)
3. **Activer l'API** :
   - Dans le menu, "APIs & Services" → "Enable APIs and Services"
   - Chercher "Google Drive API"
   - Cliquer "Enable"

4. **Configurer OAuth Consent Screen** :
   - "APIs & Services" → "OAuth consent screen"
   - Type : **External** (ou Internal si G Workspace)
   - Remplir :
     - **App name** : "PentestHAR"
     - **User support email** : Votre email
     - **Developer contact** : Votre email
   - **Scopes** : Ajouter `https://www.googleapis.com/auth/drive.file`
     - ⚠️ **Scope minimal** : Accès uniquement aux fichiers créés par l'app
   - Sauvegarder

5. **Créer les credentials OAuth** :
   - "APIs & Services" → "Credentials"
   - "Create Credentials" → "OAuth client ID"
   - **Application type** : "Web application"
   - **Name** : "PentestHAR Extension"
   - **Authorized redirect URIs** :
     ```
     https://YOUR_EXTENSION_ID.extensions.allizom.org/
     ```
     (Voir section "Obtenir l'Extension ID" ci-dessous)
   - Cliquer "Create"
   - **Copier** le **Client ID** affiché

---

## 🔑 Obtenir l'Extension ID

### Firefox

1. **Ouvrir** : `about:debugging#/runtime/this-firefox`
2. **Trouver** "PentestHAR" dans la liste
3. **Copier** l'UUID affiché (ex: `{12345678-1234-1234-1234-123456789012}`)
4. **Redirect URI** : `https://12345678-1234-1234-1234-123456789012.extensions.allizom.org/`

### Chrome (si portage futur)

1. **Ouvrir** : `chrome://extensions/`
2. **Activer** "Developer mode"
3. **Copier** l'ID affiché sous l'extension
4. **Redirect URI** : `https://YOUR_EXTENSION_ID.chromiumapp.org/`

---

## ⚙️ Configuration dans PentestHAR

### 1. Ouvrir les Settings

```
Firefox DevTools (F12) → Onglet "PentestHAR" → Cliquer ⚙️ (en haut à droite)
```

### 2. Section "Cloud Sync"

**Activer la synchronisation** :
- Toggle "Auto-sync" : **ON**
- Provider : **Google Drive**

**Configurer Google OAuth** :
- **Client ID** : Coller le Client ID obtenu depuis Google Cloud Console
- **Client Secret** : Laisser vide (non nécessaire pour extension)

**Cliquer** "Sauvegarder"

### 3. Authentification

**Cliquer** "🔐 Connecter Google Drive"

- Une fenêtre popup s'ouvre
- **Se connecter** avec votre compte Google
- **Autoriser** PentestHAR à accéder à Google Drive
  - ⚠️ Scope demandé : `drive.file` (accès fichiers créés par l'app uniquement)
- La fenêtre se ferme automatiquement

**Statut** : "✅ Connecté"

---

## 📂 Structure des Fichiers

### Organisation Automatique

Les fichiers sont organisés selon la structure :

```
Google Drive/
  PentestHAR/
    example.com/
      example.com_2024-01-15_143052_a1b2c3d4.har
      example.com_2024-01-15_150234_a1b2c3d4.har
    api.target.com/
      api.target.com_2024-01-16_091523_a1b2c3d4.har
    intranet.company.local/
      intranet.company.local_2024-01-17_103045_a1b2c3d4.har
```

### Format des Noms de Fichiers

```
{domain}_{date}_{time}_{machineId}.{extension}
```

**Exemple** :
```
example.com_2024-01-15_143052_a1b2c3d4.har
```

- **domain** : `example.com` (domaine cible)
- **date** : `2024-01-15` (YYYY-MM-DD)
- **time** : `143052` (HHmmss)
- **machineId** : `a1b2c3d4` (8 premiers caractères du Machine ID)
- **extension** : `har` (ou `json` selon le type d'export)

### Machine ID

Un **UUID unique** est généré lors de la première utilisation :

```
a1b2c3d4-5678-4abc-y123-456789abcdef
```

**Utilité** :
- Identifier la machine source de chaque audit
- Traçabilité multi-postes
- Agrégation par équipe/département

**Persistance** : Stocké dans `localStorage` (`pentesthar_machine_id`)

**Voir le Machine ID** :
```
Settings → Cloud Sync → Machine ID
```

**Copier** : Bouton "📋 Copier" à côté du Machine ID

---

## 🚀 Utilisation

### Sauvegarde Automatique

Une fois configuré, **chaque export** déclenche automatiquement :

1. **Sauvegarde locale** : `Downloads/PentestHAR/{fichier}`
2. **Upload Google Drive** : `PentestHAR/{domain}/{fichier}`

**Aucune action manuelle requise** ✅

### Exports Concernés

- **Export HAR** : Full HAR, Filtered HAR
- **Export AI** : AI Brief, Structured Format
- **Export Tools** : ffuf, nuclei, Burp
- **Export OpenAPI** : Spec YAML

Tous les exports sont automatiquement sauvegardés localement + cloud.

### Désactiver Temporairement

**Settings → Cloud Sync → Toggle "Auto-sync" : OFF**

Les fichiers seront uniquement sauvegardés localement (Downloads).

---

## 🔐 Sécurité

### Tokens OAuth

**Stockage** :
- localStorage : `pentesthar_cloud_tokens`
- **Encodage** : Base64 (obfuscation simple)
- **Expiration** : Refresh automatique avant expiration

⚠️ **Recommandation** : Ne pas partager le localStorage de votre navigateur

### Permissions Google Drive

**Scope minimal** : `https://www.googleapis.com/auth/drive.file`

**Signification** :
- ✅ Accès uniquement aux fichiers **créés par PentestHAR**
- ❌ **PAS** d'accès aux autres fichiers de votre Drive
- ❌ **PAS** d'accès aux fichiers partagés par d'autres

### Révocation d'Accès

**Méthode 1 : Dans PentestHAR**
```
Settings → Cloud Sync → "🗑️ Révoquer Accès"
```

**Méthode 2 : Dans Google Account**
1. Aller sur : https://myaccount.google.com/permissions
2. Trouver "PentestHAR"
3. Cliquer "Remove access"

**Effet** :
- Tokens supprimés
- PentestHAR ne peut plus uploader
- Fichiers existants sur Drive **non supprimés**

---

## 📊 Agrégation Organisationnelle

### Cas d'Usage

**Équipe RedTeam** : 3 pentesteurs avec PentestHAR

**Configuration** :
- Tous configurés avec le **même compte Google Drive**
- Chaque machine a un **Machine ID unique**

**Résultat** :
```
Google Drive/PentestHAR/
  app1.company.com/
    app1_2024-01-15_143052_machineA.har  ← Pentesteur A
    app1_2024-01-15_150234_machineB.har  ← Pentesteur B
  app2.company.com/
    app2_2024-01-16_091523_machineC.har  ← Pentesteur C
  app3.company.com/
    app3_2024-01-17_103045_machineA.har  ← Pentesteur A
```

**Analyse Centralisée** :
- Tous les audits dans un seul Drive
- Filtrage par domaine
- Traçabilité par Machine ID
- Chronologie complète

### Script d'Agrégation (Python)

```python
import os
import json
from pathlib import Path

# Télécharger tous les fichiers du Drive
drive_folder = Path("~/Google Drive/PentestHAR")

# Agréger par domaine
domains = {}
for domain_folder in drive_folder.iterdir():
    if domain_folder.is_dir():
        domain = domain_folder.name
        files = list(domain_folder.glob("*.har"))

        domains[domain] = {
            "count": len(files),
            "files": [f.name for f in files],
            "machines": set([f.name.split('_')[-1].split('.')[0] for f in files])
        }

# Rapport
print(f"📊 Rapport Agrégé : {len(domains)} domaines")
for domain, data in domains.items():
    print(f"  {domain}: {data['count']} audits, {len(data['machines'])} machines")
```

---

## 🛠️ Troubleshooting

### Erreur "Client ID non configuré"

**Cause** : Client ID Google manquant

**Solution** :
1. Vérifier que le Client ID est bien copié depuis Google Cloud Console
2. Settings → Cloud Sync → Coller le Client ID
3. Sauvegarder

---

### Erreur "Échec authentification"

**Cause** : Redirect URI incorrect dans Google Cloud Console

**Solution** :
1. Vérifier l'Extension ID : `about:debugging`
2. Vérifier le Redirect URI dans Google Cloud Console
3. Format correct : `https://{EXTENSION_ID}.extensions.allizom.org/`

---

### Erreur "Token expiré"

**Cause** : Access token expiré (normal après 1h)

**Solution** : Automatique, PentestHAR refresh le token
- Si échec : "🔐 Reconnecter" dans Settings

---

### Fichiers non uploadés

**Causes possibles** :
1. Auto-sync désactivé
2. Non authentifié
3. Quota Drive dépassé
4. Connexion internet coupée

**Vérification** :
```
Settings → Cloud Sync → Statut
```

**Solution** :
- Vérifier toggle "Auto-sync" : ON
- Vérifier statut : "✅ Connecté"
- Vérifier quota Drive
- Tester connexion internet

---

### Supprimer Machine ID

**Cas d'usage** : Réinitialiser pour nouvelle machine

**Solution** :
```javascript
// Dans la console DevTools
localStorage.removeItem('pentesthar_machine_id');
// Recharger l'extension
```

**Nouveau Machine ID** : Généré automatiquement au prochain démarrage

---

## 📚 Ressources

### Google Cloud Console
- **Console** : https://console.cloud.google.com/
- **OAuth Consent** : https://console.cloud.google.com/apis/credentials/consent
- **Credentials** : https://console.cloud.google.com/apis/credentials

### Google Drive API
- **Documentation** : https://developers.google.com/drive/api/guides/about-sdk
- **Scopes** : https://developers.google.com/drive/api/guides/api-specific-auth

### Permissions Google
- **Gérer les apps** : https://myaccount.google.com/permissions

---

## 🎯 Prochaines Étapes (Roadmap)

**Phase 2 : Providers Additionnels**
- [ ] Dropbox
- [ ] OneDrive
- [ ] AWS S3
- [ ] Self-hosted (WebDAV)

**Phase 3 : Fonctionnalités Avancées**
- [ ] Compression automatique (gzip)
- [ ] Chiffrement end-to-end
- [ ] Sync bidirectionnelle (download depuis cloud)
- [ ] Webhooks (notifications Slack/Teams)

**Phase 4 : Analytics**
- [ ] Dashboard d'agrégation web
- [ ] Statistiques multi-machines
- [ ] Timeline d'audits
- [ ] Alertes automatiques (nouvelles vulns)

---

## 📞 Support

**Problème avec Cloud Sync ?**
- Issues GitHub : https://github.com/venantvr-security/firefox-autohar-extension/issues
- Tag : `cloud-sync`

---

**Version** : PentestHAR v2.2.0
**Auteur** : venantvr-security
**License** : MIT

*Créé pour centraliser les audits de sécurité organisationnels* 🔒
