# 🦊 Installation Permanente Firefox - PentestHAR

> **Guide rapide** pour installer PentestHAR de manière permanente (survit aux redémarrages)

---

## 🎯 Objectif

Installer l'extension avec **signature locale Mozilla** pour :
- ✅ Installation permanente (pas temporaire)
- ✅ Survit aux redémarrages de Firefox
- ✅ Pas de distribution publique nécessaire
- ✅ Contrôle total sur les versions

---

## ⚡ Installation Rapide (5 minutes)

### 1️⃣ Créer Compte Mozilla

**URL** : https://addons.mozilla.org
- Cliquer "Log in" → "Register"
- Utiliser email ou Firefox Account

### 2️⃣ Générer Clés API

**URL** : https://addons.mozilla.org/developers/addon/api/key/

- Cliquer "Generate new credentials"
- **Name** : `PentestHAR Local Signing`
- Copier les 2 clés affichées :

```
API Key:     user:12345678:901
API Secret:  abcd1234...très longue chaîne...
```

⚠️ **Le secret ne s'affiche qu'UNE FOIS** - Copiez-le immédiatement !

### 3️⃣ Configurer le Projet

```bash
# Créer le fichier de configuration
cp .env.example .env

# Éditer avec vos vraies clés
nano .env
```

**Contenu de `.env`** :
```bash
export WEB_EXT_API_KEY='user:12345678:901'
export WEB_EXT_API_SECRET='votre_secret_très_long_ici'
```

Sauvegarder : `Ctrl+O` puis `Ctrl+X`

### 4️⃣ Charger les Variables

```bash
source .env
```

### 5️⃣ Vérifier la Configuration

```bash
make sign-info
```

**Résultat attendu** :
```
✓ WEB_EXT_API_KEY    : Configurée
✓ WEB_EXT_API_SECRET : Configurée
```

Si vous voyez `✗ Non configurée`, recommencez l'étape 3-4.

### 6️⃣ Signer l'Extension

```bash
make release-signed
```

**Durée** : ~30 secondes

**Résultat** : Fichier `web-ext-artifacts/pentesthar-X.X.X.xpi` créé et signé

### 7️⃣ Installer dans Firefox

**Méthode 1 (Recommandée)** :
```bash
firefox web-ext-artifacts/pentesthar-*.xpi
```

**Méthode 2** :
1. Ouvrir Firefox
2. Aller sur `about:addons`
3. Icône ⚙️ → "Install Add-on From File..."
4. Sélectionner le fichier `.xpi`
5. Confirmer "Add"

### 8️⃣ Vérifier l'Installation Permanente

```bash
# Redémarrer Firefox
pkill firefox
firefox

# Aller sur about:addons
# ✅ PentestHAR doit toujours être présent !
```

---

## 🔄 Workflow Complet

```bash
# Première fois seulement
cp .env.example .env
nano .env  # Coller vos clés API

# À chaque build
source .env
make release-signed
firefox web-ext-artifacts/pentesthar-*.xpi
```

---

## 📊 Comparaison des Méthodes

| Méthode | Commande | Persiste ? | Usage |
|---------|----------|------------|-------|
| **Temporaire** | `make run` | ❌ Non | Dev/test |
| **Signée locale** | `make release-signed` | ✅ Oui | Prod perso |
| **AMO publique** | Soumission manuelle | ✅ Oui | Grand public |

---

## 🛠️ Commandes Utiles

```bash
# Aide complète
make help

# Info sur la signature
make sign-info

# Build non signé (temporaire)
make build

# Build signé (permanent)
make release-signed

# Tests avant signature
make check

# Version actuelle
make version
```

---

## 🔧 Dépannage

### ❌ "Missing API key"

**Solution** :
```bash
source .env
make sign-info
```

### ❌ "Authentication failed"

**Solution** : Régénérer les clés sur https://addons.mozilla.org/developers/addon/api/key/

### ❌ Extension disparaît au redémarrage

**Causes possibles** :
1. Extension non signée (fichier `.zip` au lieu de `.xpi`)
2. Installation temporaire via `make run`

**Solution** : Réinstaller depuis le `.xpi` signé

### ❌ "Validation failed"

**Solution** :
```bash
make lint
make validate-manifest
# Corriger les erreurs puis :
make release-signed
```

---

## 📚 Documentation Complète

- **Guide détaillé** : [`docs/GUIDE_SIGNATURE_LOCALE.md`](docs/GUIDE_SIGNATURE_LOCALE.md)
- **Build et Release** : [`docs/BUILD_AND_RELEASE.md`](docs/BUILD_AND_RELEASE.md)
- **Makefile** : [`Makefile`](Makefile) - Toutes les commandes

---

## 🔐 Sécurité

⚠️ **IMPORTANT** : Le fichier `.env` contient vos clés secrètes

- ✅ `.env` est dans `.gitignore` (pas commité)
- ✅ Ne partagez JAMAIS vos clés API
- ✅ Régénérez les clés si compromises

---

## 💡 Astuce : Script d'Installation

Créez un script `sign-and-install.sh` :

```bash
#!/bin/bash
set -e

echo "🔐 Chargement des clés API..."
source .env

echo "📦 Signature de l'extension..."
make release-signed

echo "🚀 Installation dans Firefox..."
firefox web-ext-artifacts/pentesthar-*.xpi

echo "✅ Terminé ! Redémarrez Firefox pour tester la persistance."
```

Utilisation :
```bash
chmod +x sign-and-install.sh
./sign-and-install.sh
```

---

## 🎓 Pour Aller Plus Loin

### Automatiser les Mises à Jour

```bash
# 1. Modifier le code
# 2. Incrémenter version dans manifest.json
# 3. Re-signer
source .env && make release-signed

# 4. Firefox détectera la mise à jour automatiquement
# OU désinstaller/réinstaller manuellement
```

### Distribution Privée

Le fichier `.xpi` signé peut être :
- Partagé par email
- Hébergé sur un serveur interne
- Distribué à une équipe de pentest
- Installé sur plusieurs machines

Chaque installation sera **permanente** et **survira aux redémarrages**.

---

## 📞 Support

**Problème avec la signature ?**
- Consulter : [`docs/GUIDE_SIGNATURE_LOCALE.md`](docs/GUIDE_SIGNATURE_LOCALE.md)
- Issues GitHub : https://github.com/venantvr-security/firefox-autohar-extension/issues
- Documentation Mozilla : https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/

---

**Version** : PentestHAR v2.1.0
**Auteur** : venantvr-security
**License** : MIT

---

## ✅ Checklist d'Installation

- [ ] Compte Mozilla créé
- [ ] Clés API générées
- [ ] Fichier `.env` créé avec les clés
- [ ] Variables chargées (`source .env`)
- [ ] Configuration vérifiée (`make sign-info`)
- [ ] Extension signée (`make release-signed`)
- [ ] Fichier `.xpi` installé dans Firefox
- [ ] Redémarrage Firefox testé
- [ ] Extension toujours présente dans `about:addons`

**Tout coché ?** Vous avez une installation permanente ! 🎉
