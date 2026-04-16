# 🔐 Guide de Signature Locale - Installation Permanente

**Objectif** : Signer l'extension pour installation permanente dans Firefox

**Temps requis** : ~10 minutes
**Coût** : Gratuit

---

## ✅ Étape 1 : Créer un Compte Mozilla

1. **Aller sur** : https://addons.mozilla.org
2. **Cliquer** : "Log in" (en haut à droite)
3. **S'inscrire** avec :
   - Email
   - Mot de passe
   - OU utiliser Firefox Account existant

**✓ Résultat** : Compte créé et connecté

---

## 🔑 Étape 2 : Générer les Clés API

1. **Aller sur** : https://addons.mozilla.org/developers/addon/api/key/

2. **Vous verrez** :
   ```
   API Credentials

   Generate new credentials

   Your API credentials allow you to interact with the
   Add-ons website programmatically.
   ```

3. **Cliquer** : "Generate new credentials"

4. **Remplir le formulaire** :
   - **Name** : `PentestHAR Local Signing`
   - **Notes** : `Signature locale pour développement`
   - Cliquer "Generate credentials"

5. **IMPORTANT** : Copier immédiatement les clés affichées

**Vous obtiendrez 2 clés** :

```
JWT issuer (API Key):
user:12345678:901

JWT secret (API Secret):
1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd
```

⚠️ **ATTENTION** : Le secret ne sera affiché qu'UNE SEULE FOIS !
Copiez-le immédiatement dans un endroit sûr.

---

## 💾 Étape 3 : Configurer les Variables d'Environnement

### Option A : Fichier .env (Recommandé)

```bash
# Copier le template
cp .env.example .env

# Éditer le fichier
nano .env
```

**Contenu du fichier .env** :
```bash
# Remplacez par VOS vraies clés
export WEB_EXT_API_KEY='user:12345678:901'
export WEB_EXT_API_SECRET='1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd'
```

**Sauvegarder** : `Ctrl+O` puis `Ctrl+X`

### Option B : Export Direct (Temporaire)

```bash
# Dans le terminal
export WEB_EXT_API_KEY='user:12345678:901'
export WEB_EXT_API_SECRET='votre_secret_ici'
```

⚠️ **Note** : Ces variables seront perdues à la fermeture du terminal

---

## 🧪 Étape 4 : Vérifier la Configuration

```bash
# Charger les variables (si .env)
source .env

# Vérifier
make sign-info
```

**Résultat attendu** :
```
Variables d'environnement actuelles :
  WEB_EXT_API_KEY    : ✓ Configurée
  WEB_EXT_API_SECRET : ✓ Configurée
```

Si vous voyez ✗ au lieu de ✓, recommencez l'étape 3.

---

## 🚀 Étape 5 : Signer l'Extension

```bash
make release-signed
```

**Ce que fait cette commande** :
1. ✅ Nettoie les anciens builds
2. ✅ Vérifie le code (lint)
3. ✅ Exécute les tests
4. ✅ Valide le manifest.json
5. ✅ Build l'extension
6. ✅ Envoie à Mozilla pour signature
7. ✅ Télécharge le .xpi signé

**Durée** : ~30 secondes

**Résultat attendu** :
```
🔑 Clés API détectées, signature en cours...
Your add-on has been submitted for signing.
Downloaded signed files:
  pentesthar-2.1.0.xpi

✅ Extension signée : web-ext-artifacts/pentesthar-2.1.0.xpi
```

---

## 📦 Étape 6 : Installer l'Extension Signée

### Méthode 1 : Double-clic (Plus Simple)

```bash
# Ouvrir l'explorateur de fichiers
xdg-open web-ext-artifacts/

# Double-cliquer sur le fichier .xpi
# Firefox s'ouvrira automatiquement
```

### Méthode 2 : Depuis Firefox

1. **Ouvrir Firefox**

2. **Aller sur** : `about:addons`

3. **Cliquer** sur l'icône ⚙️ (Settings) en haut à droite

4. **Sélectionner** : "Install Add-on From File..."

5. **Naviguer vers** : `web-ext-artifacts/pentesthar-2.1.0.xpi`

6. **Cliquer** : "Open"

7. **Confirmer** : "Add" dans la popup

### Méthode 3 : Ligne de commande

```bash
# Ouvrir directement avec Firefox
firefox web-ext-artifacts/pentesthar-2.1.0.xpi
```

**✓ Résultat** : Extension installée et active !

---

## ✅ Étape 7 : Vérifier l'Installation Permanente

### Test 1 : Vérifier l'extension

1. Aller sur `about:addons`
2. Chercher "PentestHAR"
3. **Vérifier** : Aucune mention "temporaire"

### Test 2 : Redémarrer Firefox

```bash
# Fermer complètement Firefox
pkill firefox

# Attendre 2 secondes

# Relancer
firefox
```

**Aller sur** : `about:addons`

**✓ L'extension doit toujours être présente !**

### Test 3 : Utiliser l'extension

1. **Ouvrir DevTools** : `F12`
2. **Onglet** : "PentestHAR"
3. **Cliquer** : "Start Capture"
4. **Naviguer** sur un site
5. **Vérifier** : Requêtes capturées

---

## 🔄 Mettre à Jour l'Extension

Quand vous modifiez le code :

```bash
# 1. Incrémenter la version dans manifest.json
nano manifest.json
# version: "2.0.0" → "2.1.0"

# 2. Charger les clés API
source .env

# 3. Re-signer
make release-signed

# 4. Firefox détectera automatiquement la mise à jour
# OU désinstaller l'ancienne et réinstaller la nouvelle
```

---

## 🔧 Troubleshooting

### Erreur : "Missing API key"

**Problème** : Variables d'environnement non chargées

**Solution** :
```bash
source .env
make sign-info  # Vérifier
make release-signed
```

---

### Erreur : "Authentication failed"

**Problème** : Clés API incorrectes

**Solution** :
1. Vérifier les clés sur https://addons.mozilla.org/developers/addon/api/key/
2. Régénérer si nécessaire
3. Mettre à jour `.env`
4. Recommencer

---

### Erreur : "Validation failed"

**Problème** : Code ou manifest invalide

**Solution** :
```bash
# Vérifier le code
make lint

# Vérifier le manifest
make validate-manifest

# Corriger les erreurs puis re-signer
make release-signed
```

---

### Extension Disparaît au Redémarrage

**Problème** : Extension non signée ou mal installée

**Solution** :
1. Vérifier que le fichier est un `.xpi` (pas `.zip`)
2. Vérifier que la signature a réussi (voir logs)
3. Réinstaller depuis le `.xpi` signé

---

## 📊 Comparaison : Temporaire vs Permanente

| Critère | Extension Temporaire | Extension Signée |
|---------|---------------------|------------------|
| **Commande** | `make run` | `make release-signed` + install |
| **Fichier** | `.zip` | `.xpi` signé |
| **Redémarrage** | ❌ Disparaît | ✅ Persiste |
| **about:addons** | "Temporaire" | Extension normale |
| **Mises à jour** | Manuelle | Détection auto |
| **Usage** | Dev/test | Production perso |

---

## 🎯 Récapitulatif Rapide

```bash
# 1. Créer compte : https://addons.mozilla.org
# 2. Générer clés : https://addons.mozilla.org/developers/addon/api/key/
# 3. Configurer
cp .env.example .env
nano .env  # Coller vos clés
source .env

# 4. Signer
make release-signed

# 5. Installer
firefox web-ext-artifacts/pentesthar-*.xpi

# 6. Tester redémarrage
pkill firefox
firefox
# ✅ Extension toujours là !
```

---

## 📚 Liens Utiles

- **Clés API** : https://addons.mozilla.org/developers/addon/api/key/
- **Doc Signature** : https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/
- **API Mozilla** : https://addons-server.readthedocs.io/en/latest/topics/api/signing.html

---

**Auteur** : venantvr-security
**Support** : Si problème, ouvrir une issue GitHub
