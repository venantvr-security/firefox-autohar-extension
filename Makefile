# Makefile pour PentestHAR Extension Firefox
# ==================================================

# Variables
EXTENSION_NAME = pentesthar
VERSION = $(shell grep '"version"' manifest.json | head -1 | sed 's/.*"\(.*\)".*/\1/')
BUILD_DIR = web-ext-artifacts
FIREFOX_PROFILE = /tmp/pentesthar-profile
FIREFOX_BIN = firefox

# Couleurs pour les messages
GREEN = \033[0;32m
YELLOW = \033[0;33m
RED = \033[0;31m
NC = \033[0m # No Color

# ==================================================
# Commandes Principales
# ==================================================

.PHONY: help
help: ## Affiche l'aide
	@echo "$(GREEN)═══════════════════════════════════════════════$(NC)"
	@echo "$(GREEN)  PentestHAR - Makefile Commands$(NC)"
	@echo "$(GREEN)═══════════════════════════════════════════════$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(GREEN)═══════════════════════════════════════════════$(NC)"

.PHONY: install
install: ## Installe web-ext (nécessite npm)
	@echo "$(GREEN)📦 Installation de web-ext...$(NC)"
	npm install --global web-ext

.PHONY: test
test: ## Exécute les tests unitaires
	@echo "$(GREEN)🧪 Exécution des tests...$(NC)"
	node tests/test-modules.js

.PHONY: lint
lint: ## Vérifie la conformité du code
	@echo "$(GREEN)🔍 Linting du code...$(NC)"
	web-ext lint

.PHONY: run
run: ## Lance l'extension en mode développement
	@echo "$(GREEN)🚀 Lancement de Firefox avec l'extension...$(NC)"
	web-ext run \
		--firefox=$(FIREFOX_BIN) \
		--browser-console \
		--devtools \
		--start-url="about:debugging#/runtime/this-firefox" \
		--keep-profile-changes \
		--profile-create-if-missing

.PHONY: run-clean
run-clean: ## Lance avec un profil propre
	@echo "$(GREEN)🧹 Lancement avec profil propre...$(NC)"
	rm -rf $(FIREFOX_PROFILE)
	web-ext run \
		--firefox=$(FIREFOX_BIN) \
		--profile=$(FIREFOX_PROFILE) \
		--browser-console \
		--devtools

# ==================================================
# Build & Packaging
# ==================================================

.PHONY: clean
clean: ## Nettoie les fichiers de build
	@echo "$(YELLOW)🧹 Nettoyage...$(NC)"
	rm -rf $(BUILD_DIR)
	rm -f $(EXTENSION_NAME)-*.zip
	rm -f $(EXTENSION_NAME)-*.xpi

.PHONY: build
build: clean lint test ## Build l'extension (non signée)
	@echo "$(GREEN)📦 Build de l'extension v$(VERSION)...$(NC)"
	web-ext build \
		--overwrite-dest \
		--artifacts-dir=$(BUILD_DIR)
	@echo "$(GREEN)✅ Build terminé : $(BUILD_DIR)/$(shell ls -t $(BUILD_DIR) | head -1)$(NC)"
	@ls -lh $(BUILD_DIR)

.PHONY: package
package: build ## Crée le package ZIP (alias de build)
	@echo "$(GREEN)✅ Package créé$(NC)"

# ==================================================
# Signature (Nécessite Configuration)
# ==================================================

.PHONY: sign
sign: ## Signe l'extension avec les clés API Mozilla (nécessite configuration)
	@echo "$(YELLOW)⚠️  Signature de l'extension...$(NC)"
	@echo ""
	@if [ -z "$$WEB_EXT_API_KEY" ] || [ -z "$$WEB_EXT_API_SECRET" ]; then \
		echo "$(RED)❌ ERREUR: Variables d'environnement manquantes$(NC)"; \
		echo ""; \
		echo "Configuration requise :"; \
		echo "  1. Créez un compte sur https://addons.mozilla.org"; \
		echo "  2. Générez des clés API : https://addons.mozilla.org/developers/addon/api/key/"; \
		echo "  3. Exportez les variables :"; \
		echo "     export WEB_EXT_API_KEY='votre_clé'"; \
		echo "     export WEB_EXT_API_SECRET='votre_secret'"; \
		echo ""; \
		echo "Puis relancez : make sign"; \
		exit 1; \
	fi
	@echo "$(GREEN)🔑 Clés API détectées, signature en cours...$(NC)"
	web-ext sign \
		--channel=unlisted \
		--artifacts-dir=$(BUILD_DIR) \
		--api-key=$$WEB_EXT_API_KEY \
		--api-secret=$$WEB_EXT_API_SECRET
	@echo "$(GREEN)✅ Extension signée : $(BUILD_DIR)/*.xpi$(NC)"

.PHONY: sign-info
sign-info: ## Affiche les instructions pour la signature
	@echo "$(GREEN)═══════════════════════════════════════════════$(NC)"
	@echo "$(GREEN)  Configuration de la Signature$(NC)"
	@echo "$(GREEN)═══════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(YELLOW)Options de Distribution :$(NC)"
	@echo ""
	@echo "1️⃣  $(GREEN)Développement Local (NON SIGNÉ)$(NC)"
	@echo "   └─ Commande : make run"
	@echo "   └─ Usage    : Tests en développement uniquement"
	@echo ""
	@echo "2️⃣  $(GREEN)Firefox Developer/Nightly (NON SIGNÉ)$(NC)"
	@echo "   └─ Configuration : about:config"
	@echo "   └─ Paramètre     : xpinstall.signatures.required = false"
	@echo "   └─ Installer     : about:debugging → Load Temporary Add-on"
	@echo ""
	@echo "3️⃣  $(GREEN)Auto-Distribution (SIGNÉ LOCALEMENT)$(NC)"
	@echo "   └─ Étapes :"
	@echo "      1. Compte AMO : https://addons.mozilla.org"
	@echo "      2. Clés API   : https://addons.mozilla.org/developers/addon/api/key/"
	@echo "      3. Variables  :"
	@echo "         export WEB_EXT_API_KEY='user:12345:67'"
	@echo "         export WEB_EXT_API_SECRET='abcdef123456...'"
	@echo "      4. Commande   : make sign"
	@echo ""
	@echo "4️⃣  $(GREEN)Distribution Publique (AMO)$(NC)"
	@echo "   └─ Build         : make build"
	@echo "   └─ Soumettre à   : https://addons.mozilla.org/developers/"
	@echo "   └─ Signature     : Automatique par Mozilla après review"
	@echo ""
	@echo "$(GREEN)═══════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(YELLOW)Variables d'environnement actuelles :$(NC)"
	@if [ -n "$$WEB_EXT_API_KEY" ]; then \
		echo "  WEB_EXT_API_KEY    : $(GREEN)✓ Configurée$(NC)"; \
	else \
		echo "  WEB_EXT_API_KEY    : $(RED)✗ Non configurée$(NC)"; \
	fi
	@if [ -n "$$WEB_EXT_API_SECRET" ]; then \
		echo "  WEB_EXT_API_SECRET : $(GREEN)✓ Configurée$(NC)"; \
	else \
		echo "  WEB_EXT_API_SECRET : $(RED)✗ Non configurée$(NC)"; \
	fi
	@echo ""

# ==================================================
# Développement
# ==================================================

.PHONY: watch
watch: ## Lance en mode watch (rechargement automatique)
	@echo "$(GREEN)👀 Mode watch activé...$(NC)"
	web-ext run \
		--firefox=$(FIREFOX_BIN) \
		--browser-console \
		--reload

.PHONY: dev
dev: test run ## Lance les tests puis l'extension (workflow dev)

.PHONY: check
check: lint test ## Vérifie le code (lint + tests)
	@echo "$(GREEN)✅ Vérifications OK$(NC)"

# ==================================================
# Utilitaires
# ==================================================

.PHONY: version
version: ## Affiche la version actuelle
	@echo "$(GREEN)PentestHAR v$(VERSION)$(NC)"

.PHONY: info
info: version ## Affiche les informations du projet
	@echo ""
	@echo "$(YELLOW)Informations :$(NC)"
	@echo "  Nom       : $(EXTENSION_NAME)"
	@echo "  Version   : $(VERSION)"
	@echo "  Build dir : $(BUILD_DIR)"
	@echo "  Firefox   : $(FIREFOX_BIN)"
	@echo ""
	@echo "$(YELLOW)Fichiers :$(NC)"
	@find . -type f -name "*.js" ! -path "./node_modules/*" ! -path "./$(BUILD_DIR)/*" | wc -l | xargs echo "  Fichiers JS    :"
	@find . -type f -name "*.html" ! -path "./node_modules/*" ! -path "./$(BUILD_DIR)/*" | wc -l | xargs echo "  Fichiers HTML  :"
	@find . -type f -name "*.css" ! -path "./node_modules/*" ! -path "./$(BUILD_DIR)/*" | wc -l | xargs echo "  Fichiers CSS   :"
	@echo ""

.PHONY: validate-manifest
validate-manifest: ## Valide le manifest.json
	@echo "$(GREEN)🔍 Validation du manifest.json...$(NC)"
	@node -e "JSON.parse(require('fs').readFileSync('manifest.json'))" && echo "$(GREEN)✅ Manifest valide$(NC)" || echo "$(RED)❌ Manifest invalide$(NC)"

# ==================================================
# Release
# ==================================================

.PHONY: release-check
release-check: clean lint test validate-manifest ## Vérifie avant release
	@echo "$(GREEN)✅ Prêt pour release v$(VERSION)$(NC)"

.PHONY: release-local
release-local: release-check build ## Crée une release locale (non signée)
	@echo "$(GREEN)📦 Release locale v$(VERSION) créée$(NC)"
	@echo "$(YELLOW)⚠️  Extension NON SIGNÉE - Utilisable uniquement en dev$(NC)"
	@echo ""
	@echo "Installation :"
	@echo "  1. Ouvrir Firefox"
	@echo "  2. Aller à about:debugging#/runtime/this-firefox"
	@echo "  3. 'Load Temporary Add-on'"
	@echo "  4. Sélectionner : $(BUILD_DIR)/*.zip"

.PHONY: release-signed
release-signed: release-check sign ## Crée une release signée
	@echo "$(GREEN)✅ Release signée v$(VERSION) créée$(NC)"
	@ls -lh $(BUILD_DIR)/*.xpi

# ==================================================
# Documentation
# ==================================================

.PHONY: docs
docs: ## Génère la documentation
	@echo "$(GREEN)📚 Documentation disponible :$(NC)"
	@echo "  - CLAUDE.md"
	@echo "  - docs/AI_EXPORT_OPTIMIZATION.md"
	@echo "  - docs/CHANGELOG_AI_OPTIMIZATION.md"

# ==================================================
# CI/CD Helper
# ==================================================

.PHONY: ci
ci: lint test build ## Pipeline CI complet
	@echo "$(GREEN)✅ Pipeline CI terminé$(NC)"

# Commande par défaut
.DEFAULT_GOAL := help
