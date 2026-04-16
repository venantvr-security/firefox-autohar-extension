#!/bin/bash
# Script d'installation automatique PentestHAR
# ============================================

set -e  # Arrêt en cas d'erreur

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  PentestHAR - Installation Automatique${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo ""

# Vérifier que .env existe
if [ ! -f .env ]; then
    echo -e "${RED}❌ Erreur: Fichier .env manquant${NC}"
    echo ""
    echo "Créez d'abord votre fichier .env :"
    echo "  1. cp .env.example .env"
    echo "  2. Éditez .env avec vos clés API Mozilla"
    echo "  3. Relancez ce script"
    echo ""
    echo "Obtenir des clés API : https://addons.mozilla.org/developers/addon/api/key/"
    exit 1
fi

# Charger les variables
echo -e "${YELLOW}🔐 Chargement des clés API...${NC}"
source .env

# Vérifier que les clés sont configurées
if [ -z "$WEB_EXT_API_KEY" ] || [ -z "$WEB_EXT_API_SECRET" ]; then
    echo -e "${RED}❌ Erreur: Clés API non configurées dans .env${NC}"
    echo ""
    echo "Éditez le fichier .env et ajoutez :"
    echo "  export WEB_EXT_API_KEY='votre_clé'"
    echo "  export WEB_EXT_API_SECRET='votre_secret'"
    echo ""
    exit 1
fi

echo -e "${GREEN}✓ Clés API détectées${NC}"
echo ""

# Vérifier la configuration
echo -e "${YELLOW}🔍 Vérification de la configuration...${NC}"
make sign-info | grep -q "✓ Configurée" || {
    echo -e "${RED}❌ Configuration invalide${NC}"
    exit 1
}
echo -e "${GREEN}✓ Configuration OK${NC}"
echo ""

# Lancer les tests
echo -e "${YELLOW}🧪 Exécution des tests...${NC}"
if make test > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Tests OK${NC}"
else
    echo -e "${RED}❌ Tests échoués${NC}"
    echo "Voulez-vous continuer quand même ? (y/N)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi
echo ""

# Signer l'extension
echo -e "${YELLOW}📦 Signature de l'extension...${NC}"
echo -e "${YELLOW}   (Cela peut prendre 30 secondes)${NC}"
echo ""

if make release-signed; then
    echo ""
    echo -e "${GREEN}✅ Extension signée avec succès !${NC}"
else
    echo -e "${RED}❌ Échec de la signature${NC}"
    exit 1
fi

# Trouver le fichier .xpi
XPI_FILE=$(ls -t web-ext-artifacts/*.xpi 2>/dev/null | head -1)

if [ -z "$XPI_FILE" ]; then
    echo -e "${RED}❌ Fichier .xpi non trouvé${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}📄 Fichier créé : ${XPI_FILE}${NC}"
echo ""

# Proposer l'installation
echo -e "${YELLOW}🚀 Installation de l'extension...${NC}"
echo ""
echo "Options :"
echo "  1) Ouvrir avec Firefox (installation automatique)"
echo "  2) Afficher le chemin uniquement (installation manuelle)"
echo "  3) Annuler"
echo ""
read -p "Votre choix (1-3) : " choice

case $choice in
    1)
        echo ""
        echo -e "${GREEN}📂 Ouverture de Firefox...${NC}"
        if command -v firefox &> /dev/null; then
            firefox "$XPI_FILE" &
            echo -e "${GREEN}✓ Firefox lancé${NC}"
            echo ""
            echo -e "${YELLOW}Instructions :${NC}"
            echo "  1. Cliquer 'Add' dans la popup Firefox"
            echo "  2. Aller sur about:addons pour vérifier"
            echo "  3. Redémarrer Firefox pour tester la persistance"
        else
            echo -e "${RED}❌ Firefox non trouvé dans le PATH${NC}"
            echo "Chemin du fichier : $XPI_FILE"
        fi
        ;;
    2)
        echo ""
        echo -e "${GREEN}📂 Chemin du fichier :${NC}"
        echo "$XPI_FILE"
        echo ""
        echo -e "${YELLOW}Installation manuelle :${NC}"
        echo "  1. Ouvrir Firefox"
        echo "  2. Aller sur about:addons"
        echo "  3. Icône ⚙️ → Install Add-on From File..."
        echo "  4. Sélectionner : $XPI_FILE"
        ;;
    3)
        echo ""
        echo -e "${YELLOW}Installation annulée${NC}"
        echo "Fichier disponible : $XPI_FILE"
        exit 0
        ;;
    *)
        echo ""
        echo -e "${RED}Choix invalide${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Processus Terminé !${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Prochaines étapes :${NC}"
echo "  1. Vérifier l'installation dans about:addons"
echo "  2. Redémarrer Firefox : pkill firefox && firefox"
echo "  3. Confirmer que l'extension est toujours présente"
echo ""
echo -e "${YELLOW}Support :${NC}"
echo "  - Documentation : docs/GUIDE_SIGNATURE_LOCALE.md"
echo "  - Aide : make help"
echo ""
