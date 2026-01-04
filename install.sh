#!/usr/bin/env bash
# install.sh – CrackBox dependency checker and installer
# Verifies all required tools are present; offers to install missing ones.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

REQUIRED_APT=(hashcat john hydra hash-identifier)
REQUIRED_PIP=(netexec)
MISSING_APT=()
MISSING_PIP=()

echo ""
echo "  CrackBox – Dependency Installer"
echo "  ================================"
echo ""

# --- Check Python version ---
PYTHON_VERSION=$(python3 -c 'import sys; print(sys.version_info[:2] >= (3, 8))')
if [[ "$PYTHON_VERSION" != "True" ]]; then
    echo -e "${RED}[✗] Python 3.8+ is required. Please upgrade Python.${NC}"
    exit 1
else
    echo -e "${GREEN}[✓] Python version OK${NC}"
fi

# --- Check apt-installed tools ---
for tool in "${REQUIRED_APT[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "${GREEN}[✓] $tool found${NC}"
    else
        echo -e "${YELLOW}[!] $tool not found${NC}"
        MISSING_APT+=("$tool")
    fi
done

# --- Check pip-installed tools ---
for tool in "${REQUIRED_PIP[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "${GREEN}[✓] $tool found${NC}"
    else
        echo -e "${YELLOW}[!] $tool not found${NC}"
        MISSING_PIP+=("$tool")
    fi
done

# --- Nothing missing ---
if [[ ${#MISSING_APT[@]} -eq 0 && ${#MISSING_PIP[@]} -eq 0 ]]; then
    echo ""
    echo -e "${GREEN}[✓] All dependencies satisfied. Run with: python3 crackbox.py${NC}"
    echo ""
    exit 0
fi

# --- Offer to install ---
echo ""
echo -e "${YELLOW}[!] Missing tools: ${MISSING_APT[*]:-} ${MISSING_PIP[*]:-}${NC}"
read -rp "    Install missing tools now? (Y/n): " answer
answer="${answer:-Y}"

if [[ "$answer" =~ ^[Yy]$ ]]; then

    if [[ ${#MISSING_APT[@]} -gt 0 ]]; then
        echo ""
        echo "[*] Installing via apt: ${MISSING_APT[*]}"
        sudo apt-get update -qq
        sudo apt-get install -y "${MISSING_APT[@]}"
    fi

    if [[ ${#MISSING_PIP[@]} -gt 0 ]]; then
        echo ""
        echo "[*] Installing via pip: ${MISSING_PIP[*]}"
        pip install --upgrade "${MISSING_PIP[@]}"
    fi

    echo ""
    echo -e "${GREEN}[✓] Installation complete. Run with: python3 crackbox.py${NC}"
    echo ""

else
    echo ""
    echo "    Skipped. Install the missing tools manually and re-run."
    echo ""
    exit 1
fi
