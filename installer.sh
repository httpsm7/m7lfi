#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# m7lfi Installer
# Milkyway Intelligence | Author: Sharlix
# Authorized lab testing / bug bounty use only
# ─────────────────────────────────────────────────────────────────

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo "    __  __ _____ _     _____ ___ "
echo "   |  \/  |___  | |   |  ___|_ _|"
echo "   | |\/| |  / /| |   | |_   | | "
echo "   | |  | | / / | |___|  _|  | | "
echo "   |_|  |_|/_/  |_____|_|   |___|"
echo ""
echo "   ⚡ LFI Testing Framework v1.0"
echo "   🛸 Milkyway Intelligence | Sharlix"
echo -e "${NC}"

# ── Determine install location ──────────────────────────────────
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo -e "${YELLOW}[*] Install directory: ${INSTALL_DIR}${NC}"

# ── Check Python 3.11+ ──────────────────────────────────────────
echo -e "${YELLOW}[*] Checking Python version...${NC}"
PYTHON_BIN=""
for py in python3.11 python3.12 python3.13 python3; do
    if command -v "$py" &>/dev/null; then
        VERSION=$($py -c "import sys; print(sys.version_info[:2])")
        if $py -c "import sys; assert sys.version_info >= (3,11)" 2>/dev/null; then
            PYTHON_BIN="$py"
            echo -e "${GREEN}[+] Found: $py ($VERSION)${NC}"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[!] Python 3.11+ not found. Install it first.${NC}"
    exit 1
fi

# ── Install pip dependencies ─────────────────────────────────────
echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
$PYTHON_BIN -m pip install --upgrade pip --quiet

DEPS=(
    "httpx[http2]>=0.25.0"
    "pyyaml>=6.0"
)

for dep in "${DEPS[@]}"; do
    echo -e "    Installing: ${dep}"
    $PYTHON_BIN -m pip install "$dep" --quiet
done

echo -e "${GREEN}[+] Dependencies installed.${NC}"

# ── Create output directories ────────────────────────────────────
mkdir -p "${INSTALL_DIR}/output/reports"
mkdir -p "${INSTALL_DIR}/output/logs"
echo -e "${GREEN}[+] Output directories created.${NC}"

# ── Create wrapper script ────────────────────────────────────────
WRAPPER="/usr/local/bin/m7lfi"

echo -e "${YELLOW}[*] Creating executable wrapper at ${WRAPPER}...${NC}"

cat > /tmp/m7lfi_wrapper << EOF
#!/usr/bin/env bash
cd "${INSTALL_DIR}"
exec ${PYTHON_BIN} "${INSTALL_DIR}/cli/main.py" "\$@"
EOF

# Try to install system-wide, fall back to ~/.local/bin
if sudo cp /tmp/m7lfi_wrapper "$WRAPPER" 2>/dev/null && sudo chmod +x "$WRAPPER"; then
    echo -e "${GREEN}[+] Installed at ${WRAPPER}${NC}"
else
    LOCAL_BIN="${HOME}/.local/bin"
    mkdir -p "$LOCAL_BIN"
    cp /tmp/m7lfi_wrapper "${LOCAL_BIN}/m7lfi"
    chmod +x "${LOCAL_BIN}/m7lfi"
    echo -e "${YELLOW}[~] Installed at ${LOCAL_BIN}/m7lfi (add to PATH if needed)${NC}"
    echo -e "    Add to ~/.bashrc or ~/.zshrc: export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

rm -f /tmp/m7lfi_wrapper

# ── Verify ───────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   m7lfi installed successfully! ⚡        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Usage examples:"
echo -e "  ${YELLOW}m7lfi -u \"https://target.com/page.php?file=test\"${NC}"
echo -e "  ${YELLOW}m7lfi -l urls.txt --threads 100 --mode smart${NC}"
echo -e "  ${YELLOW}m7lfi -u \"https://target.com/?page=home\" --mode stealth --exploit${NC}"
echo -e "  ${YELLOW}m7lfi --manual${NC}"
echo ""
echo -e "  ${RED}⚠  For authorized lab testing and bug bounty research only.${NC}"
echo ""
