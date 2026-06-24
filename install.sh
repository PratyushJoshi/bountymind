#!/usr/bin/env bash
# =============================================================================
# BountyMind — Automated Bootstrap Installer
# =============================================================================
# Usage:
#   git clone https://github.com/PratyushJoshi/bountymind.git
#   cd bountymind
#   chmod +x install.sh && sudo ./install.sh
#
# What this does:
#   1. Detects Kali / Ubuntu / Debian
#   2. Installs system packages (apt)
#   3. Installs / verifies Go
#   4. Installs all Go-based tools
#   5. Installs Python dependencies
#   6. Installs pip-based tools
#   7. Clones GitHub-only tools (SecretFinder, dirsearch)
#   8. Installs nuclei templates
#   9. Registers 'bountymind' as a global CLI command
#  10. Copies default config if not present
# =============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${CYAN}  $*${NC}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}\n"; }

# ── Sanity checks ─────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "This installer needs root. Run: sudo ./install.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

header "BountyMind Installer"
info "Script directory : $SCRIPT_DIR"
info "Installing for   : $REAL_USER ($REAL_HOME)"

# ── Detect distro ─────────────────────────────────────────────────────────────
DISTRO=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"' | tr '[:upper:]' '[:lower:]')
info "Detected distro  : $DISTRO"

# ── 1. System packages ────────────────────────────────────────────────────────
header "Step 1/9 — System Packages (apt)"

apt-get update -qq

APT_TOOLS=(
    git curl wget unzip python3 python3-pip python3-venv
    nmap ffuf amass whatweb wafw00f
    golang-go
)

# Kali has nuclei, httpx-toolkit, subfinder in apt; Ubuntu needs Go installs
if [[ "$DISTRO" == "kali" ]]; then
    APT_TOOLS+=(nuclei httpx-toolkit subfinder)
fi

for pkg in "${APT_TOOLS[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        info "  $pkg — already installed"
    else
        info "  Installing $pkg ..."
        apt-get install -y -qq "$pkg" && success "  $pkg installed" || warn "  $pkg failed (non-fatal)"
    fi
done

# seclists wordlists
if ! dpkg -s seclists &>/dev/null; then
    info "Installing seclists wordlists (this may take a moment)..."
    apt-get install -y -qq seclists || warn "seclists not available; using dirb fallback"
fi

# ── 2. Go environment ─────────────────────────────────────────────────────────
header "Step 2/9 — Go Environment"

GO_BIN="$REAL_HOME/go/bin"
export GOPATH="$REAL_HOME/go"
export PATH="$PATH:/usr/local/go/bin:$GO_BIN"

if command -v go &>/dev/null; then
    GO_VER=$(go version | awk '{print $3}')
    success "Go already installed: $GO_VER"
else
    warn "Go not found — attempting install from golang.org..."
    GO_ARCHIVE="go1.22.4.linux-amd64.tar.gz"
    wget -q "https://go.dev/dl/$GO_ARCHIVE" -O /tmp/$GO_ARCHIVE
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/$GO_ARCHIVE
    rm /tmp/$GO_ARCHIVE
    # Persist PATH for the real user
    PROFILE="$REAL_HOME/.bashrc"
    grep -qxF 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' "$PROFILE" || \
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$PROFILE"
    export PATH="$PATH:/usr/local/go/bin"
    success "Go installed: $(go version | awk '{print $3}')"
fi

mkdir -p "$GO_BIN"

# Helper: run go install as the real (non-root) user
go_install() {
    local module="$1"
    local binary
    binary=$(basename "${module%%@*}" | cut -d'/' -f1)
    if command -v "$binary" &>/dev/null || [[ -f "$GO_BIN/$binary" ]]; then
        info "  $binary — already installed"
        return
    fi
    info "  Installing $binary via go install ..."
    sudo -u "$REAL_USER" env GOPATH="$GOPATH" PATH="$PATH" \
        go install "$module" 2>/dev/null && success "  $binary installed" \
        || warn "  $binary failed (non-fatal)"
    # Symlink to /usr/local/bin for system-wide access
    if [[ -f "$GO_BIN/$binary" ]]; then
        ln -sf "$GO_BIN/$binary" "/usr/local/bin/$binary" 2>/dev/null || true
    fi
}

# ── 3. Go-based security tools ────────────────────────────────────────────────
header "Step 3/9 — Go Security Tools"

go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
go_install "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
go_install "github.com/lc/gau/v2/cmd/gau@latest"
go_install "github.com/tomnomnom/waybackurls@latest"
go_install "github.com/tomnomnom/httprobe@latest"
go_install "github.com/PentestPad/subzy@latest"
go_install "github.com/sensepost/gowitness@latest"
go_install "github.com/ffuf/ffuf/v2@latest"
go_install "github.com/owasp-amass/amass/v4/...@latest"

echo ""
echo "══════════════════════════════════════════"
echo "  Step 4/9 — Python Dependencies"
echo "══════════════════════════════════════════"

# ------------------------------------------------------------
# 1. Ensure pipx for the real user (Kali-safe)
# ------------------------------------------------------------
export PATH="$REAL_HOME/.local/bin:$PATH"

if ! command -v pipx &>/dev/null; then
    echo "[*] pipx not found – installing for $REAL_USER..."
    # Try to install pipx via pip in user mode (works on most systems)
    if sudo -u "$REAL_USER" env HOME="$REAL_HOME" PATH="$REAL_HOME/.local/bin:$PATH" \
        python3 -m pip install --user pipx &>/dev/null; then
        echo "[+] pipx installed (user mode)"
    else
        # Fallback to system package manager (apt / dnf)
        if command -v apt &>/dev/null; then
            sudo apt update -y && sudo apt install -y pipx
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y pipx
        else
            echo "[!] Could not install pipx automatically."
            echo "    Please install pipx manually: https://pipx.pypa.io/stable/installation/"
            exit 1
        fi
    fi
fi

# Make sure pipx-installed binaries are on PATH (for this session)
PIPX_BIN="$(command -v pipx || true)"
if [[ -z "$PIPX_BIN" && -x "$REAL_HOME/.local/bin/pipx" ]]; then
    PIPX_BIN="$REAL_HOME/.local/bin/pipx"
fi

if [[ -z "$PIPX_BIN" ]]; then
    echo "[!] pipx is still unavailable after installation attempt."
    exit 1
fi

sudo -u "$REAL_USER" env HOME="$REAL_HOME" PATH="$REAL_HOME/.local/bin:$PATH" \
    "$PIPX_BIN" ensurepath &>/dev/null || true

# ------------------------------------------------------------
# 2. Install all Python CLI tools via pipx
# ------------------------------------------------------------
PYTHON_TOOLS=(
    "cloud_enum"
    "s3scanner"
    "uro"
    "xnlinkfinder"
    "wafw00f"
    "arjun"
)

for tool in "${PYTHON_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo "[*]   $tool — already installed"
    else
        echo "[*]   Installing $tool via pipx ..."
        if sudo -u "$REAL_USER" env HOME="$REAL_HOME" PATH="$REAL_HOME/.local/bin:$PATH" \
            "$PIPX_BIN" install "$tool" --verbose 2>&1; then
            echo "[+]   $tool installed"
        else
            echo "[!]   $tool install failed (non-fatal)"
            continue
        fi
    fi

    tool_path="$REAL_HOME/.local/bin/$tool"
    if [[ -x "$tool_path" ]]; then
        ln -sf "$tool_path" "/usr/local/bin/$tool" 2>/dev/null || true
    fi
done

# ------------------------------------------------------------
# 3. SecretFinder – local venv (no system pip)
# ------------------------------------------------------------
mkdir -p "$SCRIPT_DIR/tools"
SF_DIR="$SCRIPT_DIR/tools/SecretFinder"
if [ ! -d "$SF_DIR" ]; then
    echo "[*] Cloning SecretFinder repository..."
    git clone https://github.com/m4ll0k/SecretFinder.git "$SF_DIR"
fi

if [ -f "$SF_DIR/SecretFinder.py" ]; then
    echo "[*] Creating local virtual environment..."
    python3 -m venv "$SF_DIR/venv"
    if "$SF_DIR/venv/bin/pip" install -q -r "$SF_DIR/requirements.txt"; then
        echo "[+] SecretFinder installed (venv)"
    else
        echo "[!] SecretFinder dependencies failed (non-fatal)"
    fi
else
    echo "[!] SecretFinder not available (non-fatal)"
fi

echo "[✓] Python dependencies ready"

# ── 5. Python security tool checks ────────────────────────────────────────────
header "Step 5/9 — Python Security Tool Checks"

for tool in "${PYTHON_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        success "  $tool available"
    else
        warn "  $tool not found on PATH (non-fatal)"
    fi
done

# ── 6. GitHub-cloned tools ────────────────────────────────────────────────────
header "Step 6/9 — GitHub Tools"

# SecretFinder
SF_DIR="$SCRIPT_DIR/tools/SecretFinder"
if [[ -f "$SF_DIR/SecretFinder.py" ]]; then
    success "SecretFinder ready"
else
    warn "SecretFinder missing (non-fatal)"
fi

# dirsearch
DIRSEARCH_DIR="/opt/dirsearch"
if [[ -d "$DIRSEARCH_DIR" ]]; then
    info "dirsearch — already present"
else
    info "Cloning dirsearch..."
    git clone -q https://github.com/maurosoria/dirsearch.git "$DIRSEARCH_DIR" \
        || warn "dirsearch clone failed (non-fatal)"
fi

if [[ -f "$DIRSEARCH_DIR/dirsearch.py" ]]; then
    python3 -m venv "$DIRSEARCH_DIR/venv"
    if "$DIRSEARCH_DIR/venv/bin/pip" install -q -r "$DIRSEARCH_DIR/requirements.txt"; then
        cat > /usr/local/bin/dirsearch << EOF
#!/usr/bin/env bash
exec "$DIRSEARCH_DIR/venv/bin/python" "$DIRSEARCH_DIR/dirsearch.py" "\$@"
EOF
        chmod +x /usr/local/bin/dirsearch
        success "dirsearch ready (venv)"
    else
        warn "dirsearch dependencies failed (non-fatal)"
    fi
fi

# ── 7. Nuclei templates ───────────────────────────────────────────────────────
header "Step 7/9 — Nuclei Templates"

if command -v nuclei &>/dev/null; then
    info "Downloading/updating nuclei templates..."
    sudo -u "$REAL_USER" nuclei -update-templates -silent && success "Templates updated" \
        || warn "Template update failed (non-fatal)"
else
    warn "nuclei not found — skipping template update"
fi

# ── 8. Config setup ───────────────────────────────────────────────────────────
header "Step 8/9 — Configuration"

mkdir -p "$SCRIPT_DIR/config" "$SCRIPT_DIR/logs" \
         "$SCRIPT_DIR/output/raw" "$SCRIPT_DIR/output/parsed" \
         "$SCRIPT_DIR/output/reports" "$SCRIPT_DIR/output/screenshots"

if [[ ! -f "$SCRIPT_DIR/config/config.yaml" ]]; then
    if [[ -f "$SCRIPT_DIR/config/config.example.yaml" ]]; then
        cp "$SCRIPT_DIR/config/config.example.yaml" "$SCRIPT_DIR/config/config.yaml"
        success "Created config/config.yaml from example"
    fi
else
    info "config/config.yaml already exists — skipping"
fi

# Fix ownership for all output dirs
chown -R "$REAL_USER:$REAL_USER" "$SCRIPT_DIR" 2>/dev/null || true

# ── 9. CLI entrypoint registration ────────────────────────────────────────────
header "Step 9/9 — CLI Registration (bountymind)"

# Install BountyMind's own Python dependencies in a project-local venv.
APP_VENV="$SCRIPT_DIR/.venv"
python3 -m venv "$APP_VENV"
"$APP_VENV/bin/pip" install -q --upgrade pip
if "$APP_VENV/bin/pip" install -q -e "$SCRIPT_DIR"; then
    success "Package installed in local venv"
else
    error "Could not install BountyMind dependencies in local venv"
    exit 1
fi

# Also create a direct symlink as belt-and-braces fallback
MAIN_SCRIPT="$SCRIPT_DIR/main.py"
chmod +x "$MAIN_SCRIPT"

if [[ -L /usr/local/bin/bountymind ]]; then
    rm /usr/local/bin/bountymind
fi

# Create a wrapper that handles the Python path correctly
cat > /usr/local/bin/bountymind << EOF
#!/usr/bin/env bash
# BountyMind CLI wrapper — auto-generated by install.sh
cd "$SCRIPT_DIR"
exec "$APP_VENV/bin/python" "$MAIN_SCRIPT" "\$@"
EOF
chmod +x /usr/local/bin/bountymind
success "Registered: /usr/local/bin/bountymind"

# Add Go bin to system PATH permanently
PROFILE_D="/etc/profile.d/bountymind.sh"
cat > "$PROFILE_D" << 'EOF'
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
EOF
chmod +x "$PROFILE_D"

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║        BountyMind Installation Complete      ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Usage examples:${NC}"
echo -e "    ${BOLD}bountymind -d example.com${NC}"
echo -e "    ${BOLD}bountymind -l targets.txt${NC}"
echo -e "    ${BOLD}bountymind -d example.com --format markdown,html${NC}"
echo -e "    ${BOLD}bountymind --check-env${NC}"
echo -e "    ${BOLD}bountymind --update-tools${NC}"
echo -e "    ${BOLD}bountymind --help${NC}"
echo ""
echo -e "  ${YELLOW}Add optional API keys in:${NC} config/config.yaml"
echo -e "  ${YELLOW}Logs written to:${NC}          logs/framework.log"
echo -e "  ${YELLOW}Repository:${NC}             https://github.com/PratyushJoshi/bountymind"
echo -e "  ${YELLOW}Reports saved to:${NC}          output/reports/"
echo ""
warn "AUTHORIZED USE ONLY — Run only against systems you own or have explicit written permission to test."
echo ""
