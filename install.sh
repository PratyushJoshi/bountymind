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

# ── 4. Python dependencies ────────────────────────────────────────────────────
header "Step 4/9 — Python Dependencies"

cd "$SCRIPT_DIR"
pip3 install -q --upgrade pip
pip3 install -q -r requirements.txt && success "Python requirements installed"

# ── 5. Pip security tools ─────────────────────────────────────────────────────
header "Step 5/9 — Pip Security Tools"

PIP_TOOLS=("wafw00f" "arjun" "cloud_enum")
for tool in "${PIP_TOOLS[@]}"; do
    if pip3 show "$tool" &>/dev/null; then
        info "  $tool — already installed"
    else
        info "  Installing $tool ..."
        pip3 install -q "$tool" && success "  $tool installed" || warn "  $tool failed (non-fatal)"
    fi
done

# ── 6. GitHub-cloned tools ────────────────────────────────────────────────────
header "Step 6/9 — GitHub Tools"

# SecretFinder
SF_DIR="$SCRIPT_DIR/tools/SecretFinder"
if [[ -f "$SF_DIR/SecretFinder.py" ]]; then
    info "SecretFinder — already present"
else
    info "Cloning SecretFinder..."
    mkdir -p "$SCRIPT_DIR/tools"
    git clone -q https://github.com/m4ll0k/SecretFinder.git "$SF_DIR" \
        && pip3 install -q -r "$SF_DIR/requirements.txt" \
        && success "SecretFinder installed" \
        || warn "SecretFinder clone failed (non-fatal)"
fi

# dirsearch
DIRSEARCH_DIR="/opt/dirsearch"
if [[ -d "$DIRSEARCH_DIR" ]]; then
    info "dirsearch — already present"
else
    info "Cloning dirsearch..."
    git clone -q https://github.com/maurosoria/dirsearch.git "$DIRSEARCH_DIR" \
        && pip3 install -q -r "$DIRSEARCH_DIR/requirements.txt" \
        && success "dirsearch installed" \
        || warn "dirsearch clone failed (non-fatal)"
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

# Install the Python package in editable mode so 'bountymind' goes into PATH
pip3 install -q -e "$SCRIPT_DIR" && success "Package installed (editable)"

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
exec python3 "$MAIN_SCRIPT" "\$@"
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
