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
#   2. Checks & installs prerequisites (Python 3.9+, git, curl, Go, …)
#   3. Installs system packages (apt)
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

have_cmd() { command -v "$1" &>/dev/null; }

python_ok() {
    have_cmd python3 && python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null
}

prereq_fail() {
    error "$1"
    echo ""
    warn "Manual install options:"
    echo "  • Debian/Ubuntu/Kali: sudo apt update && sudo apt install -y python3 python3-pip python3-venv git curl wget golang-go"
    echo "  • Go (fallback):      https://go.dev/dl/  → extract to /usr/local/go"
    echo "  • Python 3.9+:        https://www.python.org/downloads/"
    echo "  • Then re-run:        sudo ./install.sh"
    exit 1
}

install_go_tarball() {
    local archive="go1.22.4.linux-amd64.tar.gz"
    info "Downloading Go from https://go.dev/dl/$archive ..."
    if have_cmd wget; then
        wget -q "https://go.dev/dl/$archive" -O "/tmp/$archive" || return 1
    elif have_cmd curl; then
        curl -fsSL "https://go.dev/dl/$archive" -o "/tmp/$archive" || return 1
    else
        return 1
    fi
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/$archive"
    rm -f "/tmp/$archive"
    export PATH="$PATH:/usr/local/go/bin"
    PROFILE="$REAL_HOME/.bashrc"
    grep -qxF 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' "$PROFILE" 2>/dev/null || \
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$PROFILE"
    have_cmd go
}

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

SUPPORTED_DISTROS=(kali ubuntu debian)
if [[ ! " ${SUPPORTED_DISTROS[*]} " =~ " ${DISTRO} " ]]; then
    warn "Distro '$DISTRO' is not officially tested. Kali / Ubuntu / Debian work best."
fi

# ── 0. Prerequisites ──────────────────────────────────────────────────────────
header "Step 0 — Prerequisites (Python, git, network, Go)"

if ! have_cmd apt-get; then
    prereq_fail "apt-get not found — automated prerequisite install requires Debian/Ubuntu/Kali."
fi

info "Ensuring core packages via apt..."
apt-get update -qq
CORE_PREREQ=(python3 python3-pip python3-venv git curl wget)
for pkg in "${CORE_PREREQ[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        info "  $pkg — ok"
    else
        info "  Installing $pkg ..."
        apt-get install -y -qq "$pkg" || prereq_fail "Failed to install $pkg via apt."
        success "  $pkg installed"
    fi
done

if ! python_ok; then
    prereq_fail "Python 3.9+ is required but 'python3' is missing or too old."
fi
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')
success "Python $PY_VER — ok"

if ! have_cmd git; then
    prereq_fail "git is required but could not be installed."
fi
success "git — ok ($(git --version | head -1))"

if ! have_cmd curl && ! have_cmd wget; then
    prereq_fail "curl or wget is required for downloading tools."
fi
success "Network tools — ok (curl/wget)"

# Go — try apt first, then official tarball
if ! have_cmd go; then
    warn "Go not found — installing golang-go via apt..."
    apt-get install -y -qq golang-go || true
fi
if ! have_cmd go; then
    warn "apt golang-go unavailable — trying golang.org tarball..."
    install_go_tarball || prereq_fail "Go is required but could not be installed automatically."
fi
success "Go — ok ($(go version | awk '{print $3}'))"

# Optional: Rust/cargo for ppfuzz and x8
if ! have_cmd cargo; then
    warn "cargo (Rust) not found — optional, needed for ppfuzz/x8."
    info "  Install later with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    info "  Or re-run this installer after rustup (Step 6.5 will pick it up)."
else
    success "cargo — ok ($(cargo --version))"
fi

echo ""
info "Prerequisite summary:"
printf "  %-22s %s\n" "python3 (>=3.9)" "$PY_VER"
printf "  %-22s %s\n" "git" "$(git --version | awk '{print $3}')"
NET_HINT=""
have_cmd curl && NET_HINT+="curl "
have_cmd wget && NET_HINT+="wget"
NET_HINT="${NET_HINT:-missing}"
printf "  %-22s %s\n" "curl/wget" "$NET_HINT"
printf "  %-22s %s\n" "go" "$(go version | awk '{print $3}')"
printf "  %-22s %s\n" "cargo (optional)" "$(have_cmd cargo && cargo --version | awk '{print $2}' || echo 'not installed')"
echo ""

# ── 1. System packages ────────────────────────────────────────────────────────
header "Step 1/9 — System Packages (apt)"

apt-get update -qq

APT_TOOLS=(
    git curl wget unzip python3 python3-pip python3-venv
    nmap ffuf amass whatweb wafw00f
    sqlmap
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
    warn "Go not found after prerequisite step — retrying tarball install..."
    install_go_tarball || prereq_fail "Go is still missing — check PATH or install manually."
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
go_install "github.com/hahwul/dalfox/v2@latest"

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
    "s3scanner"
    "uro"
    "xnlinkfinder"
    "wafw00f"
    "arjun"
    "jwt_tool"
    "tplmap"
    "schemathesis"   # API schema fuzzing (OpenAPI/Swagger logic + mass-assignment bugs)
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
            if [[ "$tool" == "tplmap" ]]; then
                echo "[*]   Falling back to local tplmap wrapper ..."
                TPLMAP_DIR="$SCRIPT_DIR/tools/tplmap"
                if [ ! -d "$TPLMAP_DIR" ]; then
                    git clone https://github.com/epinna/tplmap.git "$TPLMAP_DIR"
                fi
                if [ ! -d "$TPLMAP_DIR/venv" ]; then
                    python3 -m venv "$TPLMAP_DIR/venv"
                    "$TPLMAP_DIR/venv/bin/pip" install -q -r "$TPLMAP_DIR/requirements.txt" || true
                fi
                mkdir -p "$REAL_HOME/.local/bin"
                cat > "$REAL_HOME/.local/bin/tplmap" <<EOF
#!/bin/bash
"$TPLMAP_DIR/venv/bin/python" "$TPLMAP_DIR/tplmap.py" "\$@"
EOF
                chmod +x "$REAL_HOME/.local/bin/tplmap"
                echo "[+]   tplmap wrapper created"
            fi
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

# ── 6.5 High-bounty scanners (Rust / git) ─────────────────────────────────────
header "Step 6.5 — High-Bounty Scanners (Rust + git)"

# Rust toolchain (needed for ppfuzz + x8). Installed for the real user.
if ! sudo -u "$REAL_USER" env HOME="$REAL_HOME" bash -lc 'command -v cargo' &>/dev/null; then
    info "Rust/cargo not found — installing via rustup (non-interactive)..."
    sudo -u "$REAL_USER" env HOME="$REAL_HOME" bash -lc \
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y" \
        && success "Rust installed" || warn "Rust install failed (ppfuzz/x8 will be skipped)"
fi

# cargo-based scanners: ppfuzz (prototype pollution), x8 (hidden params)
for crate in ppfuzz x8; do
    if sudo -u "$REAL_USER" env HOME="$REAL_HOME" bash -lc "command -v $crate" &>/dev/null; then
        info "  $crate — already installed"
    else
        info "  cargo installing $crate ..."
        sudo -u "$REAL_USER" env HOME="$REAL_HOME" bash -lc \
            "source \$HOME/.cargo/env 2>/dev/null; cargo install $crate" \
            && success "  $crate installed" || warn "  $crate failed (non-fatal)"
    fi
    # Expose cargo bin system-wide
    CARGO_BIN="$REAL_HOME/.cargo/bin/$crate"
    if [[ -x "$CARGO_BIN" ]]; then
        ln -sf "$CARGO_BIN" "/usr/local/bin/$crate" 2>/dev/null || true
    fi
done

# smuggler (HTTP request smuggling) — python script via git + wrapper
SMUGGLER_DIR="$SCRIPT_DIR/tools/smuggler"
if [[ ! -f "$SMUGGLER_DIR/smuggler.py" ]]; then
    info "Cloning smuggler..."
    git clone -q https://github.com/defparam/smuggler.git "$SMUGGLER_DIR" \
        || warn "smuggler clone failed (non-fatal)"
fi
if [[ -f "$SMUGGLER_DIR/smuggler.py" ]]; then
    cat > /usr/local/bin/smuggler << EOF
#!/usr/bin/env bash
exec python3 "$SMUGGLER_DIR/smuggler.py" "\$@"
EOF
    chmod +x /usr/local/bin/smuggler
    success "smuggler ready (wrapper)"
fi

# bypass-403 (403/401 bypass) — shell script via git + wrapper
BYPASS_DIR="$SCRIPT_DIR/tools/bypass-403"
if [[ ! -f "$BYPASS_DIR/bypass-403.sh" ]]; then
    info "Cloning bypass-403..."
    git clone -q https://github.com/iamj0ker/bypass-403.git "$BYPASS_DIR" \
        || warn "bypass-403 clone failed (non-fatal)"
fi
if [[ -f "$BYPASS_DIR/bypass-403.sh" ]]; then
    chmod +x "$BYPASS_DIR/bypass-403.sh" 2>/dev/null || true
    ln -sf "$BYPASS_DIR/bypass-403.sh" /usr/local/bin/bypass-403 2>/dev/null || true
    success "bypass-403 ready"
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

# Compatibility alias for the common shorthand/typo.
ln -sf /usr/local/bin/bountymind /usr/local/bin/bountymin 2>/dev/null || true
success "Registered alias: /usr/local/bin/bountymin"

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
echo -e "    ${BOLD}bountymind --update${NC}"
echo -e "    ${BOLD}bountymin --update${NC}  ${YELLOW}(alias)${NC}"
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
