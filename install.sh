#!/usr/bin/env bash
# =============================================================================
# install.sh — Automated Recon Framework setup script
#
# Installs all external tool dependencies on Debian/Ubuntu/Kali systems.
#
# Usage:
#   bash install.sh                  # full install
#   bash install.sh --no-go-tools    # skip Go-based tools (subfinder etc.)
#   bash install.sh --no-apt         # skip apt packages (nmap, whatweb)
#   bash install.sh --no-python-pkgs # skip optional Python packages
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*" >&2; }
section() { echo -e "\n${CYAN}${BOLD}==> $*${NC}"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
SKIP_GO=0
SKIP_APT=0
SKIP_PY=0

for arg in "$@"; do
    case "$arg" in
        --no-go-tools)    SKIP_GO=1  ;;
        --no-apt)         SKIP_APT=1 ;;
        --no-python-pkgs) SKIP_PY=1  ;;
        -h|--help)
            sed -n '2,11p' "$0" | sed 's/^# //'
            exit 0
            ;;
        *)
            warn "Unknown argument: $arg"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Python version check
# ---------------------------------------------------------------------------
section "Checking Python"

if ! command -v python3 &>/dev/null; then
    error "Python 3 not found. Please install Python 3.8+ before running this script."
    exit 1
fi

PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYMINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

if [[ "$PYMINOR" -lt 8 ]]; then
    error "Python 3.8 or later is required (found Python $PYVER)."
    exit 1
fi

info "Python $PYVER — OK"

# ---------------------------------------------------------------------------
# APT packages: nmap, whatweb
# ---------------------------------------------------------------------------
if [[ $SKIP_APT -eq 0 ]]; then
    section "Installing apt packages (nmap, whatweb)"
    if ! command -v apt-get &>/dev/null; then
        warn "apt-get not found — skipping system packages. Install nmap and whatweb manually."
    else
        sudo apt-get update -qq
        sudo apt-get install -y nmap whatweb
        info "nmap and whatweb installed via apt."
    fi
else
    warn "Skipping apt packages (--no-apt)."
fi

# ---------------------------------------------------------------------------
# Go-based tools: subfinder, httpx, nuclei, amass
# ---------------------------------------------------------------------------
if [[ $SKIP_GO -eq 0 ]]; then
    section "Installing Go-based tools"

    if ! command -v go &>/dev/null; then
        warn "Go not found — skipping ProjectDiscovery and Amass tools."
        warn "Install Go from https://go.dev/dl/ and re-run this script."
    else
        GOPATH_BIN="$(go env GOPATH)/bin"
        info "Go found. Installing tools to $GOPATH_BIN"

        declare -A GO_TOOLS=(
            ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
            ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            ["amass"]="github.com/owasp-amass/amass/v4/...@master"
        )

        for tool in "${!GO_TOOLS[@]}"; do
            info "Installing $tool …"
            go install "${GO_TOOLS[$tool]}" && info "  $tool installed." \
                || warn "  $tool install failed — check Go version and network connectivity."
        done

        # Make GOPATH/bin available for the rest of this script
        export PATH="$PATH:$GOPATH_BIN"

        # Update Nuclei templates
        if command -v nuclei &>/dev/null; then
            info "Updating Nuclei templates (this may take a moment) …"
            nuclei -update-templates -silent \
                && info "Nuclei templates updated." \
                || warn "Nuclei template update failed (will use existing templates)."
        fi

        echo ""
        info "Add the following to your shell profile (~/.zshrc or ~/.bashrc):"
        echo -e "    ${BOLD}export PATH=\$PATH:$GOPATH_BIN${NC}"
    fi
else
    warn "Skipping Go-based tools (--no-go-tools)."
fi

# ---------------------------------------------------------------------------
# Optional Python packages: networkx + matplotlib (for graph generation)
# ---------------------------------------------------------------------------
if [[ $SKIP_PY -eq 0 ]]; then
    section "Installing optional Python packages"

    if command -v pip3 &>/dev/null; then
        pip3 install --quiet networkx matplotlib \
            && info "networkx and matplotlib installed (graph generation enabled)." \
            || warn "pip install failed — graph generation (--graph) will be unavailable."
    else
        warn "pip3 not found — skipping optional Python packages."
    fi
else
    warn "Skipping optional Python packages (--no-python-pkgs)."
fi

# ---------------------------------------------------------------------------
# Verification summary
# ---------------------------------------------------------------------------
section "Verifying tool availability"

ALL_OK=1
declare -A TOOLS=(
    ["subfinder"]="Subdomain enumeration (ProjectDiscovery)"
    ["amass"]="Subdomain enumeration (OWASP)"
    ["nmap"]="Port scanning"
    ["httpx"]="Live host detection (ProjectDiscovery)"
    ["whatweb"]="Technology detection"
    ["nuclei"]="Vulnerability scanning (ProjectDiscovery)"
)

for tool in "${!TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        info "  [OK]      $tool — ${TOOLS[$tool]}"
    else
        warn "  [MISSING] $tool — ${TOOLS[$tool]}"
        ALL_OK=0
    fi
done

echo ""
if [[ $ALL_OK -eq 1 ]]; then
    info "All tools available — the full pipeline is ready."
else
    warn "Some tools are missing. Affected pipeline stages will be skipped automatically."
fi

# ---------------------------------------------------------------------------
# Usage hint
# ---------------------------------------------------------------------------
section "You're ready to run"
echo -e "  ${BOLD}cd \"$SCRIPT_DIR/recon_framework\"${NC}"
echo -e "  ${BOLD}python3 main.py -d example.com --html-report --json${NC}"
echo ""
