#!/usr/bin/env bash
#
# install-deps.sh - Install dependencies for secure-llm
#
# Usage:
#   ./scripts/install-deps.sh [OPTIONS]
#
# Options:
#   --musl      Install musl toolchain for static builds
#   --no-rust   Skip Rust/Cargo setup
#   --help      Show this help message
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }

# Defaults
INSTALL_MUSL=false
INSTALL_RUST=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --musl)
            INSTALL_MUSL=true
            shift
            ;;
        --no-rust)
            INSTALL_RUST=false
            shift
            ;;
        --help|-h)
            head -20 "$0" | tail -n +2 | sed 's/^# \?//'
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Detect package manager
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

PKG_MANAGER=$(detect_pkg_manager)
info "Detected package manager: $PKG_MANAGER"

# Install system packages
install_packages() {
    info "Installing system dependencies..."

    case $PKG_MANAGER in
        apt)
            sudo apt-get update
            sudo apt-get install -y bubblewrap tmux zellij
            if $INSTALL_MUSL; then
                sudo apt-get install -y musl-tools
            fi
            ;;
        dnf)
            sudo dnf install -y bubblewrap tmux zellij
            if $INSTALL_MUSL; then
                sudo dnf install -y musl-gcc musl-libc-static
            fi
            ;;
        pacman)
            sudo pacman -Sy --noconfirm bubblewrap tmux zellij
            if $INSTALL_MUSL; then
                sudo pacman -S --noconfirm musl
            fi
            ;;
        *)
            error "Unsupported package manager. Please install manually:"
            error "  - bubblewrap (bwrap)"
            error "  - tmux"
            error "  - zellij"
            if $INSTALL_MUSL; then
                error "  - musl toolchain"
            fi
            exit 1
            ;;
    esac

    success "System packages installed"
}

# Install Rust toolchain
install_rust() {
    if ! $INSTALL_RUST; then
        info "Skipping Rust installation (--no-rust)"
        return
    fi

    if command -v rustc &>/dev/null; then
        info "Rust already installed: $(rustc --version)"
    else
        info "Installing Rust via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        success "Rust installed"
    fi

    if $INSTALL_MUSL; then
        info "Adding musl target..."
        rustup target add x86_64-unknown-linux-musl
        success "musl target added"
    fi
}

# Create config directory
setup_config() {
    local config_dir="$HOME/.config/secure-llm"
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    local default_config="$script_dir/config/default.toml"

    info "Setting up configuration directory..."

    mkdir -p "$config_dir"

    if [[ -f "$config_dir/config.toml" ]]; then
        info "Config already exists at $config_dir/config.toml"
    elif [[ -f "$default_config" ]]; then
        cp "$default_config" "$config_dir/config.toml"
        success "Copied default config to $config_dir/config.toml"
    else
        warn "Default config not found, skipping config copy"
    fi
}

# Check user namespace support
check_userns() {
    info "Checking user namespace support..."

    local userns_file="/proc/sys/kernel/unprivileged_userns_clone"

    if [[ -f "$userns_file" ]]; then
        local userns_enabled
        userns_enabled=$(cat "$userns_file")
        if [[ "$userns_enabled" == "1" ]]; then
            success "User namespaces enabled"
        else
            warn "User namespaces disabled. bubblewrap may not work correctly."
            warn "Enable with: sudo sysctl -w kernel.unprivileged_userns_clone=1"
        fi
    else
        # File doesn't exist on most modern kernels - assume enabled
        success "User namespaces supported (modern kernel)"
    fi
}

# Verify installation
verify_install() {
    info "Verifying installation..."
    local failed=false

    if command -v bwrap &>/dev/null; then
        success "bubblewrap: $(bwrap --version 2>&1 | head -1)"
    else
        error "bubblewrap not found"
        failed=true
    fi

    if command -v tmux &>/dev/null; then
        success "tmux: $(tmux -V)"
    else
        warn "tmux not found (optional, zellij can be used instead)"
    fi

    if command -v zellij &>/dev/null; then
        success "zellij: $(zellij --version)"
    else
        warn "zellij not found (optional, tmux can be used instead)"
    fi

    if $INSTALL_RUST; then
        if command -v cargo &>/dev/null; then
            success "cargo: $(cargo --version)"
        else
            error "cargo not found"
            failed=true
        fi
    fi

    if $failed; then
        error "Some dependencies failed to install"
        exit 1
    fi
}

# Print manual steps
print_manual_steps() {
    echo ""
    info "=========================================="
    info "Manual steps required:"
    info "=========================================="
    echo ""
    echo "1. Install your AI coding assistant(s):"
    echo "   - Claude Code: npm install -g @anthropic-ai/claude-code"
    echo "   - Cursor:      https://cursor.sh"
    echo "   - Windsurf:    https://codeium.com/windsurf"
    echo "   - Gemini CLI:  https://github.com/google-gemini/gemini-cli"
    echo ""
    echo "2. Edit your configuration:"
    echo "   $HOME/.config/secure-llm/config.toml"
    echo ""
    echo "   Key settings to customize:"
    echo "   - [network.host_rewrite] - Set your corporate LLM gateway URLs"
    echo "   - [tools.<name>.binary]  - Path to tool executables if not in PATH"
    echo "   - [network.allowlist]    - Add internal domains your tools need"
    echo ""
    echo "3. Build secure-llm:"
    echo "   cargo build --release"
    echo ""
    echo "4. Run secure-llm:"
    echo "   ./target/release/secure-llm claude"
    echo ""
}

# Main
main() {
    echo ""
    info "secure-llm dependency installer"
    echo ""

    install_packages
    install_rust
    setup_config
    check_userns
    verify_install
    print_manual_steps

    success "Installation complete!"
}

main
