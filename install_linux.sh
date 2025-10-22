#!/usr/bin/env bash
# Phobos Port Scanner - Linux Installation Script
# Usage: curl -sSL https://raw.githubusercontent.com/ibrahmsql/phobos/main/install_linux.sh | bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
REPO="ibrahmsql/phobos"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="phobos"
CONFIG_DIR="$HOME/.config/phobos"
COMPLETION_DIR="$HOME/.local/share/bash-completion/completions"

# Banner
print_banner() {
    echo -e "${RED}"
    echo "____  _   _   ___   ____   ___   ____   _____ "
    echo "|  _ \\| | | | / _ \\ | __ ) / _ \\ |  _ \\ | ____| "
    echo "| |_) | |_| || | | ||  _ \\| | | || | | ||  _|  "
    echo "|  __/|  _  || |_| || |_) | |_| || |_| || |___ "
    echo "|_|   |_| |_| \\___/ |____/ \\___/ |____/ |_____| "
    echo -e "${NC}"
    echo -e "${CYAN}Phobos Installer for Linux${NC}"
    echo -e "${YELLOW}The Blazingly Fast Port Scanner${NC}"
    echo ""
}

# Utility functions
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
    exit 1
}

# Detect system architecture
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64)
            echo "x86_64"
            ;;
        aarch64|arm64)
            echo "aarch64"
            ;;
        armv7l|armv7)
            echo "armv7"
            ;;
        *)
            error "Unsupported architecture: $arch"
            ;;
    esac
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

# Check if running with sudo/root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

# Install dependencies based on distro
install_dependencies() {
    local distro="$1"
    
    info "Installing dependencies for $distro..."
    
    case "$distro" in
        ubuntu|debian|pop|linuxmint)
            if check_root; then
                apt-get update
                apt-get install -y curl wget ca-certificates
            else
                warning "Not running as root. Please install dependencies manually:"
                echo "  sudo apt-get install curl wget ca-certificates"
            fi
            ;;
        fedora|rhel|centos)
            if check_root; then
                dnf install -y curl wget ca-certificates
            else
                warning "Not running as root. Please install dependencies manually:"
                echo "  sudo dnf install curl wget ca-certificates"
            fi
            ;;
        arch|manjaro)
            if check_root; then
                pacman -S --noconfirm curl wget ca-certificates
            else
                warning "Not running as root. Please install dependencies manually:"
                echo "  sudo pacman -S curl wget ca-certificates"
            fi
            ;;
        *)
            warning "Unknown distribution. Please ensure curl and wget are installed."
            ;;
    esac
}

# Download and install Phobos
install_phobos() {
    local arch="$1"
    local temp_dir
    temp_dir="$(mktemp -d)"
    
    info "Downloading Phobos for $arch..."
    
    # Get latest release URL
    local latest_url
    latest_url="https://github.com/$REPO/releases/latest/download/phobos-linux-$arch"
    
    # Download binary
    if ! curl -fsSL "$latest_url" -o "$temp_dir/$BINARY_NAME"; then
        error "Failed to download Phobos. Please check your internet connection."
    fi
    
    # Make executable
    chmod +x "$temp_dir/$BINARY_NAME"
    
    # Install binary
    info "Installing Phobos to $INSTALL_DIR..."
    if check_root; then
        mv "$temp_dir/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    else
        if ! sudo mv "$temp_dir/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"; then
            warning "Failed to install to $INSTALL_DIR. Installing to ~/.local/bin instead..."
            mkdir -p "$HOME/.local/bin"
            mv "$temp_dir/$BINARY_NAME" "$HOME/.local/bin/$BINARY_NAME"
            INSTALL_DIR="$HOME/.local/bin"
            
            # Add to PATH if not already
            if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
                echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
                warning "Added ~/.local/bin to PATH. Please run: source ~/.bashrc"
            fi
        fi
    fi
    
    # Cleanup
    rm -rf "$temp_dir"
    
    success "Phobos installed successfully!"
}

# Install shell completions
install_completions() {
    info "Installing shell completions..."
    
    # Bash completion
    if [ -n "$BASH_VERSION" ]; then
        mkdir -p "$COMPLETION_DIR"
        curl -fsSL "https://raw.githubusercontent.com/$REPO/main/completions/phobos.bash" \
            -o "$COMPLETION_DIR/phobos" 2>/dev/null || true
    fi
    
    # Zsh completion
    if [ -n "$ZSH_VERSION" ]; then
        local zsh_comp_dir="${ZDOTDIR:-$HOME}/.zsh/completions"
        mkdir -p "$zsh_comp_dir"
        curl -fsSL "https://raw.githubusercontent.com/$REPO/main/completions/phobos.zsh" \
            -o "$zsh_comp_dir/_phobos" 2>/dev/null || true
    fi
    
    # Fish completion
    if command -v fish &> /dev/null; then
        local fish_comp_dir="$HOME/.config/fish/completions"
        mkdir -p "$fish_comp_dir"
        curl -fsSL "https://raw.githubusercontent.com/$REPO/main/completions/phobos.fish" \
            -o "$fish_comp_dir/phobos.fish" 2>/dev/null || true
    fi
    
    success "Shell completions installed"
}

# Create config directory
setup_config() {
    info "Setting up configuration directory..."
    mkdir -p "$CONFIG_DIR"
    
    # Download example config if it doesn't exist
    if [ ! -f "$CONFIG_DIR/config.toml" ]; then
        curl -fsSL "https://raw.githubusercontent.com/$REPO/main/phobos.toml.example" \
            -o "$CONFIG_DIR/config.toml" 2>/dev/null || true
    fi
    
    success "Configuration directory created at $CONFIG_DIR"
}

# Install man page
install_man() {
    info "Installing man page..."
    
    local man_dir="/usr/local/share/man/man1"
    
    if check_root; then
        mkdir -p "$man_dir"
        curl -fsSL "https://raw.githubusercontent.com/$REPO/main/man/phobos.1" \
            -o "$man_dir/phobos.1" 2>/dev/null || true
        mandb &> /dev/null || true
        success "Man page installed (run: man phobos)"
    else
        warning "Skipping man page installation (requires root)"
    fi
}

# Post-installation instructions
post_install() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Phobos Installation Complete! 🚀${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}Installation Details:${NC}"
    echo -e "  Binary: ${YELLOW}$INSTALL_DIR/$BINARY_NAME${NC}"
    echo -e "  Config: ${YELLOW}$CONFIG_DIR${NC}"
    echo ""
    echo -e "${CYAN}Quick Start:${NC}"
    echo -e "  ${YELLOW}phobos --help${NC}                    # Show help"
    echo -e "  ${YELLOW}phobos scanme.nmap.org${NC}          # Basic scan"
    echo -e "  ${YELLOW}phobos target.com -p 1-1000${NC}     # Port range"
    echo -e "  ${YELLOW}phobos target.com --wrath${NC}       # Aggressive scan"
    echo ""
    echo -e "${CYAN}Documentation:${NC}"
    echo -e "  ${BLUE}https://github.com/$REPO${NC}"
    echo ""
    
    # Check for GPU support
    if command -v clinfo &> /dev/null && clinfo &> /dev/null; then
        echo -e "${CYAN}GPU Detected:${NC}"
        echo -e "  ${GREEN}✓${NC} OpenCL is available"
        echo -e "  For GPU acceleration, rebuild with: ${YELLOW}--features gpu${NC}"
        echo ""
    fi
    
    # Root privileges notice
    if ! check_root; then
        echo -e "${YELLOW}Note:${NC} SYN scans require root privileges or CAP_NET_RAW"
        echo -e "  Grant capability: ${YELLOW}sudo setcap cap_net_raw+ep $INSTALL_DIR/$BINARY_NAME${NC}"
        echo ""
    fi
    
    # Verify installation
    if command -v phobos &> /dev/null; then
        local version
        version="$(phobos --version 2>/dev/null | head -n1)"
        echo -e "${GREEN}Installation verified:${NC} $version"
    else
        warning "Phobos command not found. You may need to restart your terminal or run:"
        echo -e "  ${YELLOW}source ~/.bashrc${NC}"
    fi
    
    echo ""
    echo -e "${RED}\"Let your ports tremble.\"${NC} ⚡"
    echo ""
}

# Main installation
main() {
    print_banner
    
    # Detect system
    local arch distro
    arch="$(detect_arch)"
    distro="$(detect_distro)"
    
    info "Detected: $distro ($arch)"
    
    # Install dependencies
    install_dependencies "$distro"
    
    # Install Phobos
    install_phobos "$arch"
    
    # Setup configuration
    setup_config
    
    # Install completions
    install_completions
    
    # Install man page
    install_man
    
    # Show post-installation info
    post_install
}

# Run main installation
main "$@"
