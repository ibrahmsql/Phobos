#!/usr/bin/env bash
# Phobos Port Scanner - macOS Installation Script
# Usage: curl -sSL https://raw.githubusercontent.com/ibrahmsql/phobos/main/install_macos.sh | bash

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

# Banner
print_banner() {
    echo -e "${RED}"
    echo "____  _   _   ___   ____   ___   ____   _____ "
    echo "|  _ \\| | | | / _ \\ | __ ) / _ \\ |  _ \\ | ____| "
    echo "| |_) | |_| || | | ||  _ \\| | | || | | ||  _|  "
    echo "|  __/|  _  || |_| || |_) | |_| || |_| || |___ "
    echo "|_|   |_| |_| \\___/ |____/ \\___/ |____/ |_____| "
    echo -e "${NC}"
    echo -e "${CYAN}Phobos Installer for macOS${NC}"
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

# Detect architecture
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64)
            echo "x86_64"
            ;;
        arm64)
            echo "aarch64"
            ;;
        *)
            error "Unsupported architecture: $arch"
            ;;
    esac
}

# Check for Homebrew
check_homebrew() {
    if command -v brew &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Install via Homebrew (preferred method)
install_via_homebrew() {
    info "Attempting to install via Homebrew..."
    
    if ! check_homebrew; then
        warning "Homebrew not found. Install from https://brew.sh/"
        return 1
    fi
    
    # Check if tap exists
    if brew tap | grep -q "ibrahmsql/phobos"; then
        info "Installing from Homebrew tap..."
        brew install ibrahmsql/phobos/phobos
        return 0
    else
        warning "Homebrew tap not available yet. Using direct download..."
        return 1
    fi
}

# Download and install Phobos manually
install_manually() {
    local arch="$1"
    local temp_dir
    temp_dir="$(mktemp -d)"
    
    info "Downloading Phobos for $arch..."
    
    # Get latest release URL
    local latest_url
    latest_url="https://github.com/$REPO/releases/latest/download/phobos-macos-$arch"
    
    # Download binary
    if ! curl -fsSL "$latest_url" -o "$temp_dir/$BINARY_NAME"; then
        error "Failed to download Phobos. Please check your internet connection."
    fi
    
    # Make executable
    chmod +x "$temp_dir/$BINARY_NAME"
    
    # Check for quarantine attribute and remove it
    if xattr -l "$temp_dir/$BINARY_NAME" 2>/dev/null | grep -q "com.apple.quarantine"; then
        info "Removing quarantine attribute..."
        xattr -d com.apple.quarantine "$temp_dir/$BINARY_NAME" 2>/dev/null || true
    fi
    
    # Install binary
    info "Installing Phobos to $INSTALL_DIR..."
    if [ -w "$INSTALL_DIR" ]; then
        mv "$temp_dir/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    else
        if ! sudo mv "$temp_dir/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"; then
            warning "Failed to install to $INSTALL_DIR. Installing to ~/.local/bin instead..."
            mkdir -p "$HOME/.local/bin"
            mv "$temp_dir/$BINARY_NAME" "$HOME/.local/bin/$BINARY_NAME"
            INSTALL_DIR="$HOME/.local/bin"
            
            # Add to PATH if not already
            if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
                echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
                echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
                warning "Added ~/.local/bin to PATH. Please run: source ~/.zshrc"
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
    
    # Zsh completion (default on macOS)
    if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
        local zsh_comp_dir="$HOME/.zsh/completions"
        mkdir -p "$zsh_comp_dir"
        curl -fsSL "https://raw.githubusercontent.com/$REPO/main/completions/phobos.zsh" \
            -o "$zsh_comp_dir/_phobos" 2>/dev/null || true
        
        # Add to fpath if not already
        if ! grep -q "fpath=($zsh_comp_dir \$fpath)" "$HOME/.zshrc" 2>/dev/null; then
            echo "fpath=($zsh_comp_dir \$fpath)" >> "$HOME/.zshrc"
            echo "autoload -Uz compinit && compinit" >> "$HOME/.zshrc"
        fi
    fi
    
    # Bash completion
    if [ -n "$BASH_VERSION" ] || [ -f "$HOME/.bashrc" ]; then
        local bash_comp_dir="$HOME/.bash_completion.d"
        mkdir -p "$bash_comp_dir"
        curl -fsSL "https://raw.githubusercontent.com/$REPO/main/completions/phobos.bash" \
            -o "$bash_comp_dir/phobos" 2>/dev/null || true
        
        if ! grep -q "source $bash_comp_dir/phobos" "$HOME/.bashrc" 2>/dev/null; then
            echo "[ -f $bash_comp_dir/phobos ] && source $bash_comp_dir/phobos" >> "$HOME/.bashrc"
        fi
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

# Setup configuration
setup_config() {
    info "Setting up configuration directory..."
    mkdir -p "$CONFIG_DIR"
    
    success "Configuration directory created at $CONFIG_DIR"
    info "Example config available at: https://github.com/$REPO/blob/main/phobos.toml.example"
}

# Install man page
install_man() {
    info "Installing man page..."
    
    local man_dir="$HOME/.local/share/man/man1"
    mkdir -p "$man_dir"
    
    curl -fsSL "https://raw.githubusercontent.com/$REPO/main/man/phobos.1" \
        -o "$man_dir/phobos.1" 2>/dev/null || true
    
    # Update MANPATH if needed
    if ! grep -q "MANPATH.*$HOME/.local/share/man" "$HOME/.zshrc" 2>/dev/null; then
        echo 'export MANPATH="$HOME/.local/share/man:$MANPATH"' >> "$HOME/.zshrc"
    fi
    
    success "Man page installed (run: man phobos)"
}

# Check for OpenCL support (GPU acceleration)
check_opencl() {
    info "Checking for GPU support..."
    
    # macOS has built-in OpenCL support
    if [ -f "/System/Library/Frameworks/OpenCL.framework/OpenCL" ]; then
        success "OpenCL detected - GPU acceleration available"
        echo ""
        info "To enable GPU acceleration, rebuild Phobos with:"
        echo "  cargo build --release --features gpu"
        echo ""
    else
        warning "OpenCL not detected - GPU acceleration unavailable"
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
    
    # Apple Silicon specific notes
    if [ "$(uname -m)" = "arm64" ]; then
        echo -e "${CYAN}Apple Silicon Notes:${NC}"
        echo -e "  ${GREEN}✓${NC} Running native ARM64 binary"
        echo -e "  ${GREEN}✓${NC} GPU acceleration supported via Metal/OpenCL"
        echo ""
    fi
    
    # Root privileges notice
    echo -e "${YELLOW}Note:${NC} SYN scans require root privileges"
    echo -e "  Use sudo: ${YELLOW}sudo phobos target.com -s syn${NC}"
    echo ""
    
    # Verify installation
    if command -v phobos &> /dev/null; then
        local version
        version="$(phobos --version 2>/dev/null | head -n1)"
        echo -e "${GREEN}Installation verified:${NC} $version"
    else
        warning "Phobos command not found. You may need to restart your terminal or run:"
        echo -e "  ${YELLOW}source ~/.zshrc${NC}"
    fi
    
    echo ""
    echo -e "${RED}\"Let your ports tremble.\"${NC} ⚡"
    echo ""
}

# Main installation
main() {
    print_banner
    
    # Detect architecture
    local arch
    arch="$(detect_arch)"
    
    info "Detected: macOS ($arch)"
    
    # Try Homebrew first, fall back to manual installation
    if ! install_via_homebrew; then
        install_manually "$arch"
    fi
    
    # Setup configuration
    setup_config
    
    # Install completions
    install_completions
    
    # Install man page
    install_man
    
    # Check OpenCL
    check_opencl
    
    # Show post-installation info
    post_install
}

# Run main installation
main "$@"
