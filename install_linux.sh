#!/bin/bash

# Phobos Linux Installation Script
# Socket pool error fix and running without root privileges

set -e

echo "🚀 Phobos Linux Installation Script"
echo "===================================="

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Root check
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}Do not run this script as root!${NC}"
   echo "Run as normal user, it will ask for sudo when needed."
   exit 1
fi

# System check
echo -e "${BLUE}Checking system information...${NC}"
echo "OS: $(uname -s)"
echo "Arch: $(uname -m)"
echo "User: $(whoami)"
echo ""

# Required packages check
echo -e "${BLUE}Checking required packages...${NC}"

# For Debian/Ubuntu
if command -v apt-get &> /dev/null; then
    echo "Debian/Ubuntu system detected"
    
    # Install required packages
    echo -e "${YELLOW}Installing required packages...${NC}"
    sudo apt-get update
    sudo apt-get install -y libcap2-bin curl build-essential git
    
# For RHEL/CentOS/Fedora
elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
    echo "RHEL/CentOS/Fedora system detected"
    
    if command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    else
        PKG_MANAGER="yum"
    fi
    
    echo -e "${YELLOW}Installing required packages...${NC}"
    sudo $PKG_MANAGER install -y libcap curl gcc git
    
# For Arch Linux
elif command -v pacman &> /dev/null; then
    echo "Arch Linux system detected"
    
    echo -e "${YELLOW}Installing required packages...${NC}"
    sudo pacman -S --noconfirm libcap curl base-devel git
    
else
    echo -e "${RED}Unsupported Linux distribution!${NC}"
    echo "Please install libcap and curl packages manually."
    exit 1
fi

# Rust installation check
echo -e "${BLUE}Checking Rust installation...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "${YELLOW}Rust not found, installing...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
else
    echo -e "${GREEN}Rust already installed: $(rustc --version)${NC}"
fi

# Clone and compile Phobos
echo -e "${BLUE}Cloning and compiling Phobos...${NC}"

# Create temporary directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Clone the repository
echo -e "${YELLOW}Cloning Phobos repository...${NC}"
git clone https://github.com/ibrahmsql/phobos.git
cd phobos

# Build the project
echo -e "${YELLOW}Building Phobos...${NC}"
cargo build --release

# Copy binary
echo -e "${BLUE}Installing Phobos...${NC}"
BINARY_PATH="target/release/phobos"
INSTALL_PATH="/usr/local/bin/phobos"

if [ -f "$BINARY_PATH" ]; then
    # Copy binary to system directory
    sudo cp "$BINARY_PATH" "$INSTALL_PATH"
    
    # Set capabilities (for raw socket usage without root)
    echo -e "${YELLOW}Setting network capabilities...${NC}"
    sudo setcap cap_net_raw,cap_net_admin+eip "$INSTALL_PATH"
    
    # Set executable permissions
    sudo chmod +x "$INSTALL_PATH"
    
    echo -e "${GREEN}✅ Phobos successfully installed!${NC}"
    echo ""
    echo -e "${BLUE}Usage:${NC}"
    echo "  phobos --help"
    echo "  phobos scanme.nmap.org"
    echo "  phobos -p 1-1000 target.com"
    echo ""
    echo -e "${GREEN}🎉 You can now use it without root privileges!${NC}"
    
    # Clean up temporary directory
    echo -e "${BLUE}Cleaning up...${NC}"
    cd /
    rm -rf "$TEMP_DIR"
    
    # Test
    echo -e "${BLUE}Testing...${NC}"
    if phobos --version &> /dev/null; then
        echo -e "${GREEN}✅ Test successful!${NC}"
    else
        echo -e "${RED}❌ Test failed!${NC}"
        echo "Test manually: phobos --help"
    fi
    
else
    echo -e "${RED}❌ Compilation failed! Binary not found.${NC}"
    cd /
    rm -rf "$TEMP_DIR"
    exit 1
fi

# Usage tips
echo ""
echo -e "${YELLOW}💡 Tips:${NC}"
echo "• If you get socket pool error: sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/phobos"
echo "• For faster scanning: phobos --threads 1000 target.com"
echo "• For JSON output: phobos --greppable target.com"
echo "• For top 1000 ports: phobos --top target.com"
echo ""
echo -e "${GREEN}🚀 Installation completed!${NC}"