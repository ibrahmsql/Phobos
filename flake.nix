{
  description = "Phobos: The Blazingly Fast Rust-Based Port Scanner That Outspeeds Nmap & Masscan";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "clippy" "rustfmt" ];
        };

        # Build dependencies
        buildInputs = with pkgs; [
          openssl
          pkg-config
          libpcap
        ] ++ lib.optionals stdenv.isDarwin [
          darwin.apple_sdk.frameworks.Security
          darwin.apple_sdk.frameworks.SystemConfiguration
        ];

        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
        ];

      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "phobos";
          version = "1.0.0";
          
          src = ./.;
          
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
          
          inherit buildInputs nativeBuildInputs;
          
          # Environment variables for OpenSSL
          OPENSSL_NO_VENDOR = 1;
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
          
          # Post-install setup for Linux capabilities
          postInstall = ''
            # Create wrapper script for automatic capability setup
            mkdir -p $out/share/phobos
            cat > $out/share/phobos/install-linux.sh << 'EOF'
#!/bin/bash
# Phobos Linux Installation Script
# Automatically sets up required capabilities for raw socket access

set -e

echo "🚀 Setting up Phobos for Linux..."

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "⚠️  Running as root. Consider using regular user with setcap instead."
fi

# Find phobos binary
PHOBOS_BIN=$(which phobos 2>/dev/null || echo "$out/bin/phobos")

if [[ ! -f "$PHOBOS_BIN" ]]; then
    echo "❌ Phobos binary not found. Please ensure it's installed."
    exit 1
fi

echo "📍 Found Phobos at: $PHOBOS_BIN"

# Set capabilities for raw socket access
echo "🔧 Setting up raw socket capabilities..."
if command -v setcap >/dev/null 2>&1; then
    if sudo setcap cap_net_raw,cap_net_admin+eip "$PHOBOS_BIN"; then
        echo "✅ Raw socket capabilities set successfully!"
        echo "🎉 Phobos is now ready for high-performance scanning!"
    else
        echo "⚠️  Failed to set capabilities. You may need to run Phobos with sudo."
    fi
else
    echo "⚠️  setcap not found. Please install libcap2-bin package."
    echo "   Ubuntu/Debian: sudo apt install libcap2-bin"
    echo "   CentOS/RHEL: sudo yum install libcap"
fi

echo ""
echo "📖 Usage:"
echo "   phobos 192.168.1.1 -p 1-1000    # Scan ports 1-1000"
echo "   phobos 10.0.0.0/24 --top-ports  # Scan top ports on subnet"
echo "   phobos --help                   # Show all options"
echo ""
echo "🔗 Documentation: https://github.com/ibrahmsql/phobos"
EOF
            chmod +x $out/share/phobos/install-linux.sh
            
            # Create desktop entry
            mkdir -p $out/share/applications
            cat > $out/share/applications/phobos.desktop << 'EOF'
[Desktop Entry]
Name=Phobos Port Scanner
Comment=Blazingly Fast Rust-Based Port Scanner
Exec=phobos
Icon=network-wired
Terminal=true
Type=Application
Categories=Network;Security;System;
Keywords=port;scanner;network;security;nmap;
EOF
          '';
          
          meta = with pkgs.lib; {
            description = "Phobos: The Blazingly Fast Rust-Based Port Scanner That Outspeeds Nmap & Masscan";
            homepage = "https://github.com/ibrahmsql/phobos";
            license = licenses.mit;
            maintainers = [ "ibrahimsql" ];
            platforms = platforms.unix;
            mainProgram = "phobos";
          };
        };
        
        # Development shell
        devShells.default = pkgs.mkShell {
          inherit buildInputs;
          nativeBuildInputs = nativeBuildInputs ++ (with pkgs; [
            cargo-watch
            cargo-edit
            cargo-audit
            cargo-outdated
            rust-analyzer
          ]);
          
          shellHook = ''
            echo "🚀 Phobos Development Environment"
            echo "📦 Rust version: $(rustc --version)"
            echo "🔧 Available commands:"
            echo "   cargo build --release  # Build optimized binary"
            echo "   cargo test             # Run tests"
            echo "   cargo bench            # Run benchmarks"
            echo "   cargo watch -x check   # Watch for changes"
            echo ""
          '';
        };
        
        # Apps for easy running
        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };
      }
    );
}