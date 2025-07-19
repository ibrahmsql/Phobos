{ pkgs ? import <nixpkgs> {
    overlays = [
      (import (fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz"))
    ];
  }
}:

let
  rustToolchain = pkgs.rust-bin.stable.latest.default.override {
    extensions = [ "rust-src" "clippy" "rustfmt" ];
  };
in

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Rust toolchain
    rustToolchain
    
    # Build dependencies
    openssl
    pkg-config
    libpcap
    
    # Development tools
    cargo-watch
    cargo-edit
    cargo-audit
    cargo-outdated
    rust-analyzer
    
    # System tools
    git
    curl
    wget
    
    # Optional: for cross-compilation
    gcc
    
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.Security
    darwin.apple_sdk.frameworks.SystemConfiguration
  ];
  
  # Environment variables
  OPENSSL_NO_VENDOR = 1;
  PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
  RUST_BACKTRACE = 1;
  
  shellHook = ''
    echo "🚀 Phobos Development Environment (Legacy Nix)"
    echo "📦 Rust version: $(rustc --version)"
    echo "🔧 Available commands:"
    echo "   cargo build --release  # Build optimized binary"
    echo "   cargo test             # Run tests"
    echo "   cargo bench            # Run benchmarks"
    echo "   cargo watch -x check   # Watch for changes"
    echo "   cargo audit            # Security audit"
    echo "   cargo outdated         # Check for updates"
    echo ""
    echo "📖 Documentation: https://github.com/ibrahmsql/phobos"
    echo ""
    
    # Check for Linux and suggest capability setup
    if [[ "$(uname)" == "Linux" ]]; then
      echo "🐧 Linux detected. For optimal performance:"
      echo "   sudo setcap cap_net_raw,cap_net_admin+eip ./target/release/phobos"
      echo "   Or run: ./install_linux.sh"
      echo ""
    fi
  '';
}