{ lib
, rustPlatform
, fetchFromGitHub
, pkg-config
, openssl
, libpcap
, stdenv
, darwin
}:

rustPlatform.buildRustPackage rec {
  pname = "phobos";
  version = "1.0.0";

  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    openssl
    libpcap
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.Security
    darwin.apple_sdk.frameworks.SystemConfiguration
  ];

  # Environment variables for OpenSSL
  OPENSSL_NO_VENDOR = 1;
  PKG_CONFIG_PATH = "${openssl.dev}/lib/pkgconfig";

  # Post-install setup
  postInstall = ''
    # Create installation script for Linux
    mkdir -p $out/share/phobos
    cat > $out/share/phobos/setup-linux.sh << 'EOF'
#!/bin/bash
# Phobos Linux Setup Script

set -e

echo "🚀 Setting up Phobos for Linux..."

# Find phobos binary
PHOBOS_BIN=$(which phobos 2>/dev/null || echo "$out/bin/phobos")

if [[ ! -f "$PHOBOS_BIN" ]]; then
    echo "❌ Phobos binary not found."
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
fi

echo ""
echo "📖 Usage Examples:"
echo "   phobos 192.168.1.1 -p 1-1000    # Scan ports 1-1000"
echo "   phobos 10.0.0.0/24 --top-ports  # Scan top ports on subnet"
echo "   phobos --help                   # Show all options"
EOF
    chmod +x $out/share/phobos/setup-linux.sh
    
    # Create man page
    mkdir -p $out/share/man/man1
    cat > $out/share/man/man1/phobos.1 << 'EOF'
.TH PHOBOS 1 "2024" "phobos 1.0.0" "User Commands"
.SH NAME
phobos \- blazingly fast Rust-based port scanner
.SH SYNOPSIS
.B phobos
[\fIOPTIONS\fR] \fITARGET\fR
.SH DESCRIPTION
Phobos is a high-performance port scanner written in Rust that aims to be faster than Nmap and Masscan while maintaining accuracy and reliability.
.SH OPTIONS
.TP
\fB\-p\fR, \fB\-\-ports\fR \fIPORTS\fR
Specify ports to scan (e.g., 1-1000, 80,443,8080)
.TP
\fB\-\-top\-ports\fR
Scan the most common ports
.TP
\fB\-t\fR, \fB\-\-threads\fR \fINUM\fR
Number of threads to use
.TP
\fB\-\-timeout\fR \fIMILLIS\fR
Connection timeout in milliseconds
.TP
\fB\-h\fR, \fB\-\-help\fR
Show help message
.SH EXAMPLES
.TP
Scan common ports on a single host:
\fBphobos 192.168.1.1\fR
.TP
Scan specific port range:
\fBphobos 192.168.1.1 -p 1-1000\fR
.TP
Scan subnet with top ports:
\fBphobos 10.0.0.0/24 --top-ports\fR
.SH AUTHOR
Written by ibrahimsql.
.SH REPORTING BUGS
Report bugs to: https://github.com/ibrahmsql/phobos/issues
.SH COPYRIGHT
Copyright © 2024 ibrahimsql. License MIT.
EOF
  '';

  meta = with lib; {
    description = "Phobos: The Blazingly Fast Rust-Based Port Scanner That Outspeeds Nmap & Masscan";
    longDescription = ''
      Phobos is a high-performance port scanner written in Rust that combines speed,
      accuracy, and modern features. It supports multiple scan techniques including
      TCP Connect, SYN, FIN, and UDP scans with automatic fallback mechanisms for
      maximum compatibility across different systems.
      
      Key features:
      - Blazingly fast scanning with async/await architecture
      - Multiple scan techniques (TCP Connect, SYN, FIN, UDP)
      - Automatic privilege detection and fallback
      - Real-time progress reporting
      - Service detection and OS fingerprinting
      - Multiple output formats (JSON, XML, CSV)
      - Cross-platform compatibility (Linux, macOS, Windows)
    '';
    homepage = "https://github.com/ibrahmsql/phobos";
    license = licenses.mit;
    maintainers = [ "ibrahimsql" ];
    platforms = platforms.unix;
    mainProgram = "phobos";
  };
}