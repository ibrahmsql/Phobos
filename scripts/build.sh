#!/bin/bash
# Cross-platform build script for ultra-scanner

set -e

echo "🚀 Building ultra-scanner for multiple platforms..."

# Create build directory
mkdir -p target/release-builds

# Build targets
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-pc-windows-gnu"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
)

# Install targets if not already installed
for target in "${TARGETS[@]}"; do
    echo "📦 Installing target: $target"
    rustup target add "$target" || true
done

# Build for each target
for target in "${TARGETS[@]}"; do
    echo "🔨 Building for $target..."
    
    if [[ "$target" == *"windows"* ]]; then
        # Windows build
        cargo build --release --target "$target"
        cp "target/$target/release/ultra-scanner.exe" "target/release-builds/ultra-scanner-$target.exe"
    else
        # Unix builds
        cargo build --release --target "$target"
        cp "target/$target/release/ultra-scanner" "target/release-builds/ultra-scanner-$target"
    fi
    
    echo "✅ Built for $target"
done

echo "🎉 All builds completed!"
echo "📁 Binaries available in: target/release-builds/"
ls -la target/release-builds/

# Create checksums
echo "🔐 Generating checksums..."
cd target/release-builds
sha256sum * > checksums.txt
echo "✅ Checksums generated"

echo "🚀 Production builds ready for deployment!"