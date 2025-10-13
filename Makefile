# Phobos Port Scanner Makefile
# This Makefile provides convenient commands for building, testing, and managing Phobos

.PHONY: help build release build-nogpu release-nogpu test clean install uninstall fmt clippy bench audit run dev setup docs

# Default target
help:
	@echo "🔥 Phobos Port Scanner - Makefile Commands"
	@echo ""
	@echo "📦 Build Commands:"
	@echo "  make build       - Build debug version (with GPU)"
	@echo "  make release     - Build optimized release version (with GPU)"
	@echo "  make build-nogpu - Build debug version (without GPU)"
	@echo "  make release-nogpu - Build release version (without GPU)"
	@echo "  make install     - Install Phobos globally (with GPU)"
	@echo "  make uninstall   - Uninstall Phobos"
	@echo ""
	@echo "🧪 Testing Commands:"
	@echo "  make test      - Run all tests"
	@echo "  make bench     - Run benchmarks"
	@echo "  make audit     - Security audit"
	@echo ""
	@echo "🔧 Development Commands:"
	@echo "  make fmt       - Format code"
	@echo "  make clippy    - Run clippy linter"
	@echo "  make dev       - Development build with watch"
	@echo "  make setup     - Setup development environment"
	@echo ""
	@echo "🍺 Homebrew Commands:"
	@echo "  make homebrew-audit - Audit Homebrew formula"
	@echo "  make homebrew-test  - Test Homebrew installation"
	@echo "  make homebrew-uninstall - Uninstall via Homebrew"
	@echo "  make homebrew-clean - Clean Homebrew cache"
	@echo "  make package        - Create distribution package"
	@echo ""
	@echo "🚀 Usage Commands:"
	@echo "  make run TARGET=<target> PORTS=<ports> - Run Phobos"
	@echo "  make example   - Run example scan"
	@echo ""
	@echo "📚 Documentation:"
	@echo "  make docs      - Generate documentation"
	@echo ""
	@echo "🧹 Cleanup:"
	@echo "  make clean     - Clean build artifacts"

# Build commands
build:
	@echo "🔨 Building Phobos (debug) with GPU acceleration..."
	cargo build --features gpu
	@echo "✅ Build complete with GPU support!"

release:
	@echo "🚀 Building Phobos (release) with GPU acceleration..."
	cargo build --release --features gpu
	@echo "✅ Release build complete with GPU support!"
	@echo "📍 Binary location: ./target/release/phobos"

# Build without GPU (for normal cargo-compatible builds)
build-nogpu:
	@echo "🔨 Building Phobos (debug) without GPU..."
	cargo build
	@echo "✅ Build complete without GPU!"

release-nogpu:
	@echo "🚀 Building Phobos (release) without GPU..."
	cargo build --release
	@echo "✅ Release build complete without GPU!"
	@echo "📍 Binary location: ./target/release/phobos"

# Installation commands
install: release
	@echo "📦 Installing Phobos with GPU support..."
	cargo install --path . --features gpu
	@echo "✅ Phobos installed globally with GPU support!"
	@echo "💡 You can now run 'phobos' from anywhere"

uninstall:
	@echo "🗑️  Uninstalling Phobos..."
	cargo uninstall phobos
	@echo "✅ Phobos uninstalled!"

# Testing commands
test:
	@echo "🧪 Running tests..."
	cargo test
	@echo "✅ All tests passed!"

test-verbose:
	@echo "🧪 Running tests (verbose)..."
	cargo test -- --nocapture

bench:
	@echo "📊 Running benchmarks..."
	cargo bench
	@echo "✅ Benchmarks complete!"

audit:
	@echo "🔒 Running security audit..."
	cargo audit
	@echo "✅ Security audit complete!"

# Development commands
fmt:
	@echo "🎨 Formatting code..."
	cargo fmt
	@echo "✅ Code formatted!"

fmt-check:
	@echo "🎨 Checking code format..."
	cargo fmt -- --check

clippy:
	@echo "📎 Running clippy..."
	cargo clippy -- -D warnings
	@echo "✅ Clippy checks passed!"

dev:
	@echo "👨‍💻 Starting development mode..."
	cargo watch -x "build"

setup:
	@echo "🛠️  Setting up development environment..."
	@echo "📦 Installing required tools..."
	cargo install cargo-watch cargo-audit
	@echo "✅ Development environment ready!"

# Documentation
docs:
	@echo "📚 Generating documentation..."
	cargo doc --open
	@echo "✅ Documentation generated!"

# Usage commands
run:
	@echo "🚀 Running Phobos..."
	@if [ -z "$(TARGET)" ]; then \
		echo "❌ Please specify TARGET: make run TARGET=example.com"; \
		exit 1; \
	fi
	@if [ -n "$(PORTS)" ]; then \
		cargo run -- $(TARGET) -p $(PORTS); \
	else \
		cargo run -- $(TARGET); \
	fi

example:
	@echo "🎯 Running example scan..."
	cargo run -- scanme.nmap.org -p 22,80,443

example-fast:
	@echo "⚡ Running fast example scan..."
	cargo run -- scanme.nmap.org -p 80,443 -s syn -T 4

example-stealth:
	@echo "🥷 Running stealth example scan..."
	cargo run -- scanme.nmap.org -p 80,443 --stealth

# Cleanup
clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean
	@echo "✅ Clean complete!"

clean-all: clean
	@echo "🧹 Cleaning all artifacts including dependencies..."
	rm -rf target/
	rm -f Cargo.lock
	@echo "✅ Deep clean complete!"

# Release preparation
prepare-release: fmt clippy test audit
	@echo "🚀 Preparing for release..."
	@echo "✅ All checks passed! Ready for release."

# CI/CD simulation
ci: fmt-check clippy test audit
	@echo "🤖 CI checks complete!"

# Quick development cycle
quick: fmt clippy test
	@echo "⚡ Quick development cycle complete!"

# Performance testing
perf-test:
	@echo "📈 Running performance tests..."
	cargo build --release
	@echo "Testing against scanme.nmap.org..."
	time ./target/release/phobos scanme.nmap.org -p 1-1000

# Help for specific commands
help-run:
	@echo "🚀 Run Command Help:"
	@echo ""
	@echo "Usage: make run TARGET=<target> [PORTS=<ports>]"
	@echo ""
	@echo "Examples:"
	@echo "  make run TARGET=example.com"
	@echo "  make run TARGET=192.168.1.1 PORTS=22,80,443"
	@echo "  make run TARGET=10.0.0.1 PORTS=1-1000"

# Version info
version:
	@echo "📋 Phobos Version Information:"
	@echo "Phobos: $(shell cargo pkgid | cut -d# -f2)"
	@echo "Rust: $(shell rustc --version)"
	@echo "Cargo: $(shell cargo --version)"

# Homebrew related commands
homebrew-audit:
	@echo "🍺 Running Homebrew formula audit..."
	@./scripts/homebrew_audit.sh

homebrew-test:
	@echo "🧪 Testing Homebrew formula..."
	@brew install --build-from-source --verbose ./phobos.rb

homebrew-uninstall:
	@echo "🗑️  Uninstalling Homebrew formula..."
	@brew uninstall phobos || true

homebrew-clean:
	@echo "🧹 Cleaning Homebrew cache..."
	@brew cleanup phobos || true

# Package for distribution
package:
	@echo "📦 Creating distribution package..."
	@mkdir -p dist
	@tar -czf dist/phobos-$(shell cargo pkgid | cut -d# -f2).tar.gz \
		--exclude=target \
		--exclude=dist \
		--exclude=.git \
		.
	@echo "✅ Package created: dist/phobos-$(shell cargo pkgid | cut -d# -f2).tar.gz"

# All-in-one commands
all: clean build test
	@echo "🎉 Full build cycle complete!"

check-all: fmt-check clippy test audit
	@echo "✅ All quality checks passed!"