# Phobos Justfile - Build automation commands

# Build the project in release mode
build:
    cargo build --release

# Run tests
test:
    cargo test

# Run benchmarks
bench:
    cargo bench

# Format code
fmt:
    cargo fmt

# Check code with clippy
clippy:
    cargo clippy -- -D warnings

# Clean build artifacts
clean:
    cargo clean

# Run Phobos with default settings
run target="127.0.0.1" ports="1-1000":
    cargo run --release -- {{target}} -p {{ports}}

# Run Phobos with open ports only
run-open target="127.0.0.1" ports="1-1000":
    cargo run --release -- {{target}} -p {{ports}} --open

# Install Phobos locally
install:
    cargo install --path .

# Check project health
check:
    cargo check
    cargo fmt --check
    cargo clippy -- -D warnings
    cargo test

# Development workflow
dev:
    just fmt
    just clippy
    just test
    just build

# Quick scan localhost
scan-local:
    cargo run --release -- 127.0.0.1 -p 1-10000 --open

# Performance test
perf-test:
    cargo run --release -- 127.0.0.1 -p 1-65535 --threads 1000