# Technology Stack & Build System

## Core Technologies
- **Language**: Rust 2021 edition (minimum 1.70+)
- **Async Runtime**: Tokio with full feature set for high-performance networking
- **CLI Framework**: Clap v4 with derive macros for argument parsing
- **Serialization**: Serde with JSON/TOML support for configuration and output
- **Network**: pnet for packet crafting, socket2 for low-level socket operations
- **Concurrency**: Rayon for CPU-bound parallelism, async-trait for trait objects

## Key Dependencies
```toml
tokio = { version = "1.0", features = ["full"] }
pnet = "0.33"                    # Packet crafting and network interfaces
socket2 = "0.5"                  # Low-level socket operations
clap = { version = "4.0", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
colored = "2.0"                  # Terminal colors
indicatif = "0.17"              # Progress bars
```

## Build System
The project uses both **Cargo** (primary) and **Make/Just** (convenience):

### Common Commands
```bash
# Development
cargo build                      # Debug build
cargo build --release           # Optimized release build
cargo test                      # Run all tests
cargo bench                     # Run benchmarks

# Using Make
make build                      # Debug build with status messages
make release                    # Release build with location info
make test                       # Tests with colored output
make install                    # Global installation

# Using Just
just build                      # Release build
just dev                        # Full development workflow
just check                      # Code quality checks
```

## Performance Optimizations
- **Release Profile**: LTO enabled, single codegen unit, panic=abort, stripped binaries
- **Thread Management**: Default 4500 concurrent connections, auto-calculated batch sizes
- **Rate Limiting**: 10M packets/second default for ultra-fast scanning
- **Memory**: Aggressive batch sizing (up to 2000 ports per batch)

## Code Organization
- Modular architecture with clear separation of concerns
- Async-first design throughout the codebase
- Error handling with `thiserror` and `anyhow`
- Configuration-driven behavior with TOML support
- Extensive use of Rust's type system for safety

## Development Tools
- **Formatting**: `cargo fmt` (required before commits)
- **Linting**: `cargo clippy -- -D warnings` (zero warnings policy)
- **Testing**: Unit tests, integration tests, and benchmarks
- **Documentation**: `cargo doc` for API documentation