# Project Structure & Architecture

## Directory Layout
```
phobos/
├── src/                         # Main source code
│   ├── main.rs                  # CLI entry point with argument parsing
│   ├── lib.rs                   # Library exports and common types
│   ├── config.rs                # Configuration management and validation
│   ├── error.rs                 # Error types and handling
│   ├── benchmark.rs             # Performance measurement utilities
│   ├── top_ports.rs             # Common port lists and definitions
│   ├── adaptive/                # Adaptive learning system
│   │   ├── mod.rs               # Module exports
│   │   ├── learning.rs          # Machine learning algorithms
│   │   ├── optimizer.rs         # Performance optimization
│   │   ├── predictor.rs         # Network condition prediction
│   │   └── storage.rs           # Learning data persistence
│   ├── discovery/               # Host and network discovery
│   │   ├── mod.rs               # Discovery engine coordination
│   │   ├── engine.rs            # Main discovery logic
│   │   ├── ipv6.rs              # IPv6 specific discovery
│   │   ├── methods.rs           # Discovery techniques
│   │   └── os_detection.rs      # Operating system fingerprinting
│   ├── intelligence/            # Network intelligence and analysis
│   │   ├── mod.rs               # Intelligence system exports
│   │   ├── core.rs              # Core intelligence engine
│   │   ├── asset_management.rs  # Asset tracking and management
│   │   ├── network_discovery.rs # Advanced network mapping
│   │   ├── service_detection.rs # Service identification
│   │   ├── performance.rs       # Performance analysis
│   │   └── distributed.rs       # Distributed scanning coordination
│   ├── network/                 # Network protocols and packet handling
│   │   ├── mod.rs               # Network types and enums
│   │   ├── packet.rs            # Packet crafting and parsing
│   │   ├── protocol.rs          # Protocol implementations
│   │   ├── socket.rs            # Socket management
│   │   ├── icmp.rs              # ICMP protocol handling
│   │   └── stealth.rs           # Stealth and evasion techniques
│   ├── scanner/                 # Core scanning engine
│   │   ├── mod.rs               # Scanner types and utilities
│   │   ├── engine.rs            # Main scanning engine
│   │   └── techniques.rs        # Scan technique implementations
│   ├── scripts/                 # Script execution system
│   │   ├── mod.rs               # Script system exports
│   │   ├── engine.rs            # Script execution engine
│   │   ├── executor.rs          # Script runner and manager
│   │   ├── nmap.rs              # Nmap integration
│   │   └── parser.rs            # Script output parsing
│   ├── output/                  # Output formatting and management
│   └── utils/                   # Utility modules
│       ├── mod.rs               # Utility exports
│       ├── config.rs            # Configuration utilities
│       ├── file_input.rs        # File input parsing
│       ├── profiles.rs          # Scan profile management
│       ├── target_parser.rs     # Target parsing (IP, CIDR, hostnames)
│       └── timing.rs            # Timing and rate limiting
├── tests/                       # Integration and system tests
├── benches/                     # Performance benchmarks
├── examples/                    # Usage examples
└── config.toml                  # Default configuration
```

## Architecture Patterns

### Module Organization
- **Separation of Concerns**: Each module has a single, well-defined responsibility
- **Hierarchical Structure**: Related functionality grouped under parent modules
- **Clear Interfaces**: Public APIs defined in `mod.rs` files with re-exports

### Key Architectural Principles
1. **Async-First**: All I/O operations use Tokio's async runtime
2. **Configuration-Driven**: Behavior controlled through `ScanConfig` and TOML files
3. **Modular Design**: Core functionality split into independent, testable modules
4. **Error Propagation**: Consistent error handling with `Result<T>` types
5. **Type Safety**: Extensive use of enums and structs for compile-time guarantees

### Core Data Flow
```
CLI Args → ScanConfig → ScanEngine → Network Layer → Results → Output
```

### Module Dependencies
- `main.rs` orchestrates all modules but contains minimal logic
- `config.rs` is imported by most modules for configuration access
- `network/` provides low-level primitives used by `scanner/`
- `intelligence/` builds on `scanner/` and `network/` for advanced analysis
- `output/` consumes results from all scanning modules

### Naming Conventions
- **Modules**: Snake_case (e.g., `service_detection.rs`)
- **Types**: PascalCase (e.g., `ScanConfig`, `PortResult`)
- **Functions**: Snake_case (e.g., `parse_target`, `scan_ports`)
- **Constants**: SCREAMING_SNAKE_CASE (e.g., `DEFAULT_TIMEOUT`)

### Testing Structure
- Unit tests alongside source code using `#[cfg(test)]`
- Integration tests in `tests/` directory
- Benchmarks in `benches/` directory using Criterion
- Examples in `examples/` directory for documentation