# Phobos Modular Architecture Design

## Overview

The Scanner Trait System provides a clean, extensible architecture for implementing different scanning techniques.

## Core Concepts

### 1. PortScanner Trait

The universal interface all scanners must implement:

```rust
#[async_trait]
pub trait PortScanner: Send + Sync {
    async fn scan_port(&self, target: IpAddr, port: u16) -> Result<PortResult, ScanError>;
    async fn scan_ports(&self, target: IpAddr, ports: &[u16]) -> Vec<Result<PortResult, ScanError>>;
    fn name(&self) -> &str;
    fn capabilities(&self) -> ScannerCapabilities;
    fn can_run(&self) -> Result<(), String>;
}
```

### 2. Scanner Implementations

#### TCP Connect Scanner
- **No privileges required**
- **Cross-platform**
- **IPv6 support**
- **Batch size: 10,000**

#### SYN Scanner (Stealth)
- **Requires root/admin**
- **Faster than TCP Connect**
- **Less detectable**
- **Batch size: 50,000**

### 3. Scanner Factory

Automatic scanner selection based on privileges:

```rust
let scanner = ScannerFactory::create_best_scanner(timeout);
// Returns SYN scanner if root, TCP Connect otherwise
```

## Benefits

1. **Extensibility**: Easy to add new scan techniques
2. **Testability**: Mock scanners for unit tests
3. **Type Safety**: Compile-time guarantees
4. **Performance**: Zero-cost abstractions
5. **Maintainability**: Clean separation of concerns

## Usage Examples

### Basic Usage

```rust
use phobos::core::{ScannerFactory, PortScanner};

let scanner = ScannerFactory::create_best_scanner(Duration::from_secs(1));
let result = scanner.scan_port("192.168.1.1".parse().unwrap(), 80).await?;

if result.state == PortState::Open {
    println!("Port 80 is open!");
}
```

### Batch Scanning

```rust
let ports = vec![80, 443, 8080, 8443];
let results = scanner.scan_ports(target_ip, &ports).await;

for result in results {
    if let Ok(port_result) = result {
        println!("{}: {:?}", port_result.port, port_result.state);
    }
}
```

### Custom Scanner

```rust
pub struct CustomScanner;

#[async_trait]
impl PortScanner for CustomScanner {
    async fn scan_port(&self, target: IpAddr, port: u16) -> Result<PortResult, ScanError> {
        // Custom implementation
    }
    
    fn name(&self) -> &str { "Custom" }
    fn capabilities(&self) -> ScannerCapabilities { /* ... */ }
}
```

## Migration Path

### Phase 1: Core Traits ✅
- [x] Define PortScanner trait
- [x] Implement TCP Connect scanner
- [x] Create scanner factory

### Phase 2: Integration (Next)
- [ ] Integrate with existing ScanEngine
- [ ] Add UDP scanner trait
- [ ] Plugin system for custom scanners

### Phase 3: Optimization (Future)
- [ ] Parallel scanner execution
- [ ] Result caching
- [ ] Performance profiling

## File Structure

```
src/
├── core/
│   ├── mod.rs
│   └── scanner_trait.rs    # Core trait definitions
├── scanners/
│   ├── mod.rs
│   ├── tcp_connect.rs      # TCP Connect implementation
│   ├── syn_scanner.rs      # SYN stealth implementation
│   └── udp_scanner.rs      # UDP implementation
└── scanner/
    └── engine.rs           # Existing engine (to be refactored)
```

## Testing

```bash
# Run modular architecture tests
cargo test --lib core::scanner_trait

# Test specific scanner
cargo test tcp_connect_scanner
```

## Performance

The trait-based design has **zero runtime overhead** due to:
- Static dispatch when scanner type is known
- Dynamic dispatch (`Arc<dyn PortScanner>`) only when needed
- Compiler optimizations (inlining, etc.)

---

**Status**: Core traits implemented  
**Next**: Integration with ScanEngine
