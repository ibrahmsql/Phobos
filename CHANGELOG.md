# Changelog

All notable changes to Phobos will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive documentation (CONTRIBUTING.md, GPU_ACCELERATION.md, SECURITY.md)
- Shell completion scripts for Bash, Zsh, and Fish
- Man pages for Unix systems
- Example configuration files
- Profiling and performance guides
- Platform-specific installers

### Changed
- Improved GPU acceleration documentation
- Enhanced code formatting standards

### Fixed
- Documentation references to missing files

## [1.1.1] - 2024-10-21

### Added
- **World's First GPU-Accelerated Port Scanner** 🎮
  - OpenCL-based GPU acceleration for 10x-50x faster scanning
  - Support for NVIDIA, AMD, Intel, and Apple Silicon GPUs
  - Automatic GPU detection and optimal batch sizing
  - GPU memory management and multi-GPU support (experimental)
- **Advanced Stealth Scanning** 👻
  - Shadow scan mode for near-invisible detection evasion
  - Firewall evasion techniques (fragmentation, decoy scanning)
  - Randomized scan order and timing profiles
  - Custom source port and interface selection
- **Intelligent Adaptive Scanning** 🧠
  - Machine learning-based network condition detection
  - Automatic parameter adjustment for optimal performance
  - Target type recognition (cloud, enterprise, IoT, etc.)
  - Learning insights and recommendations
- **Enhanced Network Intelligence** 🌐
  - Advanced OS fingerprinting and detection
  - Service version detection
  - Network topology mapping
  - Security posture assessment
- **Script Engine System** 📜
  - Nmap NSE-style script execution
  - Custom script support with Lua integration
  - Pre-built scripts for common vulnerabilities
  - Adaptive script selection based on detected services
- **Phobos Fear Modes** 😱
  - Wrath mode: Maximum aggression with evasion
  - Shadow mode: Ultra-stealth scanning
  - Multiple timing profiles (0-5)
  - Custom stealth levels
- **Multi-Format Output Support** 📊
  - Text, JSON, XML, CSV, Nmap-compatible formats
  - Greppable output for scripting
  - Custom output templates
  - Real-time streaming results
- **Target Input Flexibility** 🎯
  - IPv4 and IPv6 support
  - CIDR notation for subnet scanning
  - Hostname resolution with DNS lookup
  - File input (TXT, CSV, JSON, Nmap XML)
  - IP range support with exclusions
- **Advanced Configuration** ⚙️
  - Profile system (stealth, aggressive, comprehensive, quick)
  - TOML configuration files
  - Environment variable support
  - Command-line override options

### Changed
- **Performance Optimizations** ⚡
  - Native CPU optimization (AVX2, AES, SSE4.2)
  - Ultra-fast batch processing (15000 ports/batch)
  - Intelligent timeout handling
  - Memory-efficient streaming architecture
  - Adaptive rate limiting (10M PPS default)
- **Improved Error Handling** 🛡️
  - Comprehensive error types and messages
  - Graceful degradation on failures
  - Better permission error messages
  - Network error recovery
- **Enhanced User Interface** 🎨
  - Colored terminal output
  - Real-time progress indicators with ETA
  - Accessible mode for screen readers
  - Verbose and quiet modes
  - Beautiful ASCII art banner

### Fixed
- Memory leaks in long-running scans
- Race conditions in concurrent scanning
- UDP scan accuracy improvements
- IPv6 scanning edge cases
- Port range parsing corner cases
- Configuration file loading issues

### Security
- Raw socket permission checks
- Input validation for all user inputs
- Safe handling of network errors
- Sandboxed script execution
- Secure temporary file handling

## [1.0.0] - 2024-08-15

### Added
- Initial public release
- **Core Scanning Engine** 🚀
  - TCP Connect scan
  - SYN Stealth scan
  - UDP scan
  - Multi-threaded async architecture
- **Basic Features**
  - Port range specification
  - Top 1000 ports scanning
  - Service detection
  - Timing templates
  - Nmap integration
- **Output Formats**
  - Text output
  - JSON format
  - Greppable format
- **Configuration**
  - Command-line arguments
  - Basic config file support
- **Platform Support**
  - Linux (x86_64, aarch64)
  - macOS (x86_64, arm64)
  - Windows (x86_64)

### Performance
- Scans 1000 ports in < 1 second
- Full 65535 port scan in ~15 seconds
- 10x faster than traditional Nmap
- Memory efficient (< 20MB RAM usage)

## [0.9.0] - 2024-07-01 (Beta)

### Added
- Beta release for testing
- Core port scanning functionality
- TCP and UDP support
- Basic output formats
- Simple configuration

### Known Issues
- Limited platform support
- No GPU acceleration yet
- Basic stealth features
- Performance not fully optimized

## [0.5.0] - 2024-05-15 (Alpha)

### Added
- Alpha release for early adopters
- Proof of concept implementation
- Basic TCP scanning
- Command-line interface
- Experimental features

### Known Issues
- Unstable API
- Limited testing
- Performance issues
- Missing features

## [0.1.0] - 2024-03-01 (Initial Development)

### Added
- Project initialization
- Basic Rust project structure
- Core dependencies
- Development environment setup

---

## Version History Summary

| Version | Release Date | Status | Major Changes |
|---------|--------------|--------|---------------|
| 1.1.1   | 2024-10-21   | **Current** | GPU acceleration, advanced stealth, adaptive scanning |
| 1.0.0   | 2024-08-15   | Stable | Initial public release, core features |
| 0.9.0   | 2024-07-01   | Beta | Testing phase |
| 0.5.0   | 2024-05-15   | Alpha | Early preview |
| 0.1.0   | 2024-03-01   | Dev | Initial development |

## Upgrade Guide

### From 1.0.x to 1.1.x

**Breaking Changes:**
- None! Fully backward compatible.

**New Features:**
```bash
# GPU acceleration (automatic if detected)
phobos target.com -p 1-65535

# Shadow scan mode
phobos target.com --shadow

# Wrath mode
phobos target.com --wrath

# Adaptive scanning
phobos target.com --adaptive
```

**Configuration Changes:**
- New GPU-related options in config files
- Enhanced stealth configuration
- Script engine configuration

**Migration Steps:**
1. Rebuild with GPU support: `cargo build --release --features gpu`
2. Update config files with new options (optional)
3. Install new shell completions (optional)
4. Read GPU_ACCELERATION.md for GPU setup

### From 0.9.x to 1.0.x

**Breaking Changes:**
- Config file format changed from INI to TOML
- Some CLI arguments renamed for consistency
- Output format structure modified

**Migration Steps:**
1. Convert config files to TOML format
2. Update CLI scripts with new argument names
3. Adjust output parsing if using JSON/XML formats

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute changes.

## Release Process

1. Update version in `Cargo.toml`
2. Update CHANGELOG.md with changes
3. Commit: `git commit -am "Release v1.x.x"`
4. Tag: `git tag -a v1.x.x -m "Release v1.x.x"`
5. Push: `git push origin main --tags`
6. CI/CD automatically builds and publishes

## Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/ibrahmsql/phobos/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/ibrahmsql/phobos/discussions)
- 📧 **Email**: ibrahimsql@proton.me

---

**Let your changelog tell the story of fear.** ⚡
