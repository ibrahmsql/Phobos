# Contributing to Phobos

Thank you for your interest in contributing to Phobos! This document provides guidelines and instructions for contributing.

## 🌟 Welcome Contributors!

We welcome contributions of all kinds:
- 🐛 Bug reports and fixes
- ✨ New features and enhancements
- 📚 Documentation improvements
- 🧪 Test coverage improvements
- 🎨 UI/UX improvements
- 🌍 Translations
- 💡 Ideas and suggestions

## 🚀 Getting Started

### Prerequisites

- **Rust 1.70+** - Install from [rustup.rs](https://rustup.rs/)
- **Git** - Version control
- **OpenCL** (optional) - For GPU acceleration
  - Linux: `sudo apt install opencl-headers ocl-icd-opencl-dev`
  - macOS: Built-in with Xcode
  - Windows: Install from your GPU vendor (NVIDIA/AMD/Intel)

### Setting Up Your Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/phobos.git
   cd phobos
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/ibrahmsql/phobos.git
   ```

4. **Build the project**:
   ```bash
   # Standard build
   cargo build
   
   # Release build with optimizations
   cargo build --release
   
   # With GPU support
   cargo build --release --features gpu
   ```

5. **Run tests**:
   ```bash
   cargo test
   cargo test --release
   ```

## 📋 Development Workflow

### 1. Create a Branch

Always create a new branch for your work:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions/improvements
- `perf/` - Performance improvements

### 2. Make Your Changes

- Write clean, readable code
- Follow Rust best practices and idioms
- Add tests for new features
- Update documentation as needed
- Keep commits atomic and focused

### 3. Code Style

We follow standard Rust formatting:

```bash
# Format your code
cargo fmt

# Check for common issues
cargo clippy -- -D warnings

# Check for all warnings
cargo clippy --all-targets --all-features -- -D warnings
```

**Code style guidelines:**
- Use `rustfmt` for consistent formatting
- Follow Rust naming conventions (snake_case for functions/variables, CamelCase for types)
- Write descriptive variable names
- Add comments for complex logic
- Use meaningful commit messages

### 4. Write Tests

All new features should include tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_your_feature() {
        // Your test code
    }
    
    #[tokio::test]
    async fn test_async_feature() {
        // Async test code
    }
}
```

Run tests before submitting:
```bash
cargo test --all-features
cargo test --release
```

### 5. Update Documentation

- Add/update doc comments for public APIs
- Update README.md if needed
- Add examples for new features
- Update CHANGELOG.md

Doc comment example:
```rust
/// Scans the specified target for open ports
///
/// # Arguments
///
/// * `target` - The IP address or hostname to scan
/// * `ports` - List of ports to scan
///
/// # Returns
///
/// A `Result` containing the scan results or an error
///
/// # Examples
///
/// ```
/// use phobos::ScanEngine;
/// 
/// let engine = ScanEngine::new(config);
/// let results = engine.scan("192.168.1.1", &[80, 443]).await?;
/// ```
pub async fn scan(&self, target: &str, ports: &[u16]) -> Result<ScanResult>
```

### 6. Commit Your Changes

Write clear, descriptive commit messages:

```bash
git add .
git commit -m "feat: add stealth scan timing profiles

- Implement paranoid, sneaky, and polite timing modes
- Add tests for timing profiles
- Update documentation"
```

**Commit message format:**
```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Test additions/changes
- `perf:` - Performance improvements
- `chore:` - Build process or auxiliary tool changes

### 7. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create a Pull Request on GitHub
```

## 🧪 Testing Guidelines

### Unit Tests

Test individual functions and components:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_parsing() {
        let ports = parse_port_range("80,443,8080-8090");
        assert_eq!(ports.len(), 13);
    }
}
```

### Integration Tests

Test complete workflows in `tests/` directory:

```rust
#[tokio::test]
async fn test_full_scan_workflow() {
    let config = ScanConfig::default();
    let engine = ScanEngine::new(config);
    let results = engine.scan("scanme.nmap.org", &[80, 443]).await;
    assert!(results.is_ok());
}
```

### Benchmark Tests

Performance-critical code should have benchmarks:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_port_scan(c: &mut Criterion) {
    c.bench_function("scan 1000 ports", |b| {
        b.iter(|| {
            // Your benchmark code
        })
    });
}

criterion_group!(benches, benchmark_port_scan);
criterion_main!(benches);
```

## 🔍 Code Review Process

1. **Automated Checks**: CI/CD will run tests and linting
2. **Manual Review**: Maintainers will review your code
3. **Feedback**: Address any requested changes
4. **Approval**: Once approved, your PR will be merged

### What We Look For

- ✅ Code quality and readability
- ✅ Test coverage
- ✅ Documentation
- ✅ Performance implications
- ✅ Security considerations
- ✅ Backward compatibility

## 📝 Documentation Standards

### Code Documentation

Use Rust doc comments (`///` or `//!`):

```rust
//! Module-level documentation

/// Function documentation
///
/// # Arguments
/// # Returns
/// # Errors
/// # Examples
/// # Panics (if applicable)
/// # Safety (if applicable for unsafe code)
```

### README Updates

Update README.md when:
- Adding new features
- Changing CLI arguments
- Modifying installation instructions
- Updating performance benchmarks

### Changelog

Add entries to CHANGELOG.md for all notable changes:

```markdown
## [Unreleased]

### Added
- New feature description

### Changed
- Changed feature description

### Fixed
- Bug fix description

### Deprecated
- Deprecated feature description
```

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Description**: Clear description of the bug
2. **Steps to Reproduce**: Minimal steps to reproduce
3. **Expected Behavior**: What should happen
4. **Actual Behavior**: What actually happens
5. **Environment**:
   - OS and version
   - Rust version (`rustc --version`)
   - Phobos version
   - Relevant configuration
6. **Logs**: Error messages and logs
7. **Additional Context**: Screenshots, etc.

Use the bug report template when creating issues.

## 💡 Feature Requests

For feature requests, please include:

1. **Problem Statement**: What problem does this solve?
2. **Proposed Solution**: How should it work?
3. **Alternatives Considered**: Other approaches you've considered
4. **Use Cases**: Real-world scenarios
5. **Impact**: Who benefits and how?

## 🔒 Security Issues

**DO NOT** report security vulnerabilities publicly!

Instead:
1. Email security issues to: **ibrahimsql@proton.me**
2. Include "SECURITY" in the subject line
3. Provide detailed information about the vulnerability
4. Allow reasonable time for a fix before disclosure

See [SECURITY.md](SECURITY.md) for more details.

## 📦 Release Process

Releases are managed by maintainers:

1. Version bump in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create git tag: `git tag -a v1.2.0 -m "Release v1.2.0"`
4. Push tag: `git push origin v1.2.0`
5. CI/CD builds and publishes binaries
6. Create GitHub release with notes

## 🤝 Community

- **GitHub Discussions**: For questions and discussions
- **Issues**: For bug reports and feature requests
- **Pull Requests**: For code contributions

### Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Assume good intentions
- Keep discussions on-topic

## 🎓 Learning Resources

### Rust Resources
- [The Rust Book](https://doc.rust-lang.org/book/)
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/)
- [Async Book](https://rust-lang.github.io/async-book/)

### Network Programming
- [TCP/IP Guide](http://www.tcpipguide.com/)
- [Nmap Book](https://nmap.org/book/)
- [Raw Sockets Programming](https://www.cs.dartmouth.edu/~sergey/cs60/raw-sockets-guide.pdf)

### Testing
- [Rust Testing Guide](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Criterion.rs Benchmarking](https://github.com/bheisler/criterion.rs)

## ❓ Questions?

If you have questions:
1. Check existing [documentation](README.md)
2. Search [closed issues](https://github.com/ibrahmsql/phobos/issues?q=is%3Aissue+is%3Aclosed)
3. Ask in [GitHub Discussions](https://github.com/ibrahmsql/phobos/discussions)
4. Create a new issue if needed

## 🌟 Recognition

Contributors will be recognized in:
- README.md Contributors section
- Release notes
- GitHub contributors graph

Thank you for contributing to Phobos! 🚀

---

*Let your contributions make ports tremble.* ⚡
