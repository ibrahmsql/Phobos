# 🤝 Contributing to Phobos

Thank you for your interest in contributing to Phobos! We welcome contributions from the community and are excited to see what you'll bring to the project.

## 🚀 Quick Start

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/yourusername/phobos.git`
3. **Create** a new branch: `git checkout -b feature/your-feature-name`
4. **Make** your changes
5. **Test** your changes: `cargo test`
6. **Commit** your changes: `git commit -m "Add your feature"`
7. **Push** to your fork: `git push origin feature/your-feature-name`
8. **Create** a Pull Request

## 🛠️ Development Setup

### Prerequisites
- Rust 1.70 or later
- Git
- A text editor or IDE

### Setup
```bash
# Clone the repository
git clone https://github.com/ibrahmsql/phobos.git
cd phobos

# Build the project
cargo build

# Run tests
cargo test

# Run with sample target
cargo run -- scanme.nmap.org -p 80,443
```

## 📋 Development Guidelines

### Code Style
- Follow Rust conventions and idioms
- Use `cargo fmt` to format your code
- Run `cargo clippy` and fix any warnings
- Write clear, self-documenting code
- Add comments for complex logic

### Testing
- Write unit tests for new functionality
- Ensure all tests pass: `cargo test`
- Add integration tests for major features
- Test on multiple platforms when possible

### Performance
- Phobos prioritizes speed and efficiency
- Profile your changes if they affect performance
- Run benchmarks: `cargo bench`
- Consider memory usage and CPU efficiency

## 🐛 Reporting Bugs

1. **Search** existing issues first
2. **Use** the bug report template
3. **Include** system information
4. **Provide** reproduction steps
5. **Add** relevant logs or screenshots

## ✨ Suggesting Features

1. **Check** existing feature requests
2. **Use** the feature request template
3. **Explain** the use case and motivation
4. **Consider** implementation complexity
5. **Discuss** with maintainers if needed

## 🔄 Pull Request Process

### Before Submitting
- [ ] Code follows project style guidelines
- [ ] Tests pass locally
- [ ] Documentation is updated
- [ ] Commit messages are clear
- [ ] Branch is up to date with main

### PR Requirements
- Clear description of changes
- Link to related issues
- Test coverage for new code
- No breaking changes (unless discussed)
- Passes all CI checks

### Review Process
1. Automated checks run (CI/CD)
2. Code review by maintainers
3. Feedback and requested changes
4. Final approval and merge

## 🏗️ Project Structure

```
src/
├── main.rs          # CLI entry point
├── lib.rs           # Library root
├── config.rs        # Configuration handling
├── error.rs         # Error types
├── network/         # Network operations
│   ├── mod.rs
│   ├── packet.rs    # Packet crafting
│   ├── protocol.rs  # Protocol implementations
│   ├── socket.rs    # Socket operations
│   └── stealth.rs   # Stealth techniques
├── scanner/         # Core scanning logic
│   ├── mod.rs
│   ├── engine.rs    # Scan engine
│   └── techniques.rs # Scan techniques
├── output/          # Output formatting
│   └── mod.rs
└── utils/           # Utility functions
    ├── mod.rs
    ├── config.rs    # Config utilities
    └── timing.rs    # Timing utilities
```

## 🎯 Areas for Contribution

### High Priority
- 🚀 Performance optimizations
- 🔒 Security enhancements
- 🧪 Test coverage improvements
- 📚 Documentation updates

### Medium Priority
- ✨ New scan techniques
- 🎨 Output format improvements
- 🔧 Configuration enhancements
- 🌐 IPv6 support improvements

### Good First Issues
- 📝 Documentation fixes
- 🐛 Small bug fixes
- 🧹 Code cleanup
- ✅ Adding tests

## 📚 Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Tokio Documentation](https://tokio.rs/)
- [Network Programming in Rust](https://github.com/rust-lang/rfcs)

## 🤔 Questions?

- 💬 [GitHub Discussions](https://github.com/ibrahmsql/phobos/discussions)
- 📧 Email: ibrahimsql@proton.me
- 🐛 [Issues](https://github.com/ibrahmsql/phobos/issues)

## 📜 Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Maintain a professional environment
- Report inappropriate behavior

## 🙏 Recognition

Contributors will be:
- Listed in the project README
- Mentioned in release notes
- Given credit in documentation
- Invited to join the core team (for significant contributions)

---

**Thank you for contributing to Phobos! Together, we're building the fastest port scanner in the Rust ecosystem. 🦀⚡**