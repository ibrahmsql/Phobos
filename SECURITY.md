# Security Policy

## 🔒 Reporting Security Vulnerabilities

The Phobos team takes security seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report a Security Vulnerability

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by email to:

📧 **ibrahimsql@proton.me**

**Subject line:** `[SECURITY] Brief description of the vulnerability`

### What to Include in Your Report

Please include the following information:

1. **Type of vulnerability** (e.g., buffer overflow, injection, privilege escalation)
2. **Affected component(s)** (e.g., scanner engine, GPU module, script executor)
3. **Affected version(s)** (e.g., v1.1.1, commit hash, or "main branch")
4. **Steps to reproduce** the vulnerability
5. **Proof of concept** or exploit code (if available)
6. **Impact assessment** (what can an attacker do?)
7. **Suggested fix** (if you have one)
8. **Your contact information** for follow-up questions

### Example Report Format

```
Subject: [SECURITY] Buffer overflow in port parsing

Vulnerability Type: Buffer Overflow
Component: Port range parser (src/utils/port_parser.rs)
Version: v1.1.1
Severity: High

Description:
When parsing malformed port ranges, the application reads beyond 
allocated buffer boundaries, potentially leading to arbitrary code execution.

Steps to Reproduce:
1. Run: phobos target.com -p "1-9999999999999999"
2. Observe: Segmentation fault

Impact:
Attacker can potentially execute arbitrary code with scanner privileges.

Proof of Concept:
[Attach exploit code or detailed steps]

Suggested Fix:
Add bounds checking in parse_port_range() function before allocation.

Contact: your-email@example.com
```

## 🕐 Response Timeline

We will acknowledge your email within **48 hours** and will send a more detailed response within **7 days** indicating the next steps in handling your report.

After the initial reply, we will:
- Confirm the vulnerability and determine its severity
- Work on a fix and release timeline
- Keep you updated on progress
- Credit you in the security advisory (unless you prefer to remain anonymous)

## 🎯 Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | ✅ Yes             |
| 1.0.x   | ✅ Yes             |
| < 1.0   | ❌ No              |

## 🛡️ Security Best Practices

### For Users

#### Running Phobos Safely

1. **Use Minimum Required Privileges**
   ```bash
   # For TCP connect scans (no root needed)
   phobos target.com -p 80,443
   
   # For SYN scans (requires root/sudo)
   sudo phobos target.com -s syn -p 80,443
   ```

2. **Isolate Network Scanning**
   - Run in isolated networks when possible
   - Use VMs or containers for untrusted targets
   - Be aware of your network traffic

3. **Validate Input Files**
   ```bash
   # Always verify target lists before scanning
   cat targets.txt
   phobos -i targets.txt
   ```

4. **Secure Configuration Files**
   ```bash
   # Protect config files with sensitive data
   chmod 600 ~/.config/phobos/config.toml
   ```

5. **Update Regularly**
   ```bash
   # Check for updates frequently
   phobos --update
   
   # Or rebuild from source
   git pull origin main
   cargo build --release
   ```

#### Permissions

- **TCP Connect Scan**: No special permissions required ✅
- **SYN Scan**: Requires `CAP_NET_RAW` or root privileges ⚠️
- **Raw Socket Operations**: Requires elevated privileges ⚠️

```bash
# Grant capabilities instead of running as root (Linux)
sudo setcap cap_net_raw+ep /usr/local/bin/phobos

# Now can run SYN scans without sudo
phobos target.com -s syn
```

### For Developers

#### Secure Coding Practices

1. **Input Validation**
   ```rust
   // Always validate and sanitize user input
   fn parse_target(target: &str) -> Result<IpAddr> {
       if target.len() > MAX_TARGET_LENGTH {
           return Err(Error::InvalidInput);
       }
       // Additional validation...
   }
   ```

2. **Bounds Checking**
   ```rust
   // Use safe indexing
   let port = ports.get(index).ok_or(Error::IndexOutOfBounds)?;
   
   // Avoid: ports[index]  // Can panic!
   ```

3. **Resource Limits**
   ```rust
   // Limit resource consumption
   const MAX_PORTS: usize = 65535;
   const MAX_TARGETS: usize = 1000;
   const MAX_BATCH_SIZE: usize = 15000;
   ```

4. **Memory Safety**
   ```rust
   // Leverage Rust's ownership system
   // Use Arc/Mutex for shared state
   // Avoid unsafe blocks unless absolutely necessary
   ```

5. **Dependency Auditing**
   ```bash
   # Regularly audit dependencies
   cargo audit
   cargo outdated
   ```

#### Script Execution Security

When executing custom scripts:

1. **Sandbox Execution**
   - Scripts run in isolated environment
   - Limited system access
   - Timeout enforcement

2. **Script Validation**
   ```bash
   # Validate scripts before execution
   phobos target.com --scripts custom --script-dir ./scripts
   ```

3. **Resource Limits**
   - CPU time limits
   - Memory limits
   - Network access restrictions

## 🚨 Known Security Considerations

### 1. Raw Socket Access

**Issue**: SYN scanning requires raw socket access (elevated privileges)

**Risk**: If compromised, attacker gains network-level access

**Mitigation**:
- Use TCP connect scan when possible (no special privileges)
- Use capability-based permissions instead of root
- Run in containers/VMs for isolation

### 2. GPU Memory Access

**Issue**: GPU acceleration accesses device memory directly

**Risk**: Potential information leakage from GPU memory

**Mitigation**:
- GPU memory is zeroed before use
- Results are cleared after transfer
- Use separate GPU for sensitive scans if concerned

### 3. Denial of Service

**Issue**: Aggressive scanning can impact target systems

**Risk**: Unintentional DoS of target services

**Mitigation**:
- Use appropriate timing profiles (`-T 0-3` for production)
- Implement rate limiting (`--rate-limit`)
- Test in controlled environments first

### 4. Network Fingerprinting

**Issue**: Scanning patterns can be detected and blocked

**Risk**: Scanner identification and IP blocking

**Mitigation**:
- Use stealth modes (`--stealth`, `--shadow`)
- Randomize scan order (`--scan-order random`)
- Use decoy scanning (`-D`)

### 5. Script Injection

**Issue**: Custom scripts could contain malicious code

**Risk**: Code execution on scanner system

**Mitigation**:
- Scripts run in sandboxed environment
- Limited system access
- Review custom scripts before use

## 🔍 Security Auditing

### Self-Audit Checklist

- [ ] Input validation on all user-supplied data
- [ ] Bounds checking on array accesses
- [ ] Resource limit enforcement
- [ ] No unsafe blocks without justification
- [ ] Dependencies are up-to-date and audited
- [ ] Secrets are not hardcoded
- [ ] Error messages don't leak sensitive info
- [ ] Logging doesn't include sensitive data

### Automated Security Checks

```bash
# Run security audit
cargo audit

# Check for unsafe code
cargo geiger

# Run clippy with security lints
cargo clippy -- -W clippy::all -W clippy::pedantic

# Dependency license check
cargo deny check

# Static analysis
cargo semver-checks
```

## 🐛 Common Vulnerabilities (CVE)

| CVE ID | Severity | Version | Status | Description |
|--------|----------|---------|--------|-------------|
| N/A    | -        | -       | -      | No known vulnerabilities |

## 🎖️ Security Hall of Fame

We thank the following security researchers for responsibly disclosing vulnerabilities:

*No vulnerabilities reported yet. Be the first!*

### Recognition

Security researchers who report valid vulnerabilities will be:
- Listed in our Security Hall of Fame (unless anonymous)
- Mentioned in release notes
- Eligible for swag/bounty (if program is active)

## 📚 Security Resources

### External Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Related Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [README.md](README.md) - General usage
- [GPU_ACCELERATION.md](GPU_ACCELERATION.md) - GPU security considerations

## 📖 Legal & Ethical Use

### Disclaimer

Phobos is a powerful network scanning tool. Users must:

1. **Obtain Authorization**: Only scan networks you own or have explicit permission to scan
2. **Comply with Laws**: Follow all applicable local, state, and federal laws
3. **Respect Privacy**: Don't scan systems without permission
4. **Be Responsible**: Understand the impact of your scans

**Unauthorized network scanning may be illegal in your jurisdiction.**

### Legal Use Cases

✅ **Authorized Uses:**
- Scanning your own infrastructure
- Authorized penetration testing
- Security audits with written permission
- Educational use on lab environments
- Bug bounty programs with proper authorization

❌ **Unauthorized Uses:**
- Scanning networks without permission
- Attacking or compromising systems
- Denial of service attacks
- Privacy violations
- Any illegal activities

### Ethical Guidelines

As a security tool user, you should:
- Always obtain explicit permission before scanning
- Document your authorization
- Use appropriate scan intensities
- Respect rate limits and system resources
- Report vulnerabilities responsibly
- Follow coordinated disclosure practices

## 🤝 Contact

For security-related inquiries:

- 🔒 **Security Email**: ibrahimsql@proton.me
- 📧 **General Email**: ibrahimsql@proton.me
- 💬 **GitHub**: [@ibrahmsql](https://github.com/ibrahmsql)

For non-security issues:
- 🐛 [GitHub Issues](https://github.com/ibrahmsql/phobos/issues)
- 💬 [GitHub Discussions](https://github.com/ibrahmsql/phobos/discussions)

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

**Security is not a feature, it's a foundation.** 🔒

*Last updated: October 21, 2024*
