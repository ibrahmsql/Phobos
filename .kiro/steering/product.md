# Product Overview

Phobos is a high-performance port scanner written in Rust that aims to outperform traditional tools like Nmap and Masscan. The project focuses on speed, accuracy, and modern user experience.

## Core Value Proposition
- **Performance**: 10x faster than traditional port scanners with multi-threaded async architecture
- **Accuracy**: Zero compromise on detection reliability 
- **Modern UX**: Beautiful terminal output with real-time progress and colored results
- **Cross-platform**: Full support for Windows, macOS, and Linux

## Key Features
- Multiple scan techniques (SYN, Connect, UDP, FIN, NULL, XMAS, ACK, Window)
- Stealth scanning with decoy support and firewall evasion
- IPv4/IPv6 support with CIDR notation
- Service detection and version fingerprinting
- Nmap integration for detailed analysis
- Adaptive learning for network optimization
- Multiple output formats (Text, JSON, XML, CSV, Nmap-compatible)

## Target Users
- Cybersecurity professionals
- Penetration testers  
- Network administrators
- Security researchers

## Architecture Philosophy
The project emphasizes Rust's safety and performance benefits while maintaining compatibility with existing security workflows through Nmap integration.