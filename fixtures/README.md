# Phobos Fixtures and Payloads

## Overview

This directory contains test fixtures, UDP payloads, and post-scan scripts for Phobos scanner.

## Structure

```
fixtures/
├── scripts/              # Post-scan analysis scripts
│   ├── http_grabber.py   # HTTP title and header extraction
│   └── ssh_banner.sh     # SSH banner grabbing
├── test_targets/         # Test target lists
│   └── hosts.txt         # Sample targets for testing
└── phobos_scripts.toml   # Script configuration

payloads/
└── udp-payloads.txt      # UDP service detection payloads
```

## UDP Payloads

The `payloads/udp-payloads.txt` file contains crafted packets for UDP service detection, including:

- **DNS** (53, 5353): DNS queries and mDNS
- **DHCP** (67): Network configuration
- **NTP** (123): Time synchronization
- **SNMP** (161): Network management
- **NetBIOS** (137): Windows networking
- **DTLS** (443, 4433): Secure communications
- **IPSec/IKE** (500, 4500): VPN services
- **STUN** (3478): WebRTC/VOIP
- **Memcached** (11211): Caching
- **Gaming** (27015-27030): Steam, Source Engine
- **IoT** (5683): CoAP protocol

### Usage

Phobos automatically uses these payloads for UDP scanning to trigger service responses.

## Post-Scan Scripts

### HTTP Grabber (`http_grabber.py`)

Extracts HTTP titles and server information.

**Usage:**
```bash
python3 fixtures/scripts/http_grabber.py <ip> <port>
```

**Example:**
```bash
python3 fixtures/scripts/http_grabber.py example.com 80
# Output:
# [*] Scanning example.com:80
# [+] Title: Example Domain
# [+] Server: ECS (dcb/7F83)
```

**Trigger Ports:** 80, 443, 8080, 8000, 8443

---

### SSH Banner Grabber (`ssh_banner.sh`)

Extracts SSH version and banner information.

**Usage:**
```bash
bash fixtures/scripts/ssh_banner.sh <ip> <port>
```

**Example:**
```bash
bash fixtures/scripts/ssh_banner.sh scanme.nmap.org 22
# Output:
# [*] Grabbing SSH banner from scanme.nmap.org:22
# [+] SSH Banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
# [+] Protocol: SSH-2.0
# [+] Server: OpenSSH
```

**Trigger Ports:** 22, 2222

---

## Script Configuration

The `phobos_scripts.toml` file defines:

- **Script metadata**: Tags, developer, description
- **Trigger ports**: Which ports activate the script
- **Interpreter**: python3, bash, etc.
- **Timeouts**: Maximum execution time
- **Global config**: Defaults and limits

### Adding Custom Scripts

1. Create your script in `fixtures/scripts/`
2. Add metadata headers:
```python
#!/usr/bin/env python3
#tags = ["custom", "web"]
#trigger_port = "8080"
#developer = ["Your Name"]
#description = "Script description"
```

3. Update `phobos_scripts.toml` with configuration
4. Make executable: `chmod +x script.py`

---

## Test Targets

The `test_targets/hosts.txt` file contains safe targets for testing:

- localhost (127.0.0.1)
- scanme.nmap.org (official Nmap test server)
- example.com (IANA example domain)

**Usage:**
```bash
# Scan test targets
./target/release/phobos --input-file fixtures/test_targets/hosts.txt -p 1-1000
```

---

## Integration with Phobos

### Automatic Script Execution

When Phobos detects open ports matching trigger ports, it can automatically run scripts:

```bash
./phobos target.com -p 1-1000 --scripts default
```

### Manual Script Execution

Run scripts independently on scan results:

```bash
# After scanning
python3 fixtures/scripts/http_grabber.py 192.168.1.1 80
```

---

## Examples

### Full Workflow

```bash
# 1. Scan with Phobos
./target/release/phobos scanme.nmap.org -p 1-1000 --greppable > results.txt

# 2. Run HTTP grabber on found ports
grep ":80" results.txt | cut -d: -f1 | while read ip; do
    python3 fixtures/scripts/http_grabber.py $ip 80
done

# 3. Run SSH banner grabber
grep ":22" results.txt | cut -d: -f1 | while read ip; do
    bash fixtures/scripts/ssh_banner.sh $ip 22
done
```

---

## Benefits

1. **UDP Service Detection**: Comprehensive payload database for accurate service identification
2. **Automated Analysis**: Post-scan scripts extract additional intelligence
3. **Extensibility**: Easy to add custom scripts and payloads
4. **Testing**: Standardized test targets for validation
5. **Compliance**: Based on Nmap's proven payload database

---

## Credits

- UDP payloads based on Nmap's nmap-payloads database
- Script architecture inspired by RustScan
- Enhanced and optimized for Phobos performance

## License

Same as Phobos - see main LICENSE file
