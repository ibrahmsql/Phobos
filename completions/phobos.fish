# Fish completion for Phobos port scanner
# Installation: Copy to ~/.config/fish/completions/

# Remove previous completions
complete -c phobos -e

# Main options
complete -c phobos -s h -l help -d "Show help message"
complete -c phobos -l version -d "Show version information"
complete -c phobos -l benchmark -d "Show detailed benchmark information"
complete -c phobos -l accessible -d "Accessible mode for screen readers"
complete -c phobos -l no-banner -d "Hide the banner"
complete -c phobos -s g -l greppable -d "Greppable output format"
complete -c phobos -s v -l verbose -d "Verbose output"
complete -c phobos -l no-color -d "Disable colored output"
complete -c phobos -l ports-only -d "Only scan ports, no scripts or Nmap"
complete -c phobos -l no-nmap -d "Disable automatic Nmap execution"
complete -c phobos -l all -d "Show all port states"
complete -c phobos -l top -d "Use top 1000 ports"
complete -c phobos -l full-range -d "Scan all 65535 ports"
complete -c phobos -l udp -d "UDP scanning mode"
complete -c phobos -l adaptive -d "Enable adaptive scanning"
complete -c phobos -l wrath -d "Wrath mode: maximum aggression"
complete -c phobos -l shadow -d "Shadow scan: ultra-stealth"
complete -c phobos -s O -l os-detect -d "Enable OS detection"
complete -c phobos -l update -d "Update Phobos to latest version"
complete -c phobos -l list-profiles -d "List all available profiles"
complete -c phobos -l system-check -d "Check system requirements"
complete -c phobos -l validate-config -d "Validate configuration"

# Port specification
complete -c phobos -s p -l ports -d "Port range to scan" -x -a "22 80 443 8080 1-1000 1-65535"

# Scan technique
complete -c phobos -s s -l scan-type -d "Scan technique" -x -a "syn connect udp fin null xmas ack window"

# Timing template
complete -c phobos -s T -l timing -d "Timing template (0-5)" -x -a "0 1 2 3 4 5"

# Stealth level
complete -c phobos -l stealth -d "Stealth level (0-5)" -x -a "0 1 2 3 4 5"

# Thread count
complete -c phobos -l threads -d "Number of concurrent threads" -x -a "10 50 100 500 1000 5000"

# Timeout
complete -c phobos -l timeout -d "Timeout in milliseconds" -x -a "1000 2000 3000 5000 10000"

# Rate limit
complete -c phobos -l rate-limit -d "Rate limit in packets per second" -x -a "1000 10000 100000 1000000 10000000"

# Batch size
complete -c phobos -s b -l batch-size -d "Batch size for port scanning" -x -a "1000 3000 5000 10000 15000"

# Output format
complete -c phobos -s o -l output -d "Output format" -x -a "text json xml csv nmap greppable"

# Output file
complete -c phobos -l output-file -d "Write output to file" -r -F

# Nmap output
complete -c phobos -l output-nmap -d "Save results in Nmap XML format" -r -F

# Config file
complete -c phobos -s c -l config -d "Configuration file path" -r -F

# Input file
complete -c phobos -s i -l input-file -d "Read targets from file" -r -F

# Profile
complete -c phobos -l profile -d "Use predefined scan profile" -x -a "stealth aggressive comprehensive quick"

# Save profile
complete -c phobos -l save-profile -d "Save current configuration as profile" -x

# Scripts
complete -c phobos -l scripts -d "Script execution mode" -x -a "none default custom all adaptive"

# Script directory
complete -c phobos -l script-dir -d "Directory containing custom scripts" -r -a "(__fish_complete_directories)"

# Script tags
complete -c phobos -l script-tags -d "Script tags to execute" -x

# Script timeout
complete -c phobos -l script-timeout -d "Timeout for script execution in seconds" -x -a "60 120 300 600"

# Max script concurrent
complete -c phobos -l max-script-concurrent -d "Maximum concurrent script executions" -x -a "5 10 20 50"

# Scan order
complete -c phobos -l scan-order -d "Order to scan ports" -x -a "serial random"

# Tries
complete -c phobos -l tries -d "Number of tries per port" -x -a "1 2 3 5"

# Max retries
complete -c phobos -l max-retries -d "Maximum retries for failed connections" -x -a "1 2 3 5"

# Source port
complete -c phobos -l source-port -d "Use specific source port" -x

# Interface
complete -c phobos -l interface -d "Network interface to use" -x

# Ulimit
complete -c phobos -s u -l ulimit -d "Automatically increase ulimit" -x -a "4096 8192 16384 65535"

# Exclude ports
complete -c phobos -s x -l exclude-ports -d "Ports to exclude" -x

# Exclude IPs
complete -c phobos -l exclude-ips -d "IPs/CIDR ranges to exclude" -x

# Nmap args
complete -c phobos -l nmap-args -d "Additional arguments for Nmap" -x

# Common targets
complete -c phobos -f -a "localhost 127.0.0.1 scanme.nmap.org"
