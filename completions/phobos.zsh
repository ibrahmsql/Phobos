#compdef phobos
# Zsh completion for Phobos port scanner
# Installation: Place in $fpath and run: compinit

_phobos() {
    local -a opts args
    
    opts=(
        '(-h --help)'{-h,--help}'[Show help message]'
        '--version[Show version information]'
        '--benchmark[Show detailed benchmark information]'
        '--accessible[Accessible mode for screen readers]'
        '--no-banner[Hide the banner]'
        '(-g --greppable)'{-g,--greppable}'[Greppable output format]'
        '(-v --verbose)'{-v,--verbose}'[Verbose output]'
        '--no-color[Disable colored output]'
        '--ports-only[Only scan ports, no scripts or Nmap]'
        '--no-nmap[Disable automatic Nmap execution]'
        '--all[Show all port states]'
        '--top[Use top 1000 ports]'
        '--full-range[Scan all 65535 ports]'
        '--udp[UDP scanning mode]'
        '--adaptive[Enable adaptive scanning]'
        '--wrath[Wrath mode: maximum aggression]'
        '--shadow[Shadow scan: ultra-stealth]'
        '(-O --os-detect)'{-O,--os-detect}'[Enable OS detection]'
        '--update[Update Phobos to latest version]'
        '--list-profiles[List all available profiles]'
        '--system-check[Check system requirements]'
        '--validate-config[Validate configuration]'
    )
    
    args=(
        '(-p --ports)'{-p,--ports}'[Port range to scan]:ports:(22 80 443 8080 1-1000 1-65535)'
        '(-s --scan-type)'{-s,--scan-type}'[Scan technique]:technique:(syn connect udp fin null xmas ack window)'
        '(-T --timing)'{-T,--timing}'[Timing template]:level:(0 1 2 3 4 5)'
        '--stealth[Stealth level]:level:(0 1 2 3 4 5)'
        '--threads[Number of concurrent threads]:count:(10 50 100 500 1000 5000)'
        '--timeout[Timeout in milliseconds]:ms:(1000 2000 3000 5000 10000)'
        '--rate-limit[Rate limit in packets per second]:pps:(1000 10000 100000 1000000 10000000)'
        '(-b --batch-size)'{-b,--batch-size}'[Batch size for port scanning]:size:(1000 3000 5000 10000 15000)'
        '(-o --output)'{-o,--output}'[Output format]:format:(text json xml csv nmap greppable)'
        '--output-file[Write output to file]:file:_files'
        '--output-nmap[Save results in Nmap XML format]:file:_files'
        '(-c --config)'{-c,--config}'[Configuration file path]:file:_files'
        '(-i --input-file)'{-i,--input-file}'[Read targets from file]:file:_files'
        '--profile[Use predefined scan profile]:profile:(stealth aggressive comprehensive quick)'
        '--save-profile[Save current configuration as profile]:name:'
        '--scripts[Script execution mode]:mode:(none default custom all adaptive)'
        '--script-dir[Directory containing custom scripts]:directory:_directories'
        '--script-tags[Script tags to execute]:tags:'
        '--script-timeout[Timeout for script execution]:seconds:(60 120 300 600)'
        '--max-script-concurrent[Max concurrent script executions]:count:(5 10 20 50)'
        '--scan-order[Order to scan ports]:order:(serial random)'
        '--tries[Number of tries per port]:count:(1 2 3 5)'
        '--max-retries[Maximum retries for failed connections]:count:(1 2 3 5)'
        '--source-port[Use specific source port]:port:'
        '--interface[Network interface to use]:interface:_net_interfaces'
        '(-u --ulimit)'{-u,--ulimit}'[Automatically increase ulimit]:limit:(4096 8192 16384 65535)'
        '(-x --exclude-ports)'{-x,--exclude-ports}'[Ports to exclude]:ports:'
        '--exclude-ips[IPs/CIDR ranges to exclude]:ips:'
        '--nmap-args[Additional arguments for Nmap]:args:'
        '1:target:_hosts'
    )
    
    _arguments -s -S $opts $args
}

_phobos "$@"
