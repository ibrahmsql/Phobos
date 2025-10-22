# Bash completion for Phobos port scanner
# Installation: source this file or copy to /etc/bash_completion.d/

_phobos_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Main options
    opts="--help --version --benchmark --accessible --no-banner --greppable --verbose --no-color --ports-only --no-nmap --all --top --full-range --udp --adaptive --wrath --shadow --os-detect --update --list-profiles --system-check --validate-config"
    
    # Options with arguments
    case "${prev}" in
        -p|--ports)
            # Port suggestions
            COMPREPLY=( $(compgen -W "22 80 443 8080 1-1000 1-65535" -- ${cur}) )
            return 0
            ;;
        -s|--scan-type)
            COMPREPLY=( $(compgen -W "syn connect udp fin null xmas ack window" -- ${cur}) )
            return 0
            ;;
        -T|--timing)
            COMPREPLY=( $(compgen -W "0 1 2 3 4 5" -- ${cur}) )
            return 0
            ;;
        --stealth)
            COMPREPLY=( $(compgen -W "0 1 2 3 4 5" -- ${cur}) )
            return 0
            ;;
        --threads)
            COMPREPLY=( $(compgen -W "10 50 100 500 1000 5000" -- ${cur}) )
            return 0
            ;;
        --timeout)
            COMPREPLY=( $(compgen -W "1000 2000 3000 5000 10000" -- ${cur}) )
            return 0
            ;;
        --rate-limit)
            COMPREPLY=( $(compgen -W "1000 10000 100000 1000000 10000000" -- ${cur}) )
            return 0
            ;;
        -b|--batch-size)
            COMPREPLY=( $(compgen -W "1000 3000 5000 10000 15000" -- ${cur}) )
            return 0
            ;;
        -o|--output|--output-format)
            COMPREPLY=( $(compgen -W "text json xml csv nmap greppable" -- ${cur}) )
            return 0
            ;;
        --profile)
            COMPREPLY=( $(compgen -W "stealth aggressive comprehensive quick" -- ${cur}) )
            return 0
            ;;
        --scripts)
            COMPREPLY=( $(compgen -W "none default custom all adaptive" -- ${cur}) )
            return 0
            ;;
        --scan-order)
            COMPREPLY=( $(compgen -W "serial random" -- ${cur}) )
            return 0
            ;;
        -c|--config|--output-file|--output-nmap|-i|--input-file|--script-dir)
            # File completion
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        --interface)
            # Network interfaces
            COMPREPLY=( $(compgen -W "$(ip -o link show | awk -F': ' '{print $2}')" -- ${cur}) )
            return 0
            ;;
        *)
            ;;
    esac
    
    # Default completion with main options
    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${opts} -p -s -T -b -o -c -i -u -v -g -x -D -O" -- ${cur}) )
        return 0
    fi
    
    # If no option, suggest hostnames or IPs
    COMPREPLY=( $(compgen -W "localhost 127.0.0.1 scanme.nmap.org" -- ${cur}) )
}

complete -F _phobos_completions phobos
