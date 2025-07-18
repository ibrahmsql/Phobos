use clap::{Arg, Command, ArgAction};
use std::process;
use std::net::{IpAddr, ToSocketAddrs};

use colored::*;
use phobos::{
    config::ScanConfig,
    network::{ScanTechnique, stealth::StealthOptions},
    output::{OutputConfig, OutputFormat, OutputManager, ProgressDisplay},
    scanner::engine::ScanEngine,
    utils::config::ConfigValidator,
    benchmark::{Benchmark, NamedTimer},
    top_ports::get_top_1000_ports,
};
use anyhow;
use chrono;



// Ulimit adjustment for Unix systems
#[cfg(unix)]
fn adjust_ulimit_size(ulimit: Option<u64>) -> u64 {
    use rlimit::Resource;
    
    if let Some(limit) = ulimit {
        if Resource::NOFILE.set(limit, limit).is_ok() {
            println!("{} {}", 
                "[~] Automatically increasing ulimit value to".bright_blue(),
                limit.to_string().bright_cyan().bold());
        } else {
            eprintln!("{}", "[!] ERROR: Failed to set ulimit value.".bright_red());
        }
    }
    
    let (soft, _) = Resource::NOFILE.get().unwrap();
    soft
}

#[cfg(not(unix))]
fn adjust_ulimit_size(_ulimit: Option<u64>) -> u64 {
    8000 // Default for non-Unix systems
}

fn print_banner() {
    println!("{}", "____  _   _   ___   ____   ___   ____   _____ ".truecolor(231, 76, 60).bold());
    println!("{}", "|  _ \\| | | | / _ \\ | __ ) / _ \\ |  _ \\ | ____| ".truecolor(231, 76, 60).bold());
    println!("{}", "| |_) | |_| || | | ||  _ \\| | | || | | ||  _|  ".truecolor(231, 76, 60).bold());
    println!("{}", "|  __/|  _  || |_| || |_) | |_| || |_| || |___ ".truecolor(231, 76, 60).bold());
    println!("{}", "|_|   |_| |_| \\___/ |____/ \\___/ |____/ |_____| ".truecolor(231, 76, 60).bold());
    println!();
    println!("{}", "Phobos – The God of Fear. Forged in Rust ⚡".truecolor(255, 215, 0).bold());
    println!();
    println!("{}", "------------------------------------------------------".bright_blue());
    println!("{}", ": 🔗 `https://github.com/ibrahmsql/phobos`                :".bright_blue());
    println!("{}", ": ⚡ written in Rust | faster than the old gods        :".bright_blue());
    println!("{}", "------------------------------------------------------".bright_blue());
    println!();
    println!("{}", "\"Let your ports tremble.\"".truecolor(231, 76, 60).bold());
    println!();
}

fn resolve_target(target: &str) -> anyhow::Result<String> {
    // Check if it's already an IP address
    if target.parse::<IpAddr>().is_ok() {
        return Ok(target.to_string());
    }
    
    // Try to resolve hostname
    let socket_addr = format!("{}:80", target);
    match socket_addr.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                println!("{} {} {} {}", 
                    "[~] Resolving".bright_blue(),
                    target.bright_yellow(),
                    "to".bright_blue(),
                    addr.ip().to_string().bright_cyan().bold());
                Ok(addr.ip().to_string())
            } else {
                Err(anyhow::anyhow!("No IP addresses found for hostname: {}", target))
            }
        }
        Err(_) => {
            Err(anyhow::anyhow!("Failed to resolve hostname: {}", target))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Initialize benchmark system
    let mut benchmark = Benchmark::init();
    let mut total_timer = NamedTimer::start("Total Scan");
    let mut phobos_bench = NamedTimer::start("Phobos");
    
    // Parse command line arguments first to check for greppable mode
    let matches = Command::new("phobos")
        .version("1.0.0")
        .author("ibrahimsql")
        .about("Phobos: The Blazingly Fast Rust-Based Port Scanner That Outspeeds Nmap & Masscan")
        .arg(
            Arg::new("target")
                .value_name("TARGET")
                .help("Target to scan (IP, hostname, or CIDR)")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("greppable")
                .short('g')
                .long("greppable")
                .help("Greppable output. Only show IP:PORT format")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ulimit")
                .short('u')
                .long("ulimit")
                .value_name("LIMIT")
                .help("Automatically increase ulimit to this value")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("benchmark")
                .long("benchmark")
                .help("Show detailed benchmark information")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("accessible")
                .long("accessible")
                .help("Accessible mode. Turns off features which negatively affect screen readers")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-banner")
                .long("no-banner")
                .help("Hide the banner")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("exclude-ports")
                .short('x')
                .long("exclude-ports")
                .help("A list of comma separated ports to be excluded from scanning")
                .value_name("PORTS")
                .value_delimiter(','),
        )
        .arg(
            Arg::new("top")
                .long("top")
                .help("Use the top 1000 ports")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("udp")
                .long("udp")
                .help("UDP scanning mode")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ports")
                .short('p')
                .long("ports")
                .value_name("PORTS")
                .help("Port range to scan (e.g., 1-1000, 80,443,8080, U:53,T:80)")
                .default_value("1-1000"),
        )
        .arg(
            Arg::new("technique")
                .short('s')
                .long("scan-type")
                .value_name("TYPE")
                .help("Scan technique")
                .value_parser(["syn", "connect", "udp", "fin", "null", "xmas", "ack", "window"])
                .default_value("syn"),
        )
        .arg(
            Arg::new("timing")
                .short('T')
                .long("timing")
                .value_name("LEVEL")
                .help("Timing template (0-5: paranoid, sneaky, polite, normal, aggressive, insane)")
                .value_parser(["0", "1", "2", "3", "4", "5"])
                .default_value("3"),
        )
        .arg(
            Arg::new("threads")
                .long("threads")
                .value_name("COUNT")
                .help("Number of concurrent threads")
                .value_parser(clap::value_parser!(usize))
                .default_value("1000"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("MS")
                .help("Timeout in milliseconds")
                .value_parser(clap::value_parser!(u64))
                .default_value("1000"),
        )
        .arg(
            Arg::new("rate-limit")
                .long("rate-limit")
                .value_name("PPS")
                .help("Rate limit in packets per second")
                .value_parser(clap::value_parser!(u64))
                .default_value("1000000"),
        )
        .arg(
            Arg::new("batch-size")
                .short('b')
                .long("batch-size")
                .value_name("SIZE")
                .help("Batch size for port scanning")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Verbose output")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .help("Disable colored output")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ports-only")
                .long("ports-only")
                .help("Only scan ports, don't run Nmap scripts")
                .action(ArgAction::SetTrue),
        )
        .get_matches();
    
    let greppable = matches.get_flag("greppable");
    let accessible = matches.get_flag("accessible");
    let no_banner = matches.get_flag("no-banner");
    let top_ports = matches.get_flag("top");
    let _udp_mode = matches.get_flag("udp");
    let exclude_ports: Option<Vec<String>> = matches.get_many::<String>("exclude-ports")
        .map(|vals| vals.map(|s| s.to_string()).collect());
    
    // Show banner unless disabled
    if !no_banner && !greppable && !accessible {
        print_banner();
    }

    // Adjust ulimit if specified
    if let Some(ulimit) = matches.get_one::<u64>("ulimit") {
        adjust_ulimit_size(Some(*ulimit));
    }
    


    // Legal warning is shown by default in stealth mode

    // Load configuration from file or use default
    let base_config = if let Some(config_file) = matches.get_one::<String>("config") {
        match ScanConfig::from_toml_file(config_file) {
            Ok(config) => {
                println!("[~] Loaded config from {}", config_file);
                config
            }
            Err(e) => {
                eprintln!("Failed to load config file: {}", e);
                process::exit(1);
            }
        }
    } else {
        // Try to load default config files
        ScanConfig::load_default_config()
    };

    // Parse arguments and override config
    let target_input = matches.get_one::<String>("target").unwrap();
    
    // Resolve hostname to IP if needed
    let target = resolve_target(target_input)?;
    
    // Parse ports
    let mut ports = if top_ports {
        get_top_1000_ports()
    } else {
        let port_spec = matches.get_one::<String>("ports").unwrap();
        parse_ports(port_spec)?
    };
    
    // Exclude ports if specified
    if let Some(exclude_list) = exclude_ports {
        let exclude_ports: Vec<u16> = exclude_list.iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        ports.retain(|&port| !exclude_ports.contains(&port));
    }
    let technique_str = matches.get_one::<String>("technique").unwrap();
    let timing_level = matches.get_one::<String>("timing").unwrap().parse::<u8>().unwrap_or(3);
    let threads = *matches.get_one::<usize>("threads").unwrap();
    let timeout = *matches.get_one::<u64>("timeout").unwrap();
    let rate_limit = *matches.get_one::<u64>("rate-limit").unwrap();

    // Parse scan technique
    let technique = match technique_str.as_str() {
        "syn" => ScanTechnique::Syn,
        "connect" => ScanTechnique::Connect,
        "udp" => ScanTechnique::Udp,
        "fin" => ScanTechnique::Fin,
        "null" => ScanTechnique::Null,
        "xmas" => ScanTechnique::Xmas,
        "ack" => ScanTechnique::Ack,
        "window" => ScanTechnique::Window,
        _ => {
            eprintln!("Invalid scan technique: {}", technique_str);
            process::exit(1);
        }
    };

    // Parse stealth options
    let stealth_options = StealthOptions::default();

    // Parse output configuration
    let output_config = OutputConfig {
        format: OutputFormat::Text,
        file: None,
        colored: !matches.get_flag("no-color"),
        verbose: matches.get_flag("verbose"),
        show_closed: false,
        show_filtered: false,
    };

    // Create scan configuration by merging base config with CLI args
    let scan_config = ScanConfig {
        target: target.clone(),
        ports,
        technique,
        threads,
        timeout,
        rate_limit,
        stealth_options: Some(stealth_options),
        timing_template: timing_level,
        top_ports: None,
        batch_size: matches.get_one::<usize>("batch-size").copied().or(base_config.batch_size), // CLI overrides config file
        realtime_notifications: base_config.realtime_notifications,
        notification_color: base_config.notification_color,
    };
    
    // Show batch size info like RustScan with colors
    let calculated_batch = scan_config.batch_size();
    println!("{} File limit higher than batch size. Can increase speed by increasing batch size {}.", 
        "[~]".bright_blue(),
        format!("'-b {}'", calculated_batch * 2).bright_green().bold()
    );
    
    if calculated_batch > 1000 {
        println!("[!] High batch size detected ({}). Consider lowering it if you experience issues.", calculated_batch);
    }

    // Validate configuration
    let validation_errors = ConfigValidator::validate_scan_config(&scan_config);
    if !validation_errors.is_empty() {
        eprintln!("Configuration errors:");
        for error in validation_errors {
            eprintln!("  - {}", error);
        }
        process::exit(1);
    }

    // Create output manager
    let output_manager = OutputManager::new(output_config.clone());
    
    // Create progress display
    let progress = ProgressDisplay::new(scan_config.ports.len());
    
    // Create and run scanner
    let engine = ScanEngine::new(scan_config.clone()).await?;
    
    println!("{} {}", "Starting Phobos".bright_green().bold(), "v1.0.0".bright_green().bold());
    println!("{} {}", "Target:".bright_yellow().bold(), target.bright_cyan().bold());
    println!("{} {} {}", "Ports:".bright_yellow().bold(), scan_config.ports.len().to_string().bright_white().bold(), "ports".bright_yellow());
    println!("{} {}", "Technique:".bright_yellow().bold(), format!("{:?}", technique).bright_white().bold());
    println!("{} {}", "Threads:".bright_yellow().bold(), threads.to_string().bright_white().bold());
    println!();
    
    match engine.scan().await {
        Ok(results) => {
            progress.finish();
            
            // Show open ports found with enhanced colors
            let open_ports: Vec<u16> = results.port_results.iter()
                .filter(|pr| matches!(pr.state, phobos::network::PortState::Open))
                .map(|pr| pr.port)
                .collect();
            
            for port in &open_ports {
                let service = results.port_results.iter()
                    .find(|pr| pr.port == *port)
                    .and_then(|pr| pr.service.as_deref())
                    .unwrap_or("unknown");
                println!("{} {}:{} ({})", 
                    "OPEN:".bright_green().bold(),
                    target.bright_cyan(),
                    port.to_string().bright_white().bold(),
                    service.bright_yellow()
                );
            }
            
            println!();
            
            // Show open ports in RustScan format
            if !open_ports.is_empty() {
                let ports_str = open_ports.iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                println!("{} {}", 
                    "Open".bright_green().bold(),
                    format!("{}:[{}]", target.bright_cyan(), ports_str.bright_white().bold())
                );
            }
            
            if let Err(e) = output_manager.write_results(&results) {
                eprintln!("Failed to write results: {}", e);
            }
            
            // Summary is already displayed by output manager
            
            // Show greppable output if enabled
            if matches.get_flag("greppable") {
                for port in &open_ports {
                    println!("{}:{}", target, port);
                }
            }
            
            // Run Nmap if not ports-only mode and open ports found
            if !matches.get_flag("ports-only") && !open_ports.is_empty() {
                println!("{} {}", "[~]".bright_blue(), "Starting Script(s)".bright_yellow().bold());
                run_nmap_scan(&target, &open_ports, matches.get_one::<String>("nmap-args"));
            }
        }
        Err(e) => {
            eprintln!("Scan failed: {:?}", e);
            process::exit(1);
        }
    }
    
    // Stop total scan timer and show benchmark if enabled
    total_timer.stop();
    phobos_bench.stop();
    benchmark.add_timer(total_timer);
    benchmark.add_timer(phobos_bench);
    
    // Benchmark summary removed as requested
    
    Ok(())
}

fn run_nmap_scan(target: &str, open_ports: &[u16], nmap_args: Option<&String>) {
    use std::process::Command;
    
    let ports_str = open_ports.iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    
    let mut cmd = Command::new("nmap");
    cmd.arg("-sV")  // Service version detection
        .arg("-sC")  // Default scripts
        .arg("-p")
        .arg(&ports_str)
        .arg(target);
    
    // Add custom nmap arguments if provided
    if let Some(args) = nmap_args {
        for arg in args.split_whitespace() {
            cmd.arg(arg);
        }
    }
    
    println!("{} {} {} {} {}", 
             "[~] Starting Nmap".bright_green().bold(),
             env!("CARGO_PKG_VERSION").bright_cyan(),
             "( https://nmap.org ) at".bright_white(),
             chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string().bright_yellow(),
             "+0300".bright_white());
    
    match cmd.output() {
        Ok(output) => {
            if output.status.success() {
                println!("{}", String::from_utf8_lossy(&output.stdout));
            } else {
                eprintln!("Nmap failed: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(e) => {
            eprintln!("Failed to run Nmap: {}. Make sure Nmap is installed.", e);
        }
    }
}





fn parse_ports(port_spec: &str) -> anyhow::Result<Vec<u16>> {
    let mut ports = Vec::new();
    
    for part in port_spec.split(',') {
        let part = part.trim();
        
        // Handle protocol-specific ports (U:53, T:80)
        let port_part = if part.contains(':') {
            part.split(':').nth(1).unwrap_or(part)
        } else {
            part
        };
        
        if port_part.contains('-') {
            let range: Vec<&str> = port_part.split('-').collect();
            if range.len() != 2 {
                return Err(anyhow::anyhow!("Invalid port range: {}", part));
            }
            let start: u16 = range[0].parse()?;
            let end: u16 = range[1].parse()?;
            for port in start..=end {
                ports.push(port);
            }
        } else {
            ports.push(port_part.parse()?);
        }
    }
    
    if ports.is_empty() {
        // Default to common ports if parsing fails
        ports = vec![21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080];
    }
    
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn _display_summary(results: &[phobos::scanner::ScanResult], target: &str) {
    let mut total_open = 0;
    let mut total_closed = 0;
    let mut total_filtered = 0;
    
    for result in results {
        total_open += result.open_ports.len();
        total_closed += result.closed_ports.len();
        total_filtered += result.filtered_ports.len();
    }
    
    println!("\n{}", "=== Scan Summary ===".bright_magenta().bold());
    println!("{} {}", "Target:".bright_yellow(), target.bright_white().bold());
    println!("{} {}", "Total ports scanned:".bright_yellow(), results.iter().map(|r| r.total_ports()).sum::<usize>().to_string().bright_white().bold());
    println!("{} {}", "Open ports:".bright_green(), total_open.to_string().bright_green().bold());
    println!("{} {}", "Closed ports:".bright_red(), total_closed.to_string().bright_red().bold());
    println!("{} {}", "Filtered ports:".bright_yellow(), total_filtered.to_string().bright_yellow().bold());
    
    if total_open > 0 {
        println!("\n{}", "=== Open Ports ===".bright_green().bold());
        for result in results {
            for port_result in &result.port_results {
                if matches!(port_result.state, phobos::network::PortState::Open) {
                    let service = port_result.service.as_deref().unwrap_or("unknown");
                    println!("{}/{}\t{}", port_result.port.to_string().bright_cyan().bold(), port_result.protocol.as_str().to_lowercase().bright_blue(), service.bright_white());
                }
            }
        }
    }
    
    println!();
}