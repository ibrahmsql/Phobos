use clap::{Arg, Command, ArgAction};
use std::process;
use colored::*;
use phobos::{
    config::ScanConfig,
    network::{ScanTechnique, stealth::StealthOptions},
    output::{OutputConfig, OutputFormat, OutputManager, ProgressDisplay},
    scanner::{engine::ScanEngine, ScanResult},
    utils::config::ConfigValidator,
};
use anyhow;
use chrono;

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
    println!("{}", ": 🔗 https://github.com/ibrahmsql/phobos               :".bright_blue());
    println!("{}", ": ⚡ written in Rust | faster than the old gods        :".bright_blue());
    println!("{}", "------------------------------------------------------".bright_blue());
    println!();
    println!("{}", "\"Let your ports tremble.\"".truecolor(231, 76, 60).bold());
    println!();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Print banner
    print_banner();
    
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
        // Stealth options
        .arg(
            Arg::new("stealth")
                .long("stealth")
                .help("Enable stealth mode")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("fragment")
                .short('f')
                .long("fragment")
                .help("Fragment packets")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("decoys")
                .short('D')
                .long("decoys")
                .value_name("DECOY_LIST")
                .help("Use decoy addresses (e.g., 192.168.1.1,192.168.1.2,ME)"),
        )
        .arg(
            Arg::new("source-ip")
                .short('S')
                .long("source-ip")
                .value_name("IP")
                .help("Spoof source IP address"),
        )
        .arg(
            Arg::new("source-port")
                .short('g')
                .long("source-port")
                .value_name("PORT")
                .help("Use specific source port"),
        )
        .arg(
            Arg::new("data-length")
                .long("data-length")
                .value_name("BYTES")
                .help("Append random data to packets"),
        )
        .arg(
            Arg::new("mtu")
                .long("mtu")
                .value_name("SIZE")
                .help("Set custom MTU size for fragmentation"),
        )
        // Output options
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .help("Output format")
                .value_parser(["text", "json", "xml", "csv", "nmap"])
                .default_value("text"),
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
            Arg::new("show-closed")
                .long("show-closed")
                .help("Show closed ports")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("show-filtered")
                .long("show-filtered")
                .help("Show filtered ports")
                .action(ArgAction::SetTrue),
        )
        // Advanced options
        .arg(
            Arg::new("top-ports")
                .long("top-ports")
                .value_name("COUNT")
                .help("Scan top N most common ports"),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file"),
        )
        .arg(
            Arg::new("legal-warning")
                .long("legal-warning")
                .help("Show legal warning")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ports-only")
                .long("ports-only")
                .help("Only scan ports, don't run Nmap scripts")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("nmap-args")
                .long("nmap-args")
                .value_name("ARGS")
                .help("Additional Nmap arguments for service detection"),
        )
        .get_matches();

    // Show legal warning if requested
    if matches.get_flag("legal-warning") {
        show_legal_warning();
    }

    // Load configuration (simplified)
    let _config = ScanConfig::default();

    // Parse arguments and override config
    let target = matches.get_one::<String>("target").unwrap();
    let ports = matches.get_one::<String>("ports").unwrap();
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
    let stealth_options = StealthOptions {
        fragment_packets: matches.get_flag("fragment") || matches.get_flag("stealth"),
        randomize_source_port: matches.get_flag("stealth"),
        spoof_source_ip: matches.get_one::<String>("source-ip")
            .and_then(|ip| ip.parse().ok()),
        decoy_addresses: parse_decoys(matches.get_one::<String>("decoys")),
        timing_randomization: matches.get_flag("stealth"),
        packet_padding: matches.get_one::<String>("data-length")
            .and_then(|s| s.parse().ok()),
        custom_mtu: matches.get_one::<String>("mtu")
            .and_then(|s| s.parse().ok()),
        randomize_ip_id: matches.get_flag("stealth"),
        randomize_sequence: matches.get_flag("stealth"),
        use_bad_checksum: false,
    };

    // Parse output configuration
    let output_format = match matches.get_one::<String>("format").unwrap().as_str() {
        "json" => OutputFormat::Json,
        "xml" => OutputFormat::Xml,
        "csv" => OutputFormat::Csv,
        "nmap" => OutputFormat::Nmap,
        _ => OutputFormat::Text,
    };

    let output_config = OutputConfig {
        format: output_format,
        file: matches.get_one::<String>("output").cloned(),
        colored: !matches.get_flag("no-color"),
        verbose: matches.get_flag("verbose"),
        show_closed: matches.get_flag("show-closed"),
        show_filtered: matches.get_flag("show-filtered"),

    };

    // Create scan configuration
    let scan_config = ScanConfig {
        target: target.clone(),
        ports: parse_ports(ports)?,
        technique,
        threads,
        timeout,
        rate_limit,
        stealth_options: Some(stealth_options),
        timing_template: timing_level,
        top_ports: matches.get_one::<String>("top-ports")
            .and_then(|s| s.parse().ok()),
    };

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
    
    println!("{} {}", "Starting Phobos".bright_green(), "v1.0.0".bright_green().bold());
    println!("{} {}", "Target:".bright_yellow(), target.bright_white().bold());
    println!("{} {} {}", "Ports:".bright_yellow(), scan_config.ports.len().to_string().bright_white().bold(), "ports".bright_yellow());
    println!("{} {:?}", "Technique:".bright_yellow(), technique);
    println!("{} {}", "Threads:".bright_yellow(), threads.to_string().bright_white().bold());
    println!();
    
    match engine.scan().await {
        Ok(results) => {
            progress.finish();
            
            // Show open ports found
            let open_ports: Vec<u16> = results.port_results.iter()
                .filter(|pr| matches!(pr.state, phobos::network::PortState::Open))
                .map(|pr| pr.port)
                .collect();
            
            for port in &open_ports {
                println!("{} {}:{}", "Open".bright_green().bold(), target.bright_white(), port.to_string().bright_cyan());
            }
            
            if let Err(e) = output_manager.write_results(&results) {
                eprintln!("Failed to write results: {}", e);
            }
            
            // Summary is already displayed by output manager
            
            // Run Nmap if not ports-only mode and open ports found
            if !matches.get_flag("ports-only") && !open_ports.is_empty() {
                println!("{}", "[~] Starting Script(s)".bright_yellow().bold());
                run_nmap_scan(&target, &open_ports, matches.get_one::<String>("nmap-args"));
            }
        }
        Err(e) => {
            eprintln!("Scan failed: {:?}", e);
            process::exit(1);
        }
    }
    
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

fn show_legal_warning() {
    println!("⚠️  Legal Notice:");
    println!("This tool should only be used on systems you own or have permission to test.");
    println!("Unauthorized port scanning may be illegal in your jurisdiction.");
    print!("Continue? (y/N): ");
    
    use std::io::{self, Write};
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    if !input.trim().to_lowercase().starts_with('y') {
        println!("Scan cancelled.");
        process::exit(0);
    }
    println!();
}

fn parse_decoys(decoys_str: Option<&String>) -> Vec<std::net::IpAddr> {
    let mut decoys = Vec::new();
    
    if let Some(decoys_str) = decoys_str {
        for decoy in decoys_str.split(',') {
            if decoy.trim() == "ME" {
                // Skip "ME" - will be handled by stealth module
                continue;
            }
            if decoy.starts_with("RND:") {
                // Random decoys - will be handled by stealth module
                continue;
            }
            if let Ok(ip) = decoy.trim().parse() {
                decoys.push(ip);
            }
        }
    }
    
    decoys
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

fn display_summary(results: &[phobos::scanner::ScanResult], target: &str) {
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