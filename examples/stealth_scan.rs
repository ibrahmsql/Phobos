//! Stealth Scanning Example
//!
//! This example demonstrates advanced stealth scanning techniques
//! to evade detection by firewalls and intrusion detection systems.

use phobos::{
    config::ScanConfig,
    scanner::engine::ScanEngine,
    network::{ScanTechnique, stealth::StealthOptions},
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("👻 Phobos Stealth Scanning Example\n");
    println!("⚠️  Legal Warning: Only scan systems you own or have explicit permission to scan!\n");
    
    // Example 1: Paranoid Stealth Scan
    println!("═══════════════════════════════════════════");
    println!("Example 1: Paranoid Stealth Scan");
    println!("═══════════════════════════════════════════\n");
    
    paranoid_stealth_scan().await?;
    
    // Example 2: Shadow Scan with Decoys
    println!("\n═══════════════════════════════════════════");
    println!("Example 2: Shadow Scan with Decoys");
    println!("═══════════════════════════════════════════\n");
    
    shadow_scan_with_decoys().await?;
    
    // Example 3: Fragmentation Evasion
    println!("\n═══════════════════════════════════════════");
    println!("Example 3: Fragmentation Evasion");
    println!("═══════════════════════════════════════════\n");
    
    fragmentation_evasion_scan().await?;
    
    println!("\n✨ Stealth Scan Examples Completed!");
    
    Ok(())
}

/// Example 1: Paranoid stealth scan with extreme caution
async fn paranoid_stealth_scan() -> Result<(), Box<dyn std::error::Error>> {
    println!("🕵️  Configuring paranoid stealth scan...");
    println!("   • Timing: Paranoid (T0)");
    println!("   • Randomized scan order");
    println!("   • Long delays between probes");
    println!("   • Minimal detection signature\n");
    
    let mut config = ScanConfig::default();
    config.technique = ScanTechnique::Syn;
    config.timeout = Duration::from_secs(30); // Long timeout
    config.max_threads = 1; // Single thread for stealth
    
    // Stealth options
    let mut stealth_opts = StealthOptions::default();
    stealth_opts.randomize_order = true;
    stealth_opts.scan_delay = Duration::from_millis(1000); // 1 second between probes
    stealth_opts.timing_template = 0; // Paranoid
    
    config.stealth = Some(stealth_opts);
    
    let engine = ScanEngine::new(config)?;
    
    // Scan only critical ports
    let ports = vec![22, 80, 443];
    
    println!("⚡ Starting paranoid scan...");
    println!("   Target: scanme.nmap.org");
    println!("   Ports: {:?}", ports);
    println!("   This will be VERY slow but extremely stealthy...\n");
    
    let start = std::time::Instant::now();
    let results = engine.scan_target("scanme.nmap.org", &ports).await?;
    let duration = start.elapsed();
    
    println!("✅ Scan completed in {:.2}s", duration.as_secs_f64());
    println!("   Open ports: {}", results.open_port_count());
    println!("   Detection risk: Minimal 👻");
    
    Ok(())
}

/// Example 2: Shadow scan using IP decoys
async fn shadow_scan_with_decoys() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎭 Configuring shadow scan with decoys...");
    println!("   • Using decoy IP addresses");
    println!("   • Spoofed source ports");
    println!("   • Makes attribution difficult\n");
    
    let mut config = ScanConfig::default();
    config.technique = ScanTechnique::Syn;
    config.timeout = Duration::from_millis(3000);
    config.max_threads = 10;
    
    let mut stealth_opts = StealthOptions::default();
    stealth_opts.randomize_order = true;
    stealth_opts.timing_template = 2; // Polite
    
    // Add decoy IPs (these should be real, unused IPs in your network)
    stealth_opts.decoy_ips = vec![
        "192.168.1.100".parse()?,
        "192.168.1.101".parse()?,
        "192.168.1.102".parse()?,
    ];
    
    config.stealth = Some(stealth_opts);
    
    let engine = ScanEngine::new(config)?;
    
    let ports = vec![80, 443, 8080, 8443];
    
    println!("⚡ Starting shadow scan with {} decoys...", 3);
    println!("   Target: scanme.nmap.org");
    println!("   Ports: {:?}\n", ports);
    
    let start = std::time::Instant::now();
    let results = engine.scan_target("scanme.nmap.org", &ports).await?;
    let duration = start.elapsed();
    
    println!("✅ Scan completed in {:.2}s", duration.as_secs_f64());
    println!("   Open ports: {}", results.open_port_count());
    println!("   Attribution: Difficult due to decoys 🎭");
    
    Ok(())
}

/// Example 3: Packet fragmentation to evade firewalls
async fn fragmentation_evasion_scan() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔀 Configuring fragmentation evasion...");
    println!("   • Small packet fragments");
    println!("   • Bypasses simple packet filters");
    println!("   • Defeats basic IDS signatures\n");
    
    let mut config = ScanConfig::default();
    config.technique = ScanTechnique::Syn;
    config.timeout = Duration::from_millis(5000);
    config.max_threads = 50;
    
    let mut stealth_opts = StealthOptions::default();
    stealth_opts.fragment_packets = true; // Enable fragmentation
    stealth_opts.timing_template = 3; // Normal timing
    
    config.stealth = Some(stealth_opts);
    
    let engine = ScanEngine::new(config)?;
    
    let ports: Vec<u16> = (1..=1000).collect();
    
    println!("⚡ Starting fragmentation scan...");
    println!("   Target: scanme.nmap.org");
    println!("   Ports: 1-1000\n");
    
    let start = std::time::Instant::now();
    let results = engine.scan_target("scanme.nmap.org", &ports).await?;
    let duration = start.elapsed();
    
    println!("✅ Scan completed in {:.2}s", duration.as_secs_f64());
    println!("   Open ports: {}", results.open_port_count());
    println!("   Firewall evasion: Enhanced 🔀");
    
    Ok(())
}
