//! Adaptive Scanning Example
//!
//! This example demonstrates adaptive scanning that automatically
//! adjusts parameters based on network conditions and target characteristics.

use phobos::{
    config::ScanConfig,
    scanner::engine::ScanEngine,
    adaptive::{AdaptiveConfig, TargetType},
    network::ScanTechnique,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧠 Phobos Adaptive Scanning Example\n");
    println!("Adaptive scanning automatically adjusts scan parameters based on:");
    println!("  • Network latency and packet loss");
    println!("  • Target responsiveness");
    println!("  • Firewall behavior");
    println!("  • Target type detection\n");
    
    // Example 1: Basic Adaptive Scan
    println!("═══════════════════════════════════════════");
    println!("Example 1: Basic Adaptive Scan");
    println!("═══════════════════════════════════════════\n");
    
    basic_adaptive_scan().await?;
    
    // Example 2: Cloud Infrastructure Scan
    println!("\n═══════════════════════════════════════════");
    println!("Example 2: Cloud Infrastructure Adaptive Scan");
    println!("═══════════════════════════════════════════\n");
    
    cloud_adaptive_scan().await?;
    
    // Example 3: IoT Device Scan
    println!("\n═══════════════════════════════════════════");
    println!("Example 3: IoT Device Adaptive Scan");
    println!("═══════════════════════════════════════════\n");
    
    iot_adaptive_scan().await?;
    
    println!("\n✨ Adaptive Scan Examples Completed!");
    
    Ok(())
}

/// Example 1: Basic adaptive scan with automatic parameter adjustment
async fn basic_adaptive_scan() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Configuring basic adaptive scan...");
    println!("   • Automatic parameter tuning");
    println!("   • Network condition detection");
    println!("   • Real-time adjustments\n");
    
    let mut config = ScanConfig::default();
    config.technique = ScanTechnique::Connect;
    config.timeout = Duration::from_millis(3000);
    
    // Enable adaptive scanning
    let adaptive_config = AdaptiveConfig {
        enabled: true,
        learning_phase_duration: Duration::from_secs(5),
        adjustment_interval: Duration::from_secs(2),
        min_samples_for_adjustment: 50,
        target_type: TargetType::Auto, // Auto-detect target type
    };
    
    config.adaptive = Some(adaptive_config);
    
    let engine = ScanEngine::new(config)?;
    
    let ports: Vec<u16> = (1..=1000).collect();
    
    println!("⚡ Starting adaptive scan...");
    println!("   Target: scanme.nmap.org");
    println!("   Ports: 1-1000");
    println!("   Mode: Auto-detect and adapt\n");
    
    let start = std::time::Instant::now();
    let results = engine.scan_target("scanme.nmap.org", &ports).await?;
    let duration = start.elapsed();
    
    println!("✅ Scan completed in {:.2}s", duration.as_secs_f64());
    println!("   Open ports: {}", results.open_port_count());
    
    // Display adaptive insights (if available)
    if let Some(insights) = &results.adaptive_insights {
        println!("\n📊 Adaptive Insights:");
        println!("   • Detected latency: {:.1}ms", insights.avg_latency_ms);
        println!("   • Packet loss: {:.1}%", insights.packet_loss_rate * 100.0);
        println!("   • Target type: {:?}", insights.detected_target_type);
        println!("   • Recommended timing: T{}", insights.recommended_timing);
        
        if insights.adjustments_made > 0 {
            println!("   • Parameters adjusted {} times", insights.adjustments_made);
        }
    }
    
    Ok(())
}

/// Example 2: Adaptive scan optimized for cloud infrastructure
async fn cloud_adaptive_scan() -> Result<(), Box<dyn std::error::Error>> {
    println!("☁️  Configuring cloud-optimized adaptive scan...");
    println!("   • Low latency networks");
    println!("   • High bandwidth");
    println!("   • Rate limiting awareness\n");
    
    let mut config = ScanConfig::default();
    config.technique = ScanTechnique::Connect;
    config.timeout = Duration::from_millis(2000);
    config.max_threads = 500;
    
    let adaptive_config = AdaptiveConfig {
        enabled: true,
        learning_phase_duration: Duration::from_secs(3),
        adjustment_interval: Duration::from_secs(1),
        min_samples_for_adjustment: 30,
        target_type: TargetType::Cloud, // Optimized for cloud
    };
    
    config.adaptive = Some(adaptive_config);
    
    let engine = ScanEngine::new(config)?;
    
    let ports: Vec<u16> = vec![
        22, 80, 443, 3000, 3306, 5432, 6379, 8080, 8443, 9000, 27017
    ];
    
    println!("⚡ Starting cloud-adaptive scan...");
    println!("   Target: scanme.nmap.org");
    println!("   Ports: Common cloud service ports");
    println!("   Optimization: Cloud infrastructure\n");
    
    let start = std::time::Instant::now();
    let results = engine.scan_target("scanme.nmap.org", &ports).await?;
    let duration = start.elapsed();
    
    println!("✅ Scan completed in {:.2}s", duration.as_secs_f64());
    println!("   Open ports: {}", results.open_port_count());
    println!("   Optimization: Cloud-specific tuning applied ☁️");
    
    Ok(())
}

/// Example 3: Adaptive scan for IoT devices (slower, more careful)
async fn iot_adaptive_scan() -> Result<(), Box<dyn std::error::Error>> {
    println!("📡 Configuring IoT-optimized adaptive scan...");
    println!("   • Higher latency tolerance");
    println!("   • Reduced scan rate");
    println!("   • Device stability awareness\n");
    
    let mut config = ScanConfig::default();
    config.technique = ScanTechnique::Connect;
    config.timeout = Duration::from_millis(5000); // Longer timeout
    config.max_threads = 20; // Fewer threads
    
    let adaptive_config = AdaptiveConfig {
        enabled: true,
        learning_phase_duration: Duration::from_secs(10), // Longer learning
        adjustment_interval: Duration::from_secs(5),
        min_samples_for_adjustment: 10,
        target_type: TargetType::IoT, // Optimized for IoT
    };
    
    config.adaptive = Some(adaptive_config);
    
    let engine = ScanEngine::new(config)?;
    
    // Common IoT device ports
    let ports: Vec<u16> = vec![
        21, 22, 23, 80, 81, 443, 554, 1883, 5000, 5001, 8080, 8081, 8883, 9000
    ];
    
    println!("⚡ Starting IoT-adaptive scan...");
    println!("   Target: scanme.nmap.org");
    println!("   Ports: Common IoT service ports");
    println!("   Optimization: IoT device friendly\n");
    
    let start = std::time::Instant::now();
    let results = engine.scan_target("scanme.nmap.org", &ports).await?;
    let duration = start.elapsed();
    
    println!("✅ Scan completed in {:.2}s", duration.as_secs_f64());
    println!("   Open ports: {}", results.open_port_count());
    println!("   Optimization: IoT-friendly parameters 📡");
    
    println!("\n💡 IoT Scan Tips:");
    println!("   • Use longer timeouts for embedded devices");
    println!("   • Reduce thread count to avoid overwhelming devices");
    println!("   • Watch for devices that reset under scan load");
    println!("   • Consider device sleep/wake cycles");
    
    Ok(())
}
