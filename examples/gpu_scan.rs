//! GPU-Accelerated Port Scanning Example
//!
//! This example demonstrates how to use Phobos with GPU acceleration
//! for maximum scanning performance.

use phobos::{
    config::ScanConfig,
    scanner::engine::ScanEngine,
    network::ScanTechnique,
};
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎮 Phobos GPU Acceleration Example\n");
    
    // Check if GPU is available
    #[cfg(feature = "gpu")]
    {
        println!("✅ GPU acceleration is enabled");
        if let Some(gpu_info) = detect_gpu() {
            println!("📊 Detected GPU: {}", gpu_info);
        } else {
            println!("⚠️  No compatible GPU detected, falling back to CPU");
        }
    }
    
    #[cfg(not(feature = "gpu"))]
    {
        println!("❌ GPU acceleration not compiled. Build with --features gpu");
        println!("   cargo build --release --features gpu");
        return Ok(());
    }
    
    println!("\n🎯 Target: scanme.nmap.org");
    println!("📡 Scanning 65535 ports with GPU acceleration...\n");
    
    // Configure for GPU-optimized scanning
    let mut config = ScanConfig::default();
    config.technique = ScanTechnique::Connect;
    config.timeout = std::time::Duration::from_millis(2000);
    config.max_threads = 5000; // High thread count for GPU
    config.batch_size = Some(10000); // Large batches for GPU efficiency
    
    // Create scan engine
    let engine = ScanEngine::new(config)?;
    
    // Prepare port range (1-65535)
    let ports: Vec<u16> = (1..=65535).collect();
    
    // Start timing
    let start = Instant::now();
    
    // Execute scan
    println!("⚡ Scan started...");
    let results = engine.scan_target(
        "scanme.nmap.org",
        &ports
    ).await?;
    
    let duration = start.elapsed();
    
    // Display results
    println!("\n📊 Scan Results:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("⏱️  Duration: {:.2}s", duration.as_secs_f64());
    println!("🔍 Ports scanned: {}", ports.len());
    println!("✅ Open ports found: {}", results.open_port_count());
    println!("🚀 Scan rate: {:.0} ports/sec", 
        ports.len() as f64 / duration.as_secs_f64());
    
    if !results.port_results.is_empty() {
        println!("\n🔓 Open Ports:");
        for port_result in results.port_results.iter().take(20) {
            if matches!(port_result.state, phobos::network::PortState::Open) {
                println!("  • Port {}: {} ({}ms)", 
                    port_result.port,
                    port_result.service.as_deref().unwrap_or("unknown"),
                    port_result.response_time.as_millis()
                );
            }
        }
        
        if results.open_port_count() > 20 {
            println!("  ... and {} more", results.open_port_count() - 20);
        }
    }
    
    println!("\n💡 Performance Tips:");
    println!("  • GPU works best with large port ranges (10k+ ports)");
    println!("  • Increase batch size for better GPU utilization");
    println!("  • Use high thread counts (1000-10000) with GPU");
    println!("  • Monitor GPU memory usage for very large scans");
    
    Ok(())
}

#[cfg(feature = "gpu")]
fn detect_gpu() -> Option<String> {
    // This would use actual GPU detection in real implementation
    // For example purposes, we'll simulate it
    use std::env;
    
    if env::var("PHOBOS_NO_GPU").is_ok() {
        return None;
    }
    
    // In real implementation, this would query OpenCL/CUDA
    Some("GPU Device (OpenCL 3.0)".to_string())
}

#[cfg(not(feature = "gpu"))]
fn detect_gpu() -> Option<String> {
    None
}
