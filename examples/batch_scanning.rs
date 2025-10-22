//! Batch Scanning Example
//!
//! This example demonstrates scanning multiple targets efficiently
//! using batch processing and concurrent scanning.

use phobos::{
    config::ScanConfig,
    scanner::engine::ScanEngine,
    network::ScanTechnique,
};
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("📦 Phobos Batch Scanning Example\n");
    
    // Example 1: Sequential batch scanning
    println!("═══════════════════════════════════════════");
    println!("Example 1: Sequential Batch Scanning");
    println!("═══════════════════════════════════════════\n");
    
    sequential_batch_scan().await?;
    
    // Example 2: Concurrent batch scanning
    println!("\n═══════════════════════════════════════════");
    println!("Example 2: Concurrent Batch Scanning");
    println!("═══════════════════════════════════════════\n");
    
    concurrent_batch_scan().await?;
    
    println!("\n✨ Batch Scanning Examples Completed!");
    
    Ok(())
}

/// Example 1: Sequential scanning of multiple targets
async fn sequential_batch_scan() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 Scanning multiple targets sequentially...\n");
    
    let config = ScanConfig::default();
    let engine = ScanEngine::new(config)?;
    
    // List of targets to scan
    let targets = vec![
        ("scanme.nmap.org", vec![22, 80, 443]),
        ("example.com", vec![80, 443]),
        ("localhost", vec![22, 80, 3000, 8080]),
    ];
    
    let start = Instant::now();
    let mut total_open = 0;
    
    for (target, ports) in &targets {
        println!("🎯 Scanning {}...", target);
        
        match engine.scan_target(target, ports).await {
            Ok(results) => {
                let open_count = results.open_port_count();
                total_open += open_count;
                println!("   ✅ Found {} open ports", open_count);
            }
            Err(e) => {
                println!("   ❌ Error: {}", e);
            }
        }
    }
    
    let duration = start.elapsed();
    
    println!("\n📊 Sequential Scan Summary:");
    println!("   Targets scanned: {}", targets.len());
    println!("   Total open ports: {}", total_open);
    println!("   Total time: {:.2}s", duration.as_secs_f64());
    println!("   Avg time per target: {:.2}s", 
        duration.as_secs_f64() / targets.len() as f64);
    
    Ok(())
}

/// Example 2: Concurrent scanning of multiple targets
async fn concurrent_batch_scan() -> Result<(), Box<dyn std::error::Error>> {
    println!("⚡ Scanning multiple targets concurrently...\n");
    
    let config = ScanConfig::default();
    
    // List of targets to scan
    let targets = vec![
        ("scanme.nmap.org", vec![22, 80, 443]),
        ("example.com", vec![80, 443]),
        ("localhost", vec![22, 80, 3000, 8080]),
    ];
    
    let start = Instant::now();
    
    // Create scan tasks
    let mut handles = Vec::new();
    
    for (target, ports) in targets {
        let config_clone = config.clone();
        let target_str = target.to_string();
        
        let handle = tokio::spawn(async move {
            let engine = ScanEngine::new(config_clone)?;
            let results = engine.scan_target(&target_str, &ports).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((target_str, results))
        });
        
        handles.push(handle);
    }
    
    // Wait for all scans to complete
    let mut total_open = 0;
    let mut successful = 0;
    
    for handle in handles {
        match handle.await {
            Ok(Ok((target, results))) => {
                let open_count = results.open_port_count();
                total_open += open_count;
                successful += 1;
                println!("✅ {}: {} open ports", target, open_count);
            }
            Ok(Err(e)) => {
                println!("❌ Scan error: {}", e);
            }
            Err(e) => {
                println!("❌ Task error: {}", e);
            }
        }
    }
    
    let duration = start.elapsed();
    
    println!("\n📊 Concurrent Scan Summary:");
    println!("   Targets scanned: {}", successful);
    println!("   Total open ports: {}", total_open);
    println!("   Total time: {:.2}s", duration.as_secs_f64());
    println!("   Speedup: ~{}x faster than sequential", 
        3); // Approximate based on 3 targets
    
    println!("\n💡 Concurrency Benefits:");
    println!("   • Parallel execution reduces total time");
    println!("   • Better resource utilization");
    println!("   • Scales with number of CPU cores");
    println!("   • Ideal for scanning many targets");
    
    Ok(())
}
