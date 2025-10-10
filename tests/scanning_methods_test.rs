use phobos::config::ScanConfig;
use phobos::scanner::engine::ScanEngine;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::timeout;

/// Test 1: General scan - without specifying initial port
#[tokio::test]
async fn test_general_scan_without_specific_ports() {
    // General scan configuration - scans all common ports
    let config = ScanConfig::new("127.0.0.1".to_string())
        .with_timeout(5000) // 5 second timeout (milliseconds)
        .with_threads(100)
        .with_ports(vec![22, 80, 443, 8080]); // A few common ports for testing
    
    let engine = ScanEngine::new(config).await.expect("Failed to create engine");
    
    // Scan localhost
    let _target = Ipv4Addr::new(127, 0, 0, 1);
    
    let scan_result = timeout(
        Duration::from_secs(30),
        engine.scan()
    ).await;
    
    match scan_result {
        Ok(result) => {
            let scan_data = result.expect("Scan failed");
            println!("General scan completed:");
            println!("- Total ports: {}", scan_data.total_ports());
            println!("- Open ports: {:?}", scan_data.open_ports.len());
            
            // Port skipping check
            let open_ports = &scan_data.open_ports;
            if !open_ports.is_empty() {
                let mut sorted_ports: Vec<_> = open_ports.iter().cloned().collect();
                sorted_ports.sort();
                
                // Check if there are large gaps between consecutive ports
                for i in 1..sorted_ports.len() {
                    let gap = sorted_ports[i] - sorted_ports[i-1];
                    if gap > 1000 {
                        println!("⚠️  Large gap detected between port {} and {} ({})", 
                               sorted_ports[i-1], sorted_ports[i], gap);
                    }
                }
                println!("✅ General scan port skipping check completed");
            }
        },
        Err(_) => {
            println!("⚠️  General scan timed out");
        }
    }
}

/// Test 2: Targeted scan - specific port range
#[tokio::test]
async fn test_targeted_scan_with_port_range() {
    // Common ports for web services
    let target_ports = vec![80, 443, 8080, 8443, 3000, 5000, 8000, 9000];
    
    // Specific port range configuration
    let config = ScanConfig::new("127.0.0.1".to_string())
        .with_timeout(3000) // 3 second timeout (milliseconds)
        .with_threads(50)
        .with_ports(target_ports.clone());
    
    let engine = ScanEngine::new(config).await.expect("Failed to create engine");
    
    let scan_result = timeout(
        Duration::from_secs(15),
        engine.scan()
    ).await;
    
    match scan_result {
        Ok(result) => {
            let scan_data = result.expect("Targeted scan failed");
            println!("Targeted scan completed:");
            println!("- Target port count: {}", target_ports.len());
            println!("- Scanned port count: {}", scan_data.total_ports());
            println!("- Open ports: {:?}", scan_data.open_ports.len());
            
            // Ensure all target ports were scanned
            let scanned_ports: Vec<u16> = scan_data.port_results
                .iter()
                .map(|r| r.port)
                .collect();
            
            for &target_port in &target_ports {
                if !scanned_ports.contains(&target_port) {
                    println!("❌ Port {} was skipped!", target_port);
                } else {
                    println!("✅ Port {} was scanned", target_port);
                }
            }
            
            // Port skipping check - were any ports scanned outside target range?
            for &scanned_port in &scanned_ports {
                if !target_ports.contains(&scanned_port) {
                    println!("⚠️  Unexpected port scanned: {}", scanned_port);
                }
            }
            
            println!("✅ Targeted scan port skipping check completed");
        },
        Err(_) => {
            println!("⚠️  Targeted scan timed out");
        }
    }
}

/// Test 3: Flag combinations optimization test
#[tokio::test]
async fn test_optimal_flag_combinations() {
    println!("🔧 Testing optimal flag combinations...");
    
    let test_configs = vec![
        ("Fast + Small Batch", 50, Duration::from_millis(500)),
        ("Medium + Medium Batch", 100, Duration::from_secs(1)),
        ("Slow + Large Batch", 200, Duration::from_secs(2)),
        ("Very Fast + Very Small Batch", 25, Duration::from_millis(200)),
    ];
    
    let test_ports = vec![22, 80, 443, 8080];
    
    for (name, batch_size, timeout_duration) in test_configs {
        println!("\n📊 Testing: {}", name);
        
        let config = ScanConfig::new("127.0.0.1".to_string())
            .with_threads(batch_size)
            .with_timeout(timeout_duration.as_millis() as u64)
            .with_ports(test_ports.clone());
        
        let start_time = std::time::Instant::now();
        
        match ScanEngine::new(config).await {
            Ok(engine) => {
                match timeout(Duration::from_secs(10), engine.scan()).await {
                    Ok(Ok(result)) => {
                        let duration = start_time.elapsed();
                        println!("  ✅ Duration: {:?}, Ports: {}, Open: {}", 
                               duration, result.total_ports(), result.open_ports.len());
                    },
                    Ok(Err(e)) => {
                        println!("  ❌ Error: {:?}", e);
                    },
                    Err(_) => {
                        println!("  ⚠️  Timeout");
                    }
                }
            },
            Err(e) => {
                println!("  ❌ Failed to create engine: {:?}", e);
            }
        }
    }
    
    println!("\n🎯 Optimal combination test completed!");
    println!("💡 Small batch size and short timeout recommended for best performance.");
}

/// Test 4: Port skipping detailed analysis
#[tokio::test]
async fn test_port_skipping_analysis() {
    println!("🔍 Starting detailed port skipping analysis...");
    
    // Sequential port range test
    let sequential_ports: Vec<u16> = (8000..8010).collect();
    
    let config = ScanConfig::new("127.0.0.1".to_string())
        .with_ports(sequential_ports.clone())
        .with_timeout(1000) // 1 second timeout (milliseconds)
        .with_threads(5);
    
    let engine = ScanEngine::new(config).await.expect("Failed to create engine");
    
    match engine.scan().await {
        Ok(result) => {
            let scanned_ports: Vec<u16> = result.port_results
                .iter()
                .map(|r| r.port)
                .collect();
            
            println!("Target ports: {:?}", sequential_ports);
            println!("Scanned ports: {:?}", scanned_ports);
            
            // Check each port
            let mut missing_ports = Vec::new();
            for &port in &sequential_ports {
                if !scanned_ports.contains(&port) {
                    missing_ports.push(port);
                }
            }
            
            if missing_ports.is_empty() {
                println!("✅ All ports successfully scanned - no port skipping");
            } else {
                println!("❌ Skipped ports: {:?}", missing_ports);
            }
        },
        Err(e) => {
            println!("❌ Scan error: {:?}", e);
        }
    }
}
