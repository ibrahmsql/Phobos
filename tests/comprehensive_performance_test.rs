use phobos::config::ScanConfig;
use phobos::scanner::engine::ScanEngine;
use std::time::{Duration, Instant};
use tokio::time::timeout;

/// Comprehensive performance test - different port ranges and configurations
#[tokio::test]
async fn test_comprehensive_performance_analysis() {
    println!("🚀 Starting comprehensive performance analysis...");
    
    let test_scenarios = vec![
        (
            "Fast Scan - Few Ports",
            vec![22, 80, 443, 8080],
            50,   // threads
            1000, // timeout ms
        ),
        (
            "Medium Scan - Medium Ports",
            (1..=100).collect::<Vec<u16>>(),
            100,  // threads
            2000, // timeout ms
        ),
        (
            "Intensive Scan - Many Ports",
            (1..=1000).collect::<Vec<u16>>(),
            200,  // threads
            3000, // timeout ms
        ),
        (
            "Web Services Scan",
            vec![80, 443, 8080, 8443, 3000, 5000, 8000, 9000, 3001, 8001],
            75,   // threads
            1500, // timeout ms
        ),
    ];
    
    for (scenario_name, ports, threads, timeout_ms) in test_scenarios {
        println!("\n📊 Scenario: {}", scenario_name);
        println!("   - Port count: {}", ports.len());
        println!("   - Thread count: {}", threads);
        println!("   - Timeout: {}ms", timeout_ms);
        
        let config = ScanConfig::new("127.0.0.1".to_string())
            .with_ports(ports.clone())
            .with_threads(threads)
            .with_timeout(timeout_ms);
        
        let start_time = Instant::now();
        
        match ScanEngine::new(config).await {
            Ok(engine) => {
                match timeout(Duration::from_secs(30), engine.scan()).await {
                    Ok(Ok(result)) => {
                        let duration = start_time.elapsed();
                        let scan_rate = result.scan_rate();
                        
                        println!("   ✅ Success!");
                        println!("   - Duration: {:?}", duration);
                        println!("   - Scanned ports: {}", result.total_ports());
                        println!("   - Open ports: {}", result.open_ports.len());
                        println!("   - Closed ports: {}", result.closed_ports.len());
                        println!("   - Filtered ports: {}", result.filtered_ports.len());
                        println!("   - Scan rate: {:.2} ports/second", scan_rate);
                        
                        // Port skipping check
                        let scanned_ports: Vec<u16> = result.port_results
                            .iter()
                            .map(|r| r.port)
                            .collect();
                        
                        let mut missing_ports = Vec::new();
                        for &expected_port in &ports {
                            if !scanned_ports.contains(&expected_port) {
                                missing_ports.push(expected_port);
                            }
                        }
                        
                        if missing_ports.is_empty() {
                            println!("   ✅ No port skipping - all ports scanned");
                        } else {
                            println!("   ⚠️  Skipped ports: {:?}", missing_ports);
                        }
                        
                        // Performance evaluation
                        if scan_rate > 1000.0 {
                            println!("   🏆 Excellent performance!");
                        } else if scan_rate > 500.0 {
                            println!("   👍 Good performance");
                        } else if scan_rate > 100.0 {
                            println!("   👌 Acceptable performance");
                        } else {
                            println!("   ⚠️  Slow performance");
                        }
                    },
                    Ok(Err(e)) => {
                        println!("   ❌ Scan error: {:?}", e);
                    },
                    Err(_) => {
                        println!("   ⏰ Timeout (30s)");
                    }
                }
            },
            Err(e) => {
                println!("   ❌ Failed to create engine: {:?}", e);
            }
        }
    }
    
    println!("\n🎯 Comprehensive performance analysis completed!");
}

/// Different flag combinations optimization test
#[tokio::test]
async fn test_flag_optimization_combinations() {
    println!("⚙️  Testing flag optimization combinations...");
    
    let base_ports = vec![22, 80, 443, 8080, 3000];
    
    let flag_combinations = vec![
        ("Ultra Fast", 25, 500),      // low threads, short timeout
        ("Fast", 50, 1000),            // medium threads, medium timeout
        ("Balanced", 100, 2000),       // high threads, long timeout
        ("Intensive", 200, 3000),      // very high threads, very long timeout
        ("Conservative", 10, 5000),    // low threads, very long timeout
    ];
    
    let mut best_combination = ("None", 0, 0, 0.0, Duration::from_secs(0));
    
    for (name, threads, timeout_ms) in flag_combinations {
        println!("\n🔧 Test: {} (threads: {}, timeout: {}ms)", name, threads, timeout_ms);
        
        let config = ScanConfig::new("127.0.0.1".to_string())
            .with_ports(base_ports.clone())
            .with_threads(threads)
            .with_timeout(timeout_ms);
        
        let start_time = Instant::now();
        
        match ScanEngine::new(config).await {
            Ok(engine) => {
                match timeout(Duration::from_secs(15), engine.scan()).await {
                    Ok(Ok(result)) => {
                        let duration = start_time.elapsed();
                        let scan_rate = result.scan_rate();
                        
                        println!("  ✅ Duration: {:?}, Speed: {:.2} port/s, Ports: {}", 
                               duration, scan_rate, result.total_ports());
                        
                        // Find best combination (balance between speed and reliability)
                        let score = scan_rate * (result.total_ports() as f64 / base_ports.len() as f64);
                        if score > best_combination.3 {
                            best_combination = (name, threads, timeout_ms, score, duration);
                        }
                    },
                    Ok(Err(e)) => {
                        println!("  ❌ Error: {:?}", e);
                    },
                    Err(_) => {
                        println!("  ⏰ Timeout");
                    }
                }
            },
            Err(e) => {
                println!("  ❌ Engine error: {:?}", e);
            }
        }
    }
    
    println!("\n🏆 MOST OPTIMAL COMBINATION:");
    println!("   - Name: {}", best_combination.0);
    println!("   - Thread count: {}", best_combination.1);
    println!("   - Timeout: {}ms", best_combination.2);
    println!("   - Performance score: {:.2}", best_combination.3);
    println!("   - Duration: {:?}", best_combination.4);
    
    println!("\n💡 RECOMMENDATIONS:");
    if best_combination.1 <= 50 {
        println!("   - Low thread count is optimal - efficient use of system resources");
    } else {
        println!("   - High thread count needed - intensive parallel processing");
    }
    
    if best_combination.2 <= 1000 {
        println!("   - Short timeout is optimal - fast response");
    } else {
        println!("   - Long timeout needed - reliable results");
    }
}

/// Real world scenarios test
#[tokio::test]
async fn test_real_world_scenarios() {
    println!("🌍 Testing real world scenarios...");
    
    let scenarios = vec![
        (
            "Web Server Scan",
            vec![80, 443, 8080, 8443, 8000, 8001, 8888, 9000, 9001, 9080],
        ),
        (
            "Database Services",
            vec![3306, 5432, 1433, 1521, 27017, 6379, 11211, 5984],
        ),
        (
            "System Services",
            vec![22, 23, 21, 25, 53, 110, 143, 993, 995],
        ),
        (
            "Development Ports",
            vec![3000, 3001, 4000, 4200, 5000, 5173, 8080, 8081, 9000, 9001],
        ),
    ];
    
    for (scenario_name, ports) in scenarios {
        println!("\n📋 Scenario: {}", scenario_name);
        
        let config = ScanConfig::new("127.0.0.1".to_string())
            .with_ports(ports.clone())
            .with_threads(75)
            .with_timeout(2000);
        
        let start_time = Instant::now();
        
        match ScanEngine::new(config).await {
            Ok(engine) => {
                match timeout(Duration::from_secs(20), engine.scan()).await {
                    Ok(Ok(result)) => {
                        let duration = start_time.elapsed();
                        
                        println!("   ✅ Completed: {:?}", duration);
                        println!("   - Target ports: {}", ports.len());
                        println!("   - Scanned ports: {}", result.total_ports());
                        println!("   - Scan ratio: {:.1}%", 
                               (result.total_ports() as f64 / ports.len() as f64) * 100.0);
                        
                        if result.total_ports() == ports.len() {
                            println!("   🎯 Perfect - all ports scanned!");
                        } else {
                            println!("   ⚠️  Some ports were skipped");
                        }
                    },
                    Ok(Err(e)) => {
                        println!("   ❌ Error: {:?}", e);
                    },
                    Err(_) => {
                        println!("   ⏰ Timeout");
                    }
                }
            },
            Err(e) => {
                println!("   ❌ Engine error: {:?}", e);
            }
        }
    }
    
    println!("\n🎉 Real world scenarios test completed!");
}
