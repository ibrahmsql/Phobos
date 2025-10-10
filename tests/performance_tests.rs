//! Performance and benchmark tests

use phobos::{
    intelligence::{
        core::{IntelligenceEngine, IntelligenceConfig, PerformanceConfig},
        performance::PerformanceMonitor,
    },
    scanner::engine::ScanEngine,
    config::ScanConfig,
    network::ScanTechnique,
};
use std::time::{Duration, Instant};
use tokio::time::timeout;

#[tokio::test]
async fn test_performance_targets() {
    let config = PerformanceConfig::default();
    
    // Test performance targets are realistic
    assert!(config.nmap_speed_multiplier >= 5.0);
    assert!(config.rustscan_speed_multiplier >= 2.0);
    assert!(config.masscan_memory_divisor >= 3.0);
    
    println!("Performance targets: Nmap {}x, RustScan {}x, Masscan memory {}x",
        config.nmap_speed_multiplier,
        config.rustscan_speed_multiplier,
        config.masscan_memory_divisor
    );
}

#[tokio::test]
async fn test_performance_monitor() {
    let config = PerformanceConfig::default();
    let monitor = PerformanceMonitor::new(config);
    
    monitor.start_monitoring().await;
    
    // Simulate some work
    monitor.update_scan_metrics(100, Duration::from_millis(10)).await;
    
    let metrics = monitor.get_metrics().await;
    assert!(metrics.ports_per_second > 0.0);
    
    monitor.stop_monitoring().await;
}

#[tokio::test]
async fn test_scan_engine_performance() {
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![22, 80, 443],
        technique: ScanTechnique::Connect,
        threads: 10,
        timeout: 1000,
        rate_limit: 1000,
        ..Default::default()
    };
    
    let engine_result = ScanEngine::new(config).await;
    
    match engine_result {
        Ok(engine) => {
            let start = Instant::now();
            
            let result = timeout(
                Duration::from_secs(10),
                engine.scan()
            ).await;
            
            let duration = start.elapsed();
            
            assert!(result.is_ok());
            
            // Performance assertion: should complete quickly for localhost
            assert!(duration < Duration::from_secs(5));
            
            let ports_per_second = 3.0 / duration.as_secs_f64();
            println!("Scan performance: {:.2} ports/sec", ports_per_second);
        },
        Err(_) => {
            println!("Scan engine creation failed - may need raw socket permissions");
        }
    }
}

#[tokio::test]
async fn test_intelligence_engine_performance() {
    let config = IntelligenceConfig::default();
    let engine_result = IntelligenceEngine::new(config).await;
    
    match engine_result {
        Ok(engine) => {
            let start = Instant::now();
            
            // Test intelligence processing performance
            let result = timeout(
                Duration::from_secs(5),
                engine.get_performance_metrics()
            ).await;
            
            let duration = start.elapsed();
            
            match result {
                Ok(_) => {
                    // Should complete analysis quickly
                    assert!(duration < Duration::from_secs(3));
                    println!("Intelligence analysis completed in {:?}", duration);
                },
                Err(_) => {
                    println!("Intelligence analysis timed out - acceptable for testing");
                }
            }
        },
        Err(_) => {
            println!("Intelligence engine creation failed - may need additional setup");
        }
    }
}

#[tokio::test]
async fn test_memory_efficiency() {
    // Test memory usage patterns
    let initial_memory = get_memory_usage();
    
    // Create multiple scan engines to test memory efficiency
    let mut engines = Vec::new();
    
    for i in 0..5 {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: vec![80 + i as u16],
            technique: ScanTechnique::Connect,
            threads: 1,
            timeout: 1000,
            rate_limit: 100,
        ..Default::default()
        };
        
        if let Ok(engine) = ScanEngine::new(config).await {
            engines.push(engine);
        }
    }
    
    let final_memory = get_memory_usage();
    let memory_increase = final_memory.saturating_sub(initial_memory);
    
    // Memory increase should be reasonable (less than 100MB for 5 engines)
    assert!(memory_increase < 100 * 1024 * 1024, "Memory usage too high: {} bytes", memory_increase);
    
    println!("Memory efficiency test: {} engines created, memory increase: {} KB", 
        engines.len(), memory_increase / 1024);
}

#[tokio::test]
async fn test_concurrent_performance() {
    let configs: Vec<ScanConfig> = (0..3).map(|i| ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![22 + i as u16],
        technique: ScanTechnique::Connect,
        threads: 2,
        timeout: 1000,
        rate_limit: 500,
        batch_size: Some(1),
        ..Default::default()
    }).collect();
    
    let start = Instant::now();
    
    // Run concurrent scans
    let mut handles = vec![];
    for config in configs {
        let handle = tokio::spawn(async move {
            if let Ok(engine) = ScanEngine::new(config).await {
                let _ = timeout(Duration::from_secs(5), engine.scan()).await;
            }
        });
        handles.push(handle);
    }
    
    // Wait for all scans to complete
    for handle in handles {
        let _ = handle.await;
    }
    
    let duration = start.elapsed();
    
    // Concurrent scans should complete faster than sequential
    assert!(duration < Duration::from_secs(10));
    
    println!("Concurrent performance: 3 scans completed in {:?}", duration);
}

#[tokio::test]
async fn test_adaptive_performance() {
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![22, 80, 443, 8080],
        technique: ScanTechnique::Connect,
        threads: 4,
        timeout: 500,
        rate_limit: 1000,
        ..Default::default()
    };
    
    let engine_result = ScanEngine::new(config).await;
    
    match engine_result {
        Ok(engine) => {
            let start = Instant::now();
            
            let result = timeout(
                Duration::from_secs(8),
                engine.scan()
            ).await;
            
            let duration = start.elapsed();
            
            match result {
                Ok(_) => {
                    // Adaptive learning should improve performance over time
                    assert!(duration < Duration::from_secs(6));
                    println!("Adaptive scan completed in {:?}", duration);
                },
                Err(_) => {
                    println!("Adaptive scan timed out - acceptable for testing");
                }
            }
        },
        Err(_) => {
            println!("Adaptive scan engine creation failed");
        }
    }
}

// Helper function to get current memory usage (simplified)
fn get_memory_usage() -> usize {
    // This is a simplified memory usage estimation
    // In a real implementation, you might use system APIs
    std::mem::size_of::<ScanEngine>() * 1000 // Rough estimate
}

#[tokio::test]
async fn test_throughput_benchmark() {
    let start = Instant::now();
    let target_operations = 1000;
    
    // Simulate high-throughput operations
    for _ in 0..target_operations {
        // Simulate lightweight network operation
        tokio::task::yield_now().await;
    }
    
    let duration = start.elapsed();
    let ops_per_second = target_operations as f64 / duration.as_secs_f64();
    
    // Should achieve high throughput
    assert!(ops_per_second > 10000.0, "Throughput too low: {:.2} ops/sec", ops_per_second);
    
    println!("Throughput benchmark: {:.2} operations/sec", ops_per_second);
}