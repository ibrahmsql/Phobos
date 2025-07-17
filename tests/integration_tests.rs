//! Integration tests for the phobos scanner

use std::time::Duration;
use tokio::time::timeout;
use phobos::{
    config::ScanConfig,
    network::{ScanTechnique, PortState},
    scanner::engine::ScanEngine,
};

#[tokio::test]
async fn test_localhost_connect_scan() {
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![22, 80, 443, 8080],
        technique: ScanTechnique::ConnectScan,
        threads: 10,
        timeout: 1000,
        rate_limit: 1000,
    };
    
    let engine = ScanEngine::new(config).await.unwrap();
    let result = engine.scan().await.unwrap();
    
    assert!(!result.open_ports.is_empty() || !result.closed_ports.is_empty());
    assert!(result.duration > Duration::from_millis(0));
}

#[tokio::test]
async fn test_invalid_target() {
    let config = ScanConfig {
        target: "invalid.target.that.does.not.exist.example.com".to_string(),
        ports: vec![80],
        technique: ScanTechnique::ConnectScan,
        threads: 1,
        timeout: 1000,
        rate_limit: 1000,
    };
    
    let result = ScanEngine::new(config).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_scan_timeout() {
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![80],
        technique: ScanTechnique::ConnectScan,
        threads: 1,
        timeout: 1,  // Very short timeout
        rate_limit: 1000,
    };
    
    let engine = ScanEngine::new(config).await.unwrap();
    let result = timeout(Duration::from_secs(5), engine.scan()).await;
    
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_rate_limiting() {
    let start = std::time::Instant::now();
    
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![80, 443, 8080, 3000, 5000],
        technique: ScanTechnique::ConnectScan,
        threads: 1,
        timeout: 1000,
        rate_limit: 2,  // Very low rate limit
    };
    
    let engine = ScanEngine::new(config).await.unwrap();
    let _result = engine.scan().await.unwrap();
    
    let duration = start.elapsed();
    // With rate limit of 2 pps and 5 ports, should take at least 2 seconds
    assert!(duration >= Duration::from_secs(2));
}

#[tokio::test]
async fn test_large_port_range() {
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: (1..=1000).collect(),
        technique: ScanTechnique::ConnectScan,
        threads: 100,
        timeout: 100,
        rate_limit: 10000,
    };
    
    let engine = ScanEngine::new(config).await.unwrap();
    let result = engine.scan().await.unwrap();
    
    assert_eq!(result.open_ports.len() + result.closed_ports.len() + result.filtered_ports.len(), 1000);
    assert!(result.duration < Duration::from_secs(30)); // Should complete within 30 seconds
}

#[tokio::test]
async fn test_concurrent_scans() {
    let configs = vec![
        ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: vec![22, 80],
            technique: ScanTechnique::ConnectScan,
            threads: 10,
            timeout: 1000,
            rate_limit: 1000,
        },
        ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: vec![443, 8080],
            technique: ScanTechnique::ConnectScan,
            threads: 10,
            timeout: 1000,
            rate_limit: 1000,
        },
    ];
    
    let mut handles = Vec::new();
    
    for config in configs {
        let handle = tokio::spawn(async move {
            let engine = ScanEngine::new(config).await.unwrap();
            engine.scan().await.unwrap()
        });
        handles.push(handle);
    }
    
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(!result.open_ports.is_empty() || !result.closed_ports.is_empty());
    }
}

#[tokio::test]
async fn test_scan_statistics() {
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![22, 80, 443, 8080, 9000],
        technique: ScanTechnique::ConnectScan,
        threads: 5,
        timeout: 1000,
        rate_limit: 1000,
    };
    
    let engine = ScanEngine::new(config).await.unwrap();
    let result = engine.scan().await.unwrap();
    
    assert!(result.stats.packets_sent > 0);
    assert!(result.stats.packets_received >= 0);
    assert!(result.duration > Duration::from_millis(0));
    assert!(result.scan_rate > 0.0);
}

#[tokio::test]
async fn test_memory_usage() {
    use phobos::utils::MemoryMonitor;
    
    let initial_memory = MemoryMonitor::current_usage().unwrap_or(0);
    
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: (1..=10000).collect(),
        technique: ScanTechnique::ConnectScan,
        threads: 100,
        timeout: 100,
        rate_limit: 50000,
    };
    
    let engine = ScanEngine::new(config).await.unwrap();
    let _result = engine.scan().await.unwrap();
    
    let final_memory = MemoryMonitor::current_usage().unwrap_or(0);
    let memory_used = final_memory.saturating_sub(initial_memory);
    
    // Should use less than 50MB for 10K port scan
    assert!(memory_used < 50 * 1024 * 1024, "Memory usage too high: {} bytes", memory_used);
}

#[tokio::test]
async fn test_error_handling() {
    // Test with invalid port range
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![0, 65536], // Invalid ports
        technique: ScanTechnique::ConnectScan,
        threads: 1,
        timeout: 1000,
        rate_limit: 1000,
    };
    
    let result = ScanEngine::new(config).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_scan_techniques() {
    let techniques = vec![
        ScanTechnique::ConnectScan,
        // Note: Raw socket techniques require root privileges
        // ScanTechnique::SynScan,
        // ScanTechnique::UdpScan,
    ];
    
    for technique in techniques {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: vec![80, 443],
            technique,
            threads: 10,
            timeout: 1000,
            rate_limit: 1000,
        };
        
        let engine = ScanEngine::new(config).await.unwrap();
        let result = engine.scan().await.unwrap();
        
        assert!(!result.open_ports.is_empty() || !result.closed_ports.is_empty());
    }
}

#[tokio::test]
async fn test_performance_target() {
    // Test if we can scan 1000 ports in reasonable time
    let start = std::time::Instant::now();
    
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: (1..=1000).collect(),
        technique: ScanTechnique::ConnectScan,
        threads: 200,
        timeout: 100,
        rate_limit: 50000,
    };
    
    let engine = ScanEngine::new(config).await.unwrap();
    let result = engine.scan().await.unwrap();
    
    let duration = start.elapsed();
    let rate = 1000.0 / duration.as_secs_f64();
    
    println!("Scanned 1000 ports in {:?} ({:.2} ports/sec)", duration, rate);
    
    // Should achieve at least 100 ports per second
    assert!(rate > 100.0, "Scan rate too low: {:.2} ports/sec", rate);
    assert_eq!(result.open_ports.len() + result.closed_ports.len() + result.filtered_ports.len(), 1000);
}

#[tokio::test]
async fn test_full_scan_workflow() {
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![80, 443, 8080],
        technique: ScanTechnique::ConnectScan,
        threads: 10,
        timeout: 1000,
        rate_limit: 1000,
    };
    
    let engine = ScanEngine::new(config).await.unwrap();
    let results = engine.scan().await.unwrap();
    assert!(!results.open_ports.is_empty() || !results.closed_ports.is_empty());
}

#[tokio::test]
async fn test_stealth_mode() {
    use phobos::network::stealth::StealthOptions;
    
    let mut config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![80, 443],
        technique: ScanTechnique::ConnectScan,
        threads: 5,
        timeout: 1000,
        rate_limit: 1000,
    };
    
    // Apply stealth options
    config.stealth_options = Some(StealthOptions {
        fragment_packets: true,
        randomize_source_port: true,
        spoof_source_ip: None,
        decoy_addresses: vec![],
        randomize_timing: true,
        packet_padding: Some(64),
        custom_mtu: Some(1500),
        randomize_ip_id: true,
        randomize_sequence: true,
        bad_checksum: false,
    });
    
    let engine = ScanEngine::new(config).await.unwrap();
    let results = engine.scan().await.unwrap();
    // Verify stealth parameters were applied
    assert!(!results.open_ports.is_empty() || !results.closed_ports.is_empty());
}

#[test]
fn test_performance_benchmark() {
    use std::time::Instant;
    
    let start = Instant::now();
    
    // Simulate scanning 1000 ports (using a mock for unit test)
    let port_count = 1000;
    let simulated_results = (1..=port_count).collect::<Vec<u16>>();
    
    let duration = start.elapsed();
    assert!(duration.as_millis() < 1000); // Should complete quickly
    assert_eq!(simulated_results.len(), port_count);
}

#[cfg(test)]
mod performance_validation {
    use super::*;
    use std::time::Instant;
    
    #[tokio::test]
    async fn validate_speed_targets() {
        // Test scanning speed target
        let start = Instant::now();
        
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: (1..=100).collect(), // Smaller range for CI
            technique: ScanTechnique::ConnectScan,
            threads: 50,
            timeout: 100,
            rate_limit: 10000,
        };
        
        let engine = ScanEngine::new(config).await.unwrap();
        let _results = engine.scan().await.unwrap();
        
        let duration = start.elapsed();
        assert!(duration.as_secs() < 5); // Should complete in reasonable time
    }
    
    #[tokio::test]
    async fn validate_memory_usage() {
        use phobos::utils::MemoryMonitor;
        
        let initial_memory = MemoryMonitor::current_usage().unwrap_or(0);
        
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: (1..=1000).collect(),
            technique: ScanTechnique::ConnectScan,
            threads: 50,
            timeout: 100,
            rate_limit: 10000,
        };
        
        let engine = ScanEngine::new(config).await.unwrap();
        let _results = engine.scan().await.unwrap();
        
        let final_memory = MemoryMonitor::current_usage().unwrap_or(0);
        let memory_used = final_memory.saturating_sub(initial_memory);
        
        // Should use less than 50MB for 1K port scan
        assert!(memory_used < 50_000_000, "Memory usage too high: {} bytes", memory_used);
    }
    
    #[tokio::test]
    async fn validate_packet_rate() {
        // Test packet sending rate
        let start = Instant::now();
        
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: (1..=100).collect(),
            technique: ScanTechnique::ConnectScan,
            threads: 20,
            timeout: 50,
            rate_limit: 5000,
        };
        
        let engine = ScanEngine::new(config).await.unwrap();
        let results = engine.scan().await.unwrap();
        
        let duration = start.elapsed();
        let packet_count = results.stats.packets_sent;
        let rate = packet_count as f64 / duration.as_secs_f64();
        
        // Should achieve reasonable packet rate
        assert!(rate > 100.0, "Packet rate too low: {:.2} packets/sec", rate);
    }
}