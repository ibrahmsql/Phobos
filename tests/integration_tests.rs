//! Integration tests for the phobos scanner

use std::time::Duration;
use tokio::time::timeout;
use phobos::{
    config::ScanConfig,
    network::ScanTechnique,
    scanner::engine::ScanEngine,
};

#[tokio::test]
async fn test_localhost_connect_scan() {
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![22, 80, 443, 8080],
        technique: ScanTechnique::Connect,
        threads: 10,
        timeout: 1000,
        rate_limit: 1000,
        ..Default::default()
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
        technique: ScanTechnique::Connect,
        threads: 1,
        timeout: 1000,
        rate_limit: 1000,
        ..Default::default()
};
    
    let result = ScanEngine::new(config).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_scan_timeout() {
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![80],
        technique: ScanTechnique::Connect,
        threads: 1,
        timeout: 1,  // Very short timeout
        rate_limit: 1000,
        ..Default::default()
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
        technique: ScanTechnique::Connect,
        threads: 1,
        timeout: 1000,
        rate_limit: 2,  // Very low rate limit
        ..Default::default()
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
        technique: ScanTechnique::Connect,
        threads: 100,
        timeout: 100,
        rate_limit: 10000,
        ..Default::default()
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
            technique: ScanTechnique::Connect,
            threads: 10,
            timeout: 1000,
            rate_limit: 1000,
        ..Default::default()
},
        ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: vec![443, 8080],
            technique: ScanTechnique::Connect,
            threads: 10,
            timeout: 1000,
            rate_limit: 1000,
        ..Default::default()
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
        technique: ScanTechnique::Connect,
        threads: 5,
        timeout: 1000,
        rate_limit: 1000,
        ..Default::default()
};
    
    let engine = ScanEngine::new(config).await.unwrap();
    let result = engine.scan().await.unwrap();
    
    assert!(result.stats.packets_sent > 0);
    assert!(result.stats.packets_received >= 0);
    assert!(result.duration > Duration::from_millis(0));
}

#[tokio::test]
async fn test_error_handling() {
    // Test with invalid port range
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![0, 65535], // Invalid ports (0 is invalid, 65535 is edge case)
        technique: ScanTechnique::Connect,
        threads: 1,
        timeout: 1000,
        rate_limit: 1000,
        ..Default::default()
};
    
    let result = ScanEngine::new(config).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_scan_techniques() {
    let techniques = vec![
        ScanTechnique::Connect,
        // Note: Raw socket techniques require root privileges
        // ScanTechnique::Syn,
        // ScanTechnique::Udp,
    ];
    
    for technique in techniques {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: vec![80, 443],
            technique,
            threads: 10,
            timeout: 1000,
            rate_limit: 1000,
        ..Default::default()
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
        technique: ScanTechnique::Connect,
        threads: 200,
        timeout: 100,
        rate_limit: 50000,
        ..Default::default()
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