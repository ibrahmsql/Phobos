//! Port accuracy and missed port detection tests
//! 
//! This module tests Phobos scanner's ability to detect all open ports
//! without missing any, especially in full-range scans.

use std::net::TcpListener;
use phobos::{ScanConfig, ScanEngine, ScanTechnique};
use phobos::network::PortState;

/// Test server that opens multiple ports
struct TestServer {
    listeners: Vec<TcpListener>,
    ports: Vec<u16>,
}

impl TestServer {
    /// Create a test server with specified number of random ports
    fn new(count: usize) -> std::io::Result<Self> {
        let mut listeners = Vec::new();
        let mut ports = Vec::new();
        
        for _ in 0..count {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let addr = listener.local_addr()?;
            ports.push(addr.port());
            listeners.push(listener);
        }
        
        Ok(Self { listeners, ports })
    }
    
    /// Get list of open ports
    fn get_ports(&self) -> Vec<u16> {
        self.ports.clone()
    }
    
    /// Keep server alive
    fn keep_alive(self) -> Self {
        self
    }
}

/// Calculate accuracy metrics
#[derive(Debug, Clone)]
struct AccuracyMetrics {
    total_open_ports: usize,
    detected_ports: usize,
    missed_ports: Vec<u16>,
    false_positives: Vec<u16>,
    accuracy_rate: f64,
    detection_rate: f64,
}

impl AccuracyMetrics {
    fn calculate(expected_ports: &[u16], detected_ports: &[u16]) -> Self {
        let total_open_ports = expected_ports.len();
        let detected_count = detected_ports.len();
        
        let mut missed_ports = Vec::new();
        for &port in expected_ports {
            if !detected_ports.contains(&port) {
                missed_ports.push(port);
            }
        }
        
        let mut false_positives = Vec::new();
        for &port in detected_ports {
            if !expected_ports.contains(&port) {
                false_positives.push(port);
            }
        }
        
        let detection_rate = if total_open_ports > 0 {
            (total_open_ports - missed_ports.len()) as f64 / total_open_ports as f64
        } else {
            0.0
        };
        
        let accuracy_rate = if detected_count > 0 {
            (detected_count - false_positives.len()) as f64 / detected_count as f64
        } else {
            0.0
        };
        
        Self {
            total_open_ports,
            detected_ports: detected_count,
            missed_ports,
            false_positives,
            accuracy_rate,
            detection_rate,
        }
    }
    
    fn print_report(&self) {
        println!("\n🎯 PORT DETECTION ACCURACY REPORT");
        println!("═══════════════════════════════════");
        println!("📊 Total Open Ports: {}", self.total_open_ports);
        println!("✅ Detected Ports: {}", self.detected_ports);
        println!("❌ Missed Ports: {}", self.missed_ports.len());
        println!("⚠️  False Positives: {}", self.false_positives.len());
        println!("🎯 Detection Rate: {:.2}%", self.detection_rate * 100.0);
        println!("✨ Accuracy Rate: {:.2}%", self.accuracy_rate * 100.0);
        
        if !self.missed_ports.is_empty() {
            println!("\n❌ Missed Ports:");
            for port in &self.missed_ports {
                println!("   - Port {}", port);
            }
        }
        
        if !self.false_positives.is_empty() {
            println!("\n⚠️  False Positives:");
            for port in &self.false_positives {
                println!("   - Port {}", port);
            }
        }
        
        println!();
    }
    
    fn is_perfect(&self) -> bool {
        self.missed_ports.is_empty() && self.false_positives.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phobos::ScanConfig;
    use phobos::ScanEngine;
    use phobos::ScanTechnique;
    use phobos::network::PortState;

    #[tokio::test]
    async fn test_small_range_accuracy() {
        // Create test server with 10 open ports
        let server = TestServer::new(10).expect("Failed to create test server");
        let expected_ports = server.get_ports();
        let _server = server.keep_alive();
        
        // Configure Phobos to scan these specific ports
        let mut config = ScanConfig::default();
        config.target = "127.0.0.1".to_string();
        config.ports = expected_ports.clone();
        config.technique = ScanTechnique::Connect;
        config.timeout = 3000;
        config.threads = 50;
        
        // Run scan
        let engine = ScanEngine::new(config).await.expect("Failed to create engine");
        let result = engine.scan().await.expect("Scan failed");
        
        // Extract detected ports
        let detected_ports: Vec<u16> = result.port_results
            .iter()
            .filter(|pr| matches!(pr.state, PortState::Open))
            .map(|pr| pr.port)
            .collect();
        
        // Calculate metrics
        let metrics = AccuracyMetrics::calculate(&expected_ports, &detected_ports);
        metrics.print_report();
        
        // Assert perfect detection
        assert!(
            metrics.is_perfect(),
            "Port detection must be 100% accurate. Missed: {:?}, False positives: {:?}",
            metrics.missed_ports,
            metrics.false_positives
        );
    }

    #[tokio::test]
    async fn test_full_range_sampling() {
        // Create test server with 50 random ports (simulates full range)
        let server = TestServer::new(50).expect("Failed to create test server");
        let expected_ports = server.get_ports();
        let _server = server.keep_alive();
        
        // Get min and max port to create range
        let min_port = *expected_ports.iter().min().unwrap();
        let max_port = *expected_ports.iter().max().unwrap();
        
        // Configure Phobos to scan full range around these ports
        let mut config = ScanConfig::default();
        config.target = "127.0.0.1".to_string();
        config.ports = (min_port..=max_port).collect();
        config.technique = ScanTechnique::Connect;
        config.timeout = 5000; // Higher timeout for full range
        config.threads = 100;
        config.batch_size = Some(500);
        
        println!("\n🔍 Testing full range scan: {} ports", config.ports.len());
        
        // Run scan
        let engine = ScanEngine::new(config).await.expect("Failed to create engine");
        let result = engine.scan().await.expect("Scan failed");
        
        // Extract detected ports
        let detected_ports: Vec<u16> = result.port_results
            .iter()
            .filter(|pr| matches!(pr.state, PortState::Open))
            .map(|pr| pr.port)
            .collect();
        
        // Calculate metrics
        let metrics = AccuracyMetrics::calculate(&expected_ports, &detected_ports);
        metrics.print_report();
        
        // For full range, allow up to 5% miss rate due to network conditions
        assert!(
            metrics.detection_rate >= 0.95,
            "Detection rate must be at least 95%. Got: {:.2}%",
            metrics.detection_rate * 100.0
        );
    }

    #[tokio::test]
    async fn test_high_port_range() {
        // Create test server with ports in high range
        let server = TestServer::new(20).expect("Failed to create test server");
        let expected_ports = server.get_ports();
        let _server = server.keep_alive();
        
        // Configure scan for high ports
        let mut config = ScanConfig::default();
        config.target = "127.0.0.1".to_string();
        config.ports = expected_ports.clone();
        config.technique = ScanTechnique::Connect;
        config.timeout = 4000;
        config.threads = 30;
        
        println!("\n🔍 Testing high port range detection");
        
        // Run scan
        let engine = ScanEngine::new(config).await.expect("Failed to create engine");
        let result = engine.scan().await.expect("Scan failed");
        
        // Extract detected ports
        let detected_ports: Vec<u16> = result.port_results
            .iter()
            .filter(|pr| matches!(pr.state, PortState::Open))
            .map(|pr| pr.port)
            .collect();
        
        // Calculate metrics
        let metrics = AccuracyMetrics::calculate(&expected_ports, &detected_ports);
        metrics.print_report();
        
        // High ports should be detected accurately
        assert!(
            metrics.detection_rate >= 0.98,
            "High port detection rate must be at least 98%. Got: {:.2}%",
            metrics.detection_rate * 100.0
        );
    }

    #[tokio::test]
    async fn test_retry_mechanism() {
        // Create test server
        let server = TestServer::new(15).expect("Failed to create test server");
        let expected_ports = server.get_ports();
        let _server = server.keep_alive();
        
        // Configure with retry enabled
        let mut config = ScanConfig::default();
        config.target = "127.0.0.1".to_string();
        config.ports = expected_ports.clone();
        config.technique = ScanTechnique::Connect;
        config.timeout = 2000;
        config.threads = 50;
        config.max_retries = Some(2); // Enable retries
        
        println!("\n🔄 Testing retry mechanism for missed ports");
        
        // Run scan
        let engine = ScanEngine::new(config).await.expect("Failed to create engine");
        let result = engine.scan().await.expect("Scan failed");
        
        // Extract detected ports
        let detected_ports: Vec<u16> = result.port_results
            .iter()
            .filter(|pr| matches!(pr.state, PortState::Open))
            .map(|pr| pr.port)
            .collect();
        
        // Calculate metrics
        let metrics = AccuracyMetrics::calculate(&expected_ports, &detected_ports);
        metrics.print_report();
        
        // With retries, detection should be near perfect
        assert!(
            metrics.detection_rate >= 0.98,
            "With retries, detection rate must be at least 98%. Got: {:.2}%",
            metrics.detection_rate * 100.0
        );
    }
}

/// Benchmark port detection accuracy
#[allow(dead_code)]
pub async fn benchmark_accuracy() {
    println!("\n🏁 PHOBOS PORT ACCURACY BENCHMARK");
    println!("═══════════════════════════════════════");
    
    let test_cases = vec![
        ("Small (10 ports)", 10, 1..=1000),
        ("Medium (50 ports)", 50, 1..=10000),
        ("Large (100 ports)", 100, 1..=65535),
    ];
    
    for (name, port_count, _range) in test_cases {
        println!("\n📋 Test Case: {}", name);
        println!("─────────────────────────────────");
        
        // Create test server
        let server = match TestServer::new(port_count) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("❌ Failed to create server: {}", e);
                continue;
            }
        };
        
        let expected_ports = server.get_ports();
        let _server = server.keep_alive();
        
        // Configure scan
        let mut config = ScanConfig::default();
        config.target = "127.0.0.1".to_string();
        config.ports = expected_ports.clone();
        config.technique = ScanTechnique::Connect;
        config.timeout = 5000;
        config.threads = 100;
        config.max_retries = Some(2);
        
        // Run scan
        let start = std::time::Instant::now();
        let engine = match ScanEngine::new(config).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!("❌ Failed to create engine: {}", e);
                continue;
            }
        };
        
        let result = match engine.scan().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("❌ Scan failed: {}", e);
                continue;
            }
        };
        let duration = start.elapsed();
        
        // Extract detected ports
        let detected_ports: Vec<u16> = result.port_results
            .iter()
            .filter(|pr| matches!(pr.state, PortState::Open))
            .map(|pr| pr.port)
            .collect();
        
        // Calculate metrics
        let metrics = AccuracyMetrics::calculate(&expected_ports, &detected_ports);
        
        println!("⏱️  Scan Duration: {:.2}s", duration.as_secs_f64());
        metrics.print_report();
    }
}
