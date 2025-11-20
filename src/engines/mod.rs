// Scan Engine Abstraction Layer
// Defines different execution strategies for port scanning

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::IpAddr;
use std::sync::Arc;
use crate::core::{PortScanner, PortResult, ScanError};

/// Engine execution statistics
#[derive(Debug, Default, Clone)]
pub struct EngineStats {
    pub total_ports_scanned: usize,
    pub successful_scans: usize,
    pub failed_scans: usize,
    pub total_duration_ms: u64,
}

/// Host scan result containing all port results
#[derive(Debug, Clone)]
pub struct HostScanResult {
    pub target: IpAddr,
    pub results: Vec<Result<PortResult, ScanError>>,
    pub stats: EngineStats,
}

/// Scan Engine Trait - Different execution strategies
#[async_trait]
pub trait ScanEngine: Send + Sync {
    /// Execute scan with given scanner
    async fn execute(
        &self,
        scanner: Arc<dyn PortScanner>,
        targets: Vec<IpAddr>,
        ports: Vec<u16>,
    ) -> Vec<HostScanResult>;
    
    /// Get engine name
    fn name(&self) -> &str;
}

/// Streaming Engine - RustScan-style continuous queue
pub struct StreamingEngine {
    batch_size: usize,
}

impl StreamingEngine {
    pub fn new(batch_size: usize) -> Self {
        Self { batch_size }
    }
}

#[async_trait]
impl ScanEngine for StreamingEngine {
    async fn execute(
        &self,
        scanner: Arc<dyn PortScanner>,
        targets: Vec<IpAddr>,
        ports: Vec<u16>,
    ) -> Vec<HostScanResult> {
        let mut results = Vec::new();
        
        for target in targets {
            let start = std::time::Instant::now();
            let mut port_results = Vec::new();
            let mut successful = 0;
            let mut failed = 0;
            
            // Create port iterator
            let mut port_iter = ports.iter().copied();
            let mut futures = FuturesUnordered::new();
            
            // Fill initial batch
            for _ in 0..self.batch_size {
                if let Some(port) = port_iter.next() {
                    let scanner_clone = Arc::clone(&scanner);
                    futures.push(async move {
                        scanner_clone.scan_port(target, port).await
                    });
                }
            }
            
            // Continuous queue pattern - RustScan style
            while let Some(result) = futures.next().await {
                match result {
                    Ok(_) => successful += 1,
                    Err(_) => failed += 1,
                }
                port_results.push(result);
                
                // Refill queue
                if let Some(port) = port_iter.next() {
                    let scanner_clone = Arc::clone(&scanner);
                    futures.push(async move {
                        scanner_clone.scan_port(target, port).await
                    });
                }
            }
            
            results.push(HostScanResult {
                target,
                results: port_results,
                stats: EngineStats {
                    total_ports_scanned: ports.len(),
                    successful_scans: successful,
                    failed_scans: failed,
                    total_duration_ms: start.elapsed().as_millis() as u64,
                },
            });
        }
        
        results
    }
    
    fn name(&self) -> &str {
        "Streaming Engine"
    }
}

/// Batch Engine - Process all at once
pub struct BatchEngine {
    batch_size: usize,
}

impl BatchEngine {
    pub fn new(batch_size: usize) -> Self {
        Self { batch_size }
    }
}

#[async_trait]
impl ScanEngine for BatchEngine {
    async fn execute(
        &self,
        scanner: Arc<dyn PortScanner>,
        targets: Vec<IpAddr>,
        ports: Vec<u16>,
    ) -> Vec<HostScanResult> {
        let mut results = Vec::new();
        
        for target in targets {
            let start = std::time::Instant::now();
            
            // Scan all ports  
            let port_results = scanner.scan_ports(target, &ports).await;
            
            let successful = port_results.iter().filter(|r| r.is_ok()).count();
            let failed = port_results.iter().filter(|r| r.is_err()).count();
            
            results.push(HostScanResult {
                target,
                results: port_results,
                stats: EngineStats {
                    total_ports_scanned: ports.len(),
                    successful_scans: successful,
                    failed_scans: failed,
                    total_duration_ms: start.elapsed().as_millis() as u64,
                },
            });
        }
        
        results
    }
    
    fn name(&self) -> &str {
        "Batch Engine"
    }
}

/// Engine Factory
pub struct EngineFactory;

impl EngineFactory {
    /// Create best engine for workload
    pub fn create_for_workload(
        total_ports: usize,
        batch_size: usize,
    ) -> Arc<dyn ScanEngine> {
        if total_ports > 10000 {
            // Use streaming for large workloads
            Arc::new(StreamingEngine::new(batch_size))
        } else {
            // Use batch for smaller workloads
            Arc::new(BatchEngine::new(batch_size))
        }
    }
    
    /// Create specific engine
    pub fn create_streaming(batch_size: usize) -> Arc<dyn ScanEngine> {
        Arc::new(StreamingEngine::new(batch_size))
    }
    
    pub fn create_batch(batch_size: usize) -> Arc<dyn ScanEngine> {
        Arc::new(BatchEngine::new(batch_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TcpConnectScanner;
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_streaming_engine() {
        let scanner = Arc::new(TcpConnectScanner::new(Duration::from_secs(1)));
        let engine = StreamingEngine::new(100);
        
        let targets = vec!["127.0.0.1".parse().unwrap()];
        let ports = vec![80, 443, 22];
        
        let results = engine.execute(scanner, targets, ports).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].results.len(), 3);
    }
}
