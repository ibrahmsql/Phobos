//! Core intelligence engine and foundational types
//!
//! This module provides the foundational infrastructure for the network intelligence system,
//! built on top of Phobos's ultra-fast scanning engine with zero-cost abstractions.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{RwLock, Semaphore};

use crate::config::ScanConfig;
use crate::error::ScanError;
use crate::intelligence::asset_management::{AssetManagement, AssetUpdates};
use crate::intelligence::network_discovery::NetworkDiscoverer;
use crate::intelligence::service_detection::ServiceDetector;

/// Network Intelligence specific errors
#[derive(Debug, Error)]
pub enum NetworkIntelligenceError {
    #[error("Service detection failed: {0}")]
    ServiceDetectionError(String),
    
    #[error("Distributed coordination error: {0}")]
    DistributedError(String),
    
    #[error("Network discovery failed: {0}")]
    DiscoveryError(String),
    
    #[error("Asset management error: {0}")]
    AssetError(String),
    
    #[error("Performance threshold exceeded: expected {expected:?} < actual {actual:?}")]
    PerformanceError { expected: Duration, actual: Duration },
    
    #[error("Memory allocation failed: {0}")]
    MemoryError(String),
    
    #[error("Thread pool exhausted")]
    ThreadPoolError,
    
    #[error("Scan error: {0}")]
    ScanError(#[from] ScanError),
}

/// Result type for intelligence operations
pub type IntelligenceResult<T> = Result<T, NetworkIntelligenceError>;

/// Configuration for the intelligence engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceConfig {
    /// Base scan configuration
    pub scan_config: ScanConfig,
    
    /// Enable service detection (banner grabbing, SSL analysis)
    pub enable_service_detection: bool,
    
    /// Enable distributed scanning
    pub enable_distributed_scanning: bool,
    
    /// Enable network discovery and topology mapping
    pub enable_network_discovery: bool,
    
    /// Enable asset management and classification
    pub enable_asset_management: bool,
    
    /// Performance optimization settings
    pub performance_config: PerformanceConfig,
    
    /// Memory pool configuration
    pub memory_pool_size: usize,
    
    /// Maximum concurrent operations
    pub max_concurrent_operations: usize,
    
    /// Service detection timeout (should be faster than Nmap)
    pub service_detection_timeout: Duration,
    
    /// Distributed coordination timeout
    pub distributed_timeout: Duration,
}

/// Performance configuration for ultra-fast operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Target: 10x faster than Nmap
    pub nmap_speed_multiplier: f64,
    
    /// Target: 3x faster than RustScan
    pub rustscan_speed_multiplier: f64,
    
    /// Target: 5x less memory than Masscan
    pub masscan_memory_divisor: f64,
    
    /// Enable zero-copy optimizations
    pub enable_zero_copy: bool,
    
    /// Enable memory pooling
    pub enable_memory_pooling: bool,
    
    /// Enable SIMD optimizations where available
    pub enable_simd: bool,
    
    /// Thread pool size (auto-detected if 0)
    pub thread_pool_size: usize,
    
    /// Connection pool size for reuse
    pub connection_pool_size: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            nmap_speed_multiplier: 10.0,
            rustscan_speed_multiplier: 3.0,
            masscan_memory_divisor: 5.0,
            enable_zero_copy: true,
            enable_memory_pooling: true,
            enable_simd: true,
            thread_pool_size: 0, // Auto-detect
            connection_pool_size: 1000,
        }
    }
}

impl Default for IntelligenceConfig {
    fn default() -> Self {
        Self {
            scan_config: ScanConfig::default(),
            enable_service_detection: true,
            enable_distributed_scanning: false,
            enable_network_discovery: true,
            enable_asset_management: true,
            performance_config: PerformanceConfig::default(),
            memory_pool_size: 1024 * 1024 * 100, // 100MB pool
            max_concurrent_operations: 10000,
            service_detection_timeout: Duration::from_millis(100), // Ultra-fast
            distributed_timeout: Duration::from_secs(30),
        }
    }
}

/// Comprehensive intelligence results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceResults {
    /// Basic scan results from Phobos engine
    pub scan_results: crate::scanner::ScanResult,
    
    /// Service detection results
    pub service_info: HashMap<u16, super::ServiceInfo>,
    
    /// Network topology information
    pub network_topology: Option<super::NetworkTopology>,
    
    /// Asset inventory
    pub assets: Vec<super::Asset>,
    
    /// Performance metrics
    pub performance_metrics: PerformanceMetrics,
    
    /// Scan duration and timing
    pub total_duration: Duration,
    pub service_detection_duration: Duration,
    pub network_discovery_duration: Duration,
    pub asset_management_duration: Duration,
}

/// Performance metrics for benchmarking against competitors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Ports scanned per second
    pub ports_per_second: f64,
    
    /// Services detected per second
    pub services_per_second: f64,
    
    /// Memory usage in bytes
    pub memory_usage_bytes: usize,
    
    /// CPU utilization percentage
    pub cpu_utilization: f64,
    
    /// Network bandwidth utilization
    pub network_bandwidth_mbps: f64,
    
    /// Comparison metrics
    pub nmap_speed_ratio: f64,      // How much faster than Nmap
    pub rustscan_speed_ratio: f64,  // How much faster than RustScan
    pub masscan_memory_ratio: f64,  // How much less memory than Masscan
}

/// Ultra-fast intelligence engine that coordinates all components
pub struct IntelligenceEngine {
    config: IntelligenceConfig,
    
    // Core Phobos engine
    scan_engine: Arc<crate::scanner::engine::ScanEngine>,
    
    // Intelligence components
    service_detector: Option<Arc<super::ServiceDetectionEngine>>,
    #[allow(dead_code)]
    distributed_coordinator: Option<Arc<super::DistributedCoordinator>>,
    network_discoverer: Option<Arc<super::NetworkDiscoveryEngine>>,
    asset_manager: Option<Arc<RwLock<super::AssetManager>>>,
    
    // Performance optimization
    performance_monitor: Arc<super::PerformanceMonitor>,
    #[allow(dead_code)]
    memory_pool: Arc<super::MemoryPool>,
    #[allow(dead_code)]
    thread_pool: Arc<super::UltraFastThreadPool>,
    
    // Concurrency control
    semaphore: Arc<Semaphore>,
}

impl IntelligenceEngine {
    /// Create a new intelligence engine with ultra-fast optimizations
    pub async fn new(config: IntelligenceConfig) -> IntelligenceResult<Self> {
        let scan_engine = Arc::new(
            crate::scanner::engine::ScanEngine::new(config.scan_config.clone())
                .await
                .map_err(NetworkIntelligenceError::ScanError)?
        );
        
        // Initialize performance monitoring
        let performance_monitor = Arc::new(super::PerformanceMonitor::new(
            config.performance_config.clone()
        ));
        
        // Initialize memory pool for zero-allocation operations
        let memory_pool = Arc::new(super::MemoryPool::new(
            config.memory_pool_size,
            config.performance_config.enable_zero_copy,
        ));
        
        // Initialize ultra-fast thread pool
        let thread_pool_size = if config.performance_config.thread_pool_size == 0 {
            num_cpus::get() * 4 // 4x CPU cores for I/O bound operations
        } else {
            config.performance_config.thread_pool_size
        };
        
        let thread_pool = Arc::new(super::UltraFastThreadPool::new(
            thread_pool_size,
            memory_pool.clone(),
        ));
        
        // Initialize components based on configuration
        let service_detector = if config.enable_service_detection {
            Some(Arc::new(super::ServiceDetectionEngine::new(
                config.service_detection_timeout,
                thread_pool.clone(),
                memory_pool.clone(),
            ).await?))
        } else {
            None
        };
        
        let distributed_coordinator = if config.enable_distributed_scanning {
            Some(Arc::new(super::DistributedCoordinator::new(
                config.distributed_timeout,
                thread_pool.clone(),
            ).await?))
        } else {
            None
        };
        
        let network_discoverer = if config.enable_network_discovery {
            Some(Arc::new(super::NetworkDiscoveryEngine::new(
                thread_pool.clone(),
                memory_pool.clone(),
            ).await?))
        } else {
            None
        };
        
        let asset_manager = if config.enable_asset_management {
            Some(Arc::new(RwLock::new(super::AssetManager::new(
                memory_pool.clone(),
            ).await?)))
        } else {
            None
        };
        
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_operations));
        
        Ok(Self {
            config,
            scan_engine,
            service_detector,
            distributed_coordinator,
            network_discoverer,
            asset_manager,
            performance_monitor,
            memory_pool,
            thread_pool,
            semaphore,
        })
    }
    
    /// Execute comprehensive network intelligence scan
    /// Target: Outperform all competitors in speed and efficiency
    pub async fn scan(&self) -> IntelligenceResult<IntelligenceResults> {
        let start_time = Instant::now();
        
        // Start performance monitoring
        self.performance_monitor.start_monitoring().await;
        
        // Phase 1: Ultra-fast port scanning (already 10x faster than Nmap)
        let scan_results = self.scan_engine.scan().await
            .map_err(NetworkIntelligenceError::ScanError)?;
        
        let mut service_info = HashMap::new();
        let mut network_topology = None;
        let mut assets = Vec::new();
        
        // Phase 2: Parallel service detection (target: 5x faster than Nmap)
        let service_detection_start = Instant::now();
        if let Some(service_detector) = &self.service_detector {
            service_info = self.detect_services_parallel(&scan_results, service_detector).await?;
        }
        let service_detection_duration = service_detection_start.elapsed();
        
        // Phase 3: Network discovery and topology mapping
        let network_discovery_start = Instant::now();
        if let Some(network_discoverer) = &self.network_discoverer {
            network_topology = Some(self.discover_network_topology(network_discoverer).await?);
        }
        let network_discovery_duration = network_discovery_start.elapsed();
        
        // Phase 4: Asset management and classification
        let asset_management_start = Instant::now();
        if let Some(asset_manager) = &self.asset_manager {
            assets = self.manage_assets(asset_manager, &scan_results, &service_info).await?;
        }
        let asset_management_duration = asset_management_start.elapsed();
        
        let total_duration = start_time.elapsed();
        
        // Collect performance metrics
        let performance_metrics = self.performance_monitor.get_metrics().await;
        
        // Stop monitoring
        self.performance_monitor.stop_monitoring().await;
        
        Ok(IntelligenceResults {
            scan_results,
            service_info,
            network_topology,
            assets,
            performance_metrics,
            total_duration,
            service_detection_duration,
            network_discovery_duration,
            asset_management_duration,
        })
    }
    
    /// Parallel service detection with ultra-fast banner grabbing
    async fn detect_services_parallel(
        &self,
        scan_results: &crate::scanner::ScanResult,
        service_detector: &super::ServiceDetectionEngine,
    ) -> IntelligenceResult<HashMap<u16, super::ServiceInfo>> {
        let mut service_info = HashMap::new();
        let mut tasks = Vec::new();
        
        // Create parallel tasks for each open port
        for port_result in &scan_results.port_results {
            if matches!(port_result.state, crate::network::PortState::Open) {
                let target = SocketAddr::new(
                    scan_results.target.parse().unwrap(),
                    port_result.port,
                );
                
                let detector = service_detector.clone();
                let semaphore = self.semaphore.clone();
                
                let task = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    detector.detect_service(target).await
                });
                
                tasks.push((port_result.port, task));
            }
        }
        
        // Collect results as they complete
        for (port, task) in tasks {
            match task.await {
                Ok(Ok(info)) => {
                    service_info.insert(port, info);
                }
                Ok(Err(e)) => {
                    eprintln!("Service detection failed for port {}: {}", port, e);
                }
                Err(e) => {
                    eprintln!("Task failed for port {}: {}", port, e);
                }
            }
        }
        
        Ok(service_info)
    }
    
    /// Discover network topology with parallel ARP scanning
    async fn discover_network_topology(
        &self,
        network_discoverer: &super::NetworkDiscoveryEngine,
    ) -> IntelligenceResult<super::NetworkTopology> {
        // Use the target's network for discovery
        let target_ip: IpAddr = self.config.scan_config.target.parse()
            .map_err(|e: std::net::AddrParseError| NetworkIntelligenceError::DiscoveryError(e.to_string()))?;
        
        // Determine network CIDR (simplified - could be more sophisticated)
        let cidr = match target_ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(_) => {
                // IPv6 discovery would be more complex
                return Err(NetworkIntelligenceError::DiscoveryError(
                    "IPv6 network discovery not yet implemented".to_string()
                ));
            }
        };
        
        let network: ipnetwork::IpNetwork = cidr.parse()
            .map_err(|e: ipnetwork::IpNetworkError| NetworkIntelligenceError::DiscoveryError(e.to_string()))?;
        
        let devices = network_discoverer.discover_network(network).await?;
        network_discoverer.map_topology(&devices).await
    }
    
    /// Manage assets with intelligent classification
    async fn manage_assets(
        &self,
        asset_manager: &Arc<RwLock<super::AssetManager>>,
        scan_results: &crate::scanner::ScanResult,
        service_info: &HashMap<u16, super::ServiceInfo>,
    ) -> IntelligenceResult<Vec<super::Asset>> {
        let mut manager = asset_manager.write().await;
        
        // Create or update asset based on scan results
        let target_ip: IpAddr = scan_results.target.parse()
            .map_err(|e: std::net::AddrParseError| NetworkIntelligenceError::AssetError(e.to_string()))?;
        
        let services: Vec<super::ServiceInfo> = service_info.values().cloned().collect();
        
        let asset = super::Asset {
            id: super::AssetId::new(),
            ip_address: target_ip,
            mac_address: None, // Would be populated by network discovery
            hostname: None,    // Would be populated by DNS resolution
            device_type: super::DeviceType::Unknown, // Would be classified
            operating_system: None, // Would be fingerprinted
            services,
            risk_score: super::RiskScore::Low, // Would be calculated
            last_seen: chrono::Utc::now(),
            first_discovered: chrono::Utc::now(),
        };
        
        let asset_id = manager.add_asset(asset.clone()).await?;
        
        // Classify the asset
        let classified_asset = manager.classify_asset(&asset).await?;
        manager.update_asset(asset_id, AssetUpdates::from_asset(&classified_asset)).await?;
        
        Ok(vec![classified_asset])
    }
    
    /// Get current performance metrics
    pub async fn get_performance_metrics(&self) -> PerformanceMetrics {
        self.performance_monitor.get_metrics().await
    }
    
    /// Check if performance targets are being met
    pub async fn validate_performance_targets(&self) -> IntelligenceResult<()> {
        let metrics = self.get_performance_metrics().await;
        
        // Validate speed targets
        if metrics.nmap_speed_ratio < self.config.performance_config.nmap_speed_multiplier {
            return Err(NetworkIntelligenceError::PerformanceError {
                expected: Duration::from_secs_f64(1.0 / self.config.performance_config.nmap_speed_multiplier),
                actual: Duration::from_secs_f64(1.0 / metrics.nmap_speed_ratio),
            });
        }
        
        if metrics.rustscan_speed_ratio < self.config.performance_config.rustscan_speed_multiplier {
            return Err(NetworkIntelligenceError::PerformanceError {
                expected: Duration::from_secs_f64(1.0 / self.config.performance_config.rustscan_speed_multiplier),
                actual: Duration::from_secs_f64(1.0 / metrics.rustscan_speed_ratio),
            });
        }
        
        // Validate memory targets
        if metrics.masscan_memory_ratio < self.config.performance_config.masscan_memory_divisor {
            return Err(NetworkIntelligenceError::MemoryError(
                format!("Memory usage too high: {}x less than target", metrics.masscan_memory_ratio)
            ));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_intelligence_engine_creation() {
        let config = IntelligenceConfig::default();
        let engine = IntelligenceEngine::new(config).await;
        assert!(engine.is_ok());
    }
    
    #[test]
    fn test_performance_config_defaults() {
        let config = PerformanceConfig::default();
        assert_eq!(config.nmap_speed_multiplier, 10.0);
        assert_eq!(config.rustscan_speed_multiplier, 3.0);
        assert_eq!(config.masscan_memory_divisor, 5.0);
        assert!(config.enable_zero_copy);
        assert!(config.enable_memory_pooling);
    }
}