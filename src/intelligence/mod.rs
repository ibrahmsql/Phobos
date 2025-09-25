//! Network Intelligence System - Ultra-fast network discovery and asset management
//!
//! This module extends Phobos's already blazing-fast port scanning capabilities
//! with comprehensive network intelligence, service detection, and distributed scanning.
//! 
//! Performance targets:
//! - 10x faster service detection than Nmap
//! - 3x faster distributed scanning than RustScan  
//! - 5x lower memory usage than Masscan

pub mod core;
pub mod service_detection;
pub mod distributed;
pub mod network_discovery;
pub mod asset_management;
pub mod performance;
pub mod smart_prediction;
pub mod os_fingerprinting;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "service_detection_tests.rs"]
mod service_detection_tests;

#[cfg(test)]
#[path = "benchmark_tests.rs"]
mod benchmark_tests;

// Speed test module removed - file not found

// Re-export core types
pub use core::{
    IntelligenceEngine, IntelligenceConfig, IntelligenceResults,
    NetworkIntelligenceError, IntelligenceResult,
};

pub use service_detection::{
    ServiceDetectionEngine, ServiceDetector, ServiceInfo, 
    BannerGrabber, SSLAnalyzer, VulnerabilityScanner,
};

pub use distributed::{
    DistributedCoordinator, DistributedScanner, WorkerNode,
    NodeManager, LoadBalancer, ScanTask,
};

pub use network_discovery::{
    NetworkDiscoveryEngine, NetworkDiscoverer, Device,
    TopologyMapper, NetworkTopology, DeviceType,
};

pub use asset_management::{
    AssetManager, AssetManagement, Asset, AssetId,
    DeviceClassifier, RiskAssessor, RiskScore,
};

pub use performance::{
    PerformanceMonitor, MemoryPool, ZeroCopyBuffer,
    UltraFastThreadPool,
};

pub use smart_prediction::{
    SmartPredictor, PortPrediction,
};

pub use os_fingerprinting::{
    OSFingerprinter, OSDetectionResult, OperatingSystem, OSFamily,
};