//! Configuration module for the phobos scanner

use crate::network::{ScanTechnique, stealth::StealthOptions};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Main configuration structure for scanning operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Target host or network to scan
    pub target: String,
    
    /// List of ports to scan
    pub ports: Vec<u16>,
    
    /// Scanning technique to use
    pub technique: ScanTechnique,
    
    /// Number of concurrent threads
    pub threads: usize,
    
    /// Timeout for each connection attempt in milliseconds
    pub timeout: u64,
    
    /// Rate limit in packets per second
    pub rate_limit: u64,
    
    /// Stealth options for evasion
    pub stealth_options: Option<StealthOptions>,
    
    /// Timing template (0-5)
    pub timing_template: u8,
    
    /// Number of top ports to scan
    pub top_ports: Option<usize>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            target: "127.0.0.1".to_string(),
            ports: (1..=1000).collect(),
            technique: ScanTechnique::Syn,
            threads: 1000,
            timeout: 1000,
            rate_limit: 1_000_000, // 1M packets per second
            stealth_options: None,
            timing_template: 3, // Default timing template
            top_ports: None,
        }
    }
}

impl ScanConfig {
    /// Create a new scan configuration
    pub fn new(target: String) -> Self {
        Self {
            target,
            ..Default::default()
        }
    }
    
    /// Set the ports to scan
    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.ports = ports;
        self
    }
    
    /// Set the scanning technique
    pub fn with_technique(mut self, technique: ScanTechnique) -> Self {
        self.technique = technique;
        self
    }
    
    /// Set the number of threads
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads;
        self
    }
    
    /// Set the timeout
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }
    
    /// Set the rate limit
    pub fn with_rate_limit(mut self, rate_limit: u64) -> Self {
        self.rate_limit = rate_limit;
        self
    }
    
    /// Get timeout as Duration
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_millis(self.timeout)
    }
    
    /// Calculate optimal batch size based on rate limit and threads
    pub fn batch_size(&self) -> usize {
        std::cmp::max(1, (self.rate_limit as usize) / (self.threads * 10))
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> crate::Result<()> {
        if self.target.is_empty() {
            return Err(crate::ScanError::InvalidTarget("Target cannot be empty".to_string()));
        }
        
        if self.ports.is_empty() {
            return Err(crate::ScanError::InvalidTarget("No ports specified".to_string()));
        }
        
        if self.threads == 0 {
            return Err(crate::ScanError::InvalidTarget("Thread count must be greater than 0".to_string()));
        }
        
        Ok(())
    }
}

/// Timing configuration for advanced users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConfig {
    /// Initial RTT timeout
    pub initial_rtt_timeout: Duration,
    
    /// Minimum RTT timeout
    pub min_rtt_timeout: Duration,
    
    /// Maximum RTT timeout
    pub max_rtt_timeout: Duration,
    
    /// Maximum retries per port
    pub max_retries: u32,
    
    /// Delay between retries
    pub retry_delay: Duration,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            initial_rtt_timeout: Duration::from_millis(1000),
            min_rtt_timeout: Duration::from_millis(100),
            max_rtt_timeout: Duration::from_millis(10000),
            max_retries: 3,
            retry_delay: Duration::from_millis(100),
        }
    }
}