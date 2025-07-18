//! Configuration module for the phobos scanner

use crate::network::{ScanTechnique, stealth::StealthOptions};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::path::Path;
use std::fs;

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
    
    /// Batch size for scanning
    pub batch_size: Option<usize>,
    
    /// Enable real-time port discovery notifications
    pub realtime_notifications: bool,
    
    /// Color for real-time notifications (orange, purple, etc.)
    pub notification_color: String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            target: "127.0.0.1".to_string(),
            ports: (1..=1000).collect(),
            technique: ScanTechnique::Syn,
            threads: 2000,
            timeout: 500, // Faster timeout for speed
            rate_limit: 5_000_000, // 5M packets per second - ULTRA FAST!
            stealth_options: None,
            timing_template: 3, // Default timing template
            top_ports: None,
            batch_size: None, // Auto-calculate if None
            realtime_notifications: true, // Enable by default
            notification_color: "orange".to_string(), // Default orange color
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
        // Use custom batch size if specified, otherwise auto-calculate
        if let Some(custom_batch) = self.batch_size {
            return custom_batch;
        }
        
        // More aggressive batch sizing for maximum speed
        let base_batch = std::cmp::max(50, (self.rate_limit as usize) / (self.threads * 2));
        std::cmp::min(base_batch, 1000) // Cap at 1000 for stability
    }
    
    /// Load configuration from TOML file
    pub fn from_toml_file<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| crate::ScanError::InvalidTarget(format!("Failed to read config file: {}", e)))?;
        
        let config: ScanConfig = toml::from_str(&content)
            .map_err(|e| crate::ScanError::InvalidTarget(format!("Failed to parse TOML: {}", e)))?;
        
        Ok(config)
    }
    
    /// Load configuration from default locations
    pub fn load_default_config() -> Self {
        // Try to load from ~/.phobos.toml first, then ~/.rustscan.toml for compatibility
        let home_dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        
        let phobos_config = home_dir.join(".phobos.toml");
        let rustscan_config = home_dir.join(".rustscan.toml");
        
        if phobos_config.exists() {
            if let Ok(config) = Self::from_toml_file(&phobos_config) {
                println!("[~] Loaded config from {}", phobos_config.display());
                return config;
            }
        }
        
        if rustscan_config.exists() {
            if let Ok(config) = Self::from_toml_file(&rustscan_config) {
                println!("[~] Loaded config from {} (RustScan compatibility)", rustscan_config.display());
                return config;
            }
        }
        
        // Return default config if no file found
        Self::default()
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