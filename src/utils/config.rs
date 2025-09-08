//! Configuration utilities and validation

use crate::config::ScanConfig;
use crate::network::ScanTechnique;
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

/// Configuration file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub default_technique: ScanTechnique,
    pub default_threads: usize,
    pub default_timeout: u64,
    pub default_rate_limit: u64,
    pub stealth_level: u8,
    pub output_format: OutputFormat,
    pub logging: LoggingConfig,
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Text,
    Json,
    Xml,
    Csv,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<String>,
    pub console: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub max_memory_mb: u64,
    pub cpu_limit_percent: f64,
    pub adaptive_timing: bool,
    pub batch_optimization: bool,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            default_technique: ScanTechnique::Syn,
            default_threads: 1000,
            default_timeout: 1000,
            default_rate_limit: 1_000_000,
            stealth_level: 3,
            output_format: OutputFormat::Text,
            logging: LoggingConfig {
                level: "info".to_string(),
                file: None,
                console: true,
            },
            performance: PerformanceConfig {
                max_memory_mb: 512,
                cpu_limit_percent: 80.0,
                adaptive_timing: true,
                batch_optimization: true,
            },
        }
    }
}

/// Configuration manager
pub struct ConfigManager {
    config_path: String,
    config: ConfigFile,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new(config_path: Option<String>) -> crate::Result<Self> {
        let config_path = config_path.unwrap_or_else(|| {
            if let Some(home) = std::env::var_os("HOME") {
                format!("{}/.phobos.toml", home.to_string_lossy())
            } else {
                "phobos.toml".to_string()
            }
        });
        
        let config = if Path::new(&config_path).exists() {
            Self::load_config(&config_path)?
        } else {
            let default_config = ConfigFile::default();
            Self::save_config(&config_path, &default_config)?;
            default_config
        };
        
        Ok(Self {
            config_path,
            config,
        })
    }
    
    /// Load configuration from file
    fn load_config(path: &str) -> crate::Result<ConfigFile> {
        let content = fs::read_to_string(path)
            .map_err(|e| crate::ScanError::NetworkError(e.to_string()))?;
        
        toml::from_str(&content)
            .map_err(|e| crate::ScanError::InvalidTarget(format!("Invalid config: {}", e)))
    }
    
    /// Save configuration to file
    fn save_config(path: &str, config: &ConfigFile) -> crate::Result<()> {
        let content = toml::to_string_pretty(config)
            .map_err(|e| crate::ScanError::InvalidTarget(format!("Config serialization error: {}", e)))?;
        
        fs::write(path, content)
            .map_err(|e| crate::ScanError::NetworkError(e.to_string()))
    }
    
    /// Get current configuration
    pub fn get_config(&self) -> &ConfigFile {
        &self.config
    }
    
    /// Update configuration
    pub fn update_config(&mut self, config: ConfigFile) -> crate::Result<()> {
        self.config = config;
        Self::save_config(&self.config_path, &self.config)
    }
    
    /// Apply configuration to scan config
    pub fn apply_to_scan_config(&self, mut scan_config: ScanConfig) -> ScanConfig {
        // Apply defaults if not explicitly set
        if scan_config.technique == ScanTechnique::Syn &&
           self.config.default_technique != ScanTechnique::Syn {
            scan_config.technique = self.config.default_technique;
        }
        
        if scan_config.threads == 1000 {
            scan_config.threads = self.config.default_threads;
        }
        
        if scan_config.timeout == 1000 {
            scan_config.timeout = self.config.default_timeout;
        }
        
        if scan_config.rate_limit == 1_000_000 {
            scan_config.rate_limit = self.config.default_rate_limit;
        }
        
        scan_config
    }
}

/// Configuration validator
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate scan configuration
    pub fn validate_scan_config(config: &ScanConfig) -> Vec<String> {
        let mut errors = Vec::new();
        
        // Validate target
        if config.target.is_empty() {
            errors.push("Target cannot be empty".to_string());
        }
        
        // Validate ports
        if config.ports.is_empty() {
            errors.push("No ports specified".to_string());
        }
        
        for &port in &config.ports {
            if port == 0 {
                errors.push("Port 0 is not valid".to_string());
                break;
            }
        }
        
        // Validate threads
        if config.threads == 0 {
            errors.push("Thread count must be greater than 0".to_string());
        } else if config.threads > 10000 {
            errors.push("Thread count is too high (max 10000)".to_string());
        }
        
        // Validate timeout
        if config.timeout == 0 {
            errors.push("Timeout must be greater than 0".to_string());
        } else if config.timeout > 300000 {
            errors.push("Timeout is too high (max 5 minutes)".to_string());
        }
        
        // Validate rate limit
        if config.rate_limit == 0 {
            errors.push("Rate limit must be greater than 0".to_string());
        } else if config.rate_limit > 10_000_000 {
            errors.push("Rate limit is too high (max 10M pps)".to_string());
        }
        
        // Validate technique compatibility
        if config.technique.requires_raw_socket() {
            #[cfg(unix)]
            {
                if unsafe { libc::geteuid() } != 0 {
                    errors.push("Raw socket techniques require root privileges".to_string());
                }
            }
            
            #[cfg(not(unix))]
            {
                errors.push("Raw socket techniques not supported on this platform".to_string());
            }
        }
        
        errors
    }
    
    /// Validate system requirements
    pub fn validate_system_requirements() -> Vec<String> {
        let mut warnings = Vec::new();
        
        // Check available memory
        if let Some(memory) = crate::utils::MemoryMonitor::current_usage() {
            let available_mb = memory / 1024 / 1024;
            if available_mb < 100 {
                warnings.push("Low memory available (< 100MB)".to_string());
            }
        }
        
        // Check file descriptor limits
        #[cfg(unix)]
        {
            let mut rlimit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            
            unsafe {
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlimit) == 0 {
                    if rlimit.rlim_cur < 1024 {
                        warnings.push(format!(
                            "Low file descriptor limit: {} (recommended: >= 1024)",
                            rlimit.rlim_cur
                        ));
                    }
                }
            }
        }
        
        warnings
    }
    
    /// Get optimization recommendations
    pub fn get_optimization_recommendations(config: &ScanConfig) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        // Thread optimization
        let optimal_threads = std::thread::available_parallelism()
            .map(|p| p.get() * 100)
            .unwrap_or(1000);
        
        if config.threads > optimal_threads * 2 {
            recommendations.push(format!(
                "Consider reducing threads to {} for better performance",
                optimal_threads
            ));
        } else if config.threads < optimal_threads / 2 {
            recommendations.push(format!(
                "Consider increasing threads to {} for better performance",
                optimal_threads
            ));
        }
        
        // Rate limit optimization
        let port_count = config.ports.len();
        if port_count > 10000 && config.rate_limit < 100000 {
            recommendations.push(
                "Consider increasing rate limit for large port scans".to_string()
            );
        }
        
        // Timeout optimization
        if config.timeout > 5000 && port_count > 1000 {
            recommendations.push(
                "Consider reducing timeout for large scans to improve speed".to_string()
            );
        }
        
        // Technique optimization
        if config.technique == ScanTechnique::Connect && port_count > 1000 {
            recommendations.push(
                "Consider using SYN scan for better performance on large scans".to_string()
            );
        }
        
        recommendations
    }
}

/// Environment configuration
pub struct EnvironmentConfig;

impl EnvironmentConfig {
    /// Get configuration from environment variables
    pub fn from_env() -> ScanConfig {
        let mut config = ScanConfig::default();
        
        if let Ok(target) = std::env::var("PHOBOS_TARGET") {
            config.target = target;
        }

        if let Ok(threads) = std::env::var("PHOBOS_THREADS") {
            if let Ok(threads) = threads.parse() {
                config.threads = threads;
            }
        }

        if let Ok(timeout) = std::env::var("PHOBOS_TIMEOUT") {
            if let Ok(timeout) = timeout.parse() {
                config.timeout = timeout;
            }
        }

        if let Ok(rate) = std::env::var("PHOBOS_RATE") {
            if let Ok(rate) = rate.parse() {
                config.rate_limit = rate;
            }
        }

        if let Ok(technique) = std::env::var("PHOBOS_TECHNIQUE") {
            config.technique = match technique.to_uppercase().as_str() {
                "SYN" => ScanTechnique::Syn,
                "CONNECT" => ScanTechnique::Connect,
                "UDP" => ScanTechnique::Udp,
                "FIN" => ScanTechnique::Fin,
                "NULL" => ScanTechnique::Null,
                "XMAS" => ScanTechnique::Xmas,
                "ACK" => ScanTechnique::Ack,
                _ => ScanTechnique::Syn,
            };
        }
        
        config
    }
    
    /// Set environment variables from config
    pub fn to_env(config: &ScanConfig) {
        std::env::set_var("PHOBOS_TARGET", &config.target);
        std::env::set_var("PHOBOS_THREADS", config.threads.to_string());
        std::env::set_var("PHOBOS_TIMEOUT", config.timeout.to_string());
        std::env::set_var("PHOBOS_RATE", config.rate_limit.to_string());
        
        let technique_str = match config.technique {
            ScanTechnique::Syn => "SYN",
            ScanTechnique::Connect => "CONNECT",
            ScanTechnique::Udp => "UDP",
            ScanTechnique::Fin => "FIN",
            ScanTechnique::Null => "NULL",
            ScanTechnique::Xmas => "XMAS",
            ScanTechnique::Ack => "ACK",
            ScanTechnique::Window => "WINDOW",
            ScanTechnique::Stealth => "STEALTH",
        };
        std::env::set_var("PHOBOS_TECHNIQUE", technique_str);
    }
}