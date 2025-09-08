//! Learning Data Storage
//!
//! This module handles persistent storage of learning data, including
//! scan statistics, target profiles, and optimization patterns.

use super::*;
use anyhow::{Context, Result};
use serde_json;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::fs as async_fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Persistent storage for learning data
#[derive(Debug)]
pub struct LearningStorage {
    storage_dir: PathBuf,
    scan_stats_file: PathBuf,
    target_profiles_file: PathBuf,
    patterns_file: PathBuf,
    config_file: PathBuf,
}

/// Serializable target profile for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTargetProfile {
    pub target: String,
    pub target_type: TargetType,
    pub scan_count: usize,
    pub port_frequencies: HashMap<u16, f64>,
    pub avg_scan_time: Duration,
    pub optimal_params: StoredOptimalParams,
    pub last_updated: SystemTime,
    pub success_rate: f64,
    pub reliability_score: f64,
}

/// Serializable optimal parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOptimalParams {
    pub threads: usize,
    pub timeout: Duration,
    pub technique: String,
    pub port_order: Vec<u16>,
    pub batch_size: usize,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorageConfig {
    version: String,
    created: SystemTime,
    last_cleanup: SystemTime,
    max_scan_history: usize,
    max_target_profiles: usize,
    compression_enabled: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            version: "1.0.0".to_string(),
            created: SystemTime::now(),
            last_cleanup: SystemTime::now(),
            max_scan_history: 10000,
            max_target_profiles: 1000,
            compression_enabled: true,
        }
    }
}

impl LearningStorage {
    /// Create a new learning storage instance
    pub async fn new() -> Result<Self> {
        let storage_dir = Self::get_storage_directory()?;
        
        // Create storage directory if it doesn't exist
        async_fs::create_dir_all(&storage_dir).await
            .context("Failed to create storage directory")?;
        
        let scan_stats_file = storage_dir.join("scan_stats.json");
        let target_profiles_file = storage_dir.join("target_profiles.json");
        let patterns_file = storage_dir.join("patterns.json");
        let config_file = storage_dir.join("config.json");
        
        let storage = Self {
            storage_dir,
            scan_stats_file,
            target_profiles_file,
            patterns_file,
            config_file,
        };
        
        // Initialize configuration if it doesn't exist
        if !storage.config_file.exists() {
            storage.save_config(&StorageConfig::default()).await?;
        }
        
        Ok(storage)
    }
    
    /// Store scan statistics
    pub async fn store_scan_stats(&self, stats: &ScanStats) -> Result<()> {
        let mut existing_stats = self.load_scan_stats().await.unwrap_or_default();
        existing_stats.push(stats.clone());
        
        // Limit the number of stored statistics
        let config = self.load_config().await?;
        if existing_stats.len() > config.max_scan_history {
            existing_stats.drain(0..existing_stats.len() - config.max_scan_history);
        }
        
        self.save_scan_stats(&existing_stats).await
    }
    
    /// Load scan statistics
    pub async fn load_scan_stats(&self) -> Result<Vec<ScanStats>> {
        if !self.scan_stats_file.exists() {
            return Ok(Vec::new());
        }
        
        let mut file = async_fs::File::open(&self.scan_stats_file).await
            .context("Failed to open scan stats file")?;
        
        let mut contents = String::new();
        file.read_to_string(&mut contents).await
            .context("Failed to read scan stats file")?;
        
        serde_json::from_str(&contents)
            .context("Failed to deserialize scan stats")
    }
    
    /// Save scan statistics
    async fn save_scan_stats(&self, stats: &[ScanStats]) -> Result<()> {
        let json = serde_json::to_string_pretty(stats)
            .context("Failed to serialize scan stats")?;
        
        let mut file = async_fs::File::create(&self.scan_stats_file).await
            .context("Failed to create scan stats file")?;
        
        file.write_all(json.as_bytes()).await
            .context("Failed to write scan stats file")?;
        
        Ok(())
    }
    
    /// Store target profile
    pub async fn store_target_profile(&self, profile: &StoredTargetProfile) -> Result<()> {
        let mut profiles = self.load_target_profiles().await.unwrap_or_default();
        
        // Update existing profile or add new one
        if let Some(existing) = profiles.iter_mut().find(|p| p.target == profile.target) {
            *existing = profile.clone();
        } else {
            profiles.push(profile.clone());
        }
        
        // Limit the number of stored profiles
        let config = self.load_config().await?;
        if profiles.len() > config.max_target_profiles {
            // Remove oldest profiles
            profiles.sort_by(|a, b| a.last_updated.cmp(&b.last_updated));
            profiles.drain(0..profiles.len() - config.max_target_profiles);
        }
        
        self.save_target_profiles(&profiles).await
    }
    
    /// Load target profile
    pub async fn load_target_profile(&self, target: &str) -> Result<Option<StoredTargetProfile>> {
        let profiles = self.load_target_profiles().await?;
        Ok(profiles.into_iter().find(|p| p.target == target))
    }
    
    /// Load all target profiles
    pub async fn load_target_profiles(&self) -> Result<Vec<StoredTargetProfile>> {
        if !self.target_profiles_file.exists() {
            return Ok(Vec::new());
        }
        
        let mut file = async_fs::File::open(&self.target_profiles_file).await
            .context("Failed to open target profiles file")?;
        
        let mut contents = String::new();
        file.read_to_string(&mut contents).await
            .context("Failed to read target profiles file")?;
        
        serde_json::from_str(&contents)
            .context("Failed to deserialize target profiles")
    }
    
    /// Save target profiles
    async fn save_target_profiles(&self, profiles: &[StoredTargetProfile]) -> Result<()> {
        let json = serde_json::to_string_pretty(profiles)
            .context("Failed to serialize target profiles")?;
        
        let mut file = async_fs::File::create(&self.target_profiles_file).await
            .context("Failed to create target profiles file")?;
        
        file.write_all(json.as_bytes()).await
            .context("Failed to write target profiles file")?;
        
        Ok(())
    }
    
    /// Store learning patterns
    pub async fn store_patterns(&self, patterns: &serde_json::Value) -> Result<()> {
        let json = serde_json::to_string_pretty(patterns)
            .context("Failed to serialize patterns")?;
        
        let mut file = async_fs::File::create(&self.patterns_file).await
            .context("Failed to create patterns file")?;
        
        file.write_all(json.as_bytes()).await
            .context("Failed to write patterns file")?;
        
        Ok(())
    }
    
    /// Load learning patterns
    pub async fn load_patterns(&self) -> Result<Option<serde_json::Value>> {
        if !self.patterns_file.exists() {
            return Ok(None);
        }
        
        let mut file = async_fs::File::open(&self.patterns_file).await
            .context("Failed to open patterns file")?;
        
        let mut contents = String::new();
        file.read_to_string(&mut contents).await
            .context("Failed to read patterns file")?;
        
        let patterns = serde_json::from_str(&contents)
            .context("Failed to deserialize patterns")?;
        
        Ok(Some(patterns))
    }
    
    /// Clean up old data
    pub async fn cleanup(&self, max_age_days: u64) -> Result<usize> {
        let cutoff_time = SystemTime::now() - Duration::from_secs(max_age_days * 24 * 3600);
        let mut cleaned_count = 0;
        
        // Clean up old scan stats
        if let Ok(mut stats) = self.load_scan_stats().await {
            let original_len = stats.len();
            stats.retain(|s| s.timestamp > cutoff_time);
            cleaned_count += original_len - stats.len();
            
            if stats.len() != original_len {
                self.save_scan_stats(&stats).await?;
            }
        }
        
        // Clean up old target profiles
        if let Ok(mut profiles) = self.load_target_profiles().await {
            let original_len = profiles.len();
            profiles.retain(|p| p.last_updated > cutoff_time);
            cleaned_count += original_len - profiles.len();
            
            if profiles.len() != original_len {
                self.save_target_profiles(&profiles).await?;
            }
        }
        
        // Update cleanup timestamp
        let mut config = self.load_config().await?;
        config.last_cleanup = SystemTime::now();
        self.save_config(&config).await?;
        
        Ok(cleaned_count)
    }
    
    /// Get storage statistics
    pub async fn get_storage_stats(&self) -> Result<HashMap<String, serde_json::Value>> {
        let mut stats = HashMap::new();
        
        // File sizes
        if let Ok(metadata) = async_fs::metadata(&self.scan_stats_file).await {
            stats.insert("scan_stats_size_bytes".to_string(), 
                serde_json::Value::Number(metadata.len().into()));
        }
        
        if let Ok(metadata) = async_fs::metadata(&self.target_profiles_file).await {
            stats.insert("target_profiles_size_bytes".to_string(), 
                serde_json::Value::Number(metadata.len().into()));
        }
        
        if let Ok(metadata) = async_fs::metadata(&self.patterns_file).await {
            stats.insert("patterns_size_bytes".to_string(), 
                serde_json::Value::Number(metadata.len().into()));
        }
        
        // Record counts
        if let Ok(scan_stats) = self.load_scan_stats().await {
            stats.insert("scan_stats_count".to_string(), 
                serde_json::Value::Number(scan_stats.len().into()));
        }
        
        if let Ok(profiles) = self.load_target_profiles().await {
            stats.insert("target_profiles_count".to_string(), 
                serde_json::Value::Number(profiles.len().into()));
        }
        
        // Configuration
        if let Ok(config) = self.load_config().await {
            stats.insert("storage_config".to_string(), serde_json::to_value(config)?);
        }
        
        Ok(stats)
    }
    
    /// Export all data for backup
    pub async fn export_all(&self) -> Result<serde_json::Value> {
        let scan_stats = self.load_scan_stats().await.unwrap_or_default();
        let target_profiles = self.load_target_profiles().await.unwrap_or_default();
        let patterns = self.load_patterns().await.unwrap_or(None).unwrap_or(serde_json::Value::Null);
        let config = self.load_config().await?;
        
        Ok(serde_json::json!({
            "version": "1.0.0",
            "exported_at": SystemTime::now(),
            "scan_stats": scan_stats,
            "target_profiles": target_profiles,
            "patterns": patterns,
            "config": config
        }))
    }
    
    /// Import data from backup
    pub async fn import_all(&self, data: &serde_json::Value) -> Result<()> {
        if let Some(scan_stats) = data.get("scan_stats") {
            let stats: Vec<ScanStats> = serde_json::from_value(scan_stats.clone())?;
            self.save_scan_stats(&stats).await?;
        }
        
        if let Some(target_profiles) = data.get("target_profiles") {
            let profiles: Vec<StoredTargetProfile> = serde_json::from_value(target_profiles.clone())?;
            self.save_target_profiles(&profiles).await?;
        }
        
        if let Some(patterns) = data.get("patterns") {
            if !patterns.is_null() {
                self.store_patterns(patterns).await?;
            }
        }
        
        Ok(())
    }
    
    /// Load storage configuration
    async fn load_config(&self) -> Result<StorageConfig> {
        if !self.config_file.exists() {
            return Ok(StorageConfig::default());
        }
        
        let mut file = async_fs::File::open(&self.config_file).await
            .context("Failed to open config file")?;
        
        let mut contents = String::new();
        file.read_to_string(&mut contents).await
            .context("Failed to read config file")?;
        
        serde_json::from_str(&contents)
            .context("Failed to deserialize config")
    }
    
    /// Save storage configuration
    async fn save_config(&self, config: &StorageConfig) -> Result<()> {
        let json = serde_json::to_string_pretty(config)
            .context("Failed to serialize config")?;
        
        let mut file = async_fs::File::create(&self.config_file).await
            .context("Failed to create config file")?;
        
        file.write_all(json.as_bytes()).await
            .context("Failed to write config file")?;
        
        Ok(())
    }
    
    /// Get storage directory path
    fn get_storage_directory() -> Result<PathBuf> {
        let home_dir = dirs::home_dir()
            .context("Failed to get home directory")?;
        
        Ok(home_dir.join(".phobos").join("learning"))
    }
    
    /// Get storage directory path (public method)
    pub fn storage_path(&self) -> &Path {
        &self.storage_dir
    }
    
    /// Check if storage is healthy
    pub async fn health_check(&self) -> Result<bool> {
        // Check if directory exists and is writable
        if !self.storage_dir.exists() {
            return Ok(false);
        }
        
        // Try to create a temporary file
        let temp_file = self.storage_dir.join(".health_check");
        match async_fs::File::create(&temp_file).await {
            Ok(_) => {
                let _ = async_fs::remove_file(&temp_file).await;
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }
}

/// Convert internal target profile to storable format
impl From<&super::learning::TargetProfile> for StoredTargetProfile {
    fn from(profile: &super::learning::TargetProfile) -> Self {
        Self {
            target: "unknown".to_string(), // Would be set by caller
            target_type: profile.target_type.clone(),
            scan_count: profile.scan_count,
            port_frequencies: profile.port_frequencies.clone(),
            avg_scan_time: profile.avg_scan_time,
            optimal_params: StoredOptimalParams {
                threads: profile.optimal_params.threads,
                timeout: profile.optimal_params.timeout,
                technique: profile.optimal_params.technique.clone(),
                port_order: profile.optimal_params.port_order.clone(),
                batch_size: 100, // Default value
            },
            last_updated: profile.last_updated,
            success_rate: 0.95, // Default value
            reliability_score: 0.8, // Default value
        }
    }
}