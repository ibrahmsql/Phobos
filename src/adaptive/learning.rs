//! Adaptive Learning Engine
//!
//! This module implements the core adaptive learning functionality that analyzes
//! scan patterns and improves performance over time.

use super::*;
use crate::config::ScanConfig;
use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
use super::storage::StoredTargetProfile;

/// Main adaptive learning engine
#[derive(Debug)]
pub struct AdaptiveLearner {
    config: AdaptiveConfig,
    storage: Arc<Mutex<LearningStorage>>,
    predictor: PortPredictor,
    scan_history: Arc<RwLock<VecDeque<ScanStats>>>,
    target_profiles: Arc<RwLock<HashMap<String, TargetProfile>>>,
}

/// Profile for a specific target or target type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetProfile {
    pub target_type: TargetType,
    pub scan_count: usize,
    pub port_frequencies: HashMap<u16, f64>,
    pub avg_scan_time: Duration,
    pub optimal_params: OptimalParams,
    pub last_updated: SystemTime,
}

/// Optimal scanning parameters learned for a target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimalParams {
    pub threads: usize,
    pub timeout: Duration,
    pub technique: String,
    pub port_order: Vec<u16>,
}

impl Default for OptimalParams {
    fn default() -> Self {
        Self {
            threads: 100,
            timeout: Duration::from_millis(1000),
            technique: "SYN".to_string(),
            port_order: Vec::new(),
        }
    }
}

impl AdaptiveLearner {
    /// Create a new adaptive learner
    pub async fn new(config: AdaptiveConfig) -> Result<Self> {
        let storage = Arc::new(Mutex::new(LearningStorage::new().await?));
        let predictor = PortPredictor::new(config.clone());
        
        Ok(Self {
            config,
            storage,
            predictor,
            scan_history: Arc::new(RwLock::new(VecDeque::new())),
            target_profiles: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Learn from a completed scan
    pub async fn learn_from_scan(&self, stats: ScanStats) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        // Add to scan history
        {
            let mut history = self.scan_history.write().unwrap();
            history.push_back(stats.clone());
            
            // Limit history size
            while history.len() > self.config.max_history {
                history.pop_front();
            }
        }
        
        // Update target profile
        self.update_target_profile(&stats).await?;
        
        // Store in persistent storage
        let storage = self.storage.lock().await;
        storage.store_scan_stats(&stats).await?;
        
        Ok(())
    }
    
    /// Get adaptive insights for a target
    pub async fn get_insights(&self, target: &str) -> Result<AdaptiveResult> {
        let target_profile = self.get_or_create_profile(target).await?;
        
        // Generate insights based on historical data
        let insights = LearningInsights {
            common_ports: self.get_common_ports(&target_profile),
            optimal_threads: target_profile.optimal_params.threads,
            optimal_timeout: target_profile.optimal_params.timeout,
            predicted_duration: target_profile.avg_scan_time,
            confidence: self.calculate_confidence(&target_profile),
            port_priority: target_profile.port_frequencies.clone(),
        };
        
        let recommendations = self.generate_recommendations(&target_profile);
        
        Ok(AdaptiveResult {
            insights,
            target_type: target_profile.target_type,
            recommendations,
        })
    }
    
    /// Optimize scan configuration based on learning
    pub async fn optimize_scan_config(&self, target: &str, config: &mut ScanConfig) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let insights = self.get_insights(target).await?;
        
        // Apply optimizations if confidence is high enough
        if insights.insights.confidence >= self.config.confidence_threshold {
            config.threads = insights.insights.optimal_threads;
            config.timeout = insights.insights.optimal_timeout.as_millis() as u64;
            
            // Prioritize common ports
            if !insights.insights.common_ports.is_empty() {
                let mut optimized_ports = insights.insights.common_ports.clone();
                
                // Add remaining ports
                for port in &config.ports {
                    if !optimized_ports.contains(port) {
                        optimized_ports.push(*port);
                    }
                }
                
                config.ports = optimized_ports;
            }
        }
        
        Ok(())
    }
    
    /// Predict likely open ports for a target
    pub async fn predict_open_ports(&self, target: &str, port_range: &[u16]) -> Result<Vec<u16>> {
        self.predictor.predict_ports(target, port_range).await
    }
    
    /// Update target profile with new scan data
    async fn update_target_profile(&self, stats: &ScanStats) -> Result<()> {
        let mut profiles = self.target_profiles.write().unwrap();
        let profile = profiles.entry(stats.target.clone()).or_insert_with(|| {
            TargetProfile {
                target_type: TargetType::classify_from_ports(&stats.open_ports),
                scan_count: 0,
                port_frequencies: HashMap::new(),
                avg_scan_time: Duration::from_secs(0),
                optimal_params: OptimalParams::default(),
                last_updated: SystemTime::now(),
            }
        });
        
        // Update scan count
        profile.scan_count += 1;
        
        // Update port frequencies
        for &port in &stats.open_ports {
            let freq = profile.port_frequencies.entry(port).or_insert(0.0);
            *freq = (*freq * (profile.scan_count - 1) as f64 + 1.0) / profile.scan_count as f64;
        }
        
        // Update average scan time
        let total_time = profile.avg_scan_time.as_millis() as f64 * (profile.scan_count - 1) as f64
            + stats.scan_duration.as_millis() as f64;
        profile.avg_scan_time = Duration::from_millis((total_time / profile.scan_count as f64) as u64);
        
        // Update optimal parameters if this scan was better
        if stats.success_rate > 0.9 && stats.scan_duration < profile.avg_scan_time {
            profile.optimal_params.threads = stats.thread_count;
            profile.optimal_params.timeout = stats.timeout;
            profile.optimal_params.technique = stats.technique_used.clone();
        }
        
        profile.last_updated = SystemTime::now();
        
        Ok(())
    }
    
    /// Get or create a target profile
    async fn get_or_create_profile(&self, target: &str) -> Result<TargetProfile> {
        let profiles = self.target_profiles.read().unwrap();
        
        if let Some(profile) = profiles.get(target) {
            Ok(profile.clone())
        } else {
            drop(profiles);
            
            // Try to load from storage
            let storage = self.storage.lock().await;
            if let Some(stored_profile) = storage.load_target_profile(target).await? {
                let mut profiles = self.target_profiles.write().unwrap();
                let target_profile = TargetProfile::from(stored_profile);
                profiles.insert(target.to_string(), target_profile.clone());
                Ok(target_profile)
            } else {
                // Create new profile
                let new_profile = TargetProfile {
                    target_type: TargetType::Unknown,
                    scan_count: 0,
                    port_frequencies: HashMap::new(),
                    avg_scan_time: Duration::from_secs(10),
                    optimal_params: OptimalParams::default(),
                    last_updated: SystemTime::now(),
                };
                
                let mut profiles = self.target_profiles.write().unwrap();
                profiles.insert(target.to_string(), new_profile.clone());
                Ok(new_profile)
            }
        }
    }
    
    /// Get most common ports for a target profile
    fn get_common_ports(&self, profile: &TargetProfile) -> Vec<u16> {
        let mut ports: Vec<(u16, f64)> = profile.port_frequencies.iter()
            .map(|(&port, &freq)| (port, freq))
            .collect();
        
        ports.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        
        ports.into_iter()
            .take(20) // Top 20 most common ports
            .filter(|(_, freq)| *freq > 0.1) // At least 10% frequency
            .map(|(port, _)| port)
            .collect()
    }
    
    /// Calculate confidence level for predictions
    fn calculate_confidence(&self, profile: &TargetProfile) -> f64 {
        if profile.scan_count < self.config.min_scans {
            return 0.0;
        }
        
        // Confidence increases with more scans, up to a maximum
        let scan_confidence = (profile.scan_count as f64 / 100.0).min(1.0);
        
        // Confidence decreases with age of data
        let age = SystemTime::now().duration_since(profile.last_updated)
            .unwrap_or(Duration::from_secs(0));
        let age_factor = (-(age.as_secs() as f64) / 86400.0 * 0.1).exp(); // Decay over days
        
        scan_confidence * age_factor
    }
    
    /// Generate recommendations based on profile
    fn generate_recommendations(&self, profile: &TargetProfile) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        if profile.scan_count < self.config.min_scans {
            recommendations.push(format!(
                "Need {} more scans for reliable predictions", 
                self.config.min_scans - profile.scan_count
            ));
        }
        
        if profile.optimal_params.threads != 100 {
            recommendations.push(format!(
                "Consider using {} threads for optimal performance", 
                profile.optimal_params.threads
            ));
        }
        
        if !profile.port_frequencies.is_empty() {
            let top_ports: Vec<u16> = self.get_common_ports(profile);
            if !top_ports.is_empty() {
                recommendations.push(format!(
                    "Focus on ports: {}", 
                    top_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
                ));
            }
        }
        
        match profile.target_type {
            TargetType::WebServer => {
                recommendations.push("Web server detected - consider HTTP/HTTPS specific scans".to_string());
            }
            TargetType::DatabaseServer => {
                recommendations.push("Database server detected - focus on database ports".to_string());
            }
            TargetType::Router => {
                recommendations.push("Router/Network device detected - check management interfaces".to_string());
            }
            _ => {}
        }
        
        recommendations
    }
    
    /// Get learning statistics
    pub fn get_stats(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();
        
        let history = self.scan_history.read().unwrap();
        let profiles = self.target_profiles.read().unwrap();
        
        stats.insert("total_scans".to_string(), serde_json::Value::Number(history.len().into()));
        stats.insert("target_profiles".to_string(), serde_json::Value::Number(profiles.len().into()));
        stats.insert("learning_enabled".to_string(), serde_json::Value::Bool(self.config.enabled));
        
        if !profiles.is_empty() {
            let avg_confidence: f64 = profiles.values()
                .map(|p| self.calculate_confidence(p))
                .sum::<f64>() / profiles.len() as f64;
            stats.insert("avg_confidence".to_string(), serde_json::Value::Number(
                serde_json::Number::from_f64(avg_confidence).unwrap_or(serde_json::Number::from(0))
            ));
        }
        
        stats
    }
}

/// Convert stored target profile to runtime format
impl From<StoredTargetProfile> for TargetProfile {
    fn from(stored: StoredTargetProfile) -> Self {
        Self {
            target_type: stored.target_type,
            scan_count: stored.scan_count,
            port_frequencies: stored.port_frequencies,
            avg_scan_time: stored.avg_scan_time,
            optimal_params: OptimalParams {
                threads: stored.optimal_params.threads,
                timeout: stored.optimal_params.timeout,
                technique: stored.optimal_params.technique,
                port_order: stored.optimal_params.port_order,
            },
            last_updated: stored.last_updated,
        }
    }
}