//! Port Predictor
//!
//! This module predicts which ports are likely to be open on a target
//! based on historical data and machine learning techniques.

use super::*;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Port prediction engine
#[derive(Debug)]
pub struct PortPredictor {
    config: AdaptiveConfig,
    port_patterns: Arc<RwLock<HashMap<TargetType, PortPattern>>>,
    correlation_matrix: Arc<RwLock<HashMap<u16, HashMap<u16, f64>>>>,
    global_statistics: Arc<RwLock<GlobalPortStats>>,
}

/// Port pattern for a specific target type
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PortPattern {
    common_ports: HashMap<u16, f64>, // port -> probability
    port_clusters: Vec<Vec<u16>>,     // groups of ports that often appear together
    conditional_probabilities: HashMap<u16, HashMap<u16, f64>>, // P(port2|port1)
    sample_count: usize,
    last_updated: SystemTime,
}

/// Global port statistics across all targets
#[derive(Debug, Clone, Default)]
struct GlobalPortStats {
    total_scans: usize,
    port_frequencies: HashMap<u16, usize>,
    service_mappings: HashMap<u16, String>,
    time_patterns: HashMap<u16, Vec<SystemTime>>, // when ports were found open
}

/// Prediction result
#[derive(Debug, Clone)]
pub struct PortPrediction {
    pub port: u16,
    pub probability: f64,
    pub confidence: f64,
    pub reasoning: String,
}

/// Prediction context
#[derive(Debug, Clone)]
struct PredictionContext {
    target_type: TargetType,
    known_open_ports: Vec<u16>,
    _scan_history_count: usize,
    time_of_day: u8, // 0-23
    day_of_week: u8,  // 0-6
}

impl PortPredictor {
    /// Create a new port predictor
    pub fn new(config: AdaptiveConfig) -> Self {
        Self {
            config,
            port_patterns: Arc::new(RwLock::new(HashMap::new())),
            correlation_matrix: Arc::new(RwLock::new(HashMap::new())),
            global_statistics: Arc::new(RwLock::new(GlobalPortStats::default())),
        }
    }
    
    /// Train the predictor with scan results
    pub async fn train(&self, scan_stats: &[ScanStats]) -> Result<()> {
        for stats in scan_stats {
            self.update_patterns(stats).await?;
            self.update_correlations(stats).await?;
            self.update_global_stats(stats).await?;
        }
        Ok(())
    }
    
    /// Predict likely open ports for a target
    pub async fn predict_ports(&self, target: &str, port_range: &[u16]) -> Result<Vec<u16>> {
        let context = self.build_prediction_context(target).await?;
        let predictions = self.generate_predictions(&context, port_range).await?;
        
        // Filter predictions by confidence threshold
        let confident_predictions: Vec<u16> = predictions
            .into_iter()
            .filter(|p| p.confidence >= self.config.confidence_threshold)
            .map(|p| p.port)
            .collect();
        
        Ok(confident_predictions)
    }
    
    /// Get detailed predictions with probabilities
    pub async fn predict_with_details(
        &self,
        target: &str,
        port_range: &[u16],
    ) -> Result<Vec<PortPrediction>> {
        let context = self.build_prediction_context(target).await?;
        self.generate_predictions(&context, port_range).await
    }
    
    /// Update port patterns for a target type
    async fn update_patterns(&self, stats: &ScanStats) -> Result<()> {
        let target_type = TargetType::classify_from_ports(&stats.open_ports);
        let mut patterns = self.port_patterns.write().await;
        
        let pattern = patterns.entry(target_type.clone()).or_insert_with(|| PortPattern {
            common_ports: HashMap::new(),
            port_clusters: Vec::new(),
            conditional_probabilities: HashMap::new(),
            sample_count: 0,
            last_updated: SystemTime::now(),
        });
        
        pattern.sample_count += 1;
        
        // Update port frequencies
        for &port in &stats.open_ports {
            let freq = pattern.common_ports.entry(port).or_insert(0.0);
            *freq = (*freq * (pattern.sample_count - 1) as f64 + 1.0) / pattern.sample_count as f64;
        }
        
        // Update conditional probabilities
        for &port1 in &stats.open_ports {
            let conditionals = pattern.conditional_probabilities.entry(port1).or_insert_with(HashMap::new);
            
            for &port2 in &stats.open_ports {
                if port1 != port2 {
                    let prob = conditionals.entry(port2).or_insert(0.0);
                    *prob = (*prob * (pattern.sample_count - 1) as f64 + 1.0) / pattern.sample_count as f64;
                }
            }
        }
        
        pattern.last_updated = SystemTime::now();
        
        // Update port clusters periodically
        if pattern.sample_count % 10 == 0 {
            pattern.port_clusters = self.discover_port_clusters(&pattern.conditional_probabilities);
        }
        
        Ok(())
    }
    
    /// Update port correlations
    async fn update_correlations(&self, stats: &ScanStats) -> Result<()> {
        let mut correlations = self.correlation_matrix.write().await;
        
        for &port1 in &stats.open_ports {
            let port1_correlations = correlations.entry(port1).or_insert_with(HashMap::new);
            
            for &port2 in &stats.open_ports {
                if port1 != port2 {
                    let correlation = port1_correlations.entry(port2).or_insert(0.0);
                    *correlation += 1.0;
                }
            }
        }
        
        Ok(())
    }
    
    /// Update global statistics
    async fn update_global_stats(&self, stats: &ScanStats) -> Result<()> {
        let mut global_stats = self.global_statistics.write().await;
        
        global_stats.total_scans += 1;
        
        for &port in &stats.open_ports {
            *global_stats.port_frequencies.entry(port).or_insert(0) += 1;
            global_stats.time_patterns.entry(port).or_insert_with(Vec::new).push(stats.timestamp);
        }
        
        Ok(())
    }
    
    /// Build prediction context
    async fn build_prediction_context(&self, _target: &str) -> Result<PredictionContext> {
        // Builds prediction context using target analysis and temporal features
        // Context includes target type, scan history, and time-based patterns
        let target_type = TargetType::Unknown; // Would be determined by previous scans or analysis
        
        let now = SystemTime::now();
        let duration_since_epoch = now.duration_since(SystemTime::UNIX_EPOCH)?;
        let seconds = duration_since_epoch.as_secs();
        
        // Simple time calculations (would be more sophisticated in practice)
        let time_of_day = ((seconds / 3600) % 24) as u8;
        let day_of_week = ((seconds / 86400) % 7) as u8;
        
        Ok(PredictionContext {
            target_type,
            known_open_ports: Vec::new(), // Would be populated from previous scans
            _scan_history_count: 0,
            time_of_day,
            day_of_week,
        })
    }
    
    /// Generate port predictions
    async fn generate_predictions(
        &self,
        context: &PredictionContext,
        port_range: &[u16],
    ) -> Result<Vec<PortPrediction>> {
        let mut predictions = Vec::new();
        
        let patterns = self.port_patterns.read().await;
        let correlations = self.correlation_matrix.read().await;
        let global_stats = self.global_statistics.read().await;
        
        // Get pattern for target type
        let pattern = patterns.get(&context.target_type);
        
        for &port in port_range {
            let mut probability = 0.0;
            let mut confidence = 0.0;
            let mut reasoning = String::new();
            
            // Base probability from global statistics
            if let Some(&freq) = global_stats.port_frequencies.get(&port) {
                probability = freq as f64 / global_stats.total_scans as f64;
                reasoning.push_str(&format!("Global frequency: {:.2}%; ", probability * 100.0));
            }
            
            // Adjust probability based on target type pattern
            if let Some(pattern) = pattern {
                if let Some(&type_prob) = pattern.common_ports.get(&port) {
                    probability = probability * 0.3 + type_prob * 0.7; // Weighted combination
                    confidence += 0.4;
                    reasoning.push_str(&format!("Target type pattern: {:.2}%; ", type_prob * 100.0));
                }
            }
            
            // Boost probability based on known open ports (correlations)
            for &known_port in &context.known_open_ports {
                if let Some(port_correlations) = correlations.get(&known_port) {
                    if let Some(&correlation) = port_correlations.get(&port) {
                        let correlation_boost = correlation / 100.0; // Normalize
                        probability += correlation_boost * 0.2;
                        confidence += 0.2;
                        reasoning.push_str(&format!("Correlation with port {}: {:.2}; ", known_port, correlation));
                    }
                }
            }
            
            // Time-based adjustments
            probability *= self.get_time_factor(port, context.time_of_day, context.day_of_week);
            
            // Adjust confidence based on sample size
            if let Some(pattern) = pattern {
                if pattern.sample_count >= self.config.min_scans {
                    confidence += 0.3;
                } else {
                    confidence *= pattern.sample_count as f64 / self.config.min_scans as f64;
                }
            }
            
            // Cap probability and confidence
            probability = probability.clamp(0.01, 0.95);
            confidence = confidence.clamp(0.0, 1.0);
            
            if reasoning.is_empty() {
                reasoning = "No specific patterns found".to_string();
            }
            
            predictions.push(PortPrediction {
                port,
                probability,
                confidence,
                reasoning,
            });
        }
        
        // Sort by probability (descending)
        predictions.sort_by(|a, b| b.probability.partial_cmp(&a.probability).unwrap());
        
        Ok(predictions)
    }
    
    /// Discover port clusters using correlation data
    fn discover_port_clusters(&self, conditionals: &HashMap<u16, HashMap<u16, f64>>) -> Vec<Vec<u16>> {
        let mut clusters = Vec::new();
        let mut processed_ports = HashSet::new();
        
        for (&port, correlations) in conditionals {
            if processed_ports.contains(&port) {
                continue;
            }
            
            let mut cluster = vec![port];
            processed_ports.insert(port);
            
            // Find highly correlated ports
            for (&correlated_port, &probability) in correlations {
                if probability > 0.7 && !processed_ports.contains(&correlated_port) {
                    cluster.push(correlated_port);
                    processed_ports.insert(correlated_port);
                }
            }
            
            if cluster.len() > 1 {
                clusters.push(cluster);
            }
        }
        
        clusters
    }
    
    /// Get time-based adjustment factor
    fn get_time_factor(&self, port: u16, hour: u8, _day: u8) -> f64 {
        // Simple time-based adjustments
        match port {
            80 | 443 => {
                // Web traffic might be higher during business hours
                if (9..=17).contains(&hour) {
                    1.2
                } else {
                    0.9
                }
            }
            22 => {
                // SSH might be more common during business hours
                if (8..=18).contains(&hour) {
                    1.1
                } else {
                    1.0
                }
            }
            _ => 1.0, // No time adjustment for other ports
        }
    }
    
    /// Get prediction statistics
    pub async fn get_prediction_stats(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();
        
        let patterns = self.port_patterns.read().await;
        let global_stats = self.global_statistics.read().await;
        
        stats.insert("total_scans".to_string(), serde_json::Value::Number(global_stats.total_scans.into()));
        stats.insert("target_types_learned".to_string(), serde_json::Value::Number(patterns.len().into()));
        stats.insert("unique_ports_seen".to_string(), serde_json::Value::Number(global_stats.port_frequencies.len().into()));
        
        // Most common ports globally
        let mut common_ports: Vec<(u16, usize)> = global_stats.port_frequencies.iter()
            .map(|(&port, &count)| (port, count))
            .collect();
        common_ports.sort_by(|a, b| b.1.cmp(&a.1));
        
        let top_ports: Vec<serde_json::Value> = common_ports.into_iter()
            .take(10)
            .map(|(port, count)| serde_json::json!({
                "port": port,
                "frequency": count,
                "percentage": (count as f64 / global_stats.total_scans as f64) * 100.0
            }))
            .collect();
        
        stats.insert("top_ports".to_string(), serde_json::Value::Array(top_ports));
        
        stats
    }
    
    /// Export learned patterns for analysis
    pub async fn export_patterns(&self) -> Result<serde_json::Value> {
        let patterns = self.port_patterns.read().await;
        let correlations = self.correlation_matrix.read().await;
        let global_stats = self.global_statistics.read().await;
        
        Ok(serde_json::json!({
            "patterns": *patterns,
            "correlations": *correlations,
            "global_stats": {
                "total_scans": global_stats.total_scans,
                "port_frequencies": global_stats.port_frequencies,
                "service_mappings": global_stats.service_mappings
            }
        }))
    }
}