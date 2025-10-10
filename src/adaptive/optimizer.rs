//! Scan Optimizer
//!
//! This module optimizes scanning parameters based on learned patterns
//! and historical performance data.

use super::*;
use crate::config::ScanConfig;
use crate::network::ScanTechnique;
use anyhow::Result;
use std::collections::HashMap;
use std::time::Duration;

/// Scan parameter optimizer
#[derive(Debug, Clone)]
pub struct ScanOptimizer {
    config: AdaptiveConfig,
    performance_cache: HashMap<String, PerformanceMetrics>,
}

/// Performance metrics for different configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    avg_duration: Duration,
    success_rate: f64,
    accuracy: f64,
    resource_usage: f64,
    sample_count: usize,
    last_updated: SystemTime,
}

/// Optimization recommendation
#[derive(Debug, Clone)]
pub struct OptimizationRecommendation {
    pub threads: Option<usize>,
    pub timeout: Option<Duration>,
    pub technique: Option<ScanTechnique>,
    pub port_order: Option<Vec<u16>>,
    pub batch_size: Option<usize>,
    pub confidence: f64,
    pub expected_improvement: f64,
}

/// Configuration profile for different scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct ConfigProfile {
    name: String,
    threads: usize,
    timeout: Duration,
    technique: String,
    batch_size: usize,
    use_case: String,
    performance: PerformanceMetrics,
}

impl ScanOptimizer {
    /// Create a new scan optimizer
    pub fn new(config: AdaptiveConfig) -> Self {
        Self {
            config,
            performance_cache: HashMap::new(),
        }
    }
    
    /// Optimize scan configuration based on target and context
    pub fn optimize_config(
        &mut self,
        target: &str,
        current_config: &ScanConfig,
        target_type: &TargetType,
        historical_data: &[ScanStats],
    ) -> Result<OptimizationRecommendation> {
        let context = self.analyze_context(target, target_type, historical_data)?;
        
        let mut recommendation = OptimizationRecommendation {
            threads: None,
            timeout: None,
            technique: None,
            port_order: None,
            batch_size: None,
            confidence: 0.0,
            expected_improvement: 0.0,
        };
        
        // Optimize thread count
        if let Some(optimal_threads) = self.optimize_threads(&context, current_config)? {
            recommendation.threads = Some(optimal_threads);
        }
        
        // Optimize timeout
        if let Some(optimal_timeout) = self.optimize_timeout(&context, current_config)? {
            recommendation.timeout = Some(optimal_timeout);
        }
        
        // Optimize scanning technique
        if let Some(optimal_technique) = self.optimize_technique(&context, current_config)? {
            recommendation.technique = Some(optimal_technique);
        }
        
        // Optimize port scanning order
        if let Some(port_order) = self.optimize_port_order(&context, current_config)? {
            recommendation.port_order = Some(port_order);
        }
        
        // Calculate confidence and expected improvement
        recommendation.confidence = self.calculate_optimization_confidence(&context);
        recommendation.expected_improvement = self.estimate_improvement(&context, &recommendation)?;
        
        Ok(recommendation)
    }
    
    /// Analyze scanning context
    fn analyze_context(
        &self,
        target: &str,
        target_type: &TargetType,
        historical_data: &[ScanStats],
    ) -> Result<ScanContext> {
        let mut context = ScanContext {
            _target: target.to_string(),
            target_type: target_type.clone(),
            historical_scans: historical_data.len(),
            avg_response_time: Duration::from_millis(100),
            common_open_ports: Vec::new(),
            peak_performance_config: None,
            _network_characteristics: NetworkCharacteristics::default(),
        };
        
        if !historical_data.is_empty() {
            // Calculate average response characteristics
            let total_duration: u64 = historical_data.iter()
                .map(|s| s.scan_duration.as_millis() as u64)
                .sum();
            context.avg_response_time = Duration::from_millis(total_duration / historical_data.len() as u64);
            
            // Find most common open ports
            let mut port_counts: HashMap<u16, usize> = HashMap::new();
            for stats in historical_data {
                for &port in &stats.open_ports {
                    *port_counts.entry(port).or_insert(0) += 1;
                }
            }
            
            let mut ports: Vec<(u16, usize)> = port_counts.into_iter().collect();
            ports.sort_by(|a, b| b.1.cmp(&a.1));
            context.common_open_ports = ports.into_iter().take(10).map(|(port, _)| port).collect();
            
            // Find peak performance configuration
            if let Some(best_scan) = historical_data.iter()
                .min_by_key(|s| s.scan_duration.as_millis()) {
                context.peak_performance_config = Some(PerfConfig {
                    threads: best_scan.thread_count,
                    _timeout: best_scan.timeout,
                    technique: best_scan.technique_used.clone(),
                });
            }
        }
        
        Ok(context)
    }
    
    /// Optimize thread count
    fn optimize_threads(
        &self,
        context: &ScanContext,
        current_config: &ScanConfig,
    ) -> Result<Option<usize>> {
        if context.historical_scans < self.config.min_scans {
            return Ok(None);
        }
        
        let optimal_threads = match context.target_type {
            TargetType::WebServer => {
                // Web servers can handle more concurrent connections
                std::cmp::min(200, current_config.threads * 2)
            }
            TargetType::DatabaseServer => {
                // Database servers might be more sensitive
                std::cmp::max(50, current_config.threads / 2)
            }
            TargetType::Router | TargetType::Firewall => {
                // Network devices might have rate limiting
                std::cmp::min(100, current_config.threads)
            }
            TargetType::IoTDevice => {
                // IoT devices are usually resource-constrained
                std::cmp::min(50, current_config.threads)
            }
            _ => {
                // Use historical peak performance if available
                if let Some(ref peak_config) = context.peak_performance_config {
                    peak_config.threads
                } else {
                    current_config.threads
                }
            }
        };
        
        if optimal_threads != current_config.threads {
            Ok(Some(optimal_threads))
        } else {
            Ok(None)
        }
    }
    
    /// Optimize timeout duration
    fn optimize_timeout(
        &self,
        context: &ScanContext,
        current_config: &ScanConfig,
    ) -> Result<Option<Duration>> {
        if context.historical_scans < self.config.min_scans {
            return Ok(None);
        }
        
        // Base timeout on average response time with some buffer
        let base_timeout = context.avg_response_time.mul_f64(3.0);
        
        let optimal_timeout = match context.target_type {
            TargetType::IoTDevice => {
                // IoT devices might be slower
                std::cmp::max(base_timeout, Duration::from_millis(2000))
            }
            TargetType::WebServer => {
                // Web servers should be responsive
                std::cmp::min(base_timeout, Duration::from_millis(1000))
            }
            _ => base_timeout,
        };
        
        if (optimal_timeout.as_millis() as i64 - current_config.timeout_duration().as_millis() as i64).abs() > 500 {
            Ok(Some(optimal_timeout))
        } else {
            Ok(None)
        }
    }
    
    /// Optimize scanning technique
    fn optimize_technique(
        &self,
        context: &ScanContext,
        _current_config: &ScanConfig,
    ) -> Result<Option<ScanTechnique>> {
        if context.historical_scans < self.config.min_scans {
            return Ok(None);
        }
        
        let optimal_technique = match context.target_type {
            TargetType::Firewall => ScanTechnique::Stealth, // Firewalls might detect SYN scans
            TargetType::WebServer => ScanTechnique::Syn,    // SYN is fast for web servers
            TargetType::IoTDevice => ScanTechnique::Connect, // IoT might not handle SYN well
            _ => {
                if let Some(ref peak_config) = context.peak_performance_config {
                    match peak_config.technique.as_str() {
                        "SYN" => ScanTechnique::Syn,
                        "Connect" => ScanTechnique::Connect,
                        "Stealth" => ScanTechnique::Stealth,
                        _ => ScanTechnique::Syn,
                    }
                } else {
                    return Ok(None);
                }
            }
        };
        
        Ok(Some(optimal_technique))
    }
    
    /// Optimize port scanning order
    fn optimize_port_order(
        &self,
        context: &ScanContext,
        current_config: &ScanConfig,
    ) -> Result<Option<Vec<u16>>> {
        if context.common_open_ports.is_empty() {
            return Ok(None);
        }
        
        let mut optimized_ports = context.common_open_ports.clone();
        
        // Add remaining ports from current config
        for &port in &current_config.ports {
            if !optimized_ports.contains(&port) {
                optimized_ports.push(port);
            }
        }
        
        // Add common ports for target type
        let type_specific_ports = match context.target_type {
            TargetType::WebServer => vec![80, 443, 8080, 8443, 3000, 8000],
            TargetType::DatabaseServer => vec![3306, 5432, 1433, 27017, 6379],
            TargetType::MailServer => vec![25, 110, 143, 993, 995, 587],
            TargetType::Router => vec![22, 23, 80, 443, 161],
            _ => Vec::new(),
        };
        
        for port in type_specific_ports {
            if !optimized_ports.contains(&port) && current_config.ports.contains(&port) {
                optimized_ports.insert(0, port); // Prioritize at the beginning
            }
        }
        
        if optimized_ports != current_config.ports {
            Ok(Some(optimized_ports))
        } else {
            Ok(None)
        }
    }
    
    /// Calculate confidence in optimization recommendations
    fn calculate_optimization_confidence(&self, context: &ScanContext) -> f64 {
        if context.historical_scans < self.config.min_scans {
            return 0.0;
        }
        
        // Confidence increases with more historical data
        let data_confidence = (context.historical_scans as f64 / 50.0).min(1.0);
        
        // Higher confidence for known target types
        let type_confidence = match context.target_type {
            TargetType::Unknown => 0.5,
            _ => 0.9,
        };
        
        data_confidence * type_confidence
    }
    
    /// Estimate performance improvement
    fn estimate_improvement(
        &self,
        context: &ScanContext,
        recommendation: &OptimizationRecommendation,
    ) -> Result<f64> {
        let mut improvement: f64 = 0.0;
        
        // Estimate improvement from thread optimization
        if recommendation.threads.is_some() {
            improvement += 0.15; // 15% improvement from better threading
        }
        
        // Estimate improvement from timeout optimization
        if recommendation.timeout.is_some() {
            improvement += 0.10; // 10% improvement from better timeouts
        }
        
        // Estimate improvement from port order optimization
        if recommendation.port_order.is_some() && !context.common_open_ports.is_empty() {
            improvement += 0.20; // 20% improvement from scanning likely ports first
        }
        
        // Estimate improvement from technique optimization
        if recommendation.technique.is_some() {
            improvement += 0.05; // 5% improvement from better technique
        }
        
        // Cap improvement estimate
        Ok(improvement.min(0.5_f64)) // Maximum 50% improvement
    }
    
    /// Update performance metrics
    pub fn update_performance(&mut self, config_key: String, metrics: PerformanceMetrics) {
        self.performance_cache.insert(config_key, metrics);
    }
    
    /// Get performance history
    pub fn get_performance_history(&self) -> &HashMap<String, PerformanceMetrics> {
        &self.performance_cache
    }
}

/// Context information for optimization decisions
#[derive(Debug, Clone)]
struct ScanContext {
    _target: String,
    target_type: TargetType,
    historical_scans: usize,
    avg_response_time: Duration,
    common_open_ports: Vec<u16>,
    peak_performance_config: Option<PerfConfig>,
    _network_characteristics: NetworkCharacteristics,
}

/// Peak performance configuration
#[derive(Debug, Clone)]
struct PerfConfig {
    threads: usize,
    _timeout: Duration,
    technique: String,
}

/// Network characteristics
#[derive(Debug, Clone, Default)]
struct NetworkCharacteristics {
    _latency: Duration,
    _bandwidth: f64,
    _packet_loss: f64,
    _jitter: Duration,
}