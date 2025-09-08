//! Adaptive Learning Module
//! 
//! This module implements an adaptive learning system that improves scanning performance
//! over time by learning from previous scan results and user patterns.

pub mod learning;
pub mod optimizer;
pub mod predictor;
pub mod storage;

pub use learning::AdaptiveLearner;
pub use optimizer::ScanOptimizer;
pub use predictor::PortPredictor;
pub use storage::LearningStorage;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Configuration for the adaptive learning system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveConfig {
    /// Enable/disable adaptive learning
    pub enabled: bool,
    /// Minimum number of scans before learning kicks in
    pub min_scans: usize,
    /// Learning rate (0.0 to 1.0)
    pub learning_rate: f64,
    /// Maximum number of historical records to keep
    pub max_history: usize,
    /// Weight decay factor for old data
    pub decay_factor: f64,
    /// Confidence threshold for predictions
    pub confidence_threshold: f64,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_scans: 10,
            learning_rate: 0.1,
            max_history: 1000,
            decay_factor: 0.95,
            confidence_threshold: 0.7,
        }
    }
}

/// Scan statistics for learning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub target: String,
    pub ports_scanned: Vec<u16>,
    pub open_ports: Vec<u16>,
    pub scan_duration: Duration,
    pub timestamp: SystemTime,
    pub success_rate: f64,
    pub technique_used: String,
    pub thread_count: usize,
    pub timeout: Duration,
}

/// Learning insights derived from historical data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningInsights {
    /// Most commonly open ports for this target type
    pub common_ports: Vec<u16>,
    /// Optimal scanning parameters
    pub optimal_threads: usize,
    pub optimal_timeout: Duration,
    /// Predicted scan duration
    pub predicted_duration: Duration,
    /// Confidence level of predictions
    pub confidence: f64,
    /// Recommended port scanning order
    pub port_priority: HashMap<u16, f64>,
}

/// Target classification for better learning
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetType {
    WebServer,
    DatabaseServer,
    MailServer,
    Router,
    Firewall,
    Desktop,
    IoTDevice,
    Unknown,
}

impl TargetType {
    /// Classify target based on open ports
    pub fn classify_from_ports(open_ports: &[u16]) -> Self {
        let web_ports = [80, 443, 8080, 8443, 3000, 8000];
        let db_ports = [3306, 5432, 1433, 27017, 6379, 5984];
        let mail_ports = [25, 110, 143, 993, 995, 587];
        let router_ports = [22, 23, 80, 443, 161, 8080];
        
        let web_score = web_ports.iter().filter(|&&p| open_ports.contains(&p)).count();
        let db_score = db_ports.iter().filter(|&&p| open_ports.contains(&p)).count();
        let mail_score = mail_ports.iter().filter(|&&p| open_ports.contains(&p)).count();
        let router_score = router_ports.iter().filter(|&&p| open_ports.contains(&p)).count();
        
        let scores = [web_score, db_score, mail_score, router_score];
        let max_score = scores.iter().max().unwrap();
        
        if *max_score == 0 {
            return Self::Unknown;
        }
        
        if web_score == *max_score {
            Self::WebServer
        } else if db_score == *max_score {
            Self::DatabaseServer
        } else if mail_score == *max_score {
            Self::MailServer
        } else if router_score == *max_score {
            Self::Router
        } else {
            Self::Unknown
        }
    }
}

/// Result of adaptive learning analysis
#[derive(Debug, Clone)]
pub struct AdaptiveResult {
    pub insights: LearningInsights,
    pub target_type: TargetType,
    pub recommendations: Vec<String>,
}