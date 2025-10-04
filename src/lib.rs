//! Phobos - A port scanner even the gods fear
//!
//! The blazingly fast Rust-based port scanner that outspeeds Nmap & Masscan.

pub mod adaptive;
pub mod benchmark;
pub mod config;
pub mod distributed;
pub mod error;
pub mod history;
pub mod intelligence;
pub mod network;
pub mod output;
pub mod scanner;
pub mod scripts;
pub mod top_ports;
pub mod utils;

// Re-export commonly used types
pub use adaptive::{AdaptiveConfig, AdaptiveResult, LearningInsights, ScanStats, TargetType};
pub use benchmark::{Benchmark, NamedTimer};
pub use error::{ScanError, ScanResult};
pub use config::ScanConfig;
pub use history::{HistoryManager, ScanHistoryEntry, ScanDiff};
pub use intelligence::{IntelligenceEngine, IntelligenceConfig, IntelligenceResults};
pub use network::ScanTechnique;
pub use scanner::engine::ScanEngine;
pub use scripts::engine::ScriptEngine;
pub use scripts::{ScriptConfig, ScriptMode, ScriptResult as ScriptExecutionResult};
pub use top_ports::{get_top_1000_ports, get_top_ports};

pub type Result<T> = std::result::Result<T, ScanError>;