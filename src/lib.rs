//! Phobos - A port scanner even the gods fear
//!
//! The blazingly fast Rust-based port scanner that outspeeds Nmap & Masscan.

pub mod benchmark;
pub mod config;
pub mod error;
pub mod network;
pub mod output;
pub mod scanner;
pub mod top_ports;
pub mod utils;

// Re-export commonly used types
pub use benchmark::{Benchmark, NamedTimer};
pub use error::{ScanError, ScanResult};
pub use config::ScanConfig;
pub use network::ScanTechnique;
pub use scanner::engine::ScanEngine;
pub use top_ports::{get_top_1000_ports, get_top_ports};

pub type Result<T> = std::result::Result<T, ScanError>;