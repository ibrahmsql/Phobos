//! Phobos Script Engine - Advanced scripting support with Nmap integration
//!
//! This module provides a powerful scripting engine that supports:
//! - Custom script execution in multiple languages (Python, Lua, Shell, etc.)
//! - Nmap integration and automatic script execution
//! - Script filtering based on tags, ports, and conditions
//! - Performance-optimized script execution
//! - Adaptive script selection based on scan results

use crate::config::ScanConfig;
use crate::{Result, ScanError};
use crate::network::{PortResult, PortState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::process::Command as AsyncCommand;

pub mod engine;
pub mod executor;
pub mod nmap;
pub mod parser;

pub use engine::ScriptEngine;
pub use executor::{ScriptExecutor, ExecutionContext, ExecutionStats};
pub use nmap::{NmapEngine, NmapConfig, NmapResult};
pub use parser::ScriptParser;

/// Script execution requirements
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptMode {
    /// No scripts will be executed
    None,
    /// Default Nmap scripts only
    Default,
    /// Custom scripts based on configuration
    Custom,
    /// All available scripts
    All,
    /// Adaptive script selection based on results
    Adaptive,
}

/// Script file representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptFile {
    /// Path to the script file
    pub path: PathBuf,
    /// Script name/identifier
    pub name: String,
    /// Script description
    pub description: Option<String>,
    /// Tags for filtering
    pub tags: Vec<String>,
    /// Supported ports (if port-specific)
    pub ports: Option<Vec<u16>>,
    /// Script language/interpreter
    pub language: ScriptLanguage,
    /// Execution format template
    pub call_format: String,
    /// Port separator for multi-port execution
    pub port_separator: String,
    /// Execution timeout
    pub timeout: Duration,
    /// Priority level (higher = more important)
    pub priority: u8,
    /// Whether script requires root privileges
    pub requires_root: bool,
}

/// Supported script languages
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptLanguage {
    Python,
    Lua,
    Shell,
    Nmap,
    Ruby,
    Perl,
    JavaScript,
    Binary,
}

/// Script execution result
#[derive(Debug, Clone)]
pub struct ScriptResult {
    pub script_name: String,
    pub target: IpAddr,
    pub ports: Vec<u16>,
    pub output: String,
    pub error: Option<String>,
    pub execution_time: Duration,
    pub exit_code: Option<i32>,
    pub success: bool,
}

/// Script configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptConfig {
    /// Script directories to search
    pub directories: Vec<PathBuf>,
    /// Tags to filter scripts
    pub tags: Option<Vec<String>>,
    /// Ports to filter scripts
    pub ports: Option<Vec<u16>>,
    /// Maximum concurrent script executions
    pub max_concurrent: usize,
    /// Global script timeout
    pub timeout: Duration,
    /// Enable Nmap integration
    pub nmap_integration: bool,
    /// Custom Nmap arguments
    pub nmap_args: Vec<String>,
    /// Script execution mode
    pub mode: ScriptMode,
}

impl Default for ScriptConfig {
    fn default() -> Self {
        Self {
            directories: vec![
                PathBuf::from("~/.phobos/scripts"),
                PathBuf::from("/usr/share/phobos/scripts"),
            ],
            tags: None,
            ports: None,
            max_concurrent: 10,
            timeout: Duration::from_secs(300), // 5 minutes
            nmap_integration: true,
            nmap_args: vec!["-sV".to_string(), "-sC".to_string()],
            mode: ScriptMode::Default,
        }
    }
}

impl ScriptLanguage {
    /// Get the interpreter command for the language
    pub fn interpreter(&self) -> Option<&'static str> {
        match self {
            ScriptLanguage::Python => Some("python3"),
            ScriptLanguage::Lua => Some("lua"),
            ScriptLanguage::Shell => Some("sh"),
            ScriptLanguage::Nmap => Some("nmap"),
            ScriptLanguage::Ruby => Some("ruby"),
            ScriptLanguage::Perl => Some("perl"),
            ScriptLanguage::JavaScript => Some("node"),
            ScriptLanguage::Binary => None,
        }
    }

    /// Detect language from file extension
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "py" => Some(ScriptLanguage::Python),
            "lua" => Some(ScriptLanguage::Lua),
            "sh" | "bash" => Some(ScriptLanguage::Shell),
            "nse" => Some(ScriptLanguage::Nmap),
            "rb" => Some(ScriptLanguage::Ruby),
            "pl" => Some(ScriptLanguage::Perl),
            "js" => Some(ScriptLanguage::JavaScript),
            _ => None,
        }
    }
}

impl ScriptFile {
    /// Create a new script file from path
    pub fn from_path(path: PathBuf) -> Result<Self> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| ScanError::ConfigError("Invalid script filename".to_string()))?
            .to_string();

        let language = path
            .extension()
            .and_then(|ext| ext.to_str())
            .and_then(ScriptLanguage::from_extension)
            .unwrap_or(ScriptLanguage::Binary);

        Ok(Self {
            path,
            name,
            description: None,
            tags: Vec::new(),
            ports: None,
            language,
            call_format: "{{interpreter}} {{script}} {{ip}} {{ports}}".to_string(),
            port_separator: ",".to_string(),
            timeout: Duration::from_secs(60),
            priority: 5,
            requires_root: false,
        })
    }

    /// Check if script matches the given criteria
    pub fn matches(&self, tags: &[String], ports: &[u16]) -> bool {
        // Check tag matching
        if !tags.is_empty() {
            let has_all_tags = tags.iter().all(|tag| self.tags.contains(tag));
            if !has_all_tags {
                return false;
            }
        }

        // Check port matching
        if let Some(script_ports) = &self.ports {
            let has_matching_port = ports.iter().any(|port| script_ports.contains(port));
            if !has_matching_port {
                return false;
            }
        }

        true
    }

    /// Generate the command to execute this script
    pub fn generate_command(&self, target: IpAddr, ports: &[u16]) -> Result<Vec<String>> {
        let ports_str = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(&self.port_separator);

        let mut command = self.call_format.clone();
        
        // Replace placeholders
        if let Some(interpreter) = self.language.interpreter() {
            command = command.replace("{{interpreter}}", interpreter);
        }
        command = command.replace("{{script}}", &self.path.to_string_lossy());
        command = command.replace("{{ip}}", &target.to_string());
        command = command.replace("{{ports}}", &ports_str);
        command = command.replace("{{target}}", &target.to_string());

        // Split command into parts
        let parts: Vec<String> = command
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if parts.is_empty() {
            return Err(ScanError::ConfigError("Empty command generated".to_string()));
        }

        Ok(parts)
    }
}

/// Script execution statistics
#[derive(Debug, Clone, Default)]
pub struct ScriptStats {
    pub total_scripts: usize,
    pub successful_scripts: usize,
    pub failed_scripts: usize,
    pub total_execution_time: Duration,
    pub average_execution_time: Duration,
}

impl ScriptStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_result(&mut self, result: &ScriptResult) {
        self.total_scripts += 1;
        self.total_execution_time += result.execution_time;
        
        if result.success {
            self.successful_scripts += 1;
        } else {
            self.failed_scripts += 1;
        }

        if self.total_scripts > 0 {
            self.average_execution_time = self.total_execution_time / self.total_scripts as u32;
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_scripts == 0 {
            0.0
        } else {
            (self.successful_scripts as f64 / self.total_scripts as f64) * 100.0
        }
    }
}