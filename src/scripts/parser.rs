//! Script Parser - Parse and validate script files and configurations

use super::*;
use crate::{Result, ScanError};
use log::{debug, warn};
use serde_json;
use std::collections::HashSet;
use toml;

/// Script configuration parser
pub struct ScriptParser;

impl ScriptParser {
    /// Parse script configuration from TOML file
    pub fn parse_config_file(path: &PathBuf) -> Result<ScriptConfig> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ScanError::ConfigError(format!("Failed to read config file: {}", e)))?;

        Self::parse_config_toml(&content)
    }

    /// Parse script configuration from TOML string
    pub fn parse_config_toml(content: &str) -> Result<ScriptConfig> {
        let config: ScriptConfigToml = toml::from_str(content)
            .map_err(|e| ScanError::ConfigError(format!("Failed to parse TOML config: {}", e)))?;

        Ok(config.into())
    }

    /// Parse script file and extract metadata
    pub fn parse_script_file(path: &PathBuf) -> Result<ScriptFile> {
        let mut script = ScriptFile::from_path(path.clone())?;
        
        // Try to parse embedded metadata
        if let Ok(metadata) = Self::parse_embedded_metadata(path) {
            script.description = metadata.description.or(script.description);
            script.tags = if metadata.tags.is_empty() { script.tags } else { metadata.tags };
            script.ports = metadata.ports.or(script.ports);
            script.timeout = metadata.timeout.unwrap_or(script.timeout);
            script.priority = metadata.priority.unwrap_or(script.priority);
            script.requires_root = metadata.requires_root.unwrap_or(script.requires_root);
            
            if !metadata.call_format.is_empty() {
                script.call_format = metadata.call_format;
            }
            
            if !metadata.port_separator.is_empty() {
                script.port_separator = metadata.port_separator;
            }
        }

        // Validate script
        Self::validate_script(&script)?;

        Ok(script)
    }

    /// Parse embedded metadata from script file
    fn parse_embedded_metadata(path: &PathBuf) -> Result<EmbeddedMetadata> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ScanError::ConfigError(format!("Failed to read script file: {}", e)))?;

        let mut metadata = EmbeddedMetadata::default();
        let mut in_metadata_block = false;
        let mut metadata_lines = Vec::new();

        for line in content.lines().take(100) { // Check first 100 lines
            let trimmed = line.trim();
            
            // Check for metadata block markers
            if trimmed.contains("@phobos-metadata-start") {
                in_metadata_block = true;
                continue;
            }
            
            if trimmed.contains("@phobos-metadata-end") {
                break;
            }

            if in_metadata_block {
                metadata_lines.push(trimmed);
                continue;
            }

            // Parse individual metadata lines
            if let Some(parsed) = Self::parse_metadata_line(trimmed) {
                match parsed {
                    MetadataField::Description(desc) => metadata.description = Some(desc),
                    MetadataField::Tags(tags) => metadata.tags = tags,
                    MetadataField::Ports(ports) => metadata.ports = Some(ports),
                    MetadataField::Timeout(timeout) => metadata.timeout = Some(timeout),
                    MetadataField::Priority(priority) => metadata.priority = Some(priority),
                    MetadataField::RequiresRoot(requires) => metadata.requires_root = Some(requires),
                    MetadataField::CallFormat(format) => metadata.call_format = format,
                    MetadataField::PortSeparator(sep) => metadata.port_separator = sep,
                }
            }
        }

        // Parse metadata block as JSON or TOML if present
        if !metadata_lines.is_empty() {
            let metadata_content = metadata_lines.join("\n");
            
            // Try JSON first
            if let Ok(json_metadata) = serde_json::from_str::<JsonMetadata>(&metadata_content) {
                metadata.merge_from_json(json_metadata);
            } else if let Ok(toml_metadata) = toml::from_str::<TomlMetadata>(&metadata_content) {
                metadata.merge_from_toml(toml_metadata);
            }
        }

        Ok(metadata)
    }

    /// Parse a single metadata line
    fn parse_metadata_line(line: &str) -> Option<MetadataField> {
        // Remove comment markers
        let content = if line.starts_with('#') {
            &line[1..]
        } else if line.starts_with("//") {
            &line[2..]
        } else if line.starts_with("--") {
            &line[2..]
        } else {
            line
        }.trim();

        // Parse @key: value format
        if content.starts_with('@') {
            if let Some(colon_pos) = content.find(':') {
                let key = content[1..colon_pos].trim();
                let value = content[colon_pos + 1..].trim();

                return match key {
                    "description" => Some(MetadataField::Description(value.to_string())),
                    "tags" => {
                        let tags: Vec<String> = value
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        Some(MetadataField::Tags(tags))
                    }
                    "ports" => {
                        let ports: Result<Vec<u16>> = value
                            .split(',')
                            .map(|s| s.trim().parse::<u16>().map_err(ScanError::from))
                            .collect();
                        if let Ok(ports) = ports {
                            Some(MetadataField::Ports(ports))
                        } else {
                            None
                        }
                    }
                    "timeout" => {
                        if let Ok(seconds) = value.parse::<u64>() {
                            Some(MetadataField::Timeout(Duration::from_secs(seconds)))
                        } else {
                            None
                        }
                    }
                    "priority" => {
                        if let Ok(priority) = value.parse::<u8>() {
                            Some(MetadataField::Priority(priority))
                        } else {
                            None
                        }
                    }
                    "requires_root" => {
                        Some(MetadataField::RequiresRoot(value.to_lowercase() == "true"))
                    }
                    "call_format" => Some(MetadataField::CallFormat(value.to_string())),
                    "port_separator" => Some(MetadataField::PortSeparator(value.to_string())),
                    _ => None,
                };
            }
        }

        None
    }

    /// Validate script configuration
    fn validate_script(script: &ScriptFile) -> Result<()> {
        // Check if script file exists and is executable
        if !script.path.exists() {
            return Err(ScanError::ConfigError(format!(
                "Script file does not exist: {:?}",
                script.path
            )));
        }

        // Check if interpreter is available (if needed)
        if let Some(interpreter) = script.language.interpreter() {
            if !Self::is_command_available(interpreter) {
                warn!(
                    "Interpreter '{}' not found for script '{}'",
                    interpreter, script.name
                );
            }
        }

        // Validate call format
        if script.call_format.is_empty() {
            return Err(ScanError::ConfigError(
                "Script call format cannot be empty".to_string(),
            ));
        }

        // Validate priority
        if script.priority > 10 {
            return Err(ScanError::ConfigError(
                "Script priority must be between 0 and 10".to_string(),
            ));
        }

        // Validate timeout
        if script.timeout.as_secs() == 0 {
            return Err(ScanError::ConfigError(
                "Script timeout must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if a command is available in PATH
    fn is_command_available(command: &str) -> bool {
        std::process::Command::new("which")
            .arg(command)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Discover and parse all scripts in a directory
    pub fn discover_scripts(directory: &PathBuf) -> Result<Vec<ScriptFile>> {
        let mut scripts = Vec::new();
        
        if !directory.exists() {
            return Ok(scripts);
        }

        let entries = std::fs::read_dir(directory)
            .map_err(|e| ScanError::ConfigError(format!("Failed to read directory: {}", e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| ScanError::ConfigError(format!("Failed to read entry: {}", e)))?;
            let path = entry.path();

            if path.is_file() {
                match Self::parse_script_file(&path) {
                    Ok(script) => {
                        debug!("Discovered script: {}", script.name);
                        scripts.push(script);
                    }
                    Err(e) => {
                        warn!("Failed to parse script {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(scripts)
    }

    /// Validate script configuration
    pub fn validate_config(config: &ScriptConfig) -> Result<()> {
        // Check directories exist
        for dir in &config.directories {
            if !dir.exists() {
                warn!("Script directory does not exist: {:?}", dir);
            }
        }

        // Validate timeout
        if config.timeout.as_secs() == 0 {
            return Err(ScanError::ConfigError(
                "Global script timeout must be greater than 0".to_string(),
            ));
        }

        // Validate max concurrent
        if config.max_concurrent == 0 {
            return Err(ScanError::ConfigError(
                "Max concurrent scripts must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}

/// TOML configuration structure
#[derive(Debug, Deserialize)]
struct ScriptConfigToml {
    directories: Option<Vec<String>>,
    tags: Option<Vec<String>>,
    ports: Option<Vec<u16>>,
    max_concurrent: Option<usize>,
    timeout: Option<u64>,
    nmap_integration: Option<bool>,
    nmap_args: Option<Vec<String>>,
    mode: Option<String>,
}

impl From<ScriptConfigToml> for ScriptConfig {
    fn from(toml_config: ScriptConfigToml) -> Self {
        let mode = toml_config.mode
            .as_deref()
            .and_then(|s| match s.to_lowercase().as_str() {
                "none" => Some(ScriptMode::None),
                "default" => Some(ScriptMode::Default),
                "custom" => Some(ScriptMode::Custom),
                "all" => Some(ScriptMode::All),
                "adaptive" => Some(ScriptMode::Adaptive),
                _ => None,
            })
            .unwrap_or(ScriptMode::Default);

        ScriptConfig {
            directories: toml_config.directories
                .unwrap_or_default()
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            tags: toml_config.tags,
            ports: toml_config.ports,
            max_concurrent: toml_config.max_concurrent.unwrap_or(10),
            timeout: Duration::from_secs(toml_config.timeout.unwrap_or(300)),
            nmap_integration: toml_config.nmap_integration.unwrap_or(true),
            nmap_args: toml_config.nmap_args.unwrap_or_else(|| vec!["-sV".to_string(), "-sC".to_string()]),
            mode,
        }
    }
}

/// Embedded metadata structure
#[derive(Debug, Default)]
struct EmbeddedMetadata {
    description: Option<String>,
    tags: Vec<String>,
    ports: Option<Vec<u16>>,
    timeout: Option<Duration>,
    priority: Option<u8>,
    requires_root: Option<bool>,
    call_format: String,
    port_separator: String,
}

impl EmbeddedMetadata {
    fn merge_from_json(&mut self, json: JsonMetadata) {
        if let Some(desc) = json.description {
            self.description = Some(desc);
        }
        if !json.tags.is_empty() {
            self.tags = json.tags;
        }
        if let Some(ports) = json.ports {
            self.ports = Some(ports);
        }
        if let Some(timeout) = json.timeout {
            self.timeout = Some(Duration::from_secs(timeout));
        }
        if let Some(priority) = json.priority {
            self.priority = Some(priority);
        }
        if let Some(requires_root) = json.requires_root {
            self.requires_root = Some(requires_root);
        }
        if let Some(call_format) = json.call_format {
            self.call_format = call_format;
        }
        if let Some(port_separator) = json.port_separator {
            self.port_separator = port_separator;
        }
    }

    fn merge_from_toml(&mut self, toml: TomlMetadata) {
        if let Some(desc) = toml.description {
            self.description = Some(desc);
        }
        if let Some(tags) = toml.tags {
            self.tags = tags;
        }
        if let Some(ports) = toml.ports {
            self.ports = Some(ports);
        }
        if let Some(timeout) = toml.timeout {
            self.timeout = Some(Duration::from_secs(timeout));
        }
        if let Some(priority) = toml.priority {
            self.priority = Some(priority);
        }
        if let Some(requires_root) = toml.requires_root {
            self.requires_root = Some(requires_root);
        }
        if let Some(call_format) = toml.call_format {
            self.call_format = call_format;
        }
        if let Some(port_separator) = toml.port_separator {
            self.port_separator = port_separator;
        }
    }
}

/// JSON metadata structure
#[derive(Debug, Deserialize)]
struct JsonMetadata {
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    ports: Option<Vec<u16>>,
    timeout: Option<u64>,
    priority: Option<u8>,
    requires_root: Option<bool>,
    call_format: Option<String>,
    port_separator: Option<String>,
}

/// TOML metadata structure
#[derive(Debug, Deserialize)]
struct TomlMetadata {
    description: Option<String>,
    tags: Option<Vec<String>>,
    ports: Option<Vec<u16>>,
    timeout: Option<u64>,
    priority: Option<u8>,
    requires_root: Option<bool>,
    call_format: Option<String>,
    port_separator: Option<String>,
}

/// Metadata field enumeration
#[derive(Debug)]
enum MetadataField {
    Description(String),
    Tags(Vec<String>),
    Ports(Vec<u16>),
    Timeout(Duration),
    Priority(u8),
    RequiresRoot(bool),
    CallFormat(String),
    PortSeparator(String),
}