//! Script Engine - Core execution engine for running scripts

use super::*;
use crate::{Result, ScanError};
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

/// Main script execution engine
pub struct ScriptEngine {
    config: ScriptConfig,
    scripts: Vec<ScriptFile>,
    stats: Arc<Mutex<ScriptStats>>,
    semaphore: Arc<Semaphore>,
}

impl ScriptEngine {
    /// Create a new script engine with configuration
    pub fn new(config: ScriptConfig) -> Result<Self> {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        let scripts = Self::discover_scripts(&config)?;
        
        info!("Initialized script engine with {} scripts", scripts.len());
        debug!("Available scripts: {:?}", scripts.iter().map(|s| &s.name).collect::<Vec<_>>());

        Ok(Self {
            config,
            scripts,
            stats: Arc::new(Mutex::new(ScriptStats::new())),
            semaphore,
        })
    }

    /// Discover available scripts in configured directories
    fn discover_scripts(config: &ScriptConfig) -> Result<Vec<ScriptFile>> {
        let mut scripts = Vec::new();

        for dir in &config.directories {
            if !dir.exists() {
                warn!("Script directory does not exist: {:?}", dir);
                continue;
            }

            let entries = std::fs::read_dir(dir)
                .map_err(|e| ScanError::ConfigError(format!("Failed to read script directory: {}", e)))?;

            for entry in entries {
                let entry = entry.map_err(|e| ScanError::ConfigError(format!("Failed to read directory entry: {}", e)))?;
                let path = entry.path();

                if path.is_file() {
                    match ScriptFile::from_path(path.clone()) {
                        Ok(mut script) => {
                            // Try to parse script metadata from file content
                            if let Ok(metadata) = Self::parse_script_metadata(&path) {
                                script.description = metadata.description;
                                script.tags = metadata.tags;
                                script.ports = metadata.ports;
                                script.timeout = metadata.timeout.unwrap_or(script.timeout);
                                script.priority = metadata.priority.unwrap_or(script.priority);
                                script.requires_root = metadata.requires_root.unwrap_or(script.requires_root);
                            }
                            scripts.push(script);
                        }
                        Err(e) => {
                            warn!("Failed to create script from path {:?}: {}", path, e);
                        }
                    }
                }
            }
        }

        // Sort scripts by priority (higher first)
        scripts.sort_by(|a, b| b.priority.cmp(&a.priority));

        Ok(scripts)
    }

    /// Parse script metadata from file comments/headers
    fn parse_script_metadata(path: &PathBuf) -> Result<ScriptMetadata> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ScanError::ConfigError(format!("Failed to read script file: {}", e)))?;

        let mut metadata = ScriptMetadata::default();
        
        // Parse metadata from comments (supports multiple comment styles)
        for line in content.lines().take(50) { // Only check first 50 lines
            let line = line.trim();
            
            // Skip empty lines
            if line.is_empty() {
                continue;
            }

            // Check for different comment styles
            let comment_content = if line.starts_with("#") {
                Some(&line[1..])
            } else if line.starts_with("//") {
                Some(&line[2..])
            } else if line.starts_with("--") {
                Some(&line[2..])
            } else {
                None
            };

            if let Some(content) = comment_content {
                let content = content.trim();
                
                if content.starts_with("@description:") {
                    metadata.description = Some(content[13..].trim().to_string());
                } else if content.starts_with("@tags:") {
                    metadata.tags = content[6..]
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                } else if content.starts_with("@ports:") {
                    let ports: Result<Vec<u16>> = content[7..]
                        .split(',')
                        .map(|s| s.trim().parse::<u16>().map_err(ScanError::from))
                        .collect();
                    if let Ok(ports) = ports {
                        metadata.ports = Some(ports);
                    }
                } else if content.starts_with("@timeout:") {
                    if let Ok(seconds) = content[9..].trim().parse::<u64>() {
                        metadata.timeout = Some(Duration::from_secs(seconds));
                    }
                } else if content.starts_with("@priority:") {
                    if let Ok(priority) = content[10..].trim().parse::<u8>() {
                        metadata.priority = Some(priority);
                    }
                } else if content.starts_with("@requires_root:") {
                    metadata.requires_root = Some(content[15..].trim().to_lowercase() == "true");
                }
            }
        }

        Ok(metadata)
    }

    /// Execute scripts for given target and ports
    pub async fn execute_scripts(
        &self,
        target: IpAddr,
        port_results: &[PortResult],
    ) -> Result<Vec<ScriptResult>> {
        let open_ports: Vec<u16> = port_results
            .iter()
            .filter(|pr| pr.state == PortState::Open)
            .map(|pr| pr.port)
            .collect();

        if open_ports.is_empty() {
            debug!("No open ports found for {}, skipping script execution", target);
            return Ok(Vec::new());
        }

        info!("Executing scripts for {} with {} open ports", target, open_ports.len());

        let filtered_scripts = self.filter_scripts(&open_ports);
        if filtered_scripts.is_empty() {
            debug!("No matching scripts found for target {}", target);
            return Ok(Vec::new());
        }

        info!("Running {} scripts for target {}", filtered_scripts.len(), target);

        let mut results = Vec::new();
        let mut handles = Vec::new();

        for script in filtered_scripts {
            let script_ports = if let Some(ref script_specific_ports) = script.ports {
                open_ports
                    .iter()
                    .filter(|&&port| script_specific_ports.contains(&port))
                    .copied()
                    .collect()
            } else {
                open_ports.clone()
            };

            if script_ports.is_empty() {
                continue;
            }

            let semaphore = Arc::clone(&self.semaphore);
            let stats = Arc::clone(&self.stats);
            let script_clone = script.clone();
            let timeout_duration = script.timeout;

            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                let result = timeout(
                    timeout_duration,
                    Self::execute_single_script(script_clone, target, &script_ports)
                ).await;

                let script_result = match result {
                    Ok(Ok(result)) => result,
                    Ok(Err(e)) => ScriptResult {
                        script_name: script.name.clone(),
                        target,
                        ports: script_ports,
                        output: String::new(),
                        error: Some(e.to_string()),
                        execution_time: Duration::from_secs(0),
                        exit_code: None,
                        success: false,
                    },
                    Err(_) => ScriptResult {
                        script_name: script.name.clone(),
                        target,
                        ports: script_ports,
                        output: String::new(),
                        error: Some("Script execution timed out".to_string()),
                        execution_time: timeout_duration,
                        exit_code: None,
                        success: false,
                    },
                };

                // Update statistics
                {
                    let mut stats_guard = stats.lock().await;
                    stats_guard.add_result(&script_result);
                }

                script_result
            });

            handles.push(handle);
        }

        // Wait for all scripts to complete
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => error!("Script execution task failed: {}", e),
            }
        }

        info!("Completed script execution for {}: {} results", target, results.len());
        Ok(results)
    }

    /// Execute a single script
    async fn execute_single_script(
        script: ScriptFile,
        target: IpAddr,
        ports: &[u16],
    ) -> Result<ScriptResult> {
        let start_time = Instant::now();
        
        debug!("Executing script '{}' for {} with ports {:?}", script.name, target, ports);

        let command_parts = script.generate_command(target, ports)?;
        if command_parts.is_empty() {
            return Err(ScanError::ConfigError("Empty command generated".to_string()));
        }

        let mut cmd = AsyncCommand::new(&command_parts[0]);
        if command_parts.len() > 1 {
            cmd.args(&command_parts[1..]);
        }

        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = cmd.output().await
            .map_err(|e| ScanError::NetworkError(format!("Failed to execute script: {}", e)))?;

        let execution_time = start_time.elapsed();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let success = output.status.success();
        let exit_code = output.status.code();

        let error = if !stderr.is_empty() && !success {
            Some(stderr)
        } else {
            None
        };

        debug!(
            "Script '{}' completed in {:?} with exit code {:?}",
            script.name, execution_time, exit_code
        );

        Ok(ScriptResult {
            script_name: script.name,
            target,
            ports: ports.to_vec(),
            output: stdout,
            error,
            execution_time,
            exit_code,
            success,
        })
    }

    /// Filter scripts based on configuration and criteria
    fn filter_scripts(&self, ports: &[u16]) -> Vec<ScriptFile> {
        let mut filtered = Vec::new();

        for script in &self.scripts {
            // Check if script matches configuration criteria
            let tags = self.config.tags.as_deref().unwrap_or(&[]);
            
            if script.matches(tags, ports) {
                filtered.push(script.clone());
            }
        }

        filtered
    }

    /// Get current script statistics
    pub async fn get_stats(&self) -> ScriptStats {
        self.stats.lock().await.clone()
    }

    /// Get list of available scripts
    pub fn get_available_scripts(&self) -> &[ScriptFile] {
        &self.scripts
    }
}

/// Script metadata parsed from file headers
#[derive(Debug, Default)]
struct ScriptMetadata {
    description: Option<String>,
    tags: Vec<String>,
    ports: Option<Vec<u16>>,
    timeout: Option<Duration>,
    priority: Option<u8>,
    requires_root: Option<bool>,
}