//! Script Executor - Execute scripts with proper isolation and resource management

use super::*;
use crate::{Result, ScanError};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as AsyncCommand;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{timeout, Duration};

/// Script execution context
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub target: String,
    pub ports: Vec<u16>,
    pub scan_results: HashMap<u16, String>,
    pub environment: HashMap<String, String>,
    pub working_directory: PathBuf,
    pub timeout: Duration,
    pub max_output_size: usize,
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self {
            target: String::new(),
            ports: Vec::new(),
            scan_results: HashMap::new(),
            environment: HashMap::new(),
            working_directory: PathBuf::from("."),
            timeout: Duration::from_secs(300),
            max_output_size: 1024 * 1024, // 1MB
        }
    }
}

/// Script executor with resource management
pub struct ScriptExecutor {
    semaphore: Arc<Semaphore>,
    running_scripts: Arc<AtomicUsize>,
    cancelled: Arc<AtomicBool>,
    stats: Arc<Mutex<ExecutionStats>>,
}

impl ScriptExecutor {
    /// Create new script executor
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            running_scripts: Arc::new(AtomicUsize::new(0)),
            cancelled: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Mutex::new(ExecutionStats::default())),
        }
    }

    /// Execute a single script
    pub async fn execute_script(
        &self,
        script: &ScriptFile,
        context: &ExecutionContext,
    ) -> Result<ScriptResult> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(ScanError::NetworkError("Execution cancelled".to_string()));
        }

        let _permit = self.semaphore.acquire().await
            .map_err(|e| ScanError::NetworkError(format!("Failed to acquire semaphore: {}", e)))?;

        self.running_scripts.fetch_add(1, Ordering::Relaxed);
        let start_time = Instant::now();

        let result = self.execute_script_internal(script, context).await;

        let duration = start_time.elapsed();
        self.running_scripts.fetch_sub(1, Ordering::Relaxed);

        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.total_executed += 1;
        stats.total_duration += duration;

        match &result {
            Ok(_) => stats.successful += 1,
            Err(_) => stats.failed += 1,
        }

        if duration > stats.max_duration {
            stats.max_duration = duration;
        }

        if stats.min_duration.is_zero() || duration < stats.min_duration {
            stats.min_duration = duration;
        }

        result
    }

    /// Internal script execution logic
    async fn execute_script_internal(
        &self,
        script: &ScriptFile,
        context: &ExecutionContext,
    ) -> Result<ScriptResult> {
        debug!("Executing script: {} for target: {}", script.name, context.target);

        // Check if script should run for these ports
        if let Some(script_ports) = &script.ports {
            let has_matching_port = context.ports.iter().any(|p| script_ports.contains(p));
            if !has_matching_port {
                debug!("Script {} skipped - no matching ports", script.name);
                return Ok(ScriptResult {
                    script_name: script.name.clone(),
                    target: context.target.parse().unwrap_or("127.0.0.1".parse().unwrap()),
                    ports: Vec::new(),
                    output: "Skipped - no matching ports".to_string(),
                    error: None,
                    execution_time: Duration::from_millis(0),
                    exit_code: Some(0),
                    success: true,
                });
            }
        }

        // Build command
        let mut command = self.build_command(script, context)?;

        // Set up execution environment
        self.setup_execution_environment(&mut command, context);

        // Execute with timeout
        let execution_timeout = script.timeout.min(context.timeout);
        let execution_result = timeout(execution_timeout, self.run_command(command, script.name.clone(), context)).await;

        match execution_result {
            Ok(result) => result,
            Err(_) => {
                warn!("Script {} timed out after {:?}", script.name, execution_timeout);
                Ok(ScriptResult {
                    script_name: script.name.clone(),
                    target: context.target.parse().unwrap_or("127.0.0.1".parse().unwrap()),
                    ports: context.ports.clone(),
                    output: String::new(),
                    error: Some(format!("Script timed out after {:?}", execution_timeout)),
                    execution_time: execution_timeout,
                    exit_code: None,
                    success: false,
                })
            }
        }
    }

    /// Build command from script and context
    fn build_command(&self, script: &ScriptFile, context: &ExecutionContext) -> Result<AsyncCommand> {
        let mut command_parts = Vec::new();

        // Add interpreter if needed
        if let Some(interpreter) = script.language.interpreter() {
            command_parts.push(interpreter.to_string());
        }

        // Add script path
        command_parts.push(script.path.to_string_lossy().to_string());

        // Parse call format and substitute variables
        let call_format = self.substitute_variables(&script.call_format, context, script)?;
        let format_parts: Vec<&str> = call_format.split_whitespace().collect();
        command_parts.extend(format_parts.iter().map(|s| s.to_string()));

        if command_parts.is_empty() {
            return Err(ScanError::ConfigError("Empty command".to_string()));
        }

        let mut command = AsyncCommand::new(&command_parts[0]);
        if command_parts.len() > 1 {
            command.args(&command_parts[1..]);
        }

        Ok(command)
    }

    /// Substitute variables in call format
    fn substitute_variables(
        &self,
        format: &str,
        context: &ExecutionContext,
        script: &ScriptFile,
    ) -> Result<String> {
        let mut result = format.to_string();

        // Basic substitutions
        result = result.replace("{target}", &context.target);
        result = result.replace("{script}", &script.path.to_string_lossy());

        // Port substitutions
        if result.contains("{ports}") {
            let ports_str = context.ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(&script.port_separator);
            result = result.replace("{ports}", &ports_str);
        }

        if result.contains("{port}") {
            if let Some(first_port) = context.ports.first() {
                result = result.replace("{port}", &first_port.to_string());
            } else {
                result = result.replace("{port}", "80");
            }
        }

        // Environment variable substitutions
        for (key, value) in &context.environment {
            let placeholder = format!("{{{}}}", key);
            result = result.replace(&placeholder, value);
        }

        // Working directory
        result = result.replace("{workdir}", &context.working_directory.to_string_lossy());

        Ok(result)
    }

    /// Setup execution environment
    fn setup_execution_environment(&self, command: &mut AsyncCommand, context: &ExecutionContext) {
        // Set working directory
        command.current_dir(&context.working_directory);

        // Set environment variables
        for (key, value) in &context.environment {
            command.env(key, value);
        }

        // Set standard I/O
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.stdin(Stdio::null());

        // Security: Clear sensitive environment variables
        command.env_remove("HOME");
        command.env_remove("USER");
        command.env_remove("PATH"); // Will be set explicitly if needed
    }

    /// Run command and capture output
    async fn run_command(&self, mut command: AsyncCommand, script_name: String, context: &ExecutionContext) -> Result<ScriptResult> {
        let start_time = Instant::now();

        let mut child = command.spawn()
            .map_err(|e| ScanError::NetworkError(format!("Failed to spawn process: {}", e)))?;

        let stdout = child.stdout.take()
            .ok_or_else(|| ScanError::NetworkError("Failed to capture stdout".to_string()))?;
        let stderr = child.stderr.take()
            .ok_or_else(|| ScanError::NetworkError("Failed to capture stderr".to_string()))?;

        // Read output streams concurrently
        let stdout_reader = BufReader::new(stdout);
        let stderr_reader = BufReader::new(stderr);

        let (stdout_result, stderr_result) = tokio::join!(
            self.read_stream_with_limit(stdout_reader, "stdout"),
            self.read_stream_with_limit(stderr_reader, "stderr")
        );

        let stdout_output = stdout_result.unwrap_or_else(|e| {
            warn!("Failed to read stdout: {}", e);
            String::new()
        });

        let stderr_output = stderr_result.unwrap_or_else(|e| {
            warn!("Failed to read stderr: {}", e);
            String::new()
        });

        // Wait for process to complete
        let exit_status = child.wait().await
            .map_err(|e| ScanError::NetworkError(format!("Failed to wait for process: {}", e)))?;

        let duration = start_time.elapsed();
        let success = exit_status.success();
        let exit_code = exit_status.code();

        let output = if !stdout_output.is_empty() {
            stdout_output
        } else {
            stderr_output.clone()
        };

        let error = if !success && !stderr_output.is_empty() {
            Some(stderr_output)
        } else {
            None
        };

        Ok(ScriptResult {
            script_name,
            target: context.target.parse().unwrap_or("127.0.0.1".parse().unwrap()),
            ports: context.ports.clone(),
            output,
            error,
            execution_time: duration,
            exit_code,
            success,
        })
    }

    /// Read stream with size limit
    async fn read_stream_with_limit<R>(
        &self,
        mut reader: BufReader<R>,
        stream_name: &str,
    ) -> Result<String>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut output = String::new();
        let mut line = String::new();
        let max_size = 1024 * 1024; // 1MB limit

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await
                .map_err(|e| ScanError::NetworkError(format!("Failed to read {}: {}", stream_name, e)))?;

            if bytes_read == 0 {
                break; // EOF
            }

            if output.len() + line.len() > max_size {
                output.push_str("\n[OUTPUT TRUNCATED - SIZE LIMIT EXCEEDED]\n");
                break;
            }

            output.push_str(&line);
        }

        Ok(output)
    }

    /// Execute multiple scripts concurrently
    pub async fn execute_scripts(
        &self,
        scripts: &[ScriptFile],
        context: &ExecutionContext,
    ) -> Vec<Result<ScriptResult>> {
        let mut handles = Vec::new();

        for script in scripts {
            let executor = self.clone();
            let script = script.clone();
            let context = context.clone();

            let handle = tokio::spawn(async move {
                executor.execute_script(&script, &context).await
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(ScanError::NetworkError(format!("Task join error: {}", e)))),
            }
        }

        results
    }

    /// Cancel all running scripts
    pub async fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
        info!("Script execution cancelled");
    }

    /// Get current execution statistics
    pub async fn get_stats(&self) -> ExecutionStats {
        self.stats.lock().await.clone()
    }

    /// Get number of currently running scripts
    pub fn running_count(&self) -> usize {
        self.running_scripts.load(Ordering::Relaxed)
    }

    /// Check if executor is cancelled
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

impl Clone for ScriptExecutor {
    fn clone(&self) -> Self {
        Self {
            semaphore: Arc::clone(&self.semaphore),
            running_scripts: Arc::clone(&self.running_scripts),
            cancelled: Arc::clone(&self.cancelled),
            stats: Arc::clone(&self.stats),
        }
    }
}

/// Execution statistics
#[derive(Debug, Clone, Default)]
pub struct ExecutionStats {
    pub total_executed: usize,
    pub successful: usize,
    pub failed: usize,
    pub total_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
}

impl ExecutionStats {
    /// Calculate average execution time
    pub fn average_duration(&self) -> Duration {
        if self.total_executed > 0 {
            self.total_duration / self.total_executed as u32
        } else {
            Duration::from_secs(0)
        }
    }

    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_executed > 0 {
            self.successful as f64 / self.total_executed as f64
        } else {
            0.0
        }
    }

    /// Reset statistics
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Script execution builder for easier configuration
pub struct ExecutionBuilder {
    context: ExecutionContext,
}

impl ExecutionBuilder {
    pub fn new() -> Self {
        Self {
            context: ExecutionContext::default(),
        }
    }

    pub fn target<S: Into<String>>(mut self, target: S) -> Self {
        self.context.target = target.into();
        self
    }

    pub fn ports(mut self, ports: Vec<u16>) -> Self {
        self.context.ports = ports;
        self
    }

    pub fn environment(mut self, env: HashMap<String, String>) -> Self {
        self.context.environment = env;
        self
    }

    pub fn working_directory<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.context.working_directory = dir.into();
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.context.timeout = timeout;
        self
    }

    pub fn max_output_size(mut self, size: usize) -> Self {
        self.context.max_output_size = size;
        self
    }

    pub fn build(self) -> ExecutionContext {
        self.context
    }
}

impl Default for ExecutionBuilder {
    fn default() -> Self {
        Self::new()
    }
}