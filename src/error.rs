//! Error handling for the phobos scanner
//!
//! This module provides comprehensive error handling with graceful degradation
//! and retry mechanisms for robust scanning operations.

use thiserror::Error;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Main error type for scanning operations
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Permission denied: {0}")]
    PermissionError(String),
    
    #[error("Invalid target: {0}")]
    InvalidTarget(String),
    
    #[error("Port range error: {0}")]
    PortRangeError(String),
    
    #[error("Timeout error")]
    TimeoutError,
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Rate limit exceeded")]
    RateLimitError,
    
    #[error("Raw socket error: {0}")]
    RawSocketError(String),
    
    #[error("Service detection error: {0}")]
    ServiceDetectionError(String),
    
    #[error("Stealth operation failed: {0}")]
    StealthError(String),
    
    #[error("Output error: {0}")]
    OutputError(String),
}

/// Result type alias for scan operations
pub type ScanResult<T> = Result<T, ScanError>;

/// Error recovery strategies
#[derive(Debug, Clone)]
pub enum RecoveryStrategy {
    /// Retry the operation with the same parameters
    Retry,
    /// Fall back to a different scan technique
    Fallback(crate::network::ScanTechnique),
    /// Skip this target/port and continue
    Skip,
    /// Abort the entire scan
    Abort,
    /// Wait and retry with circuit breaker
    CircuitBreakerWait(Duration),
}

/// Circuit breaker states
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker for protecting services from cascading failures
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    state: Arc<RwLock<CircuitBreakerState>>,
    failure_count: Arc<RwLock<u32>>,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
    failure_threshold: u32,
    recovery_timeout: Duration,
    success_threshold: u32,
    half_open_success_count: Arc<RwLock<u32>>,
}

/// Error metrics for monitoring and alerting
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorMetrics {
    pub total_errors: u64,
    pub network_errors: u64,
    pub timeout_errors: u64,
    pub permission_errors: u64,
    pub rate_limit_errors: u64,
    pub recovery_attempts: u64,
    pub successful_recoveries: u64,
    pub circuit_breaker_trips: u64,
}

/// Error handler for managing recoverable errors with circuit breaker
pub struct ErrorHandler {
    max_retries: usize,
    retry_delay_ms: u64,
    fallback_enabled: bool,
    circuit_breaker: CircuitBreaker,
    metrics: Arc<RwLock<ErrorMetrics>>,
    error_history: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
}

impl Default for ErrorHandler {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay_ms: 1000,
            fallback_enabled: true,
            circuit_breaker: CircuitBreaker::new(5, Duration::from_secs(30), 2),
            metrics: Arc::new(RwLock::new(ErrorMetrics::default())),
            error_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(failure_threshold: u32, recovery_timeout: Duration, success_threshold: u32) -> Self {
        Self {
            state: Arc::new(RwLock::new(CircuitBreakerState::Closed)),
            failure_count: Arc::new(RwLock::new(0)),
            last_failure_time: Arc::new(RwLock::new(None)),
            failure_threshold,
            recovery_timeout,
            success_threshold,
            half_open_success_count: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Check if the circuit breaker allows the operation
    pub async fn can_execute(&self) -> bool {
        let state = self.state.read().await;
        match *state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                drop(state);
                self.check_recovery_timeout().await
            }
            CircuitBreakerState::HalfOpen => true,
        }
    }
    
    /// Record a successful operation
    pub async fn record_success(&self) {
        let mut state = self.state.write().await;
        match *state {
            CircuitBreakerState::HalfOpen => {
                let mut success_count = self.half_open_success_count.write().await;
                *success_count += 1;
                if *success_count >= self.success_threshold {
                    *state = CircuitBreakerState::Closed;
                    *self.failure_count.write().await = 0;
                    *success_count = 0;
                }
            }
            CircuitBreakerState::Closed => {
                *self.failure_count.write().await = 0;
            }
            _ => {}
        }
    }
    
    /// Record a failed operation
    pub async fn record_failure(&self) {
        let mut failure_count = self.failure_count.write().await;
        *failure_count += 1;
        *self.last_failure_time.write().await = Some(Instant::now());
        
        if *failure_count >= self.failure_threshold {
            let mut state = self.state.write().await;
            *state = CircuitBreakerState::Open;
            *self.half_open_success_count.write().await = 0;
        }
    }
    
    /// Check if recovery timeout has passed and transition to half-open
    async fn check_recovery_timeout(&self) -> bool {
        let last_failure = self.last_failure_time.read().await;
        if let Some(last_time) = *last_failure {
            if last_time.elapsed() >= self.recovery_timeout {
                drop(last_failure);
                let mut state = self.state.write().await;
                *state = CircuitBreakerState::HalfOpen;
                return true;
            }
        }
        false
    }
    
    /// Get current circuit breaker state
    pub async fn get_state(&self) -> CircuitBreakerState {
        self.state.read().await.clone()
    }
}

impl ErrorHandler {
    /// Create a new error handler with custom settings
    pub fn new(max_retries: usize, retry_delay_ms: u64, fallback_enabled: bool) -> Self {
        Self {
            max_retries,
            retry_delay_ms,
            fallback_enabled,
            circuit_breaker: CircuitBreaker::new(5, Duration::from_secs(30), 2),
            metrics: Arc::new(RwLock::new(ErrorMetrics::default())),
            error_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Determine the recovery strategy for a given error with circuit breaker integration
    pub async fn get_recovery_strategy(&self, error: &ScanError, attempt: usize) -> RecoveryStrategy {
        // Update metrics
        self.update_error_metrics(error).await;
        
        // Check circuit breaker state
        if !self.circuit_breaker.can_execute().await {
            return RecoveryStrategy::CircuitBreakerWait(Duration::from_secs(5));
        }
        
        match error {
            ScanError::NetworkError(_) | ScanError::TimeoutError => {
                self.circuit_breaker.record_failure().await;
                if attempt < self.max_retries {
                    RecoveryStrategy::Retry
                } else if self.fallback_enabled {
                    RecoveryStrategy::Fallback(crate::network::ScanTechnique::Connect)
                } else {
                    RecoveryStrategy::Skip
                }
            }
            ScanError::PermissionError(_) | ScanError::RawSocketError(_) => {
                if self.fallback_enabled {
                    RecoveryStrategy::Fallback(crate::network::ScanTechnique::Connect)
                } else {
                    RecoveryStrategy::Abort
                }
            }
            ScanError::RateLimitError => {
                self.circuit_breaker.record_failure().await;
                RecoveryStrategy::CircuitBreakerWait(Duration::from_millis(self.retry_delay_ms * 2))
            }
            ScanError::InvalidTarget(_) | ScanError::PortRangeError(_) | ScanError::ConfigError(_) => {
                RecoveryStrategy::Abort
            }
            _ => RecoveryStrategy::Skip,
        }
    }
    
    /// Update error metrics based on error type
    async fn update_error_metrics(&self, error: &ScanError) {
        let mut metrics = self.metrics.write().await;
        metrics.total_errors += 1;
        
        match error {
            ScanError::NetworkError(_) => metrics.network_errors += 1,
            ScanError::TimeoutError => metrics.timeout_errors += 1,
            ScanError::PermissionError(_) => metrics.permission_errors += 1,
            ScanError::RateLimitError => metrics.rate_limit_errors += 1,
            _ => {}
        }
    }
    
    /// Record successful recovery
    pub async fn record_recovery_success(&self) {
        self.circuit_breaker.record_success().await;
        let mut metrics = self.metrics.write().await;
        metrics.successful_recoveries += 1;
    }
    
    /// Record recovery attempt
    pub async fn record_recovery_attempt(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.recovery_attempts += 1;
    }
    
    /// Get current error metrics
    pub async fn get_metrics(&self) -> ErrorMetrics {
        self.metrics.read().await.clone()
    }
    
    /// Check if error rate is too high for a specific target
    pub async fn is_error_rate_high(&self, target: &str) -> bool {
        let history = self.error_history.read().await;
        if let Some(errors) = history.get(target) {
            let recent_errors = errors.iter()
                .filter(|&&time| time.elapsed() < Duration::from_secs(60))
                .count();
            recent_errors > 10 // More than 10 errors in the last minute
        } else {
            false
        }
    }
    
    /// Record error for a specific target
    pub async fn record_target_error(&self, target: &str) {
        let mut history = self.error_history.write().await;
        history.entry(target.to_string())
            .or_insert_with(Vec::new)
            .push(Instant::now());
        
        // Clean old entries (older than 5 minutes)
        if let Some(errors) = history.get_mut(target) {
            errors.retain(|&time| time.elapsed() < Duration::from_secs(300));
        }
    }
    
    /// Calculate retry delay with exponential backoff
    pub fn get_retry_delay(&self, attempt: usize) -> u64 {
        let base_delay = self.retry_delay_ms;
        let exponential_delay = base_delay.saturating_mul(
            2_u64.saturating_pow(attempt.min(10) as u32)
        );
        std::cmp::min(exponential_delay, 30000) // Cap at 30 seconds
    }
    
    /// Check if an error is recoverable
    pub fn is_recoverable(&self, error: &ScanError) -> bool {
        matches!(
            error,
            ScanError::NetworkError(_)
                | ScanError::TimeoutError
                | ScanError::RateLimitError
                | ScanError::PermissionError(_)
                | ScanError::RawSocketError(_)
        )
    }
}

/// Graceful degradation handler
pub struct GracefulDegradation {
    fallback_techniques: Vec<crate::network::ScanTechnique>,
    current_index: usize,
}

impl Default for GracefulDegradation {
    fn default() -> Self {
        Self {
            fallback_techniques: vec![
                crate::network::ScanTechnique::Syn,
                crate::network::ScanTechnique::Connect,
                crate::network::ScanTechnique::Ack,
            ],
            current_index: 0,
        }
    }
}

impl GracefulDegradation {
    /// Create a new graceful degradation handler with custom fallback order
    pub fn new(techniques: Vec<crate::network::ScanTechnique>) -> Self {
        Self {
            fallback_techniques: techniques,
            current_index: 0,
        }
    }
    
    /// Get the next fallback technique
    pub fn next_technique(&mut self) -> Option<crate::network::ScanTechnique> {
        if self.current_index < self.fallback_techniques.len() {
            let technique = self.fallback_techniques[self.current_index].clone();
            self.current_index += 1;
            Some(technique)
        } else {
            None
        }
    }
    
    /// Reset to the first technique
    pub fn reset(&mut self) {
        self.current_index = 0;
    }
    
    /// Check if there are more fallback techniques available
    pub fn has_fallback(&self) -> bool {
        self.current_index < self.fallback_techniques.len()
    }
}

/// Maximum retry attempts before giving up
const MAX_RETRY_ATTEMPTS: usize = 5;

/// Scan with automatic fallback and circuit breaker protection
pub async fn scan_with_fallback(
    target: &str,
    ports: &[u16],
    technique: crate::network::ScanTechnique,
    config: &crate::config::ScanConfig,
) -> ScanResult<Vec<crate::scanner::ScanResult>> {
    let mut degradation = GracefulDegradation::default();
    let error_handler = ErrorHandler::default();
    let mut attempt = 0;
    
    // Check if error rate is too high for this target
    if error_handler.is_error_rate_high(target).await {
        eprintln!("Warning: High error rate detected for target {}, applying rate limiting", target);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    
    // Try the requested technique first with retry logic
    loop {
        match perform_scan_with_technique(target, ports, technique, config).await {
            Ok(results) => {
                error_handler.record_recovery_success().await;
                return Ok(results);
            }
            Err(e) => {
                error_handler.record_target_error(target).await;
                error_handler.record_recovery_attempt().await;
                
                let strategy = error_handler.get_recovery_strategy(&e, attempt).await;
                match strategy {
                    RecoveryStrategy::Retry => {
                        // Check if we've exceeded max retry attempts
                        if attempt >= MAX_RETRY_ATTEMPTS {
                            eprintln!("Max retry attempts ({}) reached for {} scan, switching to fallback", 
                                     MAX_RETRY_ATTEMPTS, technique.name());
                            error_handler.record_recovery_attempt().await;
                            error_handler.record_target_error(target).await;
                            break; // Switch to fallback techniques
                        }
                        
                        attempt += 1;
                        let delay = error_handler.get_retry_delay(attempt);
                        eprintln!("Retrying {} scan after {}ms delay (attempt {}/{})", 
                                 technique.name(), delay, attempt, MAX_RETRY_ATTEMPTS);
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        continue;
                    }
                    RecoveryStrategy::CircuitBreakerWait(duration) => {
                        eprintln!("Circuit breaker activated, waiting {:?} before fallback", duration);
                        tokio::time::sleep(duration).await;
                        break;
                    }
                    RecoveryStrategy::Fallback(_) => {
                        eprintln!("Warning: {} scan failed ({}), trying fallback techniques...", 
                                 technique.name(), e);
                        break;
                    }
                    RecoveryStrategy::Abort => return Err(e),
                    RecoveryStrategy::Skip => break,
                }
            }
        }
    }
    
    // Try fallback techniques with circuit breaker protection
    while let Some(fallback_technique) = degradation.next_technique() {
        if fallback_technique == technique {
            continue; // Skip the technique we already tried
        }
        
        // Check circuit breaker before trying fallback
        if !error_handler.circuit_breaker.can_execute().await {
            eprintln!("Circuit breaker open, skipping {} technique", fallback_technique.name());
            continue;
        }
        
        match perform_scan_with_technique(target, ports, fallback_technique, config).await {
            Ok(results) => {
                error_handler.record_recovery_success().await;
                eprintln!("Successfully fell back to {} scan", fallback_technique.name());
                return Ok(results);
            }
            Err(e) => {
                error_handler.circuit_breaker.record_failure().await;
                eprintln!("Fallback {} scan also failed: {}", fallback_technique.name(), e);
                continue;
            }
        }
    }
    
    Err(ScanError::NetworkError(
        "All scan techniques failed".to_string(),
    ))
}

/// Helper function to perform scan with a specific technique
async fn perform_scan_with_technique(
    target: &str,
    ports: &[u16],
    technique: crate::network::ScanTechnique,
    config: &crate::config::ScanConfig,
) -> ScanResult<Vec<crate::scanner::ScanResult>> {
    use crate::scanner::engine::ScanEngine;
    
    let mut scan_config = config.clone();
    scan_config.target = target.to_string();
    scan_config.ports = ports.to_vec();
    scan_config.technique = technique;
    
    let engine = ScanEngine::new(scan_config).await
        .map_err(|e| ScanError::NetworkError(e.to_string()))?;
    
    let result = engine.scan().await
        .map_err(|e| ScanError::NetworkError(e.to_string()))?;
    
    Ok(vec![result])
}

/// Retry mechanism with exponential backoff, jitter, and circuit breaker
pub async fn retry_with_backoff<F, T, Fut>(
    operation: F,
    max_retries: usize,
    _base_delay_ms: u64,
) -> ScanResult<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = ScanResult<T>>,
{
    let mut attempt = 0;
    let error_handler = ErrorHandler::default();
    let effective_max_retries = if max_retries > 0 { max_retries } else { MAX_RETRY_ATTEMPTS };
    
    loop {
        // Check circuit breaker before attempting operation
        if !error_handler.circuit_breaker.can_execute().await {
            let wait_time = Duration::from_secs(5);
            eprintln!("Circuit breaker open, waiting {:?} before retry", wait_time);
            tokio::time::sleep(wait_time).await;
            continue;
        }
        
        match operation().await {
            Ok(result) => {
                error_handler.record_recovery_success().await;
                return Ok(result);
            }
            Err(e) => {
                error_handler.record_recovery_attempt().await;
                
                let strategy = error_handler.get_recovery_strategy(&e, attempt).await;
                match strategy {
                    RecoveryStrategy::Retry => {
                        if attempt >= effective_max_retries {
                            eprintln!("Max retry attempts ({}) reached, giving up", effective_max_retries);
                            error_handler.record_recovery_attempt().await;
                            error_handler.record_target_error(&format!("retry_operation_{}", attempt)).await;
                            return Err(e);
                        }
                        eprintln!("Retrying operation (attempt {}/{})...", attempt + 1, effective_max_retries);
                        let delay = error_handler.get_retry_delay(attempt);
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        attempt += 1;
                    }
                    RecoveryStrategy::CircuitBreakerWait(duration) => {
                        tokio::time::sleep(duration).await;
                        continue;
                    }
                    _ => return Err(e),
                }
            }
        }
    }
}

/// Adaptive timeout manager for dynamic timeout adjustment
#[derive(Debug, Clone)]
pub struct AdaptiveTimeout {
    base_timeout: Duration,
    current_timeout: Duration,
    success_count: u32,
    failure_count: u32,
    adjustment_factor: f64,
}

impl Default for AdaptiveTimeout {
    fn default() -> Self {
        Self {
            base_timeout: Duration::from_secs(3),
            current_timeout: Duration::from_secs(3),
            success_count: 0,
            failure_count: 0,
            adjustment_factor: 1.5,
        }
    }
}

impl AdaptiveTimeout {
    /// Create new adaptive timeout with base timeout
    pub fn new(base_timeout: Duration) -> Self {
        Self {
            base_timeout,
            current_timeout: base_timeout,
            success_count: 0,
            failure_count: 0,
            adjustment_factor: 1.5,
        }
    }
    
    /// Record successful operation and adjust timeout
    pub fn record_success(&mut self) {
        self.success_count += 1;
        self.failure_count = 0;
        
        // Decrease timeout if we have consistent successes
        if self.success_count >= 5 {
            let new_timeout = self.current_timeout.mul_f64(0.9);
            if new_timeout >= self.base_timeout {
                self.current_timeout = new_timeout;
            }
            self.success_count = 0;
        }
    }
    
    /// Record failed operation and adjust timeout
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.success_count = 0;
        
        // Increase timeout on failures
        if self.failure_count >= 2 {
            self.current_timeout = self.current_timeout.mul_f64(self.adjustment_factor);
            // Cap at 30 seconds
            if self.current_timeout > Duration::from_secs(30) {
                self.current_timeout = Duration::from_secs(30);
            }
            self.failure_count = 0;
        }
    }
    
    /// Get current timeout value
    pub fn get_timeout(&self) -> Duration {
        self.current_timeout
    }
    
    /// Reset to base timeout
    pub fn reset(&mut self) {
        self.current_timeout = self.base_timeout;
        self.success_count = 0;
        self.failure_count = 0;
    }
}

/// Resource manager for controlling system resource usage
#[derive(Debug, Clone)]
pub struct ResourceManager {
    max_memory_mb: usize,
    max_file_descriptors: usize,
    current_memory_mb: Arc<RwLock<usize>>,
    current_file_descriptors: Arc<RwLock<usize>>,
}

impl Default for ResourceManager {
    fn default() -> Self {
        Self {
            max_memory_mb: 1024, // 1GB default
            max_file_descriptors: 1000,
            current_memory_mb: Arc::new(RwLock::new(0)),
            current_file_descriptors: Arc::new(RwLock::new(0)),
        }
    }
}

impl ResourceManager {
    /// Create new resource manager with limits
    pub fn new(max_memory_mb: usize, max_file_descriptors: usize) -> Self {
        Self {
            max_memory_mb,
            max_file_descriptors,
            current_memory_mb: Arc::new(RwLock::new(0)),
            current_file_descriptors: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Check if we can allocate more resources
    pub async fn can_allocate(&self, memory_mb: usize, file_descriptors: usize) -> bool {
        let current_memory = *self.current_memory_mb.read().await;
        let current_fds = *self.current_file_descriptors.read().await;
        
        current_memory.saturating_add(memory_mb) <= self.max_memory_mb &&
        current_fds.saturating_add(file_descriptors) <= self.max_file_descriptors
    }
    
    /// Allocate resources
    pub async fn allocate(&self, memory_mb: usize, file_descriptors: usize) -> ScanResult<()> {
        if !self.can_allocate(memory_mb, file_descriptors).await {
            return Err(ScanError::NetworkError("Resource limit exceeded".to_string()));
        }
        
        *self.current_memory_mb.write().await += memory_mb;
        *self.current_file_descriptors.write().await += file_descriptors;
        Ok(())
    }
    
    /// Release resources
    pub async fn release(&self, memory_mb: usize, file_descriptors: usize) {
        let mut current_memory = self.current_memory_mb.write().await;
        let mut current_fds = self.current_file_descriptors.write().await;
        
        *current_memory = current_memory.saturating_sub(memory_mb);
        *current_fds = current_fds.saturating_sub(file_descriptors);
    }
    
    /// Get current resource usage
    pub async fn get_usage(&self) -> (usize, usize) {
        let memory = *self.current_memory_mb.read().await;
        let fds = *self.current_file_descriptors.read().await;
        (memory, fds)
    }
}

/// Convert common errors to ScanError
impl From<std::net::AddrParseError> for ScanError {
    fn from(e: std::net::AddrParseError) -> Self {
        ScanError::InvalidTarget(e.to_string())
    }
}

impl From<std::num::ParseIntError> for ScanError {
    fn from(e: std::num::ParseIntError) -> Self {
        ScanError::ParseError(e.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for ScanError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        ScanError::TimeoutError
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_error_handler_recovery_strategy() {
        let handler = ErrorHandler::default();
        
        let network_error = ScanError::NetworkError("Connection failed".to_string());
        assert!(matches!(
            handler.get_recovery_strategy(&network_error, 0).await,
            RecoveryStrategy::Retry
        ));
        
        let permission_error = ScanError::PermissionError("Need root".to_string());
        assert!(matches!(
            handler.get_recovery_strategy(&permission_error, 0).await,
            RecoveryStrategy::Fallback(_)
        ));
        
        let config_error = ScanError::ConfigError("Invalid config".to_string());
        assert!(matches!(
            handler.get_recovery_strategy(&config_error, 0).await,
            RecoveryStrategy::Abort
        ));
    }
    
    #[test]
    fn test_graceful_degradation() {
        let mut degradation = GracefulDegradation::default();
        
        assert!(degradation.has_fallback());
        
        let first = degradation.next_technique();
        assert!(first.is_some());
        
        let second = degradation.next_technique();
        assert!(second.is_some());
        assert_ne!(first, second);
    }
    
    #[test]
    fn test_retry_delay_calculation() {
        let handler = ErrorHandler::default();
        
        assert_eq!(handler.get_retry_delay(0), 1000);
        assert_eq!(handler.get_retry_delay(1), 2000);
        assert_eq!(handler.get_retry_delay(2), 4000);
        assert_eq!(handler.get_retry_delay(10), 30000); // Capped at 30s
    }
}