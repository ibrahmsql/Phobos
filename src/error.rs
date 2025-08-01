//! Error handling for the phobos scanner
//!
//! This module provides comprehensive error handling with graceful degradation
//! and retry mechanisms for robust scanning operations.

use thiserror::Error;

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
}

/// Error handler for managing recoverable errors
pub struct ErrorHandler {
    max_retries: usize,
    retry_delay_ms: u64,
    fallback_enabled: bool,
}

impl Default for ErrorHandler {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay_ms: 1000,
            fallback_enabled: true,
        }
    }
}

impl ErrorHandler {
    /// Create a new error handler with custom settings
    pub fn new(max_retries: usize, retry_delay_ms: u64, fallback_enabled: bool) -> Self {
        Self {
            max_retries,
            retry_delay_ms,
            fallback_enabled,
        }
    }
    
    /// Determine the recovery strategy for a given error
    pub fn get_recovery_strategy(&self, error: &ScanError, attempt: usize) -> RecoveryStrategy {
        match error {
            ScanError::NetworkError(_) | ScanError::TimeoutError => {
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
                RecoveryStrategy::Retry // Will be handled with exponential backoff
            }
            ScanError::InvalidTarget(_) | ScanError::PortRangeError(_) | ScanError::ConfigError(_) => {
                RecoveryStrategy::Abort
            }
            _ => RecoveryStrategy::Skip,
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

/// Scan with automatic fallback on failure
pub async fn scan_with_fallback(
    target: &str,
    ports: &[u16],
    technique: crate::network::ScanTechnique,
    config: &crate::config::ScanConfig,
) -> ScanResult<Vec<crate::scanner::ScanResult>> {
    let mut degradation = GracefulDegradation::default();
    let error_handler = ErrorHandler::default();
    
    // Try the requested technique first
    match perform_scan_with_technique(target, ports, technique, config).await {
        Ok(results) => return Ok(results),
        Err(e) => {
            if !error_handler.is_recoverable(&e) {
                return Err(e);
            }
            eprintln!("Warning: {} scan failed ({}), trying fallback techniques...", 
                     technique.name(), e);
        }
    }
    
    // Try fallback techniques
    while let Some(fallback_technique) = degradation.next_technique() {
        if fallback_technique == technique {
            continue; // Skip the technique we already tried
        }
        
        match perform_scan_with_technique(target, ports, fallback_technique, config).await {
            Ok(results) => {
                eprintln!("Successfully fell back to {} scan", fallback_technique.name());
                return Ok(results);
            }
            Err(e) => {
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

/// Retry wrapper with exponential backoff
pub async fn retry_with_backoff<F, T, Fut>(
    operation: F,
    max_retries: usize,
    base_delay_ms: u64,
) -> ScanResult<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = ScanResult<T>>,
{
    let mut attempt = 0;
    
    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                attempt += 1;
                
                if attempt > max_retries {
                    return Err(e);
                }
                
                let delay = base_delay_ms * (2_u64.pow((attempt - 1) as u32));
                let delay = std::cmp::min(delay, 30000); // Cap at 30 seconds
                
                eprintln!("Attempt {} failed: {}. Retrying in {}ms...", attempt, e, delay);
                tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
            }
        }
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
    
    #[test]
    fn test_error_handler_recovery_strategy() {
        let handler = ErrorHandler::default();
        
        let network_error = ScanError::NetworkError("Connection failed".to_string());
        assert!(matches!(
            handler.get_recovery_strategy(&network_error, 0),
            RecoveryStrategy::Retry
        ));
        
        let permission_error = ScanError::PermissionError("Need root".to_string());
        assert!(matches!(
            handler.get_recovery_strategy(&permission_error, 0),
            RecoveryStrategy::Fallback(_)
        ));
        
        let config_error = ScanError::ConfigError("Invalid config".to_string());
        assert!(matches!(
            handler.get_recovery_strategy(&config_error, 0),
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