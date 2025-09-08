//! Comprehensive error handling and recovery tests
//! Tests circuit breaker, graceful degradation, and adaptive timeout mechanisms

use phobos::{
    error::*,
    config::ScanConfig,
    network::ScanTechnique,
    scanner::ScanResult as ScannerResult,
};
use std::time::{Duration, Instant};
use tokio::time::timeout;

#[tokio::test]
async fn test_circuit_breaker_functionality() {
    let circuit_breaker = CircuitBreaker::new(3, Duration::from_secs(5), 2);
    
    // Initially should be closed and allow execution
    assert!(circuit_breaker.can_execute().await);
    assert_eq!(circuit_breaker.get_state().await, CircuitBreakerState::Closed);
    
    // Record failures to trip the circuit breaker
    for _ in 0..3 {
        circuit_breaker.record_failure().await;
    }
    
    // Should now be open and block execution
    assert!(!circuit_breaker.can_execute().await);
    assert_eq!(circuit_breaker.get_state().await, CircuitBreakerState::Open);
    
    // Wait for recovery timeout and test half-open state
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(circuit_breaker.can_execute().await);
    
    // Record successes to close the circuit
    for _ in 0..2 {
        circuit_breaker.record_success().await;
    }
    
    assert_eq!(circuit_breaker.get_state().await, CircuitBreakerState::Closed);
}

#[tokio::test]
async fn test_error_handler_recovery_strategies() {
    let handler = ErrorHandler::new(3, 1000, true);
    
    // Test network error recovery
    let network_error = ScanError::NetworkError("Connection refused".to_string());
    let strategy = handler.get_recovery_strategy(&network_error, 0).await;
    assert!(matches!(strategy, RecoveryStrategy::Retry));
    
    // Test permission error fallback
    let permission_error = ScanError::PermissionError("Need root privileges".to_string());
    let strategy = handler.get_recovery_strategy(&permission_error, 0).await;
    assert!(matches!(strategy, RecoveryStrategy::Fallback(_)));
    
    // Test config error abort
    let config_error = ScanError::ConfigError("Invalid configuration".to_string());
    let strategy = handler.get_recovery_strategy(&config_error, 0).await;
    assert!(matches!(strategy, RecoveryStrategy::Abort));
    
    // Test rate limit error returns circuit breaker wait
    let rate_limit_error = ScanError::RateLimitError;
    let strategy = handler.get_recovery_strategy(&rate_limit_error, 0).await;
    assert!(matches!(strategy, RecoveryStrategy::CircuitBreakerWait(_)));
}

#[tokio::test]
async fn test_graceful_degradation() {
    let mut degradation = GracefulDegradation::default();
    
    assert!(degradation.has_fallback());
    
    // Test technique progression
    let techniques = vec![
        degradation.next_technique(),
        degradation.next_technique(),
        degradation.next_technique(),
    ];
    
    // Should get different techniques
    assert!(techniques[0].is_some());
    assert!(techniques[1].is_some());
    assert!(techniques[2].is_some());
    assert_ne!(techniques[0], techniques[1]);
    assert_ne!(techniques[1], techniques[2]);
    
    // Reset and test again
    degradation.reset();
    let first_after_reset = degradation.next_technique();
    assert_eq!(techniques[0], first_after_reset);
}

#[tokio::test]
async fn test_adaptive_timeout() {
    let mut adaptive_timeout = AdaptiveTimeout::new(Duration::from_millis(1000));
    
    let initial_timeout = adaptive_timeout.get_timeout();
    assert_eq!(initial_timeout, Duration::from_millis(1000));
    
    // Record successes - should decrease timeout
    for _ in 0..5 {
        adaptive_timeout.record_success();
    }
    
    let success_timeout = adaptive_timeout.get_timeout();
    assert!(success_timeout < initial_timeout);
    
    // Record failures - should increase timeout
    for _ in 0..5 {
        adaptive_timeout.record_failure();
    }
    
    let failure_timeout = adaptive_timeout.get_timeout();
    assert!(failure_timeout > success_timeout);
    
    // Reset should return to base timeout
    adaptive_timeout.reset();
    assert_eq!(adaptive_timeout.get_timeout(), Duration::from_millis(1000));
}

#[tokio::test]
async fn test_resource_manager() {
    let resource_manager = ResourceManager::new(100, 50); // 100MB, 50 FDs
    
    // Should allow allocation within limits
    assert!(resource_manager.can_allocate(50, 25).await);
    assert!(resource_manager.allocate(50, 25).await.is_ok());
    
    let (memory, fds) = resource_manager.get_usage().await;
    assert_eq!(memory, 50);
    assert_eq!(fds, 25);
    
    // Should reject allocation exceeding limits
    assert!(!resource_manager.can_allocate(60, 30).await);
    assert!(resource_manager.allocate(60, 30).await.is_err());
    
    // Release resources
    resource_manager.release(25, 10).await;
    let (memory, fds) = resource_manager.get_usage().await;
    assert_eq!(memory, 25);
    assert_eq!(fds, 15);
    
    // Should now allow previously rejected allocation
    assert!(resource_manager.can_allocate(60, 30).await);
}

#[tokio::test]
async fn test_error_metrics_tracking() {
    let handler = ErrorHandler::new(3, 1000, true);
    
    // Record various error types
    let network_error = ScanError::NetworkError("Connection failed".to_string());
    let timeout_error = ScanError::TimeoutError("Operation timed out".to_string());
    let permission_error = ScanError::PermissionError("Access denied".to_string());
    
    handler.get_recovery_strategy(&network_error, 0).await;
    handler.get_recovery_strategy(&timeout_error, 0).await;
    handler.get_recovery_strategy(&permission_error, 0).await;
    
    let metrics = handler.get_metrics().await;
    assert!(metrics.total_errors > 0);
    assert!(metrics.network_errors > 0);
    assert!(metrics.timeout_errors > 0);
    assert!(metrics.permission_errors > 0);
}

#[tokio::test]
async fn test_retry_with_backoff() {
    use std::sync::{Arc, Mutex};
    let attempt_count = Arc::new(Mutex::new(0));
    let start_time = Instant::now();
    
    let attempt_count_clone = attempt_count.clone();
    let result = retry_with_backoff(
        move || {
            let count = attempt_count_clone.clone();
            async move {
                let mut current_count = count.lock().unwrap();
                *current_count += 1;
                let attempt_num = *current_count;
                drop(current_count);
                
                if attempt_num < 3 {
                    Err(ScanError::NetworkError("Temporary failure".to_string()))
                } else {
                    Ok("Success")
                }
            }
        },
        5,
        100,
    ).await;
    
    assert!(result.is_ok());
    assert_eq!(*attempt_count.lock().unwrap(), 3);
    
    // Should have taken at least 300ms due to backoff (100ms + 200ms)
    let duration = start_time.elapsed();
    assert!(duration >= Duration::from_millis(300));
}

#[tokio::test]
async fn test_scan_with_fallback_integration() {
    let config = ScanConfig {
        target: "127.0.0.1".to_string(),
        ports: vec![22, 80, 443],
        technique: ScanTechnique::Connect,
        threads: 1,
        timeout: 1000,
        rate_limit: 100,
        stealth_options: None,
        timing_template: 3,
        top_ports: None,
        batch_size: None,
        realtime_notifications: false,
        notification_color: "orange".to_string(),
        adaptive_learning: false,
        min_response_time: 50,
        max_response_time: 3000,
    };
    
    // Test fallback mechanism with invalid target first
    let result: Result<Result<Vec<ScannerResult>, _>, _> = timeout(
        Duration::from_secs(30),
        scan_with_fallback(
            "invalid.nonexistent.target.example.com",
            &config.ports,
            config.technique,
            &config,
        )
    ).await;
    
    // Should complete within timeout (may succeed with fallback or fail gracefully)
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_error_rate_limiting() {
    let handler = ErrorHandler::new(3, 1000, true);
    let target = "test-target";
    
    // Initially should not be rate limited
    assert!(!handler.is_error_rate_high(target).await);
    
    // Record many errors quickly
    for _ in 0..15 {
        handler.record_target_error(target).await;
    }
    
    // Should now be rate limited
    assert!(handler.is_error_rate_high(target).await);
    
    // Wait for rate limit window to expire
    tokio::time::sleep(Duration::from_secs(61)).await;
    assert!(!handler.is_error_rate_high(target).await);
}

#[tokio::test]
async fn test_recovery_success_tracking() {
    let handler = ErrorHandler::new(3, 1000, true);
    
    let initial_metrics = handler.get_metrics().await;
    
    // Record recovery attempts and successes
    handler.record_recovery_attempt().await;
    handler.record_recovery_attempt().await;
    handler.record_recovery_success().await;
    
    let final_metrics = handler.get_metrics().await;
    
    assert_eq!(final_metrics.recovery_attempts, initial_metrics.recovery_attempts + 2);
    assert_eq!(final_metrics.successful_recoveries, initial_metrics.successful_recoveries + 1);
}