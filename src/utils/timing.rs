//! Timing and performance optimization utilities

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Adaptive timing controller for optimizing scan performance
pub struct AdaptiveTimer {
    target_rate: f64,
    current_rate: f64,
    response_times: VecDeque<Duration>,
    last_adjustment: Instant,
    adjustment_interval: Duration,
    min_delay: Duration,
    max_delay: Duration,
    current_delay: Duration,
}

impl AdaptiveTimer {
    /// Create a new adaptive timer
    pub fn new(target_rate: f64) -> Self {
        Self {
            target_rate,
            current_rate: 0.0,
            response_times: VecDeque::with_capacity(100),
            last_adjustment: Instant::now(),
            adjustment_interval: Duration::from_millis(1000),
            min_delay: Duration::from_micros(1),
            max_delay: Duration::from_millis(100),
            current_delay: Duration::from_millis(1),
        }
    }
    
    /// Record a response time
    pub fn record_response(&mut self, response_time: Duration) {
        self.response_times.push_back(response_time);
        
        // Keep only recent measurements
        if self.response_times.len() > 100 {
            self.response_times.pop_front();
        }
        
        // Update current rate
        self.update_current_rate();
        
        // Adjust timing if needed
        if self.last_adjustment.elapsed() >= self.adjustment_interval {
            self.adjust_timing();
            self.last_adjustment = Instant::now();
        }
    }
    
    /// Get the current delay between packets
    pub fn get_delay(&self) -> Duration {
        self.current_delay
    }
    
    /// Get current performance statistics
    pub fn get_stats(&self) -> TimingStats {
        let avg_response_time = if !self.response_times.is_empty() {
            let total: Duration = self.response_times.iter().sum();
            total / self.response_times.len() as u32
        } else {
            Duration::from_millis(0)
        };
        
        let min_response_time = self.response_times.iter().min().copied()
            .unwrap_or(Duration::from_millis(0));
        
        let max_response_time = self.response_times.iter().max().copied()
            .unwrap_or(Duration::from_millis(0));
        
        TimingStats {
            target_rate: self.target_rate,
            current_rate: self.current_rate,
            current_delay: self.current_delay,
            avg_response_time,
            min_response_time,
            max_response_time,
            efficiency: (self.current_rate / self.target_rate).min(1.0),
        }
    }
    
    /// Update current rate calculation
    fn update_current_rate(&mut self) {
        if self.response_times.len() >= 2 {
            let window_size = self.response_times.len().min(10);
            let recent_times: Vec<_> = self.response_times.iter().rev().take(window_size).collect();
            
            if !recent_times.is_empty() {
                let avg_time = recent_times.iter().map(|d| d.as_secs_f64()).sum::<f64>() / recent_times.len() as f64;
                if avg_time > 0.0 {
                    self.current_rate = 1.0 / avg_time;
                }
            }
        }
    }
    
    /// Adjust timing based on current performance
    fn adjust_timing(&mut self) {
        let rate_ratio = self.current_rate / self.target_rate;
        
        if rate_ratio > 1.1 {
            // We're going too fast, increase delay
            self.current_delay = (self.current_delay * 110 / 100).min(self.max_delay);
        } else if rate_ratio < 0.9 {
            // We're going too slow, decrease delay
            self.current_delay = (self.current_delay * 90 / 100).max(self.min_delay);
        }
        
        // Also consider response time variance
        if let Some(avg_response) = self.get_average_response_time() {
            if avg_response > Duration::from_millis(1000) {
                // High response times, slow down
                self.current_delay = (self.current_delay * 120 / 100).min(self.max_delay);
            } else if avg_response < Duration::from_millis(100) {
                // Low response times, we can speed up
                self.current_delay = (self.current_delay * 95 / 100).max(self.min_delay);
            }
        }
    }
    
    /// Get average response time
    fn get_average_response_time(&self) -> Option<Duration> {
        if self.response_times.is_empty() {
            None
        } else {
            let total: Duration = self.response_times.iter().sum();
            Some(total / self.response_times.len() as u32)
        }
    }
}

/// Timing statistics
#[derive(Debug, Clone)]
pub struct TimingStats {
    pub target_rate: f64,
    pub current_rate: f64,
    pub current_delay: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub efficiency: f64,
}

/// Congestion control for network scanning
pub struct CongestionController {
    window_size: usize,
    max_window_size: usize,
    min_window_size: usize,
    timeout_count: usize,
    success_count: usize,
    last_timeout: Option<Instant>,
    backoff_factor: f64,
}

impl CongestionController {
    pub fn new(initial_window: usize, max_window: usize) -> Self {
        Self {
            window_size: initial_window,
            max_window_size: max_window,
            min_window_size: 1,
            timeout_count: 0,
            success_count: 0,
            last_timeout: None,
            backoff_factor: 0.5,
        }
    }
    
    /// Record a successful response
    pub fn record_success(&mut self) {
        self.success_count += 1;
        
        // Increase window size gradually
        if self.success_count % 10 == 0 && self.window_size < self.max_window_size {
            self.window_size += 1;
        }
    }
    
    /// Record a timeout
    pub fn record_timeout(&mut self) {
        self.timeout_count += 1;
        self.last_timeout = Some(Instant::now());
        
        // Decrease window size aggressively
        self.window_size = ((self.window_size as f64 * self.backoff_factor) as usize)
            .max(self.min_window_size);
    }
    
    /// Get current window size
    pub fn get_window_size(&self) -> usize {
        self.window_size
    }
    
    /// Check if we should back off
    pub fn should_backoff(&self) -> bool {
        if let Some(last_timeout) = self.last_timeout {
            last_timeout.elapsed() < Duration::from_millis(1000)
        } else {
            false
        }
    }
    
    /// Get congestion statistics
    pub fn get_stats(&self) -> CongestionStats {
        let total_attempts = self.success_count + self.timeout_count;
        let loss_rate = if total_attempts > 0 {
            self.timeout_count as f64 / total_attempts as f64
        } else {
            0.0
        };
        
        CongestionStats {
            window_size: self.window_size,
            success_count: self.success_count,
            timeout_count: self.timeout_count,
            loss_rate,
        }
    }
}

/// Congestion control statistics
#[derive(Debug, Clone)]
pub struct CongestionStats {
    pub window_size: usize,
    pub success_count: usize,
    pub timeout_count: usize,
    pub loss_rate: f64,
}

/// Round-trip time estimator
pub struct RttEstimator {
    srtt: Option<Duration>, // Smoothed RTT
    rttvar: Duration,       // RTT variance
    rto: Duration,          // Retransmission timeout
    alpha: f64,             // Smoothing factor for SRTT
    beta: f64,              // Smoothing factor for RTTVAR
    k: u32,                 // RTO multiplier
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            srtt: None,
            rttvar: Duration::from_millis(0),
            rto: Duration::from_millis(1000),
            alpha: 0.125,
            beta: 0.25,
            k: 4,
        }
    }
    
    /// Update RTT estimate with a new measurement
    pub fn update(&mut self, rtt: Duration) {
        match self.srtt {
            None => {
                // First measurement
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                // Subsequent measurements
                let rtt_diff = if rtt > srtt {
                    rtt - srtt
                } else {
                    srtt - rtt
                };
                
                self.rttvar = Duration::from_secs_f64(
                    (1.0 - self.beta) * self.rttvar.as_secs_f64() + 
                    self.beta * rtt_diff.as_secs_f64()
                );
                
                self.srtt = Some(Duration::from_secs_f64(
                    (1.0 - self.alpha) * srtt.as_secs_f64() + 
                    self.alpha * rtt.as_secs_f64()
                ));
            }
        }
        
        // Calculate RTO
        if let Some(srtt) = self.srtt {
            self.rto = srtt + Duration::from_secs_f64(
                self.k as f64 * self.rttvar.as_secs_f64()
            );
            
            // Clamp RTO to reasonable bounds
            self.rto = self.rto.max(Duration::from_millis(100))
                              .min(Duration::from_millis(60000));
        }
    }
    
    /// Get current RTO (Retransmission Timeout)
    pub fn get_rto(&self) -> Duration {
        self.rto
    }
    
    /// Get smoothed RTT
    pub fn get_srtt(&self) -> Option<Duration> {
        self.srtt
    }
    
    /// Get RTT variance
    pub fn get_rttvar(&self) -> Duration {
        self.rttvar
    }
}

/// Timing profile for different scan types
#[derive(Debug, Clone)]
pub enum TimingProfile {
    Paranoid,   // Very slow and stealthy
    Sneaky,     // Slow and stealthy
    Polite,     // Normal speed
    Normal,     // Default timing
    Aggressive, // Fast scanning
    Insane,     // Very fast scanning
}

impl TimingProfile {
    /// Get timing parameters for the profile
    pub fn get_params(&self) -> TimingParams {
        match self {
            TimingProfile::Paranoid => TimingParams {
                initial_rtt_timeout: Duration::from_millis(5000),
                min_rtt_timeout: Duration::from_millis(1000),
                max_rtt_timeout: Duration::from_millis(10000),
                max_retries: 10,
                scan_delay: Duration::from_millis(1000),
                max_parallelism: 1,
            },
            TimingProfile::Sneaky => TimingParams {
                initial_rtt_timeout: Duration::from_millis(2000),
                min_rtt_timeout: Duration::from_millis(500),
                max_rtt_timeout: Duration::from_millis(5000),
                max_retries: 5,
                scan_delay: Duration::from_millis(500),
                max_parallelism: 10,
            },
            TimingProfile::Polite => TimingParams {
                initial_rtt_timeout: Duration::from_millis(1000),
                min_rtt_timeout: Duration::from_millis(200),
                max_rtt_timeout: Duration::from_millis(3000),
                max_retries: 3,
                scan_delay: Duration::from_millis(100),
                max_parallelism: 50,
            },
            TimingProfile::Normal => TimingParams {
                initial_rtt_timeout: Duration::from_millis(1000),
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_millis(2000),
                max_retries: 3,
                scan_delay: Duration::from_millis(10),
                max_parallelism: 100,
            },
            TimingProfile::Aggressive => TimingParams {
                initial_rtt_timeout: Duration::from_millis(500),
                min_rtt_timeout: Duration::from_millis(50),
                max_rtt_timeout: Duration::from_millis(1000),
                max_retries: 2,
                scan_delay: Duration::from_millis(1),
                max_parallelism: 500,
            },
            TimingProfile::Insane => TimingParams {
                initial_rtt_timeout: Duration::from_millis(250),
                min_rtt_timeout: Duration::from_millis(25),
                max_rtt_timeout: Duration::from_millis(500),
                max_retries: 1,
                scan_delay: Duration::from_micros(100),
                max_parallelism: 1000,
            },
        }
    }
}

/// Timing parameters
#[derive(Debug, Clone)]
pub struct TimingParams {
    pub initial_rtt_timeout: Duration,
    pub min_rtt_timeout: Duration,
    pub max_rtt_timeout: Duration,
    pub max_retries: u32,
    pub scan_delay: Duration,
    pub max_parallelism: usize,
}

/// Bandwidth estimator
pub struct BandwidthEstimator {
    bytes_sent: u64,
    start_time: Instant,
    window_start: Instant,
    window_bytes: u64,
    window_duration: Duration,
}

impl BandwidthEstimator {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            bytes_sent: 0,
            start_time: now,
            window_start: now,
            window_bytes: 0,
            window_duration: Duration::from_secs(1),
        }
    }
    
    /// Record bytes sent
    pub fn record_bytes(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.window_bytes += bytes;
        
        // Reset window if needed
        if self.window_start.elapsed() >= self.window_duration {
            self.window_start = Instant::now();
            self.window_bytes = 0;
        }
    }
    
    /// Get current bandwidth in bytes per second
    pub fn get_bandwidth(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.bytes_sent as f64 / elapsed
        } else {
            0.0
        }
    }
    
    /// Get instantaneous bandwidth
    pub fn get_instantaneous_bandwidth(&self) -> f64 {
        let elapsed = self.window_start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.window_bytes as f64 / elapsed
        } else {
            0.0
        }
    }
}