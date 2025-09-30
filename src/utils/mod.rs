//! Utility modules for the scanner

pub mod adaptive_performance;
pub mod address_exclusions;
pub mod address_parser;
pub mod config;
pub mod file_input;
pub mod port_exclusions;
pub mod profiles;
pub mod scan_options;
pub mod target_parser;
pub mod timing;

use std::time::{Duration, Instant};

/// Performance monitoring utilities
pub struct PerformanceMonitor {
    start_time: Instant,
    last_update: Instant,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            start_time: now,
            last_update: now,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
    
    /// Record a sent packet
    pub fn record_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
        self.last_update = Instant::now();
    }
    
    /// Record a received packet
    pub fn record_received(&mut self, bytes: usize) {
        self.packets_received += 1;
        self.bytes_received += bytes as u64;
        self.last_update = Instant::now();
    }
    
    /// Get current packets per second rate
    pub fn packets_per_second(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.packets_sent as f64 / elapsed
        } else {
            0.0
        }
    }
    
    /// Get current bytes per second rate
    pub fn bytes_per_second(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.bytes_sent as f64 / elapsed
        } else {
            0.0
        }
    }
    
    /// Get packet loss percentage
    pub fn packet_loss(&self) -> f64 {
        if self.packets_sent > 0 {
            ((self.packets_sent - self.packets_received) as f64 / self.packets_sent as f64) * 100.0
        } else {
            0.0
        }
    }
    
    /// Get total elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
    
    /// Get statistics summary
    pub fn summary(&self) -> PerformanceStats {
        PerformanceStats {
            packets_sent: self.packets_sent,
            packets_received: self.packets_received,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            packets_per_second: self.packets_per_second(),
            bytes_per_second: self.bytes_per_second(),
            packet_loss: self.packet_loss(),
            elapsed: self.elapsed(),
        }
    }
}

/// Performance statistics structure
#[derive(Debug, Clone)]
pub struct PerformanceStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub packet_loss: f64,
    pub elapsed: Duration,
}

/// Memory usage monitoring
pub struct MemoryMonitor;

impl MemoryMonitor {
    /// Get current memory usage in bytes (Unix only)
    #[cfg(unix)]
    pub fn current_usage() -> Option<u64> {
        use std::fs;
        
        let status = fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        return Some(kb * 1024); // Convert KB to bytes
                    }
                }
            }
        }
        None
    }
    
    /// Get current memory usage (fallback for non-Unix)
    #[cfg(not(unix))]
    pub fn current_usage() -> Option<u64> {
        None // Not implemented for non-Unix systems
    }
    
    /// Format bytes in human-readable format
    pub fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;
        
        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }
        
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

/// CPU usage monitoring
pub struct CpuMonitor {
    last_measurement: Option<CpuMeasurement>,
}

#[derive(Debug, Clone)]
struct CpuMeasurement {
    timestamp: Instant,
    user_time: u64,
    system_time: u64,
}

impl CpuMonitor {
    pub fn new() -> Self {
        Self {
            last_measurement: None,
        }
    }
    
    /// Get current CPU usage percentage (Unix only)
    #[cfg(unix)]
    pub fn current_usage(&mut self) -> Option<f64> {
        use std::fs;
        
        let stat = fs::read_to_string("/proc/self/stat").ok()?;
        let fields: Vec<&str> = stat.split_whitespace().collect();
        
        if fields.len() < 15 {
            return None;
        }
        
        let user_time: u64 = fields[13].parse().ok()?;
        let system_time: u64 = fields[14].parse().ok()?;
        let now = Instant::now();
        
        let current = CpuMeasurement {
            timestamp: now,
            user_time,
            system_time,
        };
        
        if let Some(ref last) = self.last_measurement {
            let time_delta = now.duration_since(last.timestamp).as_secs_f64();
            let cpu_delta = (current.user_time + current.system_time) - 
                           (last.user_time + last.system_time);
            
            // Convert from clock ticks to percentage
            // Assuming 100 clock ticks per second (typical)
            let cpu_usage = (cpu_delta as f64 / 100.0) / time_delta * 100.0;
            
            self.last_measurement = Some(current);
            Some(cpu_usage.min(100.0))
        } else {
            self.last_measurement = Some(current);
            None
        }
    }
    
    /// Get current CPU usage (fallback for non-Unix)
    #[cfg(not(unix))]
    pub fn current_usage(&mut self) -> Option<f64> {
        None // Not implemented for non-Unix systems
    }
}

/// Progress bar utilities
pub struct ProgressBar {
    total: usize,
    current: usize,
    width: usize,
    start_time: Instant,
}

impl ProgressBar {
    pub fn new(total: usize, width: usize) -> Self {
        Self {
            total,
            current: 0,
            width,
            start_time: Instant::now(),
        }
    }
    
    /// Update progress
    pub fn update(&mut self, current: usize) {
        self.current = current;
    }
    
    /// Increment progress by 1
    pub fn increment(&mut self) {
        self.current += 1;
    }
    
    /// Get progress percentage
    pub fn percentage(&self) -> f64 {
        if self.total > 0 {
            (self.current as f64 / self.total as f64) * 100.0
        } else {
            0.0
        }
    }
    
    /// Get estimated time remaining
    pub fn eta(&self) -> Option<Duration> {
        if self.current > 0 {
            let elapsed = self.start_time.elapsed();
            let rate = self.current as f64 / elapsed.as_secs_f64();
            let remaining = self.total - self.current;
            let eta_seconds = remaining as f64 / rate;
            Some(Duration::from_secs_f64(eta_seconds))
        } else {
            None
        }
    }
    
    /// Render progress bar as string
    pub fn render(&self) -> String {
        let percentage = self.percentage();
        let filled = ((percentage / 100.0) * self.width as f64) as usize;
        let empty = self.width - filled;
        
        let bar = "█".repeat(filled) + &"░".repeat(empty);
        let eta_str = if let Some(eta) = self.eta() {
            format!(" ETA: {}s", eta.as_secs())
        } else {
            String::new()
        };
        
        format!(
            "[{}] {:.1}% ({}/{}){}",
            bar, percentage, self.current, self.total, eta_str
        )
    }
}

/// Logging utilities
pub struct Logger;

impl Logger {
    /// Initialize logger with specified level
    pub fn init(level: log::LevelFilter) {
        env_logger::Builder::from_default_env()
            .filter_level(level)
            .format_timestamp_secs()
            .init();
    }
    
    /// Log scan start
    pub fn log_scan_start(target: &str, ports: usize, technique: &str) {
        log::info!("Starting scan of {} ({} ports) using {}", target, ports, technique);
    }
    
    /// Log scan completion
    pub fn log_scan_complete(duration: Duration, open_ports: usize, total_ports: usize) {
        log::info!(
            "Scan completed in {:.2}s - {}/{} ports open",
            duration.as_secs_f64(),
            open_ports,
            total_ports
        );
    }
    
    /// Log performance statistics
    pub fn log_performance(stats: &PerformanceStats) {
        log::info!(
            "Performance: {:.0} pps, {:.1}% loss, {} sent",
            stats.packets_per_second,
            stats.packet_loss,
            MemoryMonitor::format_bytes(stats.bytes_sent)
        );
    }
}

/// Error handling utilities
pub struct ErrorHandler;

impl ErrorHandler {
    /// Check if error is recoverable
    pub fn is_recoverable(error: &crate::ScanError) -> bool {
        match error {
            crate::ScanError::NetworkError(err_msg) => {
                // Check if the error message indicates a recoverable error
                err_msg.contains("WouldBlock") ||
                err_msg.contains("TimedOut") ||
                err_msg.contains("Interrupted")
            }
            crate::ScanError::TimeoutError(_) => true,
            crate::ScanError::RateLimitError => true,
            _ => false,
        }
    }
    
    /// Get retry delay for recoverable errors
    pub fn retry_delay(error: &crate::ScanError, attempt: u32) -> Duration {
        let base_delay = match error {
            crate::ScanError::NetworkError(_) => Duration::from_millis(100),
            crate::ScanError::TimeoutError(_) => Duration::from_millis(500),
            crate::ScanError::RateLimitError => Duration::from_millis(1000),
            _ => Duration::from_millis(100),
        };
        
        // Exponential backoff with jitter
        let multiplier = 2_u64.pow(attempt.min(5));
        let jitter = rand::random::<u64>() % 100;
        Duration::from_millis(base_delay.as_millis() as u64 * multiplier) + Duration::from_millis(jitter)
    }
}