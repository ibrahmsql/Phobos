//! Performance optimization based on system resources

use rlimit::Resource;
use std::time::{Duration, Instant};
use log::{info, warn, debug};

/// Performance manager for system optimization
#[derive(Debug, Clone)]
pub struct AdaptivePerformanceManager {
    system_ulimit: u64,
    optimal_batch_size: u16,
    optimal_threads: u16,
    last_optimization: Option<Instant>,
    performance_history: Vec<PerformanceMeasurement>,
}

#[derive(Debug, Clone)]
pub struct PerformanceMeasurement {
    pub batch_size: u16,
    pub threads: u16,
    pub ports_per_second: f64,
    pub memory_usage_mb: f64,
    pub timestamp: Instant,
}

impl Default for AdaptivePerformanceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptivePerformanceManager {
    pub fn new() -> Self {
        let system_ulimit = Self::get_system_ulimit();
        let optimal_batch_size = Self::calculate_initial_batch_size(system_ulimit);
        let optimal_threads = Self::calculate_initial_threads();

        info!("🚀 Adaptive Performance Manager initialized");
        info!("   System ulimit: {}", system_ulimit);
        info!("   Initial batch size: {}", optimal_batch_size);
        info!("   Initial threads: {}", optimal_threads);

        Self {
            system_ulimit,
            optimal_batch_size,
            optimal_threads,
            last_optimization: None,
            performance_history: Vec::new(),
        }
    }

    /// Get system file descriptor limit
    #[cfg(unix)]
    pub fn get_system_ulimit() -> u64 {
        match Resource::NOFILE.get() {
            Ok((soft, _hard)) => {
                debug!("System ulimit: soft={}, using soft limit", soft);
                soft
            }
            Err(e) => {
                warn!("Could not get ulimit: {}. Using safe default.", e);
                8000 // Safe default for Unix systems
            }
        }
    }

    #[cfg(not(unix))]
    pub fn get_system_ulimit() -> u64 {
        8000 // Safe default for non-Unix systems
    }

    /// Set ulimit to optimal value if needed
    #[cfg(unix)]
    pub fn optimize_ulimit(&self, desired_limit: Option<u64>) -> u64 {
        if let Some(limit) = desired_limit {
            match Resource::NOFILE.set(limit, limit) {
                Ok(_) => {
                    info!("✅ Ulimit increased to {}", limit);
                    return limit;
                }
                Err(e) => {
                    warn!("❌ Failed to set ulimit to {}: {}", limit, e);
                }
            }
        }

        self.system_ulimit
    }

    #[cfg(not(unix))]
    pub fn optimize_ulimit(&self, _desired_limit: Option<u64>) -> u64 {
        self.system_ulimit
    }

    /// Calculate optimal batch size based on system resources
    fn calculate_initial_batch_size(ulimit: u64) -> u16 {
        const SAFETY_MARGIN: u64 = 100;
        const MAX_BATCH_SIZE: u64 = 5000;
        const MIN_BATCH_SIZE: u64 = 100;

        // Start with a percentage of available file descriptors
        let available_fds = ulimit.saturating_sub(SAFETY_MARGIN);
        
        // Use 80% of available FDs, but within reasonable limits
        let calculated_batch = (available_fds * 80 / 100)
            .max(MIN_BATCH_SIZE)
            .min(MAX_BATCH_SIZE);

        debug!("Calculated batch size: {} (ulimit: {})", calculated_batch, ulimit);
        calculated_batch as u16
    }

    /// Calculate optimal thread count
    fn calculate_initial_threads() -> u16 {
        let cpu_count = num_cpus::get();
        
        // For I/O bound operations like port scanning, we can use more threads than CPU cores
        // But we need to be reasonable to avoid overwhelming the system
        let thread_multiplier = if cpu_count <= 4 { 25 } else if cpu_count <= 8 { 20 } else { 15 };
        
        let calculated_threads = (cpu_count * thread_multiplier)
            .max(50)   // Minimum threads for decent performance
            .min(1000); // Maximum to avoid system overload

        debug!("Calculated threads: {} (CPU cores: {})", calculated_threads, cpu_count);
        calculated_threads as u16
    }

    /// Get current optimal batch size
    pub fn get_optimal_batch_size(&self) -> u16 {
        self.optimal_batch_size
    }

    /// Get current optimal thread count
    pub fn get_optimal_threads(&self) -> u16 {
        self.optimal_threads
    }

    /// Adjust batch size based on current ulimit and target ports
    pub fn adjust_batch_size_for_scan(&mut self, user_batch_size: u16, total_ports: usize) -> u16 {
        let current_ulimit = self.system_ulimit;
        let user_batch = user_batch_size as u64;

        // If user specified batch size is larger than system can handle, adjust it
        if user_batch > current_ulimit {
            warn!("⚠️  Requested batch size ({}) exceeds system ulimit ({})", 
                user_batch, current_ulimit);
            
            if current_ulimit < 1000 {
                warn!("📉 Very low ulimit detected. Consider increasing with: ulimit -n 8192");
                warn!("🐳 Or use Docker for better resource management");
                
                // Use conservative batch size for low ulimit systems
                let conservative_batch = (current_ulimit / 2).max(100).min(500);
                info!("🔧 Using conservative batch size: {}", conservative_batch);
                return conservative_batch as u16;
            } else {
                // Use most of available FDs with safety margin
                let adjusted_batch = (current_ulimit - 100).min(5000);
                info!("🔧 Adjusted batch size to: {}", adjusted_batch);
                return adjusted_batch as u16;
            }
        }

        // For small scans, reduce batch size to avoid overhead
        if total_ports < 1000 && user_batch > total_ports as u64 {
            let optimized_batch = ((total_ports as u64 / 2).max(50)).min(1000);
            debug!("📊 Small scan optimization: batch size {} -> {}", user_batch, optimized_batch);
            return optimized_batch as u16;
        }

        // User batch size is reasonable
        user_batch_size
    }

    /// Record performance measurement for future optimization
    pub fn record_performance(&mut self, 
        batch_size: u16, 
        threads: u16, 
        scan_duration: Duration,
        total_ports: usize,
        memory_usage_mb: f64
    ) {
        let ports_per_second = if scan_duration.as_secs_f64() > 0.0 {
            total_ports as f64 / scan_duration.as_secs_f64()
        } else {
            0.0
        };

        let measurement = PerformanceMeasurement {
            batch_size,
            threads,
            ports_per_second,
            memory_usage_mb,
            timestamp: Instant::now(),
        };

        self.performance_history.push(measurement);
        
        // Keep only last 10 measurements to avoid memory bloat
        if self.performance_history.len() > 10 {
            self.performance_history.remove(0);
        }

        debug!("📈 Performance recorded: {:.0} ports/sec, batch: {}, threads: {}", 
            ports_per_second, batch_size, threads);
    }

    /// Optimize parameters based on performance history
    pub fn optimize_parameters(&mut self) -> bool {
        // Don't optimize too frequently
        if let Some(last_opt) = self.last_optimization {
            if last_opt.elapsed() < Duration::from_secs(30) {
                return false;
            }
        }

        if self.performance_history.len() < 2 {
            return false; // Need at least 2 measurements to compare
        }

        let recent_measurements = &self.performance_history[self.performance_history.len()-2..];
        
        // Find the measurement with best ports per second
        if let Some(best_measurement) = recent_measurements.iter().max_by(|a, b| 
            a.ports_per_second.partial_cmp(&b.ports_per_second).unwrap_or(std::cmp::Ordering::Equal)
        ) {
            let old_batch = self.optimal_batch_size;
            let old_threads = self.optimal_threads;

            self.optimal_batch_size = best_measurement.batch_size;
            self.optimal_threads = best_measurement.threads;
            self.last_optimization = Some(Instant::now());

            if old_batch != self.optimal_batch_size || old_threads != self.optimal_threads {
                info!("🎯 Performance optimized: batch {} -> {}, threads {} -> {}", 
                    old_batch, self.optimal_batch_size,
                    old_threads, self.optimal_threads);
                return true;
            }
        }

        false
    }

    /// Get performance recommendations as human-readable strings
    pub fn get_performance_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Check ulimit
        if self.system_ulimit < 4000 {
            recommendations.push(format!(
                "🔧 Low ulimit detected ({}). Consider: ulimit -n 8192", 
                self.system_ulimit
            ));
        }

        // Check if we have performance data
        if let Some(latest) = self.performance_history.last() {
            if latest.ports_per_second < 1000.0 {
                recommendations.push(
                    "⚡ Low scanning speed detected. Try increasing batch size with -b".to_string()
                );
            }

            if latest.memory_usage_mb > 500.0 {
                recommendations.push(
                    "💾 High memory usage. Consider decreasing batch size".to_string()
                );
            }
        }

        // Check batch size vs ulimit ratio
        let batch_ratio = (self.optimal_batch_size as f64) / (self.system_ulimit as f64);
        if batch_ratio > 0.8 {
            recommendations.push(
                "⚠️  Batch size close to ulimit. Consider increasing ulimit for better performance".to_string()
            );
        }

        recommendations
    }

    /// Get current performance statistics
    pub fn get_performance_stats(&self) -> PerformanceStats {
        let current_ports_per_sec = self.performance_history
            .last()
            .map(|m| m.ports_per_second)
            .unwrap_or(0.0);

        let avg_ports_per_sec = if !self.performance_history.is_empty() {
            self.performance_history.iter()
                .map(|m| m.ports_per_second)
                .sum::<f64>() / self.performance_history.len() as f64
        } else {
            0.0
        };

        PerformanceStats {
            system_ulimit: self.system_ulimit,
            optimal_batch_size: self.optimal_batch_size,
            optimal_threads: self.optimal_threads,
            current_ports_per_sec,
            average_ports_per_sec: avg_ports_per_sec,
            measurements_count: self.performance_history.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PerformanceStats {
    pub system_ulimit: u64,
    pub optimal_batch_size: u16,
    pub optimal_threads: u16,
    pub current_ports_per_sec: f64,
    pub average_ports_per_sec: f64,
    pub measurements_count: usize,
}

/// Show helpful performance tips to user
pub fn show_performance_tips(stats: &PerformanceStats) {
    println!("📊 Performance Statistics:");
    println!("   System ulimit: {}", stats.system_ulimit);
    println!("   Optimal batch size: {}", stats.optimal_batch_size);
    println!("   Optimal threads: {}", stats.optimal_threads);
    
    if stats.current_ports_per_sec > 0.0 {
        println!("   Current speed: {:.0} ports/sec", stats.current_ports_per_sec);
    }
    
    if stats.average_ports_per_sec > 0.0 {
        println!("   Average speed: {:.0} ports/sec", stats.average_ports_per_sec);
    }
}

