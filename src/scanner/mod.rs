//! Scanner module containing the main scanning engine

pub mod engine;
pub mod techniques;

use crate::config::ScanConfig;
use crate::network::{PortResult, PortState};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub use engine::{ScanEngine, StreamingScanEngine};

/// Complete scan result containing all discovered information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Target that was scanned
    pub target: String,
    
    /// List of open ports
    pub open_ports: Vec<u16>,
    
    /// List of closed ports
    pub closed_ports: Vec<u16>,
    
    /// List of filtered ports
    pub filtered_ports: Vec<u16>,
    
    /// Detailed port results
    pub port_results: Vec<PortResult>,
    
    /// Total scan duration
    pub duration: Duration,
    
    /// Scan statistics
    pub stats: ScanStats,
    
    /// Scan configuration used
    pub config: ScanConfig,
}

impl ScanResult {
    pub fn new(target: String, config: ScanConfig) -> Self {
        Self {
            target,
            open_ports: Vec::new(),
            closed_ports: Vec::new(),
            filtered_ports: Vec::new(),
            port_results: Vec::new(),
            duration: Duration::from_secs(0),
            stats: ScanStats::default(),
            config,
        }
    }
    
    /// Add a port result to the scan
    pub fn add_port_result(&mut self, result: PortResult) {
        match result.state {
            PortState::Open => self.open_ports.push(result.port),
            PortState::Closed => self.closed_ports.push(result.port),
            PortState::Filtered | PortState::OpenFiltered | PortState::ClosedFiltered => {
                self.filtered_ports.push(result.port);
            }
            PortState::Unfiltered => {
                // Handle unfiltered ports separately if needed
            }
        }
        
        self.port_results.push(result);
    }
    
    /// Set the scan duration
    pub fn set_duration(&mut self, duration: Duration) {
        self.duration = duration;
    }
    
    /// Update scan statistics
    pub fn update_stats(&mut self, stats: ScanStats) {
        self.stats = stats;
    }
    
    /// Get the total number of ports scanned
    pub fn total_ports(&self) -> usize {
        self.open_ports.len() + self.closed_ports.len() + self.filtered_ports.len()
    }
    
    /// Get scan rate in ports per second
    pub fn scan_rate(&self) -> f64 {
        if self.duration.as_secs_f64() > 0.0 {
            self.total_ports() as f64 / self.duration.as_secs_f64()
        } else {
            0.0
        }
    }
    
    /// Sort ports for consistent output
    pub fn sort_ports(&mut self) {
        self.open_ports.sort_unstable();
        self.closed_ports.sort_unstable();
        self.filtered_ports.sort_unstable();
        self.port_results.sort_by_key(|r| r.port);
    }
}


/// Scan statistics for performance monitoring
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    /// Total packets sent
    pub packets_sent: u64,
    
    /// Total packets received
    pub packets_received: u64,
    
    /// Number of timeouts
    pub timeouts: u64,
    
    /// Number of errors
    pub errors: u64,
    
    /// Average response time
    pub avg_response_time: Duration,
    
    /// Minimum response time
    pub min_response_time: Duration,
    
    /// Maximum response time
    pub max_response_time: Duration,
    
    /// Packet loss percentage
    pub packet_loss: f64,
    
    /// Actual scan rate achieved
    pub actual_rate: f64,
    
    /// Memory usage in bytes
    pub memory_usage: u64,
    
    /// CPU usage percentage
    pub cpu_usage: f64,
}

impl ScanStats {
    pub fn new() -> Self {
        Self {
            min_response_time: Duration::from_secs(u64::MAX),
            max_response_time: Duration::from_secs(0),
            ..Default::default()
        }
    }
    
    /// Update response time statistics
    pub fn update_response_time(&mut self, response_time: Duration) {
        if response_time < self.min_response_time {
            self.min_response_time = response_time;
        }
        if response_time > self.max_response_time {
            self.max_response_time = response_time;
        }
    }
    
    /// Calculate packet loss percentage
    pub fn calculate_packet_loss(&mut self) {
        if self.packets_sent > 0 {
            self.packet_loss = ((self.packets_sent - self.packets_received) as f64 / self.packets_sent as f64) * 100.0;
        }
    }
    
    /// Calculate average response time
    pub fn calculate_avg_response_time(&mut self, total_response_time: Duration) {
        if self.packets_received > 0 {
            self.avg_response_time = total_response_time / self.packets_received as u32;
        }
    }
}

/// Scan progress tracking
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub total_ports: usize,
    pub completed_ports: usize,
    pub current_port: u16,
    pub start_time: Instant,
    pub estimated_completion: Option<Instant>,
}

impl ScanProgress {
    pub fn new(total_ports: usize) -> Self {
        Self {
            total_ports,
            completed_ports: 0,
            current_port: 0,
            start_time: Instant::now(),
            estimated_completion: None,
        }
    }
    
    /// Update progress with completed port
    pub fn update(&mut self, port: u16) {
        self.completed_ports += 1;
        self.current_port = port;
        
        // Calculate estimated completion time
        if self.completed_ports > 0 {
            let elapsed = self.start_time.elapsed();
            let rate = self.completed_ports as f64 / elapsed.as_secs_f64();
            let remaining = self.total_ports - self.completed_ports;
            let eta_seconds = remaining as f64 / rate;
            self.estimated_completion = Some(Instant::now() + Duration::from_secs_f64(eta_seconds));
        }
    }
    
    /// Get completion percentage
    pub fn percentage(&self) -> f64 {
        if self.total_ports > 0 {
            (self.completed_ports as f64 / self.total_ports as f64) * 100.0
        } else {
            0.0
        }
    }
    
    /// Get current scan rate
    pub fn current_rate(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.completed_ports as f64 / elapsed
        } else {
            0.0
        }
    }
    
    /// Get estimated time remaining
    pub fn eta(&self) -> Option<Duration> {
        self.estimated_completion.map(|eta| {
            let now = Instant::now();
            if eta > now {
                eta - now
            } else {
                Duration::from_secs(0)
            }
        })
    }
}

/// Host discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostDiscoveryResult {
    pub ip: Ipv4Addr,
    pub is_alive: bool,
    pub response_time: Duration,
    pub method: String,
}

/// Batch scanning for improved performance
#[derive(Debug, Clone)]
pub struct ScanBatch {
    pub ports: Vec<u16>,
    pub target: Ipv4Addr,
    pub batch_id: usize,
}

impl ScanBatch {
    pub fn new(ports: Vec<u16>, target: Ipv4Addr, batch_id: usize) -> Self {
        Self {
            ports,
            target,
            batch_id,
        }
    }
    
    pub fn size(&self) -> usize {
        self.ports.len()
    }
}

/// Thread-safe result collector
pub type ResultCollector = std::sync::Arc<tokio::sync::Mutex<ScanResult>>;

/// Create batches from port list for parallel processing
pub fn create_batches(ports: Vec<u16>, target: Ipv4Addr, batch_size: usize) -> Vec<ScanBatch> {
        ports
            .chunks(batch_size)
            .enumerate()
            .map(|(id, chunk)| ScanBatch::new(chunk.to_vec(), target, id))
            .collect()
    }

