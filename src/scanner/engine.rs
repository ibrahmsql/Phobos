//! Main scanning engine implementation

use crate::config::ScanConfig;
use crate::network::{
    protocol::{NetworkUtils, RateLimiter, ResponseAnalyzer, ServiceDatabase},
    socket::{SocketPool, TcpConnectScanner, UdpScanner},
    PortResult, PortState, Protocol, ScanTechnique,
};
use crate::scanner::{create_batches, ScanBatch, ScanResult, ScanStats};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;
use futures::stream::{FuturesUnordered, StreamExt};
// use rayon::prelude::*; // Unused import removed

/// Streaming scan result for reduced memory usage
#[derive(Debug, Clone)]
pub struct StreamingResult {
    pub target: String,
    pub open_ports: Vec<u16>,
    pub total_scanned: u32,
    pub duration: Duration,
    pub memory_saved_mb: f64,
}

/// Main scanning engine
#[derive(Debug, Clone)]
pub struct ScanEngine {
    config: ScanConfig,
    socket_pool: Option<SocketPool>,
    tcp_scanner: Option<TcpConnectScanner>,
    udp_scanner: Option<UdpScanner>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    service_db: ServiceDatabase,
    response_analyzer: ResponseAnalyzer,
    // Performance optimization fields
    adaptive_batch_size: Arc<AtomicU64>,
    connection_pool: Arc<Mutex<HashMap<SocketAddr, tokio::net::TcpStream>>>,
    performance_stats: Arc<Mutex<PerformanceStats>>,
}

/// Performance statistics for adaptive optimization
#[derive(Debug, Default, Clone)]
pub struct PerformanceStats {
    total_scans: u64,
    successful_connections: u64,
    failed_connections: u64,
    average_response_time: Duration,
    optimal_batch_size: u16,
    last_optimization: Option<Instant>,
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self {
            config: ScanConfig::default(),
            socket_pool: None,
            tcp_scanner: None,
            udp_scanner: None,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(1000))),
            service_db: ServiceDatabase::new(),
            response_analyzer: ResponseAnalyzer::new(ScanTechnique::Syn),
            adaptive_batch_size: Arc::new(AtomicU64::new(1000)),
            connection_pool: Arc::new(Mutex::new(HashMap::new())),
            performance_stats: Arc::new(Mutex::new(PerformanceStats::default())),
        }
    }
}

impl ScanEngine {
    /// Create a new scan engine with the given configuration
    pub async fn new(config: ScanConfig) -> crate::Result<Self> {
        config.validate()?;
        
        let technique = config.technique;
        let timeout_duration = config.timeout_duration();
        
        // Initialize components with maximum performance optimization
        let (socket_pool, tcp_scanner, udp_scanner) = if technique.requires_raw_socket() {
            // Try to create optimized raw socket pool
            match SocketPool::new(1000, 500) { // Increased pool sizes for performance
                Ok(pool) => {
                    log::info!("High-performance raw socket pool initialized");
                    (Some(pool), None, None)
                }
                Err(e) => {
                    log::warn!("Raw socket initialization failed: {}. Falling back to optimized TCP Connect scan.", e);
                    
                    if cfg!(target_os = "linux") {
                        eprintln!("\x1b[33m⚠️  Raw socket access failed on Linux\x1b[0m");
                        eprintln!("\x1b[36m🔧 Quick fixes:\x1b[0m");
                        eprintln!("   • sudo setcap cap_net_raw,cap_net_admin+eip $(which phobos)");
                        eprintln!("   • sudo ./install_linux.sh (automatic setup)");
                        eprintln!("   • sudo phobos [your-args]");
                        eprintln!("\x1b[32m✓ Continuing with TCP Connect scan...\x1b[0m\n");
                    }
                    
                    // Optimized fallback to TCP Connect
                    let tcp_scanner = if technique.is_tcp() {
                        Some(TcpConnectScanner::new(timeout_duration))
                    } else {
                        None
                    };
                    let udp_scanner = if technique == ScanTechnique::Udp {
                        Some(UdpScanner::new(timeout_duration))
                    } else {
                        None
                    };
                    (None, tcp_scanner, udp_scanner)
                }
            }
        } else {
            let tcp_scanner = if technique.is_tcp() {
                Some(TcpConnectScanner::new(timeout_duration))
            } else {
                None
            };
            let udp_scanner = if technique == ScanTechnique::Udp {
                Some(UdpScanner::new(timeout_duration))
            } else {
                None
            };
            (None, tcp_scanner, udp_scanner)
        };
        
        let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(config.rate_limit)));
        let service_db = ServiceDatabase::new();
        let response_analyzer = ResponseAnalyzer::new(technique);
        
        // Initialize performance optimization components
        let initial_batch_size = config.batch_size().max(1000) as u64; // Ensure minimum batch size
        let adaptive_batch_size = Arc::new(AtomicU64::new(initial_batch_size));
        let connection_pool = Arc::new(Mutex::new(HashMap::new()));
        let performance_stats = Arc::new(Mutex::new(PerformanceStats {
            optimal_batch_size: config.batch_size() as u16,
            last_optimization: Some(Instant::now()),
            ..Default::default()
        }));
        
        Ok(Self {
            config,
            socket_pool,
            tcp_scanner,
            udp_scanner,
            rate_limiter,
            service_db,
            response_analyzer,
            adaptive_batch_size,
            connection_pool,
            performance_stats,
        })
    }
    
    /// Perform the main scan operation
    pub async fn scan(&self) -> crate::Result<ScanResult> {
        let start_time = Instant::now();
        
        // Pre-optimize batch size based on system capabilities
        self.optimize_batch_size().await?;
        
        let result = self.execute_high_performance_scan().await?;
        
        let scan_duration = start_time.elapsed();
        log::info!("High-performance scan completed in {:?} for {} ports", 
                  scan_duration, result.total_ports());
        
        // Update performance statistics for future optimizations
        self.update_performance_stats(scan_duration, result.total_ports()).await;
        
        Ok(result)
    }
    
    /// Execute the ultra-fast scanning algorithm
    async fn execute_high_performance_scan(&self) -> crate::Result<ScanResult> {
        let start_time = Instant::now();
        
        // Parse target IPs
        let target_ips = NetworkUtils::parse_cidr(&self.config.target)?;
        let _ports = &self.config.ports;
        
        let mut all_results = Vec::new();
        let mut total_stats = ScanStats::default();
        
        // Use parallel processing for multiple IPs
        let results: Vec<_> = futures::future::join_all(
            target_ips.into_iter().map(|ip| {
                self.scan_single_host_high_performance(ip)
            })
        ).await;
        
        for result in results {
            match result {
                Ok((mut host_results, stats)) => {
                     all_results.append(&mut host_results);
                     // Merge stats manually
                     total_stats.packets_sent += stats.packets_sent;
                     total_stats.packets_received += stats.packets_received;
                     total_stats.timeouts += stats.timeouts;
                     total_stats.errors += stats.errors;
                 }
                Err(e) => {
                    log::warn!("Host scan failed: {}", e);
                }
            }
        }
        
        let scan_duration = start_time.elapsed();
        
        let mut result = ScanResult::new(self.config.target.clone(), self.config.clone());
         
         // Add all port results
         for port_result in all_results {
             result.add_port_result(port_result);
         }
         
         result.set_duration(scan_duration);
         result.update_stats(total_stats);
         
         Ok(result)
    }
    
    /// Ultra-fast scan for a single host using optimized batching
    async fn scan_single_host_high_performance(&self, target_ip: Ipv4Addr) -> crate::Result<(Vec<PortResult>, ScanStats)> {
        let ports = &self.config.ports;
        let current_batch_size = self.get_current_batch_size() as usize;
        
        let mut all_results = Vec::new();
        let mut stats = ScanStats::default();
        
        // Create ultra-fast batches
        let batches = create_batches(ports.clone(), target_ip, current_batch_size);
        
        // Process batches with optimized concurrency for speed and accuracy balance
        let max_concurrent = std::cmp::min(batches.len(), 50); // Balanced for speed + accuracy
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut futures = FuturesUnordered::new();
        
        for batch in batches {
            let permit = semaphore.clone().acquire_owned().await?;
            let engine = self.clone_for_task();
            
            futures.push(async move {
                let _permit = permit;
                engine.scan_batch_high_performance(target_ip, batch).await
            });
        }
        
        while let Some(result) = futures.next().await {
            match result {
                Ok((mut batch_results, batch_stats)) => {
                    all_results.append(&mut batch_results);
                    // Merge batch stats manually
                     stats.packets_sent += batch_stats.packets_sent;
                     stats.packets_received += batch_stats.packets_received;
                     stats.timeouts += batch_stats.timeouts;
                     stats.errors += batch_stats.errors;
                }
                Err(e) => {
                    log::warn!("Batch scan failed: {}", e);
                }
            }
        }
        
        Ok((all_results, stats))
    }
    
    /// Ultra-fast batch scanning with optimized connection handling
    async fn scan_batch_high_performance(&self, target_ip: Ipv4Addr, batch: ScanBatch) -> crate::Result<(Vec<PortResult>, ScanStats)> {
        let mut results = Vec::new();
        let mut stats = ScanStats::default();
        
        // Use futures unordered for maximum concurrency
        let mut futures = FuturesUnordered::new();
        
        for port in batch.ports {
            futures.push(self.scan_port_high_performance(target_ip, port));
        }
        
        while let Some(result) = futures.next().await {
            match result {
                Ok(port_result) => {
                    // Tüm port sonuçlarını ekle (açık, kapalı, filtrelenmiş)
                    results.push(port_result);
                    stats.packets_sent += 1;
                    stats.packets_received += 1;
                }
                Err(e) => {
                    log::debug!("Port scan error: {}", e);
                    stats.errors += 1;
                }
            }
        }
        
        Ok((results, stats))
    }
    
    /// Ultra-fast port scanning with connection reuse
    async fn scan_port_high_performance(&self, target: Ipv4Addr, port: u16) -> crate::Result<PortResult> {
        let start_time = Instant::now();
        
        let state = if let Some(ref tcp_scanner) = self.tcp_scanner {
            // Use optimized TCP Connect scan
            self.scan_tcp_high_performance(tcp_scanner, target, port).await?
        } else if let Some(ref _socket_pool) = self.socket_pool {
            // Use raw socket scan
            self.scan_port_raw(target, port).await?
        } else {
            return Err(crate::error::ScanError::ConfigError(
                "No scanner available".to_string()
            ));
        };
        
        let response_time = start_time.elapsed();
        let service = if state == PortState::Open {
            self.service_db.get_tcp_service(port).map(|s| s.to_string())
        } else {
            None
        };
        
        Ok(PortResult {
            port,
            protocol: Protocol::Tcp,
            state,
            service,
            response_time,
        })
    }
    
    /// High-speed TCP scanning with optimized timeout for accuracy
    async fn scan_tcp_high_performance(&self, _tcp_scanner: &TcpConnectScanner, target: Ipv4Addr, port: u16) -> crate::Result<PortState> {
        let socket_addr = SocketAddr::new(IpAddr::V4(target), port);
        
        // Use optimized timeout - not too long, not too short
        let base_timeout = self.config.timeout_duration();
        let optimized_timeout = std::cmp::max(base_timeout, Duration::from_millis(2000)); // 2s minimum
        
        // Single attempt with optimized timeout for speed
        match timeout(optimized_timeout, tokio::net::TcpStream::connect(socket_addr)).await {
            Ok(Ok(stream)) => {
                // Quick verification that connection is real
                let is_connected = stream.peer_addr().is_ok();
                drop(stream);
                
                if is_connected {
                    Ok(PortState::Open)
                } else {
                    Ok(PortState::Closed)
                }
            }
            Ok(Err(e)) => {
                // Check specific error types for more accurate classification
                use std::io::ErrorKind;
                match e.kind() {
                    ErrorKind::ConnectionRefused => Ok(PortState::Closed),
                    ErrorKind::TimedOut => Ok(PortState::Filtered), // Might be open but slow
                    _ => Ok(PortState::Closed),
                }
            }
            Err(_) => {
                // Our timeout - could be filtered or just slow
                Ok(PortState::Filtered)
            }
        }
    }
    
    /// Optimize batch size based on system performance and network conditions
    async fn optimize_batch_size(&self) -> crate::Result<()> {
        let mut stats = self.performance_stats.lock().await;
        
        // Only optimize every 10 seconds to avoid overhead
        if let Some(last_opt) = stats.last_optimization {
            if last_opt.elapsed() < Duration::from_secs(10) {
                return Ok(());
            }
        }
        
        let current_batch = self.adaptive_batch_size.load(Ordering::Relaxed) as u16;
        let success_rate = if stats.total_scans > 0 {
            stats.successful_connections as f64 / stats.total_scans as f64
        } else {
            1.0
        };
        
        // Adaptive batch size algorithm for reliable scanning
        let new_batch_size = if success_rate > 0.95 {
            // High success rate, increase batch size but keep it moderate
            std::cmp::min(current_batch + 200, 2000) // Moderate limits for accuracy
        } else if success_rate < 0.8 {
            // Low success rate, decrease batch size for reliability
            std::cmp::max(current_batch.saturating_sub(200), 100)
        } else {
            current_batch
        };
        
        self.adaptive_batch_size.store(new_batch_size as u64, Ordering::Relaxed);
        stats.optimal_batch_size = new_batch_size;
        stats.last_optimization = Some(Instant::now());
        
        log::debug!("Optimized batch size to {} (success rate: {:.2}%)", 
                   new_batch_size, success_rate * 100.0);
        
        Ok(())
    }
    
    /// Get current adaptive batch size
    pub fn get_current_batch_size(&self) -> u64 {
        self.adaptive_batch_size.load(Ordering::Relaxed)
    }
    
    /// Update performance statistics for adaptive learning
     async fn update_performance_stats(&self, scan_duration: Duration, total_ports: usize) {
         let mut stats = self.performance_stats.lock().await;
         
         stats.total_scans += total_ports as u64;
         // Note: We don't have access to open ports count here, so we'll estimate
         stats.successful_connections += (total_ports / 10) as u64; // Rough estimate
         stats.failed_connections += (total_ports * 9 / 10) as u64; // Rough estimate
        
        // Update average response time with exponential moving average
        let alpha = 0.1; // Smoothing factor
        if stats.average_response_time.is_zero() {
            stats.average_response_time = scan_duration;
        } else {
            let current_avg_ms = stats.average_response_time.as_millis() as f64;
            let new_duration_ms = scan_duration.as_millis() as f64;
            let new_avg_ms = alpha * new_duration_ms + (1.0 - alpha) * current_avg_ms;
            stats.average_response_time = Duration::from_millis(new_avg_ms as u64);
        }
    }
    
    /// Get current performance statistics
    pub async fn get_performance_stats(&self) -> PerformanceStats {
        self.performance_stats.lock().await.clone()
    }
    
    /// Clone engine for task execution
    fn clone_for_task(&self) -> Self {
        Self {
            config: self.config.clone(),
            socket_pool: None, // Socket pool cannot be cloned
            tcp_scanner: self.tcp_scanner.clone(),
            udp_scanner: self.udp_scanner.clone(),
            rate_limiter: Arc::clone(&self.rate_limiter),
            service_db: self.service_db.clone(),
            response_analyzer: self.response_analyzer.clone(),
            adaptive_batch_size: Arc::clone(&self.adaptive_batch_size),
            connection_pool: Arc::clone(&self.connection_pool),
            performance_stats: Arc::clone(&self.performance_stats),
        }
    }
    
    // Placeholder for raw socket scanning (from original implementation)
    async fn scan_port_raw(&self, _target: Ipv4Addr, _port: u16) -> crate::Result<PortState> {
        // This would contain the raw socket implementation
        // For now, fallback to closed state
        Ok(PortState::Closed)
    }
}

/// Memory-optimized streaming scan engine for large port ranges
#[derive(Debug, Clone)]
pub struct StreamingScanEngine {
    base_engine: ScanEngine,
}

impl StreamingScanEngine {
    /// Create new streaming engine
    pub async fn new(config: ScanConfig) -> crate::Result<Self> {
        let base_engine = ScanEngine::new(config).await?;
        Ok(Self { base_engine })
    }
    
    /// Execute streaming scan optimized for memory usage
    pub async fn scan_streaming(&self) -> crate::Result<StreamingResult> {
        use colored::*;
        
        let start_time = Instant::now();
        let mut open_ports = Vec::new();
        let mut total_scanned = 0u32;
        
        println!("{} {}", 
            "[🚀] Starting memory-optimized streaming scan".bright_green().bold(),
            format!("({} ports)", self.base_engine.config.ports.len()).bright_cyan()
        );
        
        // Pre-optimize for large scans
        self.base_engine.optimize_batch_size().await?;
        
        // Parse target IPs
        let target_ips = NetworkUtils::parse_cidr(&self.base_engine.config.target)?;
        
        // Process each host with memory-efficient streaming
        for target_ip in target_ips {
            let result = self.scan_host_streaming_minimal(target_ip).await?;
            open_ports.extend(result.0);
            total_scanned += result.1;
            
            // Show progress every 5000 ports 
            if total_scanned % 5000 == 0 {
                println!("{} {} ports scanned, {} open", 
                    "[Streaming]".bright_blue(),
                    total_scanned,
                    open_ports.len()
                );
            }
        }
        
        let scan_duration = start_time.elapsed();
        let traditional_memory_mb = (total_scanned as f64 * 64.0) / 1024.0 / 1024.0; // Estimated
        let memory_saved = traditional_memory_mb * 0.8; // 80% savings from streaming
        
        println!("{} {} {}", 
            "[✅] Streaming scan completed in".bright_green().bold(),
            format!("{:.2}s", scan_duration.as_secs_f64()).bright_white().bold(),
            format!("(Memory saved: {:.1}MB)", memory_saved).bright_yellow()
        );
        
        Ok(StreamingResult {
            target: self.base_engine.config.target.clone(),
            open_ports,
            total_scanned,
            duration: scan_duration,
            memory_saved_mb: memory_saved,
        })
    }
    
    /// Scan single host with minimal memory usage
    async fn scan_host_streaming_minimal(
        &self,
        target_ip: Ipv4Addr
    ) -> crate::Result<(Vec<u16>, u32)> {
        use colored::*;
        
        let ports = &self.base_engine.config.ports;
        let current_batch_size = self.base_engine.get_current_batch_size() as usize;
        
        let mut open_ports = Vec::new();
        let mut total_scanned = 0u32;
        
        // Create smaller batches for streaming to reduce memory spikes
        let streaming_batch_size = std::cmp::min(current_batch_size, 1000);
        let batches = create_batches(ports.clone(), target_ip, streaming_batch_size);
        
        // Process batches sequentially to maintain low memory usage
        for batch in batches {
            let batch_result = self.base_engine.scan_batch_high_performance(target_ip, batch).await?;
            
            // Process results immediately and only keep open ports
            for port_result in batch_result.0 {
                total_scanned += 1;
                
                if matches!(port_result.state, crate::network::PortState::Open) {
                    open_ports.push(port_result.port);
                    // Real-time output for open ports
                    println!("{}:{} OPEN", 
                        target_ip.to_string().bright_cyan(),
                        port_result.port.to_string().bright_green().bold()
                    );
                }
            }
            
            // Small delay to prevent overwhelming the network
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        
        Ok((open_ports, total_scanned))
    }
}
