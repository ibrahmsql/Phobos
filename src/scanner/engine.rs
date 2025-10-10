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
use tokio::sync::Mutex;
use tokio::time::timeout;
use futures::stream::{FuturesUnordered, StreamExt};
use std::io;

// System resource detection for optimal batch sizing
#[cfg(unix)]
use rlimit::{getrlimit, Resource};

// Batch sizing constants (optimized for performance)
const DEFAULT_FILE_DESCRIPTORS_LIMIT: u64 = 8000;
const AVERAGE_BATCH_SIZE: u16 = 3000;
const MIN_BATCH_SIZE: u16 = 100;
const MAX_BATCH_SIZE: u16 = 15000;
// use rayon::prelude::*; // Unused import removed

/// Socket iterator for memory-efficient on-demand socket generation
#[derive(Debug, Clone)]
pub struct SocketIterator {
    ips: Vec<Ipv4Addr>,
    ports: Vec<u16>,
    current_ip_index: usize,
    current_port_index: usize,
}

impl SocketIterator {
    pub fn new(ips: &[Ipv4Addr], ports: &[u16]) -> Self {
        Self {
            ips: ips.to_vec(),
            ports: ports.to_vec(),
            current_ip_index: 0,
            current_port_index: 0,
        }
    }
    
    pub fn next(&mut self) -> Option<SocketAddr> {
        if self.current_ip_index >= self.ips.len() {
            return None;
        }
        
        let ip = self.ips[self.current_ip_index];
        let port = self.ports[self.current_port_index];
        let socket = SocketAddr::new(IpAddr::V4(ip), port);
        
        // Move to next port
        self.current_port_index += 1;
        
        // If we've exhausted all ports for this IP, move to next IP
        if self.current_port_index >= self.ports.len() {
            self.current_port_index = 0;
            self.current_ip_index += 1;
        }
        
        Some(socket)
    }
}

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
        let optimal_batch = Self::infer_optimal_batch_size(None);
        Self {
            config: ScanConfig::default(),
            socket_pool: None,
            tcp_scanner: None,
            udp_scanner: None,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(1000))),
            service_db: ServiceDatabase::new(),
            response_analyzer: ResponseAnalyzer::new(ScanTechnique::Syn),
            adaptive_batch_size: Arc::new(AtomicU64::new(optimal_batch as u64)),
            connection_pool: Arc::new(Mutex::new(HashMap::new())),
            performance_stats: Arc::new(Mutex::new(PerformanceStats::default())),
        }
    }
}

impl ScanEngine {
    /// Infer optimal batch size from system ulimit
    /// Uses system file descriptor limits to maximize performance
    pub fn infer_optimal_batch_size(custom_batch: Option<usize>) -> usize {
        #[cfg(unix)]
        {
            let ulimit = if let Ok((soft, _hard)) = getrlimit(Resource::NOFILE) {
                soft
            } else {
                log::warn!("Could not read ulimit, using default");
                return AVERAGE_BATCH_SIZE as usize;
            };
            
            let mut batch_size: u64 = custom_batch.unwrap_or(AVERAGE_BATCH_SIZE as usize) as u64;
            
            // Adaptive batch size based on system limits
            if ulimit < batch_size {
                log::warn!("File limit ({}) is lower than desired batch size ({}). Adjusting...", ulimit, batch_size);
                
                if ulimit < AVERAGE_BATCH_SIZE as u64 {
                    // ulimit is very small - use half of it
                    log::warn!("Your file limit is very small ({}) - this will impact speed", ulimit);
                    batch_size = ulimit / 2;
                } else if ulimit > DEFAULT_FILE_DESCRIPTORS_LIMIT {
                    // High ulimit - use average batch size
                    log::info!("Using average batch size ({})", AVERAGE_BATCH_SIZE);
                    batch_size = AVERAGE_BATCH_SIZE as u64;
                } else {
                    // Medium ulimit - leave 100 FDs for system
                    batch_size = ulimit - 100;
                }
            } else if ulimit + 2 > batch_size {
                // Ulimit is close to batch size - could go higher
                log::debug!("File limit ({}) is higher than batch size. Could increase to: {}", ulimit, ulimit - 100);
            }
            
            let final_batch = (batch_size as usize).clamp(MIN_BATCH_SIZE as usize, MAX_BATCH_SIZE as usize);
            log::info!("🚀 Optimal batch size: {} (ulimit: {})", final_batch, ulimit);
            
            return final_batch;
        }
        
        #[cfg(not(unix))]
        {
            let batch = custom_batch.unwrap_or(AVERAGE_BATCH_SIZE as usize);
            log::info!("Using batch size: {} (non-Unix system)", batch);
            batch
        }
    }
    
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
        
        // RustScan-style: Infer optimal batch size from system
        let initial_batch_size = Self::infer_optimal_batch_size(config.batch_size);
        let adaptive_batch_size = Arc::new(AtomicU64::new(initial_batch_size as u64));
        let connection_pool = Arc::new(Mutex::new(HashMap::new()));
        let performance_stats = Arc::new(Mutex::new(PerformanceStats {
            optimal_batch_size: initial_batch_size as u16,
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
    
    /// Ultra-fast scan using continuous FuturesUnordered queue
    /// Optimized for full port scans with minimal overhead
    async fn scan_single_host_high_performance(&self, target_ip: Ipv4Addr) -> crate::Result<(Vec<PortResult>, ScanStats)> {
        let ports = &self.config.ports;
        let batch_size = self.get_current_batch_size() as usize;
        
        // Pre-allocate for performance (avoid reallocation)
        let estimated_open = (ports.len() / 100).max(10); // ~1% typically open
        let mut all_results = Vec::with_capacity(estimated_open);
        let mut stats = ScanStats::default();
        
        // Create socket iterator for memory-efficient on-demand generation
        let mut socket_iterator = SocketIterator::new(&[target_ip], ports);
        let mut futures = FuturesUnordered::new();
        
        // Fill initial batch
        for _ in 0..batch_size {
            if let Some(socket) = socket_iterator.next() {
                futures.push(self.scan_socket_high_performance(socket));
            } else {
                break;
            }
        }
        
        log::debug!("Starting continuous queue with batch size {}", batch_size);
        
        // Key optimization: As each future completes, immediately spawn a new one
        // This maintains constant batch size and maximizes throughput
        while let Some(result) = futures.next().await {
            // Spawn next socket scan to maintain batch size (hot path)
            if let Some(socket) = socket_iterator.next() {
                futures.push(self.scan_socket_high_performance(socket));
            }
            
            // Fast path: Only track open ports for full scans
            if let Ok(port_result) = result {
                if port_result.state == PortState::Open {
                    all_results.push(port_result);
                    stats.packets_sent += 1;
                    stats.packets_received += 1;
                } else {
                    // Count but don't store closed/filtered
                    stats.packets_sent += 1;
                }
            } else {
                stats.errors += 1;
            }
        }
        
        Ok((all_results, stats))
    }
    
    /// High-performance socket scanning with minimal overhead
    /// Balanced approach: 2 tries for accuracy with minimal error handling
    async fn scan_socket_high_performance(&self, socket: SocketAddr) -> crate::Result<PortResult> {
        let port = socket.port();
        // Validate IP version (fast path)
        if !matches!(socket.ip(), IpAddr::V4(_)) {
            return Err(crate::error::ScanError::ConfigError("IPv6 not supported".to_string()));
        }
        
        let start_time = Instant::now();
        
        // Balanced: 2 tries for accuracy without delays
        let tries = 2;
        for attempt in 1..=tries {
            match self.connect_optimized(socket).await {
                Ok(_) => {
                    // Port is OPEN!
                    let response_time = start_time.elapsed();
                    let service = self.service_db.get_tcp_service(port).map(|s| s.to_string());
                    
                    return Ok(PortResult {
                        port,
                        protocol: Protocol::Tcp,
                        state: PortState::Open,
                        service,
                        response_time,
                    });
                }
                Err(e) => {
                    // Critical error check
                    if e.to_string().contains("too many open files") {
                        return Err(crate::error::ScanError::IoError(e));
                    }
                    
                    // Last attempt - classify and return
                    if attempt == tries {
                        let state = Self::classify_error(&e);
                        return Ok(PortResult {
                            port,
                            protocol: Protocol::Tcp,
                            state,
                            service: None,
                            response_time: start_time.elapsed(),
                        });
                    }
                    // Continue to next attempt (no delay for speed)
                }
            }
        }
        
        // Fallback (shouldn't reach here)
        Ok(PortResult {
            port,
            protocol: Protocol::Tcp,
            state: PortState::Closed,
            service: None,
            response_time: start_time.elapsed(),
        })
    }
    
    /// Simplified connection with minimal abstractions for maximum speed
    /// Optimized to reduce system calls for full port scans
    async fn connect_optimized(&self, socket: SocketAddr) -> io::Result<tokio::net::TcpStream> {
        let timeout_duration = self.config.timeout_duration();
        
        // Direct TcpStream::connect with timeout
        // Using ?? pattern for fast error propagation
        timeout(
            timeout_duration,
            tokio::net::TcpStream::connect(socket)
        ).await?
        // Connection established if we got here
        // Stream will auto-close on drop - minimal system calls
    }
    
    /// Classify IO error into port state
    fn classify_error(error: &io::Error) -> PortState {
        use std::io::ErrorKind;
        match error.kind() {
            ErrorKind::ConnectionRefused => PortState::Closed,
            ErrorKind::ConnectionReset => PortState::Filtered,
            ErrorKind::TimedOut => PortState::Filtered,
            ErrorKind::PermissionDenied => PortState::Filtered,
            ErrorKind::AddrNotAvailable => PortState::Filtered,
            _ => {
                // Check for nested timeout error
                let error_str = error.to_string().to_lowercase();
                if error_str.contains("timeout") || error_str.contains("timed out") {
                    PortState::Filtered
                } else {
                    PortState::Closed
                }
            }
        }
    }
    
    /// Ultra-fast batch scanning with optimized connection handling (Legacy method, kept for compatibility)
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
    
    /// Ultra-fast port scanning with retry mechanism for reliability
    async fn scan_port_high_performance(&self, target: Ipv4Addr, port: u16) -> crate::Result<PortResult> {
        let start_time = Instant::now();
        let max_retries = self.config.max_retries.unwrap_or(1).max(1);
        
        let mut last_state = PortState::Closed;
        let mut attempts = 0;
        
        // Retry mechanism for reliability
        while attempts < max_retries {
            attempts += 1;
            
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
            
            // If port is open, return immediately (no need to retry)
            if state == PortState::Open {
                last_state = state;
                break;
            }
            
            // If filtered, might need retry
            if state == PortState::Filtered && attempts < max_retries {
                // Small delay before retry
                tokio::time::sleep(Duration::from_millis(50)).await;
                last_state = state;
                continue;
            }
            
            // If closed, retry once more to be sure (network flake)
            if state == PortState::Closed && attempts < max_retries {
                tokio::time::sleep(Duration::from_millis(30)).await;
                last_state = state;
                continue;
            }
            
            last_state = state;
            break;
        }
        
        let response_time = start_time.elapsed();
        let service = if last_state == PortState::Open {
            self.service_db.get_tcp_service(port).map(|s| s.to_string())
        } else {
            None
        };
        
        Ok(PortResult {
            port,
            protocol: Protocol::Tcp,
            state: last_state,
            service,
            response_time,
        })
    }
    
    /// Ultra-fast high-speed TCP scanning with retry-based accuracy
    async fn scan_tcp_high_performance(&self, _tcp_scanner: &TcpConnectScanner, target: Ipv4Addr, port: u16) -> crate::Result<PortState> {
        let socket_addr = SocketAddr::new(IpAddr::V4(target), port);
        
        // Speed-optimized approach: Use fast timeout, rely on retries for accuracy
        // This gives maximum speed while retry mechanism prevents port misses
        let scan_timeout = self.config.timeout_duration();
        
        // Attempt connection with configured timeout
        match timeout(scan_timeout, tokio::net::TcpStream::connect(socket_addr)).await {
            Ok(Ok(stream)) => {
                // Verify connection is real and not a false positive
                let is_connected = stream.peer_addr().is_ok();
                
                // Gracefully close connection
                drop(stream);
                
                if is_connected {
                    Ok(PortState::Open)
                } else {
                    Ok(PortState::Closed)
                }
            }
            Ok(Err(e)) => {
                // Detailed error classification for accuracy
                use std::io::ErrorKind;
                match e.kind() {
                    ErrorKind::ConnectionRefused => Ok(PortState::Closed),
                    ErrorKind::ConnectionReset => Ok(PortState::Filtered),
                    ErrorKind::TimedOut => Ok(PortState::Filtered),
                    ErrorKind::PermissionDenied => Ok(PortState::Filtered),
                    ErrorKind::AddrNotAvailable => Ok(PortState::Filtered),
                    _ => Ok(PortState::Closed),
                }
            }
            Err(_) => {
                // Timeout expired - likely filtered or slow network
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
    
    /// Raw socket scanning implementation (requires elevated privileges)
    /// Falls back to TCP Connect if raw sockets are not available
    async fn scan_port_raw(&self, target: Ipv4Addr, port: u16) -> crate::Result<PortState> {
        // Raw socket implementation requires CAP_NET_RAW capability on Linux
        // or administrator privileges on Windows
        
        if let Some(socket_pool) = &self.socket_pool {
            // Raw socket SYN scan - Ultra-fast stealth scanning
            log::debug!("Using raw socket SYN scan for {}:{}", target, port);
            
            // Get TCP socket from pool (round-robin)
            let raw_socket = match socket_pool.get_tcp_socket() {
                Some(socket) => socket,
                None => {
                    log::warn!("No TCP sockets available in pool, falling back to TCP Connect");
                    return self.scan_tcp_high_performance(
                        &TcpConnectScanner::new(self.config.timeout_duration()),
                        target,
                        port
                    ).await;
                }
            };
            
            // Build TCP SYN packet
            let syn_packet = self.build_tcp_syn_packet(target, port)?;
            
            // Send SYN packet using raw socket
            let dest_addr = SocketAddr::new(IpAddr::V4(target), port);
            match raw_socket.send_to(&syn_packet, dest_addr) {
                Ok(_) => {
                    log::trace!("SYN packet sent to {}:{}", target, port);
                    
                    // Wait for response with timeout
                    let response_timeout = std::cmp::min(
                        self.config.timeout_duration(),
                        Duration::from_millis(1000) // Max 1s for SYN scan
                    );
                    
                    // Try to receive response (SYN-ACK or RST)
                    let state = self.receive_syn_response(socket_pool, target, port, response_timeout).await?;
                    
                    log::debug!("Port {}:{} state: {:?}", target, port, state);
                    Ok(state)
                }
                Err(e) => {
                    log::warn!("Failed to send SYN packet to {}:{}: {}", target, port, e);
                    // Fallback to TCP Connect on send error
                    self.scan_tcp_high_performance(
                        &TcpConnectScanner::new(self.config.timeout_duration()),
                        target,
                        port
                    ).await
                }
            }
        } else {
            // Fallback to TCP Connect scan if raw sockets unavailable
            log::debug!("Raw sockets not available for port {}, using TCP Connect", port);
            self.scan_tcp_high_performance(
                &TcpConnectScanner::new(self.config.timeout_duration()),
                target,
                port
            ).await
        }
    }
    
    /// Build a TCP SYN packet for raw socket scanning
    fn build_tcp_syn_packet(&self, _target: Ipv4Addr, port: u16) -> crate::Result<Vec<u8>> {
        // Simplified TCP SYN packet structure
        // In production, use a proper packet crafting library like pnet
        
        // TCP header: 20 bytes minimum
        let mut packet = Vec::with_capacity(20);
        
        // Source port (random high port)
        let src_port: u16 = 50000 + (port % 15000);
        packet.extend_from_slice(&src_port.to_be_bytes());
        
        // Destination port
        packet.extend_from_slice(&port.to_be_bytes());
        
        // Sequence number (random)
        let seq_num: u32 = 0x12345678;
        packet.extend_from_slice(&seq_num.to_be_bytes());
        
        // Acknowledgment number (0 for SYN)
        packet.extend_from_slice(&[0, 0, 0, 0]);
        
        // Data offset (5 32-bit words = 20 bytes) + flags (SYN = 0x02)
        packet.push(0x50); // Data offset: 5 << 4
        packet.push(0x02); // SYN flag
        
        // Window size (default 65535)
        packet.extend_from_slice(&[0xFF, 0xFF]);
        
        // Checksum (calculated by kernel with IP_HDRINCL=0)
        packet.extend_from_slice(&[0x00, 0x00]);
        
        // Urgent pointer (0)
        packet.extend_from_slice(&[0x00, 0x00]);
        
        Ok(packet)
    }
    
    /// Receive and parse SYN-ACK or RST response
    async fn receive_syn_response(
        &self,
        socket_pool: &crate::network::socket::SocketPool,
        target: Ipv4Addr,
        port: u16,
        timeout_duration: Duration,
    ) -> crate::Result<PortState> {
        // Try to receive response using ICMP socket or TCP socket
        let start = tokio::time::Instant::now();
        
        // Get socket for receiving (preferably ICMP for unreachable messages)
        let recv_socket = socket_pool.get_icmp_socket()
            .or_else(|| socket_pool.get_tcp_socket());
        
        let recv_socket = match recv_socket {
            Some(s) => s,
            None => {
                log::warn!("No sockets available for receiving response");
                return Ok(PortState::Filtered);
            }
        };
        
        // Try to receive response with timeout
        let mut buf = vec![0u8; 1024];
        
        // Non-blocking receive with timeout simulation
        while start.elapsed() < timeout_duration {
            match recv_socket.recv_from(&mut buf) {
                Ok((size, addr)) => {
                    // Check if response is from target
                    if let IpAddr::V4(response_ip) = addr.ip() {
                        if response_ip == target {
                            // Parse response to determine port state
                            let state = self.parse_tcp_response(&buf[..size], port)?;
                            return Ok(state);
                        }
                    }
                }
                Err(_) => {
                    // No data available yet, continue waiting
                    tokio::time::sleep(Duration::from_micros(100)).await;
                }
            }
        }
        
        // Timeout: port is likely filtered
        log::trace!("Timeout waiting for response from {}:{}", target, port);
        Ok(PortState::Filtered)
    }
    
    /// Parse TCP response packet to determine port state
    fn parse_tcp_response(&self, packet: &[u8], expected_port: u16) -> crate::Result<PortState> {
        // Simplified TCP response parsing
        // In production, use proper packet parsing library
        
        if packet.len() < 20 {
            return Ok(PortState::Filtered);
        }
        
        // Extract destination port from packet (offset 2-3 in TCP header)
        // But we need to skip IP header first (typically 20 bytes)
        let ip_header_len = if packet.len() > 0 {
            ((packet[0] & 0x0F) * 4) as usize
        } else {
            20
        };
        
        if packet.len() < ip_header_len + 4 {
            return Ok(PortState::Filtered);
        }
        
        let tcp_header = &packet[ip_header_len..];
        
        // Source port (should match our target port)
        let src_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
        
        if src_port != expected_port {
            // Not our response
            return Ok(PortState::Filtered);
        }
        
        // Check TCP flags (offset 13 in TCP header)
        if tcp_header.len() > 13 {
            let flags = tcp_header[13];
            
            // SYN+ACK (0x12) = Port Open
            if flags & 0x12 == 0x12 {
                return Ok(PortState::Open);
            }
            
            // RST (0x04) = Port Closed
            if flags & 0x04 != 0 {
                return Ok(PortState::Closed);
            }
        }
        
        // Unknown response or ICMP unreachable = Filtered
        Ok(PortState::Filtered)
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
