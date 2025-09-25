//! Ultra-fast scanning engine inspired by RustScan but enhanced
//! This engine combines RustScan's parallelism with additional optimizations

use crate::config::ScanConfig;
use crate::network::{
    PortResult, PortState, Protocol, ScanTechnique,
    protocol::{NetworkUtils, ServiceDatabase},
};
use crate::scanner::{ScanResult, ScanStats};
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;
use tokio::io::AsyncWriteExt;
use log::{debug, info, warn};

/// Socket iterator for efficient memory management
pub struct SocketIterator<'a> {
    ips: &'a [IpAddr],
    ports: &'a [u16],
    current_ip_idx: usize,
    current_port_idx: usize,
}

impl<'a> SocketIterator<'a> {
    pub fn new(ips: &'a [IpAddr], ports: &'a [u16]) -> Self {
        Self {
            ips,
            ports,
            current_ip_idx: 0,
            current_port_idx: 0,
        }
    }
}

impl Iterator for SocketIterator<'_> {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_port_idx >= self.ports.len() {
            return None;
        }

        let ip = self.ips[self.current_ip_idx];
        let port = self.ports[self.current_port_idx];
        let socket = SocketAddr::new(ip, port);

        // Advance to next IP, then next port
        self.current_ip_idx += 1;
        if self.current_ip_idx >= self.ips.len() {
            self.current_ip_idx = 0;
            self.current_port_idx += 1;
        }

        Some(socket)
    }
}

/// Ultra-fast scanning engine combining RustScan's best features
#[derive(Clone)]
pub struct UltraEngine {
    config: ScanConfig,
    service_db: ServiceDatabase,
    stats: Arc<Mutex<PerformanceStats>>,
    open_ports_cache: Arc<Mutex<HashSet<SocketAddr>>>,
    adaptive_timeout: Arc<AtomicU64>,
    successful_scans: Arc<AtomicUsize>,
    failed_scans: Arc<AtomicUsize>,
}

#[derive(Debug, Default, Clone)]
pub struct PerformanceStats {
    total_scans: u64,
    successful_connections: u64,
    failed_connections: u64,
    average_response_time: Duration,
    last_optimization: Option<Instant>,
}

impl UltraEngine {
    /// Create a new ultra-fast scanning engine
    pub async fn new(config: ScanConfig) -> crate::Result<Self> {
        config.validate()?;
        
        let service_db = ServiceDatabase::new();
        let initial_timeout = config.timeout;
        
        Ok(Self {
            config,
            service_db,
            stats: Arc::new(Mutex::new(PerformanceStats::default())),
            open_ports_cache: Arc::new(Mutex::new(HashSet::new())),
            adaptive_timeout: Arc::new(AtomicU64::new(initial_timeout)),
            successful_scans: Arc::new(AtomicUsize::new(0)),
            failed_scans: Arc::new(AtomicUsize::new(0)),
        })
    }
    
    /// Main scan function using RustScan's proven algorithm
    pub async fn scan(&self) -> crate::Result<ScanResult> {
        let start_time = Instant::now();
        info!("🚀 Ultra-fast scan starting with {} threads", self.config.threads);
        
        // Parse targets
        let target_ips = NetworkUtils::parse_cidr(&self.config.target)?;
        let ports = &self.config.ports;
        
        info!("📡 Scanning {} IPs × {} ports = {} total targets", 
              target_ips.len(), ports.len(), target_ips.len() * ports.len());
        
        // Convert Ipv4Addr to IpAddr
        let ip_addrs: Vec<IpAddr> = target_ips.iter()
            .map(|&ip| IpAddr::V4(ip))
            .collect();
        
        // RustScan-style socket iterator
        let mut socket_iter = SocketIterator::new(&ip_addrs, ports);
        let mut open_sockets = Vec::new();
        let mut futures = FuturesUnordered::new();
        
        // Initial batch - fill up to batch_size
        let batch_size = self.calculate_optimal_batch_size();
        for _ in 0..batch_size {
            if let Some(socket) = socket_iter.next() {
                futures.push(self.scan_socket_ultra(socket));
            } else {
                break;
            }
        }
        
        // Process futures and keep adding new ones
        while let Some(result) = futures.next().await {
            // Add next socket to maintain batch size
            if let Some(socket) = socket_iter.next() {
                futures.push(self.scan_socket_ultra(socket));
            }
            
            match result {
                Ok(Some(port_result)) => {
                    if port_result.state == PortState::Open {
                        // Real-time notification before moving port_result
                        if self.config.realtime_notifications {
                            println!("🟢 Open: {}:{} - {} ({:?})", 
                                    self.config.target, 
                                    port_result.port,
                                    port_result.service.as_ref().unwrap_or(&"unknown".to_string()),
                                    port_result.response_time);
                        }
                        
                        open_sockets.push(port_result);
                        self.successful_scans.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(None) => {
                    self.failed_scans.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    debug!("Socket scan error: {}", e);
                    self.failed_scans.fetch_add(1, Ordering::Relaxed);
                }
            }
            
            // Adaptive timeout adjustment
            self.adjust_timeout_dynamically().await;
        }
        
        let scan_duration = start_time.elapsed();
        info!("✅ Ultra scan completed in {:?}", scan_duration);
        info!("📊 Found {} open ports out of {} scanned", 
              open_sockets.len(), target_ips.len() * ports.len());
        
        // Build result
        let mut result = ScanResult::new(self.config.target.clone(), self.config.clone());
        for port_result in open_sockets {
            result.add_port_result(port_result);
        }
        result.set_duration(scan_duration);
        
        Ok(result)
    }
    
    /// Scan a single socket with multiple retry attempts (RustScan-style)
    async fn scan_socket_ultra(&self, socket: SocketAddr) -> crate::Result<Option<PortResult>> {
        let start_time = Instant::now();
        let port = socket.port();
        
        // Multiple tries like RustScan
        let max_tries = 3;
        let current_timeout = Duration::from_millis(
            self.adaptive_timeout.load(Ordering::Relaxed)
        );
        
        for attempt in 1..=max_tries {
            // Adaptive timeout per attempt
            let attempt_timeout = if attempt == 1 {
                current_timeout
            } else {
                // Increase timeout for retries
                Duration::from_millis(current_timeout.as_millis() as u64 * attempt)
            };
            
            match self.try_connect(socket, attempt_timeout).await {
                Ok(true) => {
                    // Port is definitely open
                    let response_time = start_time.elapsed();
                    let service = self.service_db.get_tcp_service(port)
                        .map(|s| s.to_string());
                    
                    return Ok(Some(PortResult {
                        port,
                        protocol: Protocol::Tcp,
                        state: PortState::Open,
                        service,
                        response_time,
                    }));
                }
                Ok(false) => {
                    // Port is definitely closed
                    return Ok(None);
                }
                Err(_) if attempt < max_tries => {
                    // Timeout or error, retry
                    debug!("Retry {} for port {}", attempt, port);
                    continue;
                }
                Err(e) => {
                    // Final attempt failed
                    debug!("Port {} failed after {} attempts: {}", port, max_tries, e);
                    return Ok(None);
                }
            }
        }
        
        Ok(None)
    }
    
    /// Try to connect to a socket with timeout
    async fn try_connect(&self, socket: SocketAddr, timeout_duration: Duration) -> crate::Result<bool> {
        match timeout(timeout_duration, TcpStream::connect(socket)).await {
            Ok(Ok(mut stream)) => {
                // Successfully connected - shutdown gracefully
                let _ = stream.shutdown().await;
                Ok(true)
            }
            Ok(Err(e)) => {
                // Connection refused or other error - port is closed
                debug!("Connection error for {}: {}", socket, e);
                Ok(false)
            }
            Err(_) => {
                // Timeout - might be filtered or slow
                Err(crate::error::ScanError::Timeout(
                    format!("Timeout scanning {}", socket)
                ))
            }
        }
    }
    
    /// Calculate optimal batch size based on system and network conditions
    fn calculate_optimal_batch_size(&self) -> usize {
        let base_batch = self.config.batch_size.unwrap_or(5000);
        let thread_count = self.config.threads;
        
        // RustScan-style calculation
        let optimal = std::cmp::min(
            base_batch,
            thread_count * 10 // Allow 10x oversubscription
        );
        
        // Ensure minimum batch size for performance
        std::cmp::max(optimal, 1000)
    }
    
    /// Dynamically adjust timeout based on success rate
    async fn adjust_timeout_dynamically(&self) {
        let successful = self.successful_scans.load(Ordering::Relaxed);
        let failed = self.failed_scans.load(Ordering::Relaxed);
        let total = successful + failed;
        
        if total < 100 {
            return; // Not enough data yet
        }
        
        let success_rate = successful as f64 / total as f64;
        let current_timeout = self.adaptive_timeout.load(Ordering::Relaxed);
        
        let new_timeout = if success_rate < 0.3 && current_timeout < 5000 {
            // Very low success rate - increase timeout
            std::cmp::min(current_timeout + 500, 5000)
        } else if success_rate > 0.8 && current_timeout > 100 {
            // High success rate - decrease timeout for speed
            std::cmp::max(current_timeout - 100, 100)
        } else {
            current_timeout
        };
        
        if new_timeout != current_timeout {
            self.adaptive_timeout.store(new_timeout, Ordering::Relaxed);
            debug!("Adjusted timeout to {}ms (success rate: {:.1}%)", 
                  new_timeout, success_rate * 100.0);
        }
    }
    
    /// UDP scanning support (RustScan-style)
    pub async fn scan_udp(&self, socket: SocketAddr) -> crate::Result<bool> {
        let local_addr = match socket {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        
        let udp_socket = UdpSocket::bind(local_addr).await?;
        udp_socket.connect(socket).await?;
        
        // Send UDP probe
        let probe = b"\x00\x00";
        udp_socket.send(probe).await?;
        
        // Wait for response
        let mut buf = [0u8; 1024];
        match timeout(Duration::from_millis(500), udp_socket.recv(&mut buf)).await {
            Ok(Ok(size)) if size > 0 => Ok(true),
            _ => Ok(false),
        }
    }
}