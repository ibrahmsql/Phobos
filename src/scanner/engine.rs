//! Main scanning engine implementation

use crate::config::ScanConfig;
use crate::network::{
    packet::{PacketParser, TcpPacketBuilder, TcpResponse, UdpPacketBuilder},
    protocol::{NetworkUtils, RateLimiter, ResponseAnalyzer, ServiceDatabase},
    socket::{SocketPool, TcpConnectScanner, UdpScanner},
    PortResult, PortState, Protocol, ScanTechnique,
};
use crate::scanner::{create_batches, ScanBatch, ScanProgress, ScanResult, ScanStats};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::timeout;

/// Main scanning engine
pub struct ScanEngine {
    config: ScanConfig,
    socket_pool: Option<SocketPool>,
    tcp_scanner: Option<TcpConnectScanner>,
    udp_scanner: Option<UdpScanner>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    service_db: ServiceDatabase,
    response_analyzer: ResponseAnalyzer,
}

impl ScanEngine {
    /// Create a new scan engine with the given configuration
    pub async fn new(config: ScanConfig) -> crate::Result<Self> {
        config.validate()?;
        
        let technique = config.technique;
        let timeout_duration = config.timeout_duration();
        
        // Initialize components with automatic fallback for Linux compatibility
        let (socket_pool, tcp_scanner, udp_scanner) = if technique.requires_raw_socket() {
            // Try to create raw socket pool, fallback to TCP Connect if failed
            match SocketPool::new(50, 25) {
                Ok(pool) => {
                    log::info!("Raw socket pool initialized successfully");
                    (Some(pool), None, None)
                }
                Err(e) => {
                    log::warn!("Raw socket initialization failed: {}. Falling back to TCP Connect scan.", e);
                    
                    if cfg!(target_os = "linux") {
                        eprintln!("\x1b[33m⚠️  Raw socket access failed on Linux\x1b[0m");
                        eprintln!("\x1b[36m🔧 Quick fixes:\x1b[0m");
                        eprintln!("   • sudo setcap cap_net_raw,cap_net_admin+eip $(which phobos)");
                        eprintln!("   • sudo ./install_linux.sh (automatic setup)");
                        eprintln!("   • sudo phobos [your-args]");
                        eprintln!("\x1b[32m✓ Continuing with TCP Connect scan...\x1b[0m\n");
                    }
                    
                    // Automatic fallback to TCP Connect
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
        
        Ok(Self {
            config,
            socket_pool,
            tcp_scanner,
            udp_scanner,
            rate_limiter,
            service_db,
            response_analyzer,
        })
    }
    
    /// Perform the main scan operation
    pub async fn scan(&self) -> crate::Result<ScanResult> {
        let start_time = Instant::now();
        
        // Parse target IPs
        let target_ips = NetworkUtils::parse_cidr(&self.config.target)?;
        
        let mut final_result = ScanResult::new(self.config.target.clone(), self.config.clone());
        
        // Scan each target IP
        for target_ip in target_ips {
            let result = self.scan_single_host(target_ip).await?;
            
            // Merge results
            final_result.open_ports.extend(result.open_ports);
            final_result.closed_ports.extend(result.closed_ports);
            final_result.filtered_ports.extend(result.filtered_ports);
            final_result.port_results.extend(result.port_results);
            
            // Update stats
            final_result.stats.packets_sent += result.stats.packets_sent;
            final_result.stats.packets_received += result.stats.packets_received;
            final_result.stats.timeouts += result.stats.timeouts;
            final_result.stats.errors += result.stats.errors;
        }
        
        final_result.set_duration(start_time.elapsed());
        final_result.sort_ports();
        
        Ok(final_result)
    }
    
    /// Scan a single host
    async fn scan_single_host(&self, target_ip: Ipv4Addr) -> crate::Result<ScanResult> {
        let start_time = Instant::now();
        let mut result = ScanResult::new(target_ip.to_string(), self.config.clone());
        
        // Create batches for parallel processing
        let batch_size = self.config.batch_size();
        let batches = create_batches(self.config.ports.clone(), target_ip, batch_size);
        
        // Create semaphore to limit concurrent operations with aggressive settings
        let semaphore = Arc::new(Semaphore::new(self.config.threads * 2)); // 2x more aggressive for better performance
        
        // Result collector
        let result_collector = Arc::new(Mutex::new(Vec::new()));
        
        // Progress tracking
        let progress = Arc::new(Mutex::new(ScanProgress::new(self.config.ports.len())));
        
        // Channel for collecting statistics
        let (stats_tx, mut stats_rx) = mpsc::unbounded_channel::<ScanStats>();
        
        // Spawn tasks for each batch
        let mut handles = Vec::new();
        
        for batch in batches {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let collector = result_collector.clone();
            let progress_tracker = progress.clone();
            let stats_sender = stats_tx.clone();
            let engine = self.clone_for_task();
            
            let handle = tokio::spawn(async move {
                let _permit = permit; // Keep permit alive
                let batch_result = engine.scan_batch(batch, progress_tracker).await;
                
                match batch_result {
                    Ok((port_results, batch_stats)) => {
                        // Collect results
                        {
                            let mut collector = collector.lock().await;
                            collector.extend(port_results);
                        }
                        
                        // Send stats
                        let _ = stats_sender.send(batch_stats);
                    }
                    Err(e) => {
                        log::error!("Batch scan failed: {}", e);
                    }
                }
            });
            
            handles.push(handle);
        }
        
        // Close stats channel
        drop(stats_tx);
        
        // Collect statistics in background
        let stats_handle = tokio::spawn(async move {
            let mut combined_stats = ScanStats::new();
            
            while let Some(batch_stats) = stats_rx.recv().await {
                combined_stats.packets_sent += batch_stats.packets_sent;
                combined_stats.packets_received += batch_stats.packets_received;
                combined_stats.timeouts += batch_stats.timeouts;
                combined_stats.errors += batch_stats.errors;
                
                if batch_stats.min_response_time < combined_stats.min_response_time {
                    combined_stats.min_response_time = batch_stats.min_response_time;
                }
                if batch_stats.max_response_time > combined_stats.max_response_time {
                    combined_stats.max_response_time = batch_stats.max_response_time;
                }
            }
            
            combined_stats.calculate_packet_loss();
            combined_stats
        });
        
        // Wait for all tasks to complete
        for handle in handles {
            let _ = handle.await;
        }
        
        // Get final statistics
        let stats = stats_handle.await.unwrap();
        
        // Collect all results
        let port_results = {
            let collector = result_collector.lock().await;
            collector.clone()
        };
        
        // Process results
        for port_result in port_results {
            result.add_port_result(port_result);
        }
        
        result.set_duration(start_time.elapsed());
        result.update_stats(stats);
        
        Ok(result)
    }
    
    /// Scan a batch of ports with adaptive optimizations
    async fn scan_batch(
        &self,
        batch: ScanBatch,
        progress: Arc<Mutex<ScanProgress>>,
    ) -> crate::Result<(Vec<PortResult>, ScanStats)> {
        let mut results = Vec::new();
        let mut stats = ScanStats::new();
        let _batch_start = Instant::now();
        let mut response_times = Vec::new();
        
        // High-performance batch processing with parallel scanning
        if self.config.technique == ScanTechnique::Connect && batch.ports.len() > 10 {
            // Parallel processing for large batches
            let mut tasks = Vec::new();
            
            for port in batch.ports {
                let target = batch.target;
                let scanner = self.tcp_scanner.clone();
                let service_db = self.service_db.clone();
                
                let task = tokio::spawn(async move {
                    let start_time = Instant::now();
                    
                    if let Some(ref scanner) = scanner {
                        let is_open = scanner.scan_port(IpAddr::V4(target), port).await.unwrap_or(false);
                        let response_time = start_time.elapsed();
                        let state = if is_open { PortState::Open } else { PortState::Closed };
                        
                        let mut result = PortResult::new(port, Protocol::Tcp, state)
                            .with_response_time(response_time);
                        
                        // Service detection
                        if state == PortState::Open {
                            if let Some(service_name) = service_db.get_tcp_service(port) {
                                result = result.with_service(service_name.to_string());
                            }
                            
                            // Real-time open port notification
                            let service_info = if let Some(ref service) = result.service {
                                format!(" ({})", service)
                            } else {
                                String::new()
                            };
                            
                            println!("\x1b[38;5;208mOPEN: {}:{}{} [{}ms]\x1b[0m", 
                                target, port, service_info, response_time.as_millis());
                        }
                        
                        (result, response_time)
                    } else {
                        let result = PortResult::new(port, Protocol::Tcp, PortState::Closed);
                        (result, Duration::from_millis(0))
                    }
                });
                tasks.push(task);
            }
            
            // Collect results from parallel tasks
             for task in tasks {
                 if let Ok((port_result, response_time)) = task.await {
                     stats.packets_sent += 1;
                     if port_result.state == PortState::Open {
                         stats.packets_received += 1;
                     }
                     stats.update_response_time(response_time);
                     response_times.push(response_time.as_millis() as u64);
                     
                     // Store port number before moving result
                     let port_num = port_result.port;
                     results.push(port_result);
                     
                     // Update progress tracking
                     {
                         let mut progress = progress.lock().await;
                         progress.update(port_num);
                     }
                 }
             }
        } else {
            // Sequential processing for small batches or raw socket techniques
            for port in batch.ports {
                // Rate limiting
                {
                    let mut limiter = self.rate_limiter.lock().await;
                    while !limiter.can_send() {
                        let delay = limiter.delay_until_next();
                        if delay > Duration::from_millis(0) {
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
                
                // Scan the port
                let port_result = self.scan_port(batch.target, port).await?;
                
                // Real-time open port notification
                if port_result.state == PortState::Open {
                    let service_info = if let Some(ref service) = port_result.service {
                        format!(" ({})", service)
                    } else {
                        String::new()
                    };
                    
                    println!("\x1b[38;5;208mOPEN: {}:{}{} [{}ms]\x1b[0m", 
                        batch.target, port, service_info, port_result.response_time.as_millis());
                }
                
                // Update statistics
                stats.packets_sent += 1;
                if port_result.state == PortState::Open {
                    stats.packets_received += 1;
                }
                stats.update_response_time(port_result.response_time);
                response_times.push(port_result.response_time.as_millis() as u64);
                
                results.push(port_result);
                
                // Update progress
                {
                    let mut progress = progress.lock().await;
                    progress.update(port);
                }
            }
        }
        
        Ok((results, stats))
    }
    
    /// Scan a single port with enhanced diagnostic logging
    async fn scan_port(&self, target: Ipv4Addr, port: u16) -> crate::Result<PortResult> {
        let start_time = Instant::now();
        
        // Enhanced timeout handling
        let mut retry_count = 0;
        let max_retries = 0;
        
        let state = loop {
            let attempt_start = Instant::now();
            
            let result = match self.config.technique {
                ScanTechnique::Connect => {
                    if let Some(ref scanner) = self.tcp_scanner {
                        match scanner.scan_port(IpAddr::V4(target), port).await {
                            Ok(is_open) => Ok(if is_open { PortState::Open } else { PortState::Closed }),
                            Err(e) => Err(e),
                        }
                    } else {
                        return Err(crate::ScanError::InvalidTarget("TCP scanner not initialized".to_string()));
                    }
                }
                ScanTechnique::Udp => {
                    if let Some(ref scanner) = self.udp_scanner {
                        match scanner.scan_port(IpAddr::V4(target), port).await {
                            Ok(is_open) => Ok(if is_open { PortState::Open } else { PortState::Closed }),
                            Err(e) => Err(e),
                        }
                    } else {
                        return Err(crate::ScanError::InvalidTarget("UDP scanner not initialized".to_string()));
                    }
                }
                _ => {
                    // Raw socket techniques
                    self.scan_port_raw(target, port).await
                }
            };
            
            let attempt_time = attempt_start.elapsed();
            
            match result {
                Ok(state) => {
                    break state;
                }
                Err(_e) => {
                    // Retry logic
                    if retry_count < max_retries {
                        retry_count += 1;
                        // Small delay before retry
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    } else {
                        // Max retries exceeded, treat as filtered/closed
                        break PortState::Filtered;
                    }
                }
            }
        };
        
        let response_time = start_time.elapsed();
        let protocol = if self.config.technique.is_tcp() { Protocol::Tcp } else { Protocol::Udp };
        
        let mut result = PortResult::new(port, protocol, state).with_response_time(response_time);
        
        // Add service information if port is open
        if state == PortState::Open {
            let service = match protocol {
                Protocol::Tcp => self.service_db.get_tcp_service(port),
                Protocol::Udp => self.service_db.get_udp_service(port),
                _ => None,
            };
            
            if let Some(service_name) = service {
                result = result.with_service(service_name.to_string());
            }
        }
        

        
        Ok(result)
    }
    
    /// Scan a port using raw sockets with automatic fallback
    async fn scan_port_raw(&self, target: Ipv4Addr, port: u16) -> crate::Result<PortState> {
        // Check if we have a socket pool (raw socket mode)
        if let Some(socket_pool) = self.socket_pool.as_ref() {
            // Try raw socket scan
            if self.config.technique.is_tcp() {
                self.scan_tcp_raw(socket_pool, target, port).await
            } else {
                self.scan_udp_raw(socket_pool, target, port).await
            }
        } else {
            // Fallback to TCP Connect scan if raw sockets not available
            if self.config.technique.is_tcp() {
                if let Some(ref scanner) = self.tcp_scanner {
                    let is_open = scanner.scan_port(IpAddr::V4(target), port).await?;
                    Ok(if is_open { PortState::Open } else { PortState::Closed })
                } else {
                    // Last resort: create a temporary TCP scanner
                    let temp_scanner = TcpConnectScanner::new(self.config.timeout_duration());
                    let is_open = temp_scanner.scan_port(IpAddr::V4(target), port).await?;
                    Ok(if is_open { PortState::Open } else { PortState::Closed })
                }
            } else {
                // UDP fallback
                if let Some(ref scanner) = self.udp_scanner {
                    let is_open = scanner.scan_port(IpAddr::V4(target), port).await?;
                    Ok(if is_open { PortState::Open } else { PortState::Closed })
                } else {
                    // Last resort: create a temporary UDP scanner
                    let temp_scanner = UdpScanner::new(self.config.timeout_duration());
                    let is_open = temp_scanner.scan_port(IpAddr::V4(target), port).await?;
                    Ok(if is_open { PortState::Open } else { PortState::Closed })
                }
            }
        }
    }
    
    /// TCP raw socket scan
    async fn scan_tcp_raw(
        &self,
        socket_pool: &SocketPool,
        target: Ipv4Addr,
        port: u16,
    ) -> crate::Result<PortState> {
        let socket = socket_pool.get_tcp_socket()
            .ok_or_else(|| crate::ScanError::InvalidTarget("No TCP socket available".to_string()))?;
        
        let source_ip = NetworkUtils::get_local_ip()?;
        let source_port = NetworkUtils::random_source_port();
        
        // Build packet based on technique
        let packet = TcpPacketBuilder::new(source_ip, target, source_port, port)
            .flags(self.config.technique.tcp_flags())
            .build();
        
        // Send packet
        let dest_addr = SocketAddr::new(IpAddr::V4(target), port);
        socket.send_to(&packet, dest_addr)?;
        
        // Wait for response
        let response = self.wait_for_tcp_response(socket_pool, target, port, source_port).await;
        
        Ok(self.response_analyzer.analyze_tcp_response(response.as_ref(), response.is_none()))
    }
    
    /// UDP raw socket scan
    async fn scan_udp_raw(
        &self,
        socket_pool: &SocketPool,
        target: Ipv4Addr,
        port: u16,
    ) -> crate::Result<PortState> {
        let socket = socket_pool.get_udp_socket()
            .ok_or_else(|| crate::ScanError::InvalidTarget("No UDP socket available".to_string()))?;
        
        let source_ip = NetworkUtils::get_local_ip()?;
        let source_port = NetworkUtils::random_source_port();
        
        // Build UDP packet with probe data
        let packet = UdpPacketBuilder::new(source_ip, target, source_port, port)
            .payload(vec![0x00, 0x00, 0x00, 0x00]) // Simple probe
            .build();
        
        // Send packet
        let dest_addr = SocketAddr::new(IpAddr::V4(target), port);
        socket.send_to(&packet, dest_addr)?;
        
        // Wait for response or ICMP unreachable
        let (udp_response, icmp_unreachable) = self.wait_for_udp_response(socket_pool, target, port).await;
        
        Ok(self.response_analyzer.analyze_udp_response(
            udp_response.as_ref(),
            icmp_unreachable,
            udp_response.is_none() && !icmp_unreachable,
        ))
    }
    
    /// Wait for TCP response
    async fn wait_for_tcp_response(
        &self,
        socket_pool: &SocketPool,
        target: Ipv4Addr,
        port: u16,
        source_port: u16,
    ) -> Option<TcpResponse> {
        let socket = socket_pool.get_tcp_socket()?;
        let mut buf = [0u8; 1500];
        
        let timeout_duration = self.config.timeout_duration();
        
        match timeout(timeout_duration, async {
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((size, _)) => {
                        if let Some(response) = PacketParser::parse_tcp_response(&buf[..size]) {
                            // Check if this response is for our probe
                            if response.source_ip == target && 
                               response.source_port == port && 
                               response.dest_port == source_port {
                                return Some(response);
                            }
                        }
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
            }
        }).await {
            Ok(response) => response,
            Err(_) => None, // Timeout
        }
    }
    
    /// Wait for UDP response or ICMP unreachable
    async fn wait_for_udp_response(
        &self,
        _socket_pool: &SocketPool,
        _target: Ipv4Addr,
        _port: u16,
    ) -> (Option<crate::network::packet::UdpResponse>, bool) {
        let timeout_duration = self.config.timeout_duration();
        
        match timeout(timeout_duration, async {
            // TODO: Implement UDP response and ICMP unreachable detection
            // This is a simplified version
            tokio::time::sleep(Duration::from_millis(100)).await;
            (None, false)
        }).await {
            Ok(result) => result,
            Err(_) => (None, false), // Timeout
        }
    }
    
    /// Clone engine for task spawning with automatic fallback
    fn clone_for_task(&self) -> Self {
        let technique = self.config.technique;
        let timeout_duration = self.config.timeout_duration();
        
        // Initialize components with same fallback logic as main engine
        let (socket_pool, tcp_scanner, udp_scanner) = if technique.requires_raw_socket() {
            // Try to create raw socket pool, fallback to TCP Connect if failed
            match SocketPool::new(10, 5) {
                Ok(pool) => (Some(pool), None, None),
                Err(_) => {
                    // Silent fallback for task clones
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
        
        Self {
            config: self.config.clone(),
            socket_pool,
            tcp_scanner,
            udp_scanner,
            rate_limiter: self.rate_limiter.clone(),
            service_db: ServiceDatabase::new(),
            response_analyzer: ResponseAnalyzer::new(self.config.technique),
        }
    }
}