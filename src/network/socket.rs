//! Raw socket management and operations

use crate::ScanError;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Raw socket wrapper for sending crafted packets
pub struct RawSocket {
    socket: Socket,
    _protocol: Protocol,
}

impl RawSocket {
    /// Create a new raw TCP socket
    pub fn new_tcp() -> crate::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::from(libc::SOCK_RAW), Some(Protocol::TCP))
            .map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    ScanError::PermissionError("Permission denied for raw socket".to_string())
                } else {
                    ScanError::NetworkError(e.to_string())
                }
            })?;
        
        // Set socket to non-blocking
        socket.set_nonblocking(true).map_err(|e| ScanError::NetworkError(e.to_string()))?;
        
        Ok(Self {
            socket,
            _protocol: Protocol::TCP,
        })
    }
    
    /// Create a new raw UDP socket
    pub fn new_udp() -> crate::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::from(libc::SOCK_RAW), Some(Protocol::UDP))
            .map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    ScanError::PermissionError("Permission denied for raw socket".to_string())
                } else {
                    ScanError::NetworkError(e.to_string())
                }
            })?;
        
        socket.set_nonblocking(true).map_err(|e| ScanError::NetworkError(e.to_string()))?;
        
        Ok(Self {
            socket,
            _protocol: Protocol::UDP,
        })
    }
    
    /// Create a new raw ICMP socket for receiving responses
    pub fn new_icmp() -> crate::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::from(libc::SOCK_RAW), Some(Protocol::ICMPV4))
            .map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    ScanError::PermissionError("Permission denied for raw socket".to_string())
                } else {
                    ScanError::NetworkError(e.to_string())
                }
            })?;
        
        socket.set_nonblocking(true).map_err(|e| ScanError::NetworkError(e.to_string()))?;
        
        Ok(Self {
            socket,
            _protocol: Protocol::ICMPV4,
        })
    }
    
    /// Send a raw packet to the specified destination
    pub fn send_to(&self, packet: &[u8], dest: SocketAddr) -> crate::Result<usize> {
        let bytes_sent = self.socket.send_to(packet, &dest.into())
            .map_err(|e| ScanError::NetworkError(e.to_string()))?;
        Ok(bytes_sent)
    }
    
    /// Receive a packet from the socket (safe implementation)
    pub fn recv_from(&self, buf: &mut [u8]) -> crate::Result<(usize, SocketAddr)> {
        use std::mem::MaybeUninit;
        
        // Create a properly initialized MaybeUninit buffer
        let mut uninit_buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); buf.len()];
        
        match self.socket.recv_from(&mut uninit_buf) {
            Ok((size, addr)) => {
                let socket_addr = match addr.as_socket() {
                    Some(addr) => addr,
                    None => return Err(ScanError::NetworkError(
                        "Invalid socket address received".to_string()
                    )),
                };
                
                // Validate received size
                if size > buf.len() {
                    return Err(ScanError::NetworkError(
                        "Received size exceeds buffer length".to_string()
                    ));
                }
                
                // Safely copy the received data to the output buffer
                for i in 0..size {
                    buf[i] = unsafe { uninit_buf[i].assume_init() };
                }
                
                Ok((size, socket_addr))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                Err(ScanError::NetworkError("Socket would block".to_string()))
            }
            Err(e) => Err(ScanError::NetworkError(format!("Socket receive error: {}", e))),
        }
    }
    
    /// Set receive timeout
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> crate::Result<()> {
        self.socket.set_read_timeout(timeout).map_err(|e| ScanError::NetworkError(e.to_string()))
    }
    
    /// Set send timeout
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> crate::Result<()> {
        self.socket.set_write_timeout(timeout).map_err(|e| ScanError::NetworkError(e.to_string()))
    }
    
    /// Get the raw file descriptor (Unix only)
    pub fn as_raw_fd(&self) -> i32 {
        self.socket.as_raw_fd()
    }
}

/// TCP connect scanner for non-raw socket scanning 
pub struct TcpConnectScanner {
    timeout: Duration,
    /// Connection pool for reusing sockets
    connection_pool: std::sync::Arc<tokio::sync::Mutex<Vec<tokio::net::TcpStream>>>,
    /// Adaptive timeout based on network conditions
    adaptive_timeout: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl TcpConnectScanner {
    pub fn new(timeout: Duration) -> Self {
        Self { 
            timeout,
            connection_pool: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
            adaptive_timeout: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(timeout.as_millis() as u64)),
        }
    }
    
    /// Perform a TCP connect scan on a single port
    pub async fn scan_port(&self, target: IpAddr, port: u16) -> crate::Result<bool> {
        let addr = SocketAddr::new(target, port);
        
        // Use adaptive timeout
        let current_timeout = Duration::from_millis(
            self.adaptive_timeout.load(std::sync::atomic::Ordering::Relaxed)
        );
        
        let start_time = std::time::Instant::now();
        
        // Fast connection attempt with optimized performance
        let result = match tokio::time::timeout(current_timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                // Connection successful - close quickly
                drop(stream);
                true
            },
            Ok(Err(_)) => false,      // Connection failed - port is closed
            Err(_) => false,          // Timeout - consider port closed/filtered
        };
        
        // Adaptive learning - adjust timeout based on response time
        let response_time = start_time.elapsed().as_millis() as u64;
        if result && response_time < 50 {
            // Very fast response - decrease timeout
            let new_timeout = std::cmp::max(current_timeout.as_millis() as u64 - 10, 50);
            self.adaptive_timeout.store(new_timeout, std::sync::atomic::Ordering::Relaxed);
        } else if !result && response_time >= current_timeout.as_millis() as u64 {
            // Timeout occurred - increase timeout
            let new_timeout = std::cmp::min(current_timeout.as_millis() as u64 + 50, 3000);
            self.adaptive_timeout.store(new_timeout, std::sync::atomic::Ordering::Relaxed);
        }
        
        Ok(result)
    }
    
    /// High-performance batch port scanning
    pub async fn scan_ports_batch(&self, target: IpAddr, ports: &[u16]) -> crate::Result<Vec<(u16, bool)>> {
        let mut tasks = Vec::new();
        
        for &port in ports {
            let scanner = self.clone();
            let task = tokio::spawn(async move {
                let result = scanner.scan_port(target, port).await.unwrap_or(false);
                (port, result)
            });
            tasks.push(task);
        }
        
        let mut results = Vec::new();
        for task in tasks {
            if let Ok(result) = task.await {
                results.push(result);
            }
        }
        
        Ok(results)
    }
}

// Clone trait for TcpConnectScanner
impl Clone for TcpConnectScanner {
    fn clone(&self) -> Self {
        Self {
            timeout: self.timeout,
            connection_pool: self.connection_pool.clone(),
            adaptive_timeout: self.adaptive_timeout.clone(),
        }
    }
}

/// UDP scanner for UDP port scanning
pub struct UdpScanner {
    timeout: Duration,
}

impl UdpScanner {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
    
    /// Perform a UDP scan on a single port
    pub async fn scan_port(&self, target: IpAddr, port: u16) -> crate::Result<bool> {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let target_addr = SocketAddr::new(target, port);
        
        let socket = UdpSocket::bind(local_addr).await.map_err(|e| ScanError::NetworkError(e.to_string()))?;
        
        // Send a UDP packet
        let probe_data = b"\x00\x00\x00\x00"; // Simple probe
        
        match tokio::time::timeout(
            self.timeout,
            socket.send_to(probe_data, target_addr)
        ).await {
            Ok(Ok(_)) => {
                // Try to receive a response
                let mut buf = [0u8; 1024];
                match tokio::time::timeout(
                    Duration::from_millis(100),
                    socket.recv_from(&mut buf)
                ).await {
                    Ok(Ok(_)) => Ok(true),  // Got response - port is open
                    Ok(Err(_)) => Ok(false), // Error receiving - likely closed
                    Err(_) => Ok(true),     // Timeout - assume open (UDP is stateless)
                }
            }
            Ok(Err(_)) => Ok(false),    // Send failed
            Err(_) => Ok(false),        // Timeout
        }
    }
}

/// Socket pool for managing multiple raw sockets
pub struct SocketPool {
    tcp_sockets: Vec<RawSocket>,
    udp_sockets: Vec<RawSocket>,
    icmp_socket: Option<RawSocket>,
    current_tcp: std::sync::atomic::AtomicUsize,
    current_udp: std::sync::atomic::AtomicUsize,
}

impl SocketPool {
    /// Create a new socket pool with the specified number of sockets
    pub fn new(tcp_count: usize, udp_count: usize) -> crate::Result<Self> {
        let mut tcp_sockets = Vec::with_capacity(tcp_count);
        let mut udp_sockets = Vec::with_capacity(udp_count);
        
        // Create TCP sockets
        for _ in 0..tcp_count {
            tcp_sockets.push(RawSocket::new_tcp()?);
        }
        
        // Create UDP sockets
        for _ in 0..udp_count {
            udp_sockets.push(RawSocket::new_udp()?);
        }
        
        // Create ICMP socket for receiving responses
        let icmp_socket = Some(RawSocket::new_icmp()?);
        
        Ok(Self {
            tcp_sockets,
            udp_sockets,
            icmp_socket,
            current_tcp: std::sync::atomic::AtomicUsize::new(0),
            current_udp: std::sync::atomic::AtomicUsize::new(0),
        })
    }
    
    /// Get the next available TCP socket (round-robin)
    pub fn get_tcp_socket(&self) -> Option<&RawSocket> {
        if self.tcp_sockets.is_empty() {
            return None;
        }
        
        let index = self.current_tcp.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.tcp_sockets.len();
        self.tcp_sockets.get(index)
    }
    
    /// Get the next available UDP socket (round-robin)
    pub fn get_udp_socket(&self) -> Option<&RawSocket> {
        if self.udp_sockets.is_empty() {
            return None;
        }
        
        let index = self.current_udp.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.udp_sockets.len();
        self.udp_sockets.get(index)
    }
    
    /// Get the ICMP socket for receiving responses
    pub fn get_icmp_socket(&self) -> Option<&RawSocket> {
        self.icmp_socket.as_ref()
    }
}