//! Raw socket management and operations

use crate::ScanError;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Raw socket wrapper for sending crafted packets
#[derive(Debug)]
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
#[derive(Debug)]
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
        
        // Use adaptive timeout with minimum safety threshold
        let base_timeout = self.adaptive_timeout.load(std::sync::atomic::Ordering::Relaxed);
        let current_timeout = Duration::from_millis(std::cmp::max(base_timeout, 200)); // Minimum 200ms
        
        let start_time = std::time::Instant::now();
        
        // Connection attempt with retry logic for timeout cases
        let mut result = false;
        let mut attempts = 0;
        let max_attempts = if current_timeout.as_millis() < 500 { 2 } else { 1 };
        
        while attempts < max_attempts && !result {
            let attempt_timeout = if attempts > 0 {
                // Second attempt gets longer timeout
                Duration::from_millis(current_timeout.as_millis() as u64 * 2)
            } else {
                current_timeout
            };
            
            match tokio::time::timeout(attempt_timeout, tokio::net::TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    // Connection successful - close quickly
                    drop(stream);
                    result = true;
                    break;
                },
                Ok(Err(_)) => {
                    // Connection failed - port is definitely closed
                    break;
                }
                Err(_) => {
                    // Timeout - try again if we have attempts left
                    attempts += 1;
                    if attempts < max_attempts {
                        // Small delay before retry
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        }
        
        // Adaptive learning with better timeout management
        let total_response_time = start_time.elapsed().as_millis() as u64;
        
        if result {
            // Successful connection - optimize timeout based on actual response time
            if total_response_time < 50 {
                // Very fast response - can decrease timeout slightly
                let new_timeout = std::cmp::max(base_timeout.saturating_sub(25), 200);
                self.adaptive_timeout.store(new_timeout, std::sync::atomic::Ordering::Relaxed);
            } else if total_response_time > current_timeout.as_millis() as u64 {
                // Response was slower than expected - increase timeout
                let new_timeout = std::cmp::min(base_timeout + 100, 3000);
                self.adaptive_timeout.store(new_timeout, std::sync::atomic::Ordering::Relaxed);
            }
        } else if attempts >= max_attempts {
            // Multiple timeouts occurred - significantly increase timeout
            let new_timeout = std::cmp::min(base_timeout + 300, 5000);
            self.adaptive_timeout.store(new_timeout, std::sync::atomic::Ordering::Relaxed);
        }
        
        Ok(result)
    }

    /// Confirm an open TCP port by repeating the connect sequence.
    /// Returns true only if all confirmation attempts succeed.
    pub async fn confirm_open(&self, target: IpAddr, port: u16, attempts: u8, delay: Duration) -> crate::Result<bool> {
        if attempts <= 1 {
            return self.scan_port(target, port).await;
        }
        for i in 0..attempts {
            let ok = self.scan_port(target, port).await?;
            if !ok {
                return Ok(false);
            }
            if i + 1 < attempts {
                tokio::time::sleep(delay).await;
            }
        }
        Ok(true)
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
#[derive(Debug)]
pub struct UdpScanner {
    timeout: Duration,
    /// Service-specific probes for better UDP detection
    service_probes: std::collections::HashMap<u16, Vec<u8>>,
    /// ICMP socket for unreachable detection
    icmp_socket: Option<RawSocket>,
}

impl UdpScanner {
    pub fn new(timeout: Duration) -> Self {
        let mut service_probes = std::collections::HashMap::new();
        
        // Add service-specific UDP probes
        service_probes.insert(53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01".to_vec()); // DNS query
        service_probes.insert(123, b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()); // NTP
        service_probes.insert(161, b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00".to_vec()); // SNMP
        service_probes.insert(69, b"\x00\x01example.txt\x00netascii\x00".to_vec()); // TFTP
        service_probes.insert(514, b"<30>Jan 1 00:00:00 test: UDP probe\n".to_vec()); // Syslog
        service_probes.insert(1900, b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\nMX: 3\r\n\r\n".to_vec()); // UPnP SSDP
        
        let icmp_socket = RawSocket::new_icmp().ok();
        
        Self { 
            timeout,
            service_probes,
            icmp_socket,
        }
    }
    
    /// Perform a UDP scan on a single port with service-specific probes
    pub async fn scan_port(&self, target: IpAddr, port: u16) -> crate::Result<bool> {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let target_addr = SocketAddr::new(target, port);
        
        let socket = UdpSocket::bind(local_addr).await.map_err(|e| ScanError::NetworkError(e.to_string()))?;
        
        // Get service-specific probe or use generic probe
        let probe_data = self.service_probes.get(&port)
            .map(|p| p.as_slice())
            .unwrap_or(b"\x00\x00\x00\x00"); // Generic probe
        
        let _start_time = std::time::Instant::now();
        
        // UDP scanning with retry logic
        let mut attempts = 0;
        let max_attempts = 2; // UDP needs more attempts due to unreliable nature
        
        while attempts < max_attempts {
            // Send UDP probe with timeout
            let send_result = tokio::time::timeout(
                self.timeout,
                socket.send_to(probe_data, target_addr)
            ).await;
            
            match send_result {
                Ok(Ok(_)) => {
                    // Wait for UDP response or ICMP unreachable
                    let (udp_response, icmp_unreachable) = self.wait_for_response(&socket, target, port).await;
                    
                    if udp_response {
                        return Ok(true);  // Got UDP response - port is definitely open
                    } else if icmp_unreachable {
                        return Ok(false); // Got ICMP unreachable - port is closed
                    }
                    // No response on this attempt - try again if we have attempts left
                }
                Ok(Err(_)) => return Ok(false),    // Send failed - port likely closed
                Err(_) => {}
            }
            
            attempts += 1;
            if attempts < max_attempts {
                // Small delay before retry
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        
        // No definitive response after all attempts
        // For common services, assume closed if no response
        // For other ports, assume open|filtered (conservative approach)
        match port {
            53 | 123 | 161 | 514 | 69 | 137 | 138 | 139 => Ok(false), // These usually respond if open
            _ => Ok(true), // Other ports might be open but not responding
        }
    }
    
    /// Wait for UDP response or ICMP unreachable message
    async fn wait_for_response(&self, socket: &UdpSocket, target: IpAddr, port: u16) -> (bool, bool) {
        let mut udp_response = false;
        let mut icmp_unreachable = false;
        
        // Create tasks for UDP response and ICMP monitoring
        let udp_task = async {
            let mut buf = [0u8; 1024];
            match tokio::time::timeout(
                Duration::from_millis(500),
                socket.recv_from(&mut buf)
            ).await {
                Ok(Ok((len, addr))) => {
                    // Validate response is from target
                    if addr.ip() == target && len > 0 {
                        return true;
                    }
                }
                _ => {}
            }
            false
        };
        
        let icmp_task = async {
            if let Some(ref icmp_socket) = self.icmp_socket {
                let mut buf = [0u8; 1500];
                match tokio::time::timeout(
                    Duration::from_millis(1000),
                    async {
                        loop {
                            if let Ok((len, _)) = icmp_socket.recv_from(&mut buf) {
                                if self.is_icmp_unreachable(&buf[..len], target, port) {
                                    return true;
                                }
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                ).await {
                    Ok(result) => result,
                    Err(_) => false,
                }
            } else {
                false
            }
        };
        
        // Race between UDP response and ICMP unreachable
        tokio::select! {
            udp_result = udp_task => {
                udp_response = udp_result;
            }
            icmp_result = icmp_task => {
                icmp_unreachable = icmp_result;
            }
        }
        
        (udp_response, icmp_unreachable)
    }
    
    /// Check if ICMP packet indicates port unreachable
    fn is_icmp_unreachable(&self, packet: &[u8], target: IpAddr, port: u16) -> bool {
        if packet.len() < 28 { // Minimum ICMP + IP header size
            return false;
        }
        
        // Parse ICMP header (simplified)
        let icmp_type = packet[20]; // ICMP type (after IP header)
        let icmp_code = packet[21]; // ICMP code
        
        // Check for Destination Unreachable (Type 3) with Port Unreachable (Code 3)
        if icmp_type == 3 && icmp_code == 3 {
            // Extract original packet info from ICMP payload
            if packet.len() >= 48 {
                // Original IP header starts at offset 28
                let orig_dest_ip = u32::from_be_bytes([
                    packet[44], packet[45], packet[46], packet[47]
                ]);
                let orig_dest_port = u16::from_be_bytes([packet[50], packet[51]]);
                
                // Check if this unreachable is for our target and port
                if let IpAddr::V4(target_v4) = target {
                    return u32::from(target_v4) == orig_dest_ip && orig_dest_port == port;
                }
            }
        }
        
        false
    }
    
    /// High-performance batch UDP scanning
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

impl Clone for UdpScanner {
    fn clone(&self) -> Self {
        Self {
            timeout: self.timeout,
            service_probes: self.service_probes.clone(),
            icmp_socket: None, // Don't clone the socket, create new if needed
        }
    }
}

// Manual Clone implementation for SocketPool
impl Clone for SocketPool {
    fn clone(&self) -> Self {
        Self {
            tcp_sockets: Vec::new(), // Create empty socket vectors
            udp_sockets: Vec::new(),
            icmp_socket: None,
            current_tcp: std::sync::atomic::AtomicUsize::new(0),
            current_udp: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

/// Socket pool for managing multiple raw sockets
#[derive(Debug)]
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