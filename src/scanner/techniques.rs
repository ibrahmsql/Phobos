//! Scanning technique implementations

use crate::network::{
    packet::{TcpPacketBuilder, UdpPacketBuilder},
    protocol::NetworkUtils,
    socket::RawSocket,
    ScanTechnique,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use std::future::Future;
use std::pin::Pin;

/// Trait for implementing different scanning techniques
pub trait ScanTechniqueImpl {
        /// Execute the scan technique on a target port
    fn scan_port<'a>(
        &'a self,
        socket: &'a RawSocket,
        target: Ipv4Addr,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = crate::Result<bool>> + Send + 'a>>;
    
    /// Get the name of the technique
    fn name(&self) -> &'static str;
    
    /// Check if the technique requires raw sockets
    fn requires_raw_socket(&self) -> bool {
        true
    }
}

/// TCP SYN scan implementation (stealth scan)
pub struct SynScan;

impl ScanTechniqueImpl for SynScan {
    fn scan_port<'a>(
        &'a self,
        socket: &'a RawSocket,
        target: Ipv4Addr,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = crate::Result<bool>> + Send + 'a>> {
        Box::pin(async move {
        let source_ip = NetworkUtils::get_local_ip()?;
        let source_port = NetworkUtils::random_source_port();
        
        // Build SYN packet
        let packet = TcpPacketBuilder::new(source_ip, target, source_port, port)
            .syn()
            .build();
        
        // Send packet
        let dest_addr = SocketAddr::new(IpAddr::V4(target), port);
        socket.send_to(&packet, dest_addr)?;
        
        // Wait for SYN+ACK response
        let mut buf = [0u8; 1500];
        socket.set_read_timeout(Some(timeout))?;
        
        match socket.recv_from(&mut buf) {
            Ok((size, _)) => {
                // Parse response and check for SYN+ACK
                if let Some(response) = crate::network::packet::PacketParser::parse_tcp_response(&buf[..size]) {
                    if response.source_ip == target && 
                       response.source_port == port && 
                       response.dest_port == source_port &&
                       response.is_syn_ack() {
                        // Send RST to close connection
                        let rst_packet = TcpPacketBuilder::new(source_ip, target, source_port, port)
                            .rst()
                            .seq_num(response.ack_num)
                            .build();
                        let _ = socket.send_to(&rst_packet, dest_addr);
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Err(_) => Ok(false), // Timeout or error
        }
        })
    }
    
    fn name(&self) -> &'static str {
        "TCP SYN Scan"
    }
}

/// TCP Connect scan implementation
pub struct ConnectScan;

impl ScanTechniqueImpl for ConnectScan {
    fn scan_port<'a>(
        &'a self,
        _socket: &'a RawSocket,
        target: Ipv4Addr,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = crate::Result<bool>> + Send + 'a>> {
        Box::pin(async move {
        let addr = SocketAddr::new(IpAddr::V4(target), port);
        
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => Ok(true),  // Connection successful
            Ok(Err(_)) => Ok(false),      // Connection failed
            Err(_) => Ok(false),          // Timeout
        }
        })
    }
    
    fn name(&self) -> &'static str {
        "TCP Connect Scan"
    }
    
    fn requires_raw_socket(&self) -> bool {
        false
    }
}

/// TCP FIN scan implementation
pub struct FinScan;

impl ScanTechniqueImpl for FinScan {
    fn scan_port<'a>(
        &'a self,
        socket: &'a RawSocket,
        target: Ipv4Addr,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = crate::Result<bool>> + Send + 'a>> {
        Box::pin(async move {
        let source_ip = NetworkUtils::get_local_ip()?;
        let source_port = NetworkUtils::random_source_port();
        
        // Build FIN packet
        let packet = TcpPacketBuilder::new(source_ip, target, source_port, port)
            .fin()
            .build();
        
        // Send packet
        let dest_addr = SocketAddr::new(IpAddr::V4(target), port);
        socket.send_to(&packet, dest_addr)?;
        
        // Wait for RST response (indicates closed port)
        let mut buf = [0u8; 1500];
        socket.set_read_timeout(Some(timeout))?;
        
        match socket.recv_from(&mut buf) {
            Ok((size, _)) => {
                if let Some(response) = crate::network::packet::PacketParser::parse_tcp_response(&buf[..size]) {
                    if response.source_ip == target && 
                       response.source_port == port && 
                       response.dest_port == source_port &&
                       response.is_rst() {
                        return Ok(false); // RST = closed
                    }
                }
                Ok(true) // No RST = open|filtered
            }
            Err(_) => Ok(true), // Timeout = open|filtered
        }
        })
    }
    
    fn name(&self) -> &'static str {
        "TCP FIN Scan"
    }
}

/// TCP NULL scan implementation
pub struct NullScan;

impl ScanTechniqueImpl for NullScan {
    fn scan_port<'a>(
        &'a self,
        socket: &'a RawSocket,
        target: Ipv4Addr,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = crate::Result<bool>> + Send + 'a>> {
        Box::pin(async move {
        let source_ip = NetworkUtils::get_local_ip()?;
        let source_port = NetworkUtils::random_source_port();
        
        // Build NULL packet (no flags set)
        let packet = TcpPacketBuilder::new(source_ip, target, source_port, port)
            .flags(0) // No flags
            .build();
        
        // Send packet
        let dest_addr = SocketAddr::new(IpAddr::V4(target), port);
        socket.send_to(&packet, dest_addr)?;
        
        // Wait for RST response
        let mut buf = [0u8; 1500];
        socket.set_read_timeout(Some(timeout))?;
        
        match socket.recv_from(&mut buf) {
            Ok((size, _)) => {
                if let Some(response) = crate::network::packet::PacketParser::parse_tcp_response(&buf[..size]) {
                    if response.source_ip == target && 
                       response.source_port == port && 
                       response.dest_port == source_port &&
                       response.is_rst() {
                        return Ok(false); // RST = closed
                    }
                }
                Ok(true) // No RST = open|filtered
            }
            Err(_) => Ok(true), // Timeout = open|filtered
        }
        })
    }
    
    fn name(&self) -> &'static str {
        "TCP NULL Scan"
    }
}

/// TCP XMAS scan implementation
pub struct XmasScan;

impl ScanTechniqueImpl for XmasScan {
    fn scan_port<'a>(
        &'a self,
        socket: &'a RawSocket,
        target: Ipv4Addr,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = crate::Result<bool>> + Send + 'a>> {
        Box::pin(async move {
        let source_ip = NetworkUtils::get_local_ip()?;
        let source_port = NetworkUtils::random_source_port();
        
        // Build XMAS packet (FIN + PSH + URG flags)
        let packet = TcpPacketBuilder::new(source_ip, target, source_port, port)
            .fin()
            .psh()
            .urg()
            .build();
        
        // Send packet
        let dest_addr = SocketAddr::new(IpAddr::V4(target), port);
        socket.send_to(&packet, dest_addr)?;
        
        // Wait for RST response
        let mut buf = [0u8; 1500];
        socket.set_read_timeout(Some(timeout))?;
        
        match socket.recv_from(&mut buf) {
            Ok((size, _)) => {
                if let Some(response) = crate::network::packet::PacketParser::parse_tcp_response(&buf[..size]) {
                    if response.source_ip == target && 
                       response.source_port == port && 
                       response.dest_port == source_port &&
                       response.is_rst() {
                        return Ok(false); // RST = closed
                    }
                }
                Ok(true) // No RST = open|filtered
            }
            Err(_) => Ok(true), // Timeout = open|filtered
        }
        })
    }
    
    fn name(&self) -> &'static str {
        "TCP XMAS Scan"
    }
}

/// TCP ACK scan implementation
pub struct AckScan;

impl ScanTechniqueImpl for AckScan {
    fn scan_port<'a>(
        &'a self,
        socket: &'a RawSocket,
        target: Ipv4Addr,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = crate::Result<bool>> + Send + 'a>> {
        Box::pin(async move {
        let source_ip = NetworkUtils::get_local_ip()?;
        let source_port = NetworkUtils::random_source_port();
        
        // Build ACK packet
        let packet = TcpPacketBuilder::new(source_ip, target, source_port, port)
            .ack()
            .build();
        
        // Send packet
        let dest_addr = SocketAddr::new(IpAddr::V4(target), port);
        socket.send_to(&packet, dest_addr)?;
        
        // Wait for RST response (indicates unfiltered)
        let mut buf = [0u8; 1500];
        socket.set_read_timeout(Some(timeout))?;
        
        match socket.recv_from(&mut buf) {
            Ok((size, _)) => {
                if let Some(response) = crate::network::packet::PacketParser::parse_tcp_response(&buf[..size]) {
                    if response.source_ip == target && 
                       response.source_port == port && 
                       response.dest_port == source_port &&
                       response.is_rst() {
                        return Ok(true); // RST = unfiltered
                    }
                }
                Ok(false) // No RST = filtered
            }
            Err(_) => Ok(false), // Timeout = filtered
        }
        })
    }
    
    fn name(&self) -> &'static str {
        "TCP ACK Scan"
    }
}

/// UDP scan implementation
pub struct UdpScan;

impl ScanTechniqueImpl for UdpScan {
    fn scan_port<'a>(
        &'a self,
        socket: &'a RawSocket,
        target: Ipv4Addr,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = crate::Result<bool>> + Send + 'a>> {
        Box::pin(async move {
        let source_ip = NetworkUtils::get_local_ip()?;
        let source_port = NetworkUtils::random_source_port();
        
        // Build UDP packet with probe data
        let probe_data = match port {
            53 => b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00".to_vec(), // DNS query
            161 => b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63".to_vec(), // SNMP
            _ => b"\x00\x00\x00\x00".to_vec(), // Generic probe
        };
        
        let packet = UdpPacketBuilder::new(source_ip, target, source_port, port)
            .payload(probe_data)
            .build();
        
        // Send packet
        let dest_addr = SocketAddr::new(IpAddr::V4(target), port);
        socket.send_to(&packet, dest_addr)?;
        
        // Wait for UDP response or ICMP unreachable
        let mut buf = [0u8; 1500];
        socket.set_read_timeout(Some(timeout))?;
        
        match socket.recv_from(&mut buf) {
            Ok((size, _)) => {
                // Check for UDP response
                if let Some(response) = crate::network::packet::PacketParser::parse_udp_response(&buf[..size]) {
                    if response.source_ip == target && response.source_port == port {
                        return Ok(true); // UDP response = open
                    }
                }
                
                // Check for ICMP unreachable (indicates closed)
                if let Some(icmp_response) = crate::network::packet::PacketParser::parse_icmp_response(&buf[..size]) {
                    if icmp_response.is_port_unreachable(target, port) {
                        return Ok(false); // ICMP unreachable = closed
                    }
                }
                
                Ok(false) // Other response types
            }
            Err(_) => Ok(true), // Timeout = open|filtered (UDP is stateless)
        }
        })
    }
    
    fn name(&self) -> &'static str {
        "UDP Scan"
    }
}

/// Factory for creating scan technique implementations
pub struct TechniqueFactory;

impl TechniqueFactory {
    /// Create a scan technique implementation
    pub fn create(technique: ScanTechnique) -> Box<dyn ScanTechniqueImpl + Send + Sync> {
        match technique {
            ScanTechnique::Syn => Box::new(SynScan),
            ScanTechnique::Connect => Box::new(ConnectScan),
            ScanTechnique::Fin => Box::new(FinScan),
            ScanTechnique::Null => Box::new(NullScan),
            ScanTechnique::Xmas => Box::new(XmasScan),
            ScanTechnique::Ack => Box::new(AckScan),
            ScanTechnique::Window => Box::new(AckScan), // Similar to ACK scan
            ScanTechnique::Udp => Box::new(UdpScan),
        }
    }
    
    /// Get all available techniques
    pub fn available_techniques() -> Vec<ScanTechnique> {
        vec![
            ScanTechnique::Syn,
            ScanTechnique::Connect,
            ScanTechnique::Fin,
            ScanTechnique::Null,
            ScanTechnique::Xmas,
            ScanTechnique::Ack,
            ScanTechnique::Window,
            ScanTechnique::Udp,
        ]
    }
    
    /// Get technique description
    pub fn get_description(technique: ScanTechnique) -> &'static str {
        technique.description()
    }
}

/// Stealth scanning utilities
pub struct StealthUtils;

impl StealthUtils {
    /// Generate random TCP sequence number
    pub fn random_seq_num() -> u32 {
        use rand::Rng;
        rand::thread_rng().gen()
    }
    
    /// Generate random IP identification
    pub fn random_ip_id() -> u16 {
        use rand::Rng;
        rand::thread_rng().gen()
    }
    
    /// Calculate optimal timing between packets
    pub fn calculate_timing(target_rate: u64, current_rate: f64) -> Duration {
        if current_rate > target_rate as f64 {
            // Slow down
            Duration::from_millis(10)
        } else {
            // Speed up
            Duration::from_millis(1)
        }
    }
    
    /// Check if we should use decoy scanning
    pub fn should_use_decoys(stealth_level: u8) -> bool {
        stealth_level >= 3
    }
    
    /// Generate decoy IP addresses
    pub fn generate_decoys(count: usize) -> Vec<Ipv4Addr> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut decoys = Vec::new();
        
        for _ in 0..count {
            let ip = Ipv4Addr::new(
                rng.gen_range(1..=223),
                rng.gen_range(0..=255),
                rng.gen_range(0..=255),
                rng.gen_range(1..=254),
            );
            decoys.push(ip);
        }
        
        decoys
    }
}