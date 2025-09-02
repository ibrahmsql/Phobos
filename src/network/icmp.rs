//! ICMP implementation for native ping functionality

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, IcmpCode, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::{Packet, MutablePacket};
use socket2::{Domain, Protocol, Socket, Type};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::ScanError;

/// ICMP ping result
#[derive(Debug, Clone)]
pub struct PingResult {
    pub target: IpAddr,
    pub success: bool,
    pub response_time: Option<Duration>,
    pub rtt: Duration,
    pub ttl: Option<u8>,
    pub error: Option<String>,
}

/// ICMP pinger for native ping functionality with advanced features
pub struct IcmpPinger {
    socket: Socket,
    _identifier: u16,
    _sequence: u16,
    /// Cache for tracking sent packets
    _pending_pings: Arc<Mutex<HashMap<u16, (Ipv4Addr, Instant)>>>,
    /// Statistics tracking
    _stats: Arc<Mutex<IcmpStats>>,
}

/// ICMP statistics for performance monitoring
#[derive(Debug, Clone, Default)]
pub struct IcmpStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub min_rtt: Duration,
    pub max_rtt: Duration,
    pub avg_rtt: Duration,
    pub total_rtt: Duration,
}

impl IcmpStats {
    pub fn new() -> Self {
        Self {
            min_rtt: Duration::from_secs(u64::MAX),
            max_rtt: Duration::from_secs(0),
            ..Default::default()
        }
    }
    
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.packets_received += 1;
        self.total_rtt += rtt;
        
        if rtt < self.min_rtt {
            self.min_rtt = rtt;
        }
        if rtt > self.max_rtt {
            self.max_rtt = rtt;
        }
        
        if self.packets_received > 0 {
            self.avg_rtt = self.total_rtt / self.packets_received as u32;
        }
    }
    
    pub fn packet_lost(&mut self) {
        self.packets_lost += 1;
    }
    
    pub fn packet_sent(&mut self) {
        self.packets_sent += 1;
    }
    
    pub fn loss_percentage(&self) -> f64 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        (self.packets_lost as f64 / self.packets_sent as f64) * 100.0
    }
}

/// Native ICMP ping implementation

impl IcmpPinger {
    /// Create a new ICMP pinger
    pub fn new() -> crate::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    ScanError::PermissionError("Permission denied for ICMP socket".to_string())
                } else {
                    ScanError::NetworkError(e.to_string())
                }
            })?;
        
        socket.set_nonblocking(true).map_err(|e| ScanError::NetworkError(e.to_string()))?;
        
        let identifier = rand::thread_rng().gen::<u16>();
        
        Ok(Self {
            socket,
            _identifier: identifier,
            _sequence: 0,
            _pending_pings: Arc::new(Mutex::new(HashMap::new())),
            _stats: Arc::new(Mutex::new(IcmpStats::new())),
        })
    }
    
    /// Ping a single host
    pub async fn ping(&self, target: Ipv4Addr, timeout_duration: Duration) -> PingResult {
        let _start_time = Instant::now();
        
        match self.send_ping(target).await {
            Ok(_) => {
                match timeout(timeout_duration, self.wait_for_reply(target)).await {
                    Ok(Ok(response_time)) => PingResult {
                         target: IpAddr::V4(target),
                         success: true,
                         response_time: Some(response_time),
                         rtt: response_time,
                         ttl: None,
                         error: None,
                     },
                     Ok(Err(e)) => PingResult {
                         target: IpAddr::V4(target),
                         success: false,
                         response_time: None,
                         rtt: Duration::from_secs(0),
                         ttl: None,
                         error: Some(e.to_string()),
                     },
                     Err(_) => PingResult {
                         target: IpAddr::V4(target),
                         success: false,
                         response_time: None,
                         rtt: Duration::from_secs(0),
                         ttl: None,
                         error: Some("Timeout".to_string()),
                     },
                }
            }
            Err(e) => PingResult {
                 target: IpAddr::V4(target),
                 success: false,
                 response_time: None,
                 rtt: Duration::from_secs(0),
                 ttl: None,
                 error: Some(e.to_string()),
             },
        }
    }
    
    /// Send ICMP echo request
    async fn send_ping(&self, target: Ipv4Addr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut icmp_buffer = [0u8; 64];
        let mut icmp_packet = MutableIcmpPacket::new(&mut icmp_buffer).unwrap();
        
        // Generate random identifier and sequence number
        let identifier = rand::thread_rng().gen::<u16>();
        let sequence = rand::thread_rng().gen::<u16>();
        
        // Set ICMP header
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_icmp_code(IcmpCode(0));
        icmp_packet.set_checksum(0);
        
        // Set identifier and sequence in payload
        let payload = icmp_packet.payload_mut();
        if payload.len() >= 4 {
            payload[0..2].copy_from_slice(&identifier.to_be_bytes());
            payload[2..4].copy_from_slice(&sequence.to_be_bytes());
        }
        
        // Fill rest of payload with timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        if payload.len() >= 12 {
            payload[4..12].copy_from_slice(&timestamp.to_be_bytes());
        }
        
        // Calculate checksum
        let checksum = Self::calculate_icmp_checksum(&icmp_packet.to_immutable());
        icmp_packet.set_checksum(checksum);
        
        // Send packet
        let dest_addr = socket2::SockAddr::from(std::net::SocketAddr::new(
            IpAddr::V4(target),
            0,
        ));
        
        self.socket.send_to(&icmp_buffer, &dest_addr)?;
        Ok(())
    }
    
    /// Wait for ICMP echo reply
    async fn wait_for_reply(&self, _target: Ipv4Addr) -> Result<Duration, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        let mut buffer = vec![std::mem::MaybeUninit::new(0u8); 1024];
        
        loop {
            match self.socket.recv_from(&mut buffer) {
                Ok((bytes_received, _addr)) => {
                    if bytes_received >= 28 { // IP header (20) + ICMP header (8)
                        // Convert MaybeUninit buffer to initialized buffer
                        let init_buffer: Vec<u8> = buffer[..bytes_received]
                            .iter()
                            .map(|x| unsafe { x.assume_init() })
                            .collect();
                        
                        // Parse IP header
                        if let Some(ip_packet) = Ipv4Packet::new(&init_buffer) {
                            if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                                let icmp_offset = (ip_packet.get_header_length() as usize) * 4;
                                if let Some(icmp_packet) = IcmpPacket::new(&init_buffer[icmp_offset..bytes_received]) {
                                    if icmp_packet.get_icmp_type() == IcmpTypes::EchoReply {
                                        return Ok(start_time.elapsed());
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available, continue waiting
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    continue;
                }
                Err(e) => return Err(Box::new(e)),
            }
        }
    }
    
    /// Calculate ICMP checksum
    fn calculate_icmp_checksum(packet: &IcmpPacket) -> u16 {
        let mut sum = 0u32;
        let data = packet.packet();
        
        // Sum all 16-bit words
        for chunk in data.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += (chunk[0] as u32) << 8;
            }
        }
        
        // Add carry
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        // One's complement
        !sum as u16
    }
}

/// High-level ping function
pub async fn ping_host(target: Ipv4Addr, timeout_ms: u64) -> PingResult {
    let timeout_duration = Duration::from_millis(timeout_ms);
    match IcmpPinger::new() {
        Ok(pinger) => pinger.ping(target, timeout_duration).await,
        Err(e) => PingResult {
             target: IpAddr::V4(target),
             success: false,
             response_time: None,
             rtt: Duration::from_secs(0),
             ttl: None,
             error: Some(format!("Failed to create pinger: {}", e)),
         },
    }
}

/// Ping multiple hosts concurrently
pub async fn ping_hosts(targets: Vec<Ipv4Addr>, timeout_ms: u64) -> Vec<PingResult> {
    let tasks: Vec<_> = targets
        .into_iter()
        .map(|target| ping_host(target, timeout_ms))
        .collect();
    
    futures::future::join_all(tasks).await
}