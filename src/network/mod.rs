//! Network module for packet crafting and protocol handling

pub mod icmp;
pub mod packet;
pub mod protocol;
pub mod socket;
pub mod stealth;
pub mod phobos_modes;

use serde::{Deserialize, Serialize};

/// Available scanning techniques
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScanTechnique {
    /// TCP SYN scan (half-open)
    Syn,
    /// TCP Connect scan (full connection)
    Connect,
    /// UDP scan
    Udp,
    /// TCP FIN scan
    Fin,
    /// TCP NULL scan (no flags)
    Null,
    /// TCP XMAS scan (FIN, PSH, URG flags)
    Xmas,
    /// TCP ACK scan
    Ack,
    /// TCP Window scan
    Window,
    /// Stealth scan (combination of techniques)
    Stealth,
}

impl ScanTechnique {
    /// Get the name of the scan technique
    pub fn name(&self) -> &'static str {
        match self {
            ScanTechnique::Syn => "SYN",
            ScanTechnique::Connect => "Connect",
            ScanTechnique::Udp => "UDP",
            ScanTechnique::Fin => "FIN",
            ScanTechnique::Null => "NULL",
            ScanTechnique::Xmas => "XMAS",
            ScanTechnique::Ack => "ACK",
            ScanTechnique::Window => "Window",
            ScanTechnique::Stealth => "Stealth",
        }
    }
    
    /// Check if the technique requires raw sockets
    pub fn requires_raw_socket(&self) -> bool {
        match self {
            ScanTechnique::Connect => false,
            _ => true,
        }
    }
    
    /// Get the protocol used by this technique
    pub fn protocol(&self) -> Protocol {
        match self {
            ScanTechnique::Udp => Protocol::Udp,
            _ => Protocol::Tcp,
        }
    }
    
    pub fn description(&self) -> &'static str {
        match self {
            ScanTechnique::Syn => "TCP SYN scan",
            ScanTechnique::Connect => "TCP connect scan",
            ScanTechnique::Fin => "TCP FIN scan",
            ScanTechnique::Null => "TCP NULL scan",
            ScanTechnique::Xmas => "TCP XMAS scan",
            ScanTechnique::Ack => "TCP ACK scan",
            ScanTechnique::Window => "TCP Window scan",
            ScanTechnique::Udp => "UDP scan",
            ScanTechnique::Stealth => "Stealth scan",
        }
    }
    
    /// Check if this technique uses TCP protocol
    pub fn is_tcp(&self) -> bool {
        match self {
            ScanTechnique::Udp => false,
            _ => true,
        }
    }
    
    /// Get TCP flags for this scan technique
    pub fn tcp_flags(&self) -> u8 {
        match self {
            ScanTechnique::Syn => 0x02,      // SYN flag
            ScanTechnique::Connect => 0x02,  // SYN flag
            ScanTechnique::Fin => 0x01,      // FIN flag
            ScanTechnique::Null => 0x00,     // No flags
            ScanTechnique::Xmas => 0x29,     // FIN + PSH + URG flags
            ScanTechnique::Ack => 0x10,      // ACK flag
            ScanTechnique::Window => 0x10,   // ACK flag
            ScanTechnique::Udp => 0x00,      // Not applicable for UDP
            ScanTechnique::Stealth => 0x02, // SYN flag for stealth
        }
    }
}

/// Port state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    ClosedFiltered,
    Unfiltered,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
            PortState::ClosedFiltered => write!(f, "closed|filtered"),
            PortState::Unfiltered => write!(f, "unfiltered"),
        }
    }
}

/// Protocol enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl Protocol {
    pub fn number(&self) -> u8 {
        match self {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmp => 1,
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
        }
    }
}

/// Scan result for a single port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<String>,
    pub response_time: std::time::Duration,
}

impl PortResult {
    pub fn new(port: u16, protocol: Protocol, state: PortState) -> Self {
        Self {
            port,
            protocol,
            state,
            service: None,
            response_time: std::time::Duration::from_millis(0),
        }
    }
    
    pub fn with_response_time(mut self, response_time: std::time::Duration) -> Self {
        self.response_time = response_time;
        self
    }
    
    pub fn with_service(mut self, service: String) -> Self {
        self.service = Some(service);
        self
    }
}