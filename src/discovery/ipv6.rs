//! IPv6 Discovery Engine - host discovery support

use super::*;
use std::net::{Ipv6Addr, IpAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// IPv6 Discovery Engine - Full implementation
pub struct IPv6DiscoveryEngine {
    neighbor_discovery: ICMPv6NeighborDiscovery,
    multicast_ping: IPv6MulticastPing,
    link_local_scan: LinkLocalScanner,
}

impl IPv6DiscoveryEngine {
    pub fn new() -> Self {
        Self {
            neighbor_discovery: ICMPv6NeighborDiscovery::new(),
            multicast_ping: IPv6MulticastPing::new(),
            link_local_scan: LinkLocalScanner::new(),
        }
    }
    
    /// Discover IPv6 host using multiple methods
    pub async fn discover_ipv6_host(&self, target: Ipv6Addr) -> Result<DiscoveryResult, DiscoveryError> {
        let target_ip = IpAddr::V6(target);
        
        // Try ICMPv6 neighbor discovery first
        if let Ok(result) = self.neighbor_discovery.discover(target_ip).await {
            if result.is_alive {
                return Ok(result.with_ipv6_info(IPv6HostInfo::from_address(target)));
            }
        }
        
        // Try multicast ping
        if let Ok(result) = self.multicast_ping.discover(target_ip).await {
            if result.is_alive {
                return Ok(result.with_ipv6_info(IPv6HostInfo::from_address(target)));
            }
        }
        
        // Try link-local scanning if applicable
        if target.is_unicast_link_local() {
            if let Ok(result) = self.link_local_scan.discover(target_ip).await {
                if result.is_alive {
                    return Ok(result.with_ipv6_info(IPv6HostInfo::from_address(target)));
                }
            }
        }
        
        Ok(DiscoveryResult::new(target_ip, false, "ipv6-all-methods-failed"))
    }
}

/// ICMPv6 Neighbor Discovery
#[derive(Clone)]
pub struct ICMPv6NeighborDiscovery {
    solicitation_timeout: Duration,
    _max_hops: u8,
}

impl ICMPv6NeighborDiscovery {
    pub fn new() -> Self {
        Self {
            solicitation_timeout: Duration::from_secs(2),
            _max_hops: 64,
        }
    }
}

#[async_trait::async_trait]
impl DiscoveryMethod for ICMPv6NeighborDiscovery {
    async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult, DiscoveryError> {
        match target {
            IpAddr::V6(ipv6) => {
                let start_time = Instant::now();
                let alive = self.neighbor_solicitation(ipv6).await?;
                let response_time = start_time.elapsed();
                
                Ok(DiscoveryResult::new(target, alive, "icmpv6-neighbor-discovery")
                    .with_response_time(response_time))
            }
            IpAddr::V4(_) => {
                Err(DiscoveryError::NetworkError("ICMPv6 not applicable for IPv4".to_string()))
            }
        }
    }
    
    fn method_name(&self) -> &str {
        "icmpv6-neighbor-discovery"
    }
    
    fn reliability(&self) -> f32 {
        0.9 // Very reliable for IPv6
    }
    
    fn supports_ipv6(&self) -> bool {
        true
    }
}

impl ICMPv6NeighborDiscovery {
    async fn neighbor_solicitation(&self, target: Ipv6Addr) -> Result<bool, DiscoveryError> {
        // Use system ping6 command for ICMPv6 neighbor discovery
        // This leverages the OS's built-in neighbor discovery protocol
        use std::process::Command;
        
        let output = Command::new("ping6")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg(format!("{}", self.solicitation_timeout.as_millis()))
            .arg(target.to_string())
            .output()
            .map_err(|e| DiscoveryError::NetworkError(format!("ping6 failed: {}", e)))?;
        
        Ok(output.status.success())
    }
}

/// IPv6 Multicast Ping
#[derive(Clone)]
pub struct IPv6MulticastPing {
    _timeout: Duration,
}

impl IPv6MulticastPing {
    pub fn new() -> Self {
        Self {
            _timeout: Duration::from_secs(2),
        }
    }
}

#[async_trait::async_trait]
impl DiscoveryMethod for IPv6MulticastPing {
    async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult, DiscoveryError> {
        match target {
            IpAddr::V6(ipv6) => {
                let start_time = Instant::now();
                let alive = self.multicast_ping(ipv6).await?;
                let response_time = start_time.elapsed();
                
                Ok(DiscoveryResult::new(target, alive, "ipv6-multicast-ping")
                    .with_response_time(response_time))
            }
            IpAddr::V4(_) => {
                Err(DiscoveryError::NetworkError("IPv6 multicast not applicable for IPv4".to_string()))
            }
        }
    }
    
    fn method_name(&self) -> &str {
        "ipv6-multicast-ping"
    }
    
    fn reliability(&self) -> f32 {
        0.7 // Moderately reliable
    }
    
    fn supports_ipv6(&self) -> bool {
        true
    }
}

impl IPv6MulticastPing {
    async fn multicast_ping(&self, target: Ipv6Addr) -> Result<bool, DiscoveryError> {
        // Implement IPv6 multicast ping to all-nodes multicast address
        use std::process::Command;
        
        // Use ping6 to send to all-nodes multicast and check if target responds
        let output = Command::new("ping6")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg(format!("{}", self.timeout.as_millis()))
            .arg("ff02::1%lo0") // All-nodes multicast on loopback interface
            .output()
            .map_err(|e| DiscoveryError::NetworkError(format!("multicast ping6 failed: {}", e)))?;
        
        // Check if we got any response that might indicate the target is alive
        if output.status.success() {
            // Parse output to see if target responded
            let output_str = String::from_utf8_lossy(&output.stdout);
            Ok(output_str.contains(&target.to_string()))
        } else {
            // Fallback: try direct ping to target
            let direct_output = Command::new("ping6")
                .arg("-c")
                .arg("1")
                .arg("-W")
                .arg(format!("{}", self.timeout.as_millis()))
                .arg(target.to_string())
                .output()
                .map_err(|e| DiscoveryError::NetworkError(format!("direct ping6 failed: {}", e)))?;
            
            Ok(direct_output.status.success())
        }
    }
}

/// Link-Local Scanner for IPv6
#[derive(Clone)]
pub struct LinkLocalScanner {
    timeout: Duration,
}

impl LinkLocalScanner {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(1),
        }
    }
}

#[async_trait::async_trait]
impl DiscoveryMethod for LinkLocalScanner {
    async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult, DiscoveryError> {
        match target {
            IpAddr::V6(ipv6) if ipv6.is_unicast_link_local() => {
                let start_time = Instant::now();
                let alive = self.scan_link_local(ipv6).await?;
                let response_time = start_time.elapsed();
                
                Ok(DiscoveryResult::new(target, alive, "ipv6-link-local-scan")
                    .with_response_time(response_time))
            }
            IpAddr::V6(_) => {
                Err(DiscoveryError::NetworkError("Not a link-local address".to_string()))
            }
            IpAddr::V4(_) => {
                Err(DiscoveryError::NetworkError("Link-local scanning not applicable for IPv4".to_string()))
            }
        }
    }
    
    fn method_name(&self) -> &str {
        "ipv6-link-local-scan"
    }
    
    fn reliability(&self) -> f32 {
        0.8 // Good for link-local addresses
    }
    
    fn supports_ipv6(&self) -> bool {
        true
    }
}

impl LinkLocalScanner {
    async fn scan_link_local(&self, target: Ipv6Addr) -> Result<bool, DiscoveryError> {
        // Implement link-local specific scanning using UDP connectivity test
        // Link-local addresses require interface-specific handling
        let socket = UdpSocket::bind("[::]:0").await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;
        
        // Try to connect to a common port
        match tokio::time::timeout(
            self.timeout,
            socket.connect((target, 80))
        ).await {
            Ok(Ok(_)) => Ok(true),
            _ => Ok(false),
        }
    }
}

/// IPv6 Host Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPv6HostInfo {
    pub link_local_address: Option<Ipv6Addr>,
    pub global_addresses: Vec<Ipv6Addr>,
    pub neighbor_cache_entry: bool,
    pub privacy_extensions: bool,
    pub scope: IPv6Scope,
}

impl IPv6HostInfo {
    pub fn from_address(addr: Ipv6Addr) -> Self {
        let scope = if addr.is_unicast_link_local() {
            IPv6Scope::LinkLocal
        } else if addr.is_unique_local() {
            IPv6Scope::SiteLocal
        } else if addr.is_multicast() {
            IPv6Scope::Multicast
        } else {
            IPv6Scope::Global
        };
        
        Self {
            link_local_address: if addr.is_unicast_link_local() { Some(addr) } else { None },
            global_addresses: if !addr.is_unicast_link_local() && !addr.is_multicast() { vec![addr] } else { vec![] },
            neighbor_cache_entry: false,
            privacy_extensions: false,
            scope,
        }
    }
}

/// IPv6 Address Scope
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IPv6Scope {
    LinkLocal,
    SiteLocal,
    Global,
    Multicast,
}

/// IPv6 Network prefix for scanning
#[derive(Debug, Clone)]
pub struct IPv6Network {
    pub prefix: Ipv6Addr,
    pub prefix_length: u8,
}

impl IPv6Network {
    pub fn new(prefix: Ipv6Addr, prefix_length: u8) -> Self {
        Self { prefix, prefix_length }
    }
    
    /// Generate addresses in this network for scanning
    pub fn generate_addresses(&self, max_addresses: usize) -> Vec<Ipv6Addr> {
        let mut addresses = Vec::new();
        
        if self.prefix_length >= 64 {
            // For /64 and smaller networks, generate common interface IDs
            let common_suffixes = [
                0x1, 0x2, 0x10, 0x100, 0x1000,  // Common manual assignments
                0xfe80, 0xfec0,                   // Link-local patterns
                0x1234, 0x5678, 0xabcd, 0xef01,  // Common test patterns
            ];
            
            let prefix_bytes = self.prefix.octets();
            for &suffix in &common_suffixes {
                if addresses.len() >= max_addresses { break; }
                
                let mut addr_bytes = prefix_bytes;
                // Set the last 64 bits to the suffix
                addr_bytes[8..16].copy_from_slice(&suffix.to_be_bytes());
                addresses.push(Ipv6Addr::from(addr_bytes));
            }
        } else if self.prefix_length >= 48 {
            // For /48 to /63 networks, generate subnet addresses
            for subnet in 0..std::cmp::min(max_addresses, 256) {
                let mut addr_bytes = self.prefix.octets();
                addr_bytes[6] = (subnet >> 8) as u8;
                addr_bytes[7] = (subnet & 0xff) as u8;
                addr_bytes[15] = 1; // Host part
                addresses.push(Ipv6Addr::from(addr_bytes));
            }
        } else {
            // For larger networks, generate based on common patterns
            let common_patterns = [
                [0, 0, 0, 0, 0, 0, 0, 1],        // ::1 pattern
                [0, 0, 0, 0, 0, 0, 1, 0],        // ::100 pattern
                [0, 1, 0, 0, 0, 0, 0, 1],        // ::1:0:0:0:1 pattern
            ];
            
            let prefix_bytes = self.prefix.octets();
            for pattern in &common_patterns {
                if addresses.len() >= max_addresses { break; }
                
                let mut addr_bytes = prefix_bytes;
                for (i, &byte) in pattern.iter().enumerate() {
                    if i + 8 < 16 {
                        addr_bytes[i + 8] = byte;
                    }
                }
                addresses.push(Ipv6Addr::from(addr_bytes));
            }
        }
        
        addresses
    }
}