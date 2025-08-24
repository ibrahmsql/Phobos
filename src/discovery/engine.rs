//! Host Discovery Engine - Main discovery orchestrator

use super::*;
use crate::discovery::methods::*;
use crate::discovery::ipv6::IPv6DiscoveryEngine;
use crate::discovery::os_detection::OSDetectionEngine;
use std::sync::Arc;
use tokio::sync::Semaphore;
use futures::future::join_all;


/// Main host discovery engine
pub struct HostDiscoveryEngine {
    config: DiscoveryConfig,
    ipv4_methods: Vec<DiscoveryMethodType>,
    ipv6_engine: Option<IPv6DiscoveryEngine>,
    os_detection: Option<OSDetectionEngine>,
    semaphore: Arc<Semaphore>,
}

impl HostDiscoveryEngine {
    /// Create new host discovery engine
    pub fn new(config: DiscoveryConfig) -> Self {
        let mut engine = Self {
            semaphore: Arc::new(Semaphore::new(config.parallel_limit)),
            config: config.clone(),
            ipv4_methods: Vec::new(),
            ipv6_engine: None,
            os_detection: None,
        };
        
        // Initialize discovery methods
        engine.initialize_methods();
        
        // Initialize features if enabled
        if config.enable_ipv6 {
            engine.ipv6_engine = Some(IPv6DiscoveryEngine::new());
        }
        
        if config.enable_os_detection {
            engine.os_detection = Some(OSDetectionEngine::new());
        }
        
        engine
    }
    
    /// Initialize discovery methods based on configuration
    fn initialize_methods(&mut self) {
        // Add ICMP discovery
        self.ipv4_methods.push(DiscoveryMethodType::Icmp(ICMPDiscovery::new(
            ICMPType::EchoRequest,
            self.config.timeout,
        )));
        
        // Add TCP SYN discovery for common ports
        self.ipv4_methods.push(DiscoveryMethodType::Tcp(TCPDiscovery::new(
            vec![22, 80, 443, 8080, 8443],
            TCPDiscoveryType::Syn,
            self.config.timeout,
        )));
        
        // Add ARP discovery for local networks
        self.ipv4_methods.push(DiscoveryMethodType::Arp(ARPDiscovery::new(
            self.config.timeout,
        )));
        
        // Add UDP discovery
        self.ipv4_methods.push(DiscoveryMethodType::Udp(UDPDiscovery::new(
            vec![53, 161, 137, 138],
            self.config.timeout,
        )));
    }
    
    /// Discover single host
    pub async fn discover_host(&self, target: IpAddr) -> DiscoveryResult {
        let _permit = self.semaphore.acquire().await.unwrap();
        
        match target {
            IpAddr::V4(ipv4) => self.discover_ipv4_host(ipv4).await,
            IpAddr::V6(ipv6) => self.discover_ipv6_host(ipv6).await,
        }
    }
    
    /// Discover multiple hosts in parallel
    pub async fn discover_hosts(&self, targets: Vec<IpAddr>) -> Vec<DiscoveryResult> {
        let tasks = targets.into_iter().map(|target| {
            self.discover_host(target)
        });
        
        join_all(tasks).await
    }
    
    /// Discover IPv4 host using multiple methods
    async fn discover_ipv4_host(&self, target: Ipv4Addr) -> DiscoveryResult {
        let target_ip = IpAddr::V4(target);
        
        // Try methods in order of reliability
        for method in &self.ipv4_methods {
            match method.discover(target_ip).await {
                Ok(mut result) => {
                    if result.is_alive {
                        // Add OS detection if enabled
                        if let Some(os_engine) = &self.os_detection {
                            if let Ok(os_hint) = os_engine.detect_os_hint(target_ip).await {
                                result = result.with_os_hint(os_hint);
                            }
                        }
                        return result;
                    }
                }
                Err(_) => continue,
            }
        }
        
        // No method succeeded
        DiscoveryResult::new(target_ip, false, "none")
    }
    
    /// Discover IPv6 host using IPv6 engine
    async fn discover_ipv6_host(&self, target: Ipv6Addr) -> DiscoveryResult {
        let target_ip = IpAddr::V6(target);
        
        if let Some(ipv6_engine) = &self.ipv6_engine {
            match ipv6_engine.discover_ipv6_host(target).await {
                Ok(mut result) => {
                    // Add OS detection if enabled
                    if let Some(os_engine) = &self.os_detection {
                        if let Ok(os_hint) = os_engine.detect_os_hint(target_ip).await {
                            result = result.with_os_hint(os_hint);
                        }
                    }
                    result
                }
                Err(_) => DiscoveryResult::new(target_ip, false, "ipv6-failed"),
            }
        } else {
            DiscoveryResult::new(target_ip, false, "ipv6-not-enabled")
        }
    }
    
    /// Perform network topology discovery
    pub async fn discover_network_topology(&self) -> NetworkTopology {
        NetworkTopology::discover().await
    }
    
    /// Get discovery statistics
    pub fn get_statistics(&self) -> DiscoveryStatistics {
        DiscoveryStatistics {
            methods_available: self.ipv4_methods.len(),
            ipv6_enabled: self.ipv6_engine.is_some(),
            os_detection_enabled: self.os_detection.is_some(),
            parallel_limit: self.config.parallel_limit,
        }
    }
}

/// Discovery statistics
#[derive(Debug, Clone)]
pub struct DiscoveryStatistics {
    pub methods_available: usize,
    pub ipv6_enabled: bool,
    pub os_detection_enabled: bool,
    pub parallel_limit: usize,
}

/// Network topology information
#[derive(Debug, Clone)]
pub struct NetworkTopology {
    pub local_networks: Vec<NetworkRange>,
    pub gateways: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub network_interfaces: Vec<NetworkInterface>,
}

impl NetworkTopology {
    /// Discover network topology
    pub async fn discover() -> Self {
        let mut topology = Self {
            local_networks: Vec::new(),
            gateways: Vec::new(),
            dns_servers: Vec::new(),
            network_interfaces: Vec::new(),
        };
        
        // Discover network interfaces
        if let Ok(interfaces) = Self::get_network_interfaces().await {
            topology.network_interfaces = interfaces;
            
            // Extract local networks from interfaces
            for interface in &topology.network_interfaces {
                for addr in &interface.addresses {
                    if !addr.is_loopback() {
                        let prefix_length = match addr {
                            IpAddr::V4(_) => 24, // Assume /24 for IPv4
                            IpAddr::V6(_) => 64, // Assume /64 for IPv6
                        };
                        
                        topology.local_networks.push(NetworkRange {
                            network: *addr,
                            prefix_length,
                            interface: interface.name.clone(),
                        });
                    }
                }
            }
        }
        
        // Discover gateways
        if let Ok(gateways) = Self::get_default_gateways().await {
            topology.gateways = gateways;
        }
        
        // Discover DNS servers
        if let Ok(dns_servers) = Self::get_dns_servers().await {
            topology.dns_servers = dns_servers;
        }
        
        topology
    }
    
    async fn get_network_interfaces() -> Result<Vec<NetworkInterface>, DiscoveryError> {
        use std::process::Command;
        
        let output = Command::new("ifconfig")
            .output()
            .map_err(|e| DiscoveryError::NetworkError(format!("ifconfig failed: {}", e)))?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut interfaces = Vec::new();
        let mut current_interface: Option<NetworkInterface> = None;
        
        for line in output_str.lines() {
            if !line.starts_with(' ') && !line.starts_with('\t') && line.contains(':') {
                // New interface
                if let Some(interface) = current_interface.take() {
                    interfaces.push(interface);
                }
                
                let name = line.split(':').next().unwrap_or("unknown").to_string();
                let is_up = line.contains("UP");
                let is_loopback = line.contains("LOOPBACK");
                
                current_interface = Some(NetworkInterface {
                    name,
                    addresses: Vec::new(),
                    is_up,
                    is_loopback,
                });
            } else if line.trim().starts_with("inet ") {
                // IPv4 address
                if let Some(ref mut interface) = current_interface {
                    if let Some(addr_str) = line.split_whitespace().nth(1) {
                        if let Ok(addr) = addr_str.parse::<std::net::Ipv4Addr>() {
                            interface.addresses.push(IpAddr::V4(addr));
                        }
                    }
                }
            } else if line.trim().starts_with("inet6 ") {
                // IPv6 address
                if let Some(ref mut interface) = current_interface {
                    if let Some(addr_str) = line.split_whitespace().nth(1) {
                        let addr_str = addr_str.split('%').next().unwrap_or(addr_str);
                        if let Ok(addr) = addr_str.parse::<std::net::Ipv6Addr>() {
                            interface.addresses.push(IpAddr::V6(addr));
                        }
                    }
                }
            }
        }
        
        if let Some(interface) = current_interface {
            interfaces.push(interface);
        }
        
        Ok(interfaces)
    }
    
    async fn get_default_gateways() -> Result<Vec<IpAddr>, DiscoveryError> {
        use std::process::Command;
        
        let output = Command::new("route")
            .arg("-n")
            .arg("get")
            .arg("default")
            .output()
            .map_err(|e| DiscoveryError::NetworkError(format!("route command failed: {}", e)))?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut gateways = Vec::new();
        
        for line in output_str.lines() {
            if line.trim().starts_with("gateway:") {
                if let Some(gateway_str) = line.split_whitespace().nth(1) {
                    if let Ok(addr) = gateway_str.parse::<IpAddr>() {
                        gateways.push(addr);
                    }
                }
            }
        }
        
        Ok(gateways)
    }
    
    async fn get_dns_servers() -> Result<Vec<IpAddr>, DiscoveryError> {
        use std::process::Command;
        
        let output = Command::new("scutil")
            .arg("--dns")
            .output()
            .map_err(|e| DiscoveryError::NetworkError(format!("scutil failed: {}", e)))?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut dns_servers = Vec::new();
        
        for line in output_str.lines() {
            if line.trim().starts_with("nameserver[") {
                if let Some(dns_str) = line.split(" : ").nth(1) {
                    if let Ok(addr) = dns_str.parse::<IpAddr>() {
                        if !dns_servers.contains(&addr) {
                            dns_servers.push(addr);
                        }
                    }
                }
            }
        }
        
        Ok(dns_servers)
    }
}

/// Network range information
#[derive(Debug, Clone)]
pub struct NetworkRange {
    pub network: IpAddr,
    pub prefix_length: u8,
    pub interface: String,
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub addresses: Vec<IpAddr>,
    pub is_up: bool,
    pub is_loopback: bool,
}