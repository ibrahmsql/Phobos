//! Host Discovery Engine - Comprehensive host discovery with IPv6 and OS detection beta features
//! 
//! This module provides advanced host discovery capabilities that rival and exceed
//! Nmap's host discovery features, with additional beta support for IPv6 and basic OS detection.

pub mod engine;
pub mod methods;
pub mod ipv6;
pub mod os_detection;


use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use serde::{Deserialize, Serialize};

pub use engine::HostDiscoveryEngine;
pub use methods::*;
pub use ipv6::*;
pub use os_detection::*;

/// Discovery result for a single host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResult {
    pub target: IpAddr,
    pub is_alive: bool,
    pub response_time: Option<Duration>,
    pub method_used: String,
    pub os_hint: Option<BasicOSFingerprint>,
    pub ipv6_info: Option<IPv6HostInfo>,
    pub additional_info: HashMap<String, String>,
}

impl DiscoveryResult {
    pub fn new(target: IpAddr, is_alive: bool, method: &str) -> Self {
        Self {
            target,
            is_alive,
            response_time: None,
            method_used: method.to_string(),
            os_hint: None,
            ipv6_info: None,
            additional_info: HashMap::new(),
        }
    }
    
    pub fn with_response_time(mut self, response_time: Duration) -> Self {
        self.response_time = Some(response_time);
        self
    }
    
    pub fn with_os_hint(mut self, os_hint: BasicOSFingerprint) -> Self {
        self.os_hint = Some(os_hint);
        self
    }
    
    pub fn with_ipv6_info(mut self, ipv6_info: IPv6HostInfo) -> Self {
        self.ipv6_info = Some(ipv6_info);
        self
    }
}

/// Discovery method trait
#[async_trait::async_trait]
pub trait DiscoveryMethod: Send + Sync {
    async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult, DiscoveryError>;
    fn method_name(&self) -> &str;
    fn reliability(&self) -> f32;
    fn supports_ipv6(&self) -> bool;
}

/// Enum wrapper for discovery methods to avoid dyn compatibility issues
#[derive(Clone)]
pub enum DiscoveryMethodType {
    Icmp(methods::ICMPDiscovery),
    Tcp(methods::TCPDiscovery),
    Udp(methods::UDPDiscovery),
    Arp(methods::ARPDiscovery),
    Ipv6Neighbor(ipv6::ICMPv6NeighborDiscovery),
    Ipv6Multicast(ipv6::IPv6MulticastPing),
    Ipv6LinkLocal(ipv6::LinkLocalScanner),
}

#[async_trait::async_trait]
impl DiscoveryMethod for DiscoveryMethodType {
    async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult, DiscoveryError> {
        match self {
            DiscoveryMethodType::Icmp(method) => method.discover(target).await,
            DiscoveryMethodType::Tcp(method) => method.discover(target).await,
            DiscoveryMethodType::Udp(method) => method.discover(target).await,
            DiscoveryMethodType::Arp(method) => method.discover(target).await,
            DiscoveryMethodType::Ipv6Neighbor(method) => method.discover(target).await,
            DiscoveryMethodType::Ipv6Multicast(method) => method.discover(target).await,
            DiscoveryMethodType::Ipv6LinkLocal(method) => method.discover(target).await,
        }
    }
    
    fn method_name(&self) -> &str {
        match self {
            DiscoveryMethodType::Icmp(method) => method.method_name(),
            DiscoveryMethodType::Tcp(method) => method.method_name(),
            DiscoveryMethodType::Udp(method) => method.method_name(),
            DiscoveryMethodType::Arp(method) => method.method_name(),
            DiscoveryMethodType::Ipv6Neighbor(method) => method.method_name(),
            DiscoveryMethodType::Ipv6Multicast(method) => method.method_name(),
            DiscoveryMethodType::Ipv6LinkLocal(method) => method.method_name(),
        }
    }
    
    fn reliability(&self) -> f32 {
        match self {
            DiscoveryMethodType::Icmp(method) => method.reliability(),
            DiscoveryMethodType::Tcp(method) => method.reliability(),
            DiscoveryMethodType::Udp(method) => method.reliability(),
            DiscoveryMethodType::Arp(method) => method.reliability(),
            DiscoveryMethodType::Ipv6Neighbor(method) => method.reliability(),
            DiscoveryMethodType::Ipv6Multicast(method) => method.reliability(),
            DiscoveryMethodType::Ipv6LinkLocal(method) => method.reliability(),
        }
    }
    
    fn supports_ipv6(&self) -> bool {
        match self {
            DiscoveryMethodType::Icmp(method) => method.supports_ipv6(),
            DiscoveryMethodType::Tcp(method) => method.supports_ipv6(),
            DiscoveryMethodType::Udp(method) => method.supports_ipv6(),
            DiscoveryMethodType::Arp(method) => method.supports_ipv6(),
            DiscoveryMethodType::Ipv6Neighbor(method) => method.supports_ipv6(),
            DiscoveryMethodType::Ipv6Multicast(method) => method.supports_ipv6(),
            DiscoveryMethodType::Ipv6LinkLocal(method) => method.supports_ipv6(),
        }
    }
}

/// Discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub timeout: Duration,
    pub max_retries: u32,
    pub parallel_limit: usize,
    pub enable_ipv6: bool,
    pub enable_os_detection: bool,
    pub stealth_level: StealthLevel,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            max_retries: 2,
            parallel_limit: 100,
            enable_ipv6: true,
            enable_os_detection: true,
            stealth_level: StealthLevel::Normal,
        }
    }
}

/// Stealth level for discovery
#[derive(Debug, Clone, Copy)]
pub enum StealthLevel {
    Paranoid,
    Sneaky,
    Polite,
    Normal,
    Aggressive,
    Insane,
}

/// Network type detection
#[derive(Debug, Clone, Copy)]
pub enum NetworkType {
    Local,      // Same subnet - prefer ARP
    Remote,     // Different subnet - prefer ICMP/TCP
    Internet,   // Internet hosts - TCP SYN preferred
    Unknown,    // Auto-detect best method
}

/// Discovery errors
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Timeout error")]
    Timeout,
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("IPv6 feature error: {0}")]
    IPv6Error(String),
    
    #[error("OS detection error: {0}")]
    OSDetectionError(String),
    
    #[error("Invalid target: {0}")]
    InvalidTarget(String),
}

pub type DiscoveryResultType = Result<DiscoveryResult, DiscoveryError>;