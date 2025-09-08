//! Target parsing utilities for IPv6 and CIDR support
//!
//! This module provides comprehensive target parsing capabilities including:
//! - IPv4 and IPv6 address parsing
//! - CIDR notation support for both IPv4 and IPv6
//! - Hostname resolution with dual-stack support
//! - Target validation and normalization

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::str::FromStr;

/// Represents a parsed target with its type and addresses
#[derive(Debug, Clone)]
pub struct ParsedTarget {
    pub original: String,
    pub target_type: TargetType,
    pub addresses: Vec<IpAddr>,
    pub cidr_info: Option<CidrInfo>,
}

/// Type of target being scanned
#[derive(Debug, Clone, PartialEq)]
pub enum TargetType {
    SingleIpv4,
    SingleIpv6,
    Ipv4Cidr,
    Ipv6Cidr,
    Hostname,
    HostnameList,
}

/// CIDR network information
#[derive(Debug, Clone)]
pub struct CidrInfo {
    pub network: IpAddr,
    pub prefix_length: u8,
    pub total_addresses: u64,
    pub is_ipv6: bool,
}

/// Target parser with IPv6 and CIDR support
pub struct TargetParser {
    max_cidr_addresses: u64,
    enable_ipv6: bool,
    resolve_hostnames: bool,
}

impl Default for TargetParser {
    fn default() -> Self {
        Self {
            max_cidr_addresses: 65536, // Limit CIDR expansion
            enable_ipv6: true,
            resolve_hostnames: true,
        }
    }
}

impl TargetParser {
    /// Create a new target parser with custom settings
    pub fn new(max_cidr_addresses: u64, enable_ipv6: bool, resolve_hostnames: bool) -> Self {
        Self {
            max_cidr_addresses,
            enable_ipv6,
            resolve_hostnames,
        }
    }
    
    /// Parse a target string into a ParsedTarget
    pub fn parse_target(&self, target: &str) -> Result<ParsedTarget> {
        let target = target.trim();
        
        // Try parsing as IPv4 CIDR
        if let Ok(cidr) = self.parse_ipv4_cidr(target) {
            return Ok(cidr);
        }
        
        // Try parsing as IPv6 CIDR
        if self.enable_ipv6 {
            if let Ok(cidr) = self.parse_ipv6_cidr(target) {
                return Ok(cidr);
            }
        }
        
        // Try parsing as single IPv4 address
        if let Ok(ipv4) = Ipv4Addr::from_str(target) {
            return Ok(ParsedTarget {
                original: target.to_string(),
                target_type: TargetType::SingleIpv4,
                addresses: vec![IpAddr::V4(ipv4)],
                cidr_info: None,
            });
        }
        
        // Try parsing as single IPv6 address
        if self.enable_ipv6 {
            if let Ok(ipv6) = Ipv6Addr::from_str(target) {
                return Ok(ParsedTarget {
                    original: target.to_string(),
                    target_type: TargetType::SingleIpv6,
                    addresses: vec![IpAddr::V6(ipv6)],
                    cidr_info: None,
                });
            }
        }
        
        // Try resolving as hostname
        if self.resolve_hostnames {
            if let Ok(hostname_target) = self.resolve_hostname(target) {
                return Ok(hostname_target);
            }
        }
        
        Err(anyhow::anyhow!("Invalid target format: {}", target))
    }
    
    /// Parse IPv4 CIDR notation
    fn parse_ipv4_cidr(&self, target: &str) -> Result<ParsedTarget> {
        if !target.contains('/') {
            return Err(anyhow::anyhow!("Not a CIDR"));
        }
        
        let parts: Vec<&str> = target.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid CIDR format"));
        }
        
        let network_addr = Ipv4Addr::from_str(parts[0])
            .context("Invalid IPv4 address in CIDR")?;
        let prefix_length: u8 = parts[1].parse()
            .context("Invalid prefix length")?;
        
        if prefix_length > 32 {
            return Err(anyhow::anyhow!("IPv4 prefix length cannot exceed 32"));
        }
        
        let addresses = self.expand_ipv4_cidr(network_addr, prefix_length)?;
        let total_addresses = 2u64.pow((32 - prefix_length) as u32);
        
        Ok(ParsedTarget {
            original: target.to_string(),
            target_type: TargetType::Ipv4Cidr,
            addresses,
            cidr_info: Some(CidrInfo {
                network: IpAddr::V4(network_addr),
                prefix_length,
                total_addresses,
                is_ipv6: false,
            }),
        })
    }
    
    /// Parse IPv6 CIDR notation
    fn parse_ipv6_cidr(&self, target: &str) -> Result<ParsedTarget> {
        if !target.contains('/') {
            return Err(anyhow::anyhow!("Not a CIDR"));
        }
        
        let parts: Vec<&str> = target.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid CIDR format"));
        }
        
        let network_addr = Ipv6Addr::from_str(parts[0])
            .context("Invalid IPv6 address in CIDR")?;
        let prefix_length: u8 = parts[1].parse()
            .context("Invalid prefix length")?;
        
        if prefix_length > 128 {
            return Err(anyhow::anyhow!("IPv6 prefix length cannot exceed 128"));
        }
        
        let addresses = self.expand_ipv6_cidr(network_addr, prefix_length)?;
        let total_addresses = if prefix_length < 64 {
            u64::MAX // Too many to count accurately
        } else {
            2u64.pow((128 - prefix_length) as u32)
        };
        
        Ok(ParsedTarget {
            original: target.to_string(),
            target_type: TargetType::Ipv6Cidr,
            addresses,
            cidr_info: Some(CidrInfo {
                network: IpAddr::V6(network_addr),
                prefix_length,
                total_addresses,
                is_ipv6: true,
            }),
        })
    }
    
    /// Expand IPv4 CIDR into individual addresses
    fn expand_ipv4_cidr(&self, network: Ipv4Addr, prefix_length: u8) -> Result<Vec<IpAddr>> {
        let host_bits = 32 - prefix_length;
        let max_hosts = 2u64.pow(host_bits as u32);
        
        if max_hosts > self.max_cidr_addresses {
            return Err(anyhow::anyhow!(
                "CIDR network too large: {} addresses (max: {})",
                max_hosts,
                self.max_cidr_addresses
            ));
        }
        
        let network_u32 = u32::from(network);
        let mask = !((1u32 << host_bits) - 1);
        let network_base = network_u32 & mask;
        
        let mut addresses = Vec::new();
        for i in 0..max_hosts {
            let addr_u32 = network_base | (i as u32);
            addresses.push(IpAddr::V4(Ipv4Addr::from(addr_u32)));
        }
        
        Ok(addresses)
    }
    
    /// Expand IPv6 CIDR into individual addresses (limited expansion)
    fn expand_ipv6_cidr(&self, network: Ipv6Addr, prefix_length: u8) -> Result<Vec<IpAddr>> {
        let host_bits = 128 - prefix_length;
        
        // For IPv6, we limit expansion more aggressively
        if host_bits > 16 {
            return Err(anyhow::anyhow!(
                "IPv6 CIDR network too large: /{} (max supported: /112)",
                prefix_length
            ));
        }
        
        let max_hosts = std::cmp::min(
            2u64.pow(host_bits as u32),
            self.max_cidr_addresses
        );
        
        let network_bytes = network.octets();
        let mut addresses = Vec::new();
        
        // Generate addresses by incrementing the host portion
        for i in 0..max_hosts {
            // Apply the host increment to the appropriate bytes
            let host_offset = i as u128;
            let addr_u128 = u128::from_be_bytes(network_bytes) | host_offset;
            let addr_bytes = addr_u128.to_be_bytes();
            
            addresses.push(IpAddr::V6(Ipv6Addr::from(addr_bytes)));
        }
        
        Ok(addresses)
    }
    
    /// Resolve hostname to IP addresses
    fn resolve_hostname(&self, hostname: &str) -> Result<ParsedTarget> {
        let socket_addrs = format!("{}:80", hostname)
            .to_socket_addrs()
            .context("Failed to resolve hostname")?;
        
        let mut addresses = Vec::new();
        let mut seen = HashSet::new();
        
        for socket_addr in socket_addrs {
            let ip = socket_addr.ip();
            
            // Filter IPv6 if disabled
            if !self.enable_ipv6 && ip.is_ipv6() {
                continue;
            }
            
            if seen.insert(ip) {
                addresses.push(ip);
            }
        }
        
        if addresses.is_empty() {
            return Err(anyhow::anyhow!("No valid IP addresses resolved for hostname"));
        }
        
        let target_type = if addresses.len() == 1 {
            match addresses[0] {
                IpAddr::V4(_) => TargetType::SingleIpv4,
                IpAddr::V6(_) => TargetType::SingleIpv6,
            }
        } else {
            TargetType::HostnameList
        };
        
        Ok(ParsedTarget {
            original: hostname.to_string(),
            target_type,
            addresses,
            cidr_info: None,
        })
    }
    
    /// Validate target before parsing
    pub fn validate_target(&self, target: &str) -> Result<()> {
        let target = target.trim();
        
        if target.is_empty() {
            return Err(anyhow::anyhow!("Target cannot be empty"));
        }
        
        // Check for obviously invalid characters
        if target.contains(' ') && !target.starts_with('[') {
            return Err(anyhow::anyhow!("Invalid characters in target"));
        }
        
        // Basic length check
        if target.len() > 253 {
            return Err(anyhow::anyhow!("Target too long (max 253 characters)"));
        }
        
        Ok(())
    }
    
    /// Get target statistics
    pub fn get_target_stats(&self, target: &ParsedTarget) -> TargetStats {
        TargetStats {
            total_addresses: target.addresses.len(),
            ipv4_count: target.addresses.iter().filter(|ip| ip.is_ipv4()).count(),
            ipv6_count: target.addresses.iter().filter(|ip| ip.is_ipv6()).count(),
            is_cidr: target.cidr_info.is_some(),
            estimated_scan_time: self.estimate_scan_time(target.addresses.len()),
        }
    }
    
    /// Estimate scan time based on address count
    fn estimate_scan_time(&self, address_count: usize) -> std::time::Duration {
        // Rough estimation: 1000 addresses per second
        let seconds = (address_count as f64 / 1000.0).ceil() as u64;
        std::time::Duration::from_secs(seconds)
    }
}

/// Target statistics
#[derive(Debug, Clone)]
pub struct TargetStats {
    pub total_addresses: usize,
    pub ipv4_count: usize,
    pub ipv6_count: usize,
    pub is_cidr: bool,
    pub estimated_scan_time: std::time::Duration,
}

/// Parse multiple targets from a string
pub fn parse_target_list(targets: &str, parser: &TargetParser) -> Result<Vec<ParsedTarget>> {
    let mut parsed_targets = Vec::new();
    
    for target in targets.split(',') {
        let target = target.trim();
        if !target.is_empty() {
            parsed_targets.push(parser.parse_target(target)?);
        }
    }
    
    Ok(parsed_targets)
}

/// Normalize IPv6 address for consistent representation
pub fn normalize_ipv6(addr: &Ipv6Addr) -> String {
    // Use the canonical representation
    format!("{}", addr)
}

/// Check if an IPv6 address is in a specific scope
pub fn ipv6_scope(addr: &Ipv6Addr) -> IPv6Scope {
    if addr.is_loopback() {
        IPv6Scope::Loopback
    } else if addr.is_unicast_link_local() {
        IPv6Scope::LinkLocal
    } else if addr.segments()[0] & 0xffc0 == 0xfec0 { // Site-local check
        IPv6Scope::SiteLocal
    } else if addr.is_multicast() {
        IPv6Scope::Multicast
    } else {
        IPv6Scope::Global
    }
}

/// IPv6 address scope
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IPv6Scope {
    Loopback,
    LinkLocal,
    SiteLocal,
    Global,
    Multicast,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ipv4_single_address() {
        let parser = TargetParser::default();
        let result = parser.parse_target("192.168.1.1").unwrap();
        
        assert_eq!(result.target_type, TargetType::SingleIpv4);
        assert_eq!(result.addresses.len(), 1);
        assert_eq!(result.addresses[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }
    
    #[test]
    fn test_ipv6_single_address() {
        let parser = TargetParser::default();
        let result = parser.parse_target("2001:db8::1").unwrap();
        
        assert_eq!(result.target_type, TargetType::SingleIpv6);
        assert_eq!(result.addresses.len(), 1);
    }
    
    #[test]
    fn test_ipv4_cidr() {
        let parser = TargetParser::default();
        let result = parser.parse_target("192.168.1.0/30").unwrap();
        
        assert_eq!(result.target_type, TargetType::Ipv4Cidr);
        assert_eq!(result.addresses.len(), 4);
        assert!(result.cidr_info.is_some());
    }
    
    #[test]
    fn test_ipv6_cidr() {
        let parser = TargetParser::default();
        let result = parser.parse_target("2001:db8::/126").unwrap();
        
        assert_eq!(result.target_type, TargetType::Ipv6Cidr);
        assert_eq!(result.addresses.len(), 4);
        assert!(result.cidr_info.is_some());
    }
    
    #[test]
    fn test_invalid_target() {
        let parser = TargetParser::default();
        assert!(parser.parse_target("invalid..target").is_err());
    }
    
    #[test]
    fn test_cidr_too_large() {
        let parser = TargetParser::new(100, true, true);
        assert!(parser.parse_target("192.168.0.0/16").is_err());
    }
}