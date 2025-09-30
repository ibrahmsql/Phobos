//! Address exclusion utilities

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashSet;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct AddressExclusions {
    ipv4_addresses: HashSet<Ipv4Addr>,
    ipv6_addresses: HashSet<Ipv6Addr>,
    ipv4_ranges: Vec<(Ipv4Addr, Ipv4Addr)>,
    ipv6_ranges: Vec<(Ipv6Addr, Ipv6Addr)>,
    cidr_blocks: Vec<IpNetwork>,
}

#[derive(Debug, Clone)]
pub enum IpNetwork {
    V4(Ipv4Network),
    V6(Ipv6Network),
}

#[derive(Debug, Clone)]
pub struct Ipv4Network {
    addr: Ipv4Addr,
    prefix: u8,
}

#[derive(Debug, Clone)]
pub struct Ipv6Network {
    addr: Ipv6Addr,
    prefix: u8,
}

impl AddressExclusions {
    pub fn new() -> Self {
        Self {
            ipv4_addresses: HashSet::new(),
            ipv6_addresses: HashSet::new(),
            ipv4_ranges: Vec::new(),
            ipv6_ranges: Vec::new(),
            cidr_blocks: Vec::new(),
        }
    }

    /// Add exclusions from comma-separated string
    pub fn from_str(exclusions: &str) -> Result<Self, String> {
        let mut excluder = Self::new();
        
        for exclusion in exclusions.split(',') {
            let exclusion = exclusion.trim();
            if exclusion.is_empty() {
                continue;
            }
            
            excluder.add_exclusion(exclusion)?;
        }
        
        Ok(excluder)
    }

    /// Add a single exclusion (IP, range, or CIDR)
    pub fn add_exclusion(&mut self, exclusion: &str) -> Result<(), String> {
        let exclusion = exclusion.trim();
        
        // Try CIDR notation first
        if exclusion.contains('/') {
            self.add_cidr(exclusion)?;
        }
        // Try range notation (IP1-IP2)
        else if exclusion.contains('-') {
            self.add_range(exclusion)?;
        }
        // Single IP address
        else {
            self.add_address(exclusion)?;
        }
        
        Ok(())
    }

    /// Add single IP address
    fn add_address(&mut self, addr_str: &str) -> Result<(), String> {
        match IpAddr::from_str(addr_str) {
            Ok(IpAddr::V4(addr)) => {
                self.ipv4_addresses.insert(addr);
            }
            Ok(IpAddr::V6(addr)) => {
                self.ipv6_addresses.insert(addr);
            }
            Err(_) => return Err(format!("Invalid IP address: {}", addr_str)),
        }
        Ok(())
    }

    /// Add IP range
    fn add_range(&mut self, range_str: &str) -> Result<(), String> {
        let parts: Vec<&str> = range_str.split('-').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid range format: {}", range_str));
        }

        let start_addr = IpAddr::from_str(parts[0].trim())
            .map_err(|_| format!("Invalid start IP: {}", parts[0]))?;
        let end_addr = IpAddr::from_str(parts[1].trim())
            .map_err(|_| format!("Invalid end IP: {}", parts[1]))?;

        match (start_addr, end_addr) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                if start <= end {
                    self.ipv4_ranges.push((start, end));
                } else {
                    return Err("Start IP must be less than or equal to end IP".to_string());
                }
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                if start <= end {
                    self.ipv6_ranges.push((start, end));
                } else {
                    return Err("Start IP must be less than or equal to end IP".to_string());
                }
            }
            _ => return Err("Start and end IP must be the same version".to_string()),
        }

        Ok(())
    }

    /// Add CIDR block
    fn add_cidr(&mut self, cidr_str: &str) -> Result<(), String> {
        let parts: Vec<&str> = cidr_str.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid CIDR format: {}", cidr_str));
        }

        let addr = IpAddr::from_str(parts[0].trim())
            .map_err(|_| format!("Invalid IP in CIDR: {}", parts[0]))?;
        let prefix: u8 = parts[1].trim().parse()
            .map_err(|_| format!("Invalid prefix length: {}", parts[1]))?;

        match addr {
            IpAddr::V4(addr) => {
                if prefix > 32 {
                    return Err(format!("IPv4 prefix length cannot exceed 32: {}", prefix));
                }
                self.cidr_blocks.push(IpNetwork::V4(Ipv4Network { addr, prefix }));
            }
            IpAddr::V6(addr) => {
                if prefix > 128 {
                    return Err(format!("IPv6 prefix length cannot exceed 128: {}", prefix));
                }
                self.cidr_blocks.push(IpNetwork::V6(Ipv6Network { addr, prefix }));
            }
        }

        Ok(())
    }

    /// Check if an IP address should be excluded
    pub fn is_excluded(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(addr) => self.is_ipv4_excluded(addr),
            IpAddr::V6(addr) => self.is_ipv6_excluded(addr),
        }
    }

    /// Check IPv4 exclusion
    fn is_ipv4_excluded(&self, addr: Ipv4Addr) -> bool {
        // Check individual addresses
        if self.ipv4_addresses.contains(&addr) {
            return true;
        }

        // Check ranges
        for (start, end) in &self.ipv4_ranges {
            if addr >= *start && addr <= *end {
                return true;
            }
        }

        // Check CIDR blocks
        for cidr in &self.cidr_blocks {
            if let IpNetwork::V4(network) = cidr {
                if network.contains_ipv4(addr) {
                    return true;
                }
            }
        }

        false
    }

    /// Check IPv6 exclusion
    fn is_ipv6_excluded(&self, addr: Ipv6Addr) -> bool {
        // Check individual addresses
        if self.ipv6_addresses.contains(&addr) {
            return true;
        }

        // Check ranges
        for (start, end) in &self.ipv6_ranges {
            if addr >= *start && addr <= *end {
                return true;
            }
        }

        // Check CIDR blocks
        for cidr in &self.cidr_blocks {
            if let IpNetwork::V6(network) = cidr {
                if network.contains_ipv6(addr) {
                    return true;
                }
            }
        }

        false
    }

    /// Filter a list of IP addresses
    pub fn filter_addresses(&self, addresses: Vec<IpAddr>) -> Vec<IpAddr> {
        addresses.into_iter().filter(|addr| !self.is_excluded(*addr)).collect()
    }

    /// Get statistics about exclusions
    pub fn stats(&self) -> ExclusionStats {
        ExclusionStats {
            individual_ipv4: self.ipv4_addresses.len(),
            individual_ipv6: self.ipv6_addresses.len(),
            ipv4_ranges: self.ipv4_ranges.len(),
            ipv6_ranges: self.ipv6_ranges.len(),
            cidr_blocks: self.cidr_blocks.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExclusionStats {
    pub individual_ipv4: usize,
    pub individual_ipv6: usize,
    pub ipv4_ranges: usize,
    pub ipv6_ranges: usize,
    pub cidr_blocks: usize,
}

impl Ipv4Network {
    fn contains_ipv4(&self, addr: Ipv4Addr) -> bool {
        let network_addr = u32::from(self.addr);
        let test_addr = u32::from(addr);
        let mask = !((1u32 << (32 - self.prefix)) - 1);
        
        (network_addr & mask) == (test_addr & mask)
    }
}

impl Ipv6Network {
    fn contains_ipv6(&self, addr: Ipv6Addr) -> bool {
        let network_octets = self.addr.octets();
        let test_octets = addr.octets();
        
        let prefix_bytes = (self.prefix / 8) as usize;
        let remaining_bits = self.prefix % 8;
        
        // Check complete bytes
        for i in 0..prefix_bytes {
            if network_octets[i] != test_octets[i] {
                return false;
            }
        }
        
        // Check remaining bits if any
        if remaining_bits > 0 && prefix_bytes < 16 {
            let mask = !((1u8 << (8 - remaining_bits)) - 1);
            if (network_octets[prefix_bytes] & mask) != (test_octets[prefix_bytes] & mask) {
                return false;
            }
        }
        
        true
    }
}

/// Common exclusion presets
pub struct ExclusionPresets;

impl ExclusionPresets {
    /// RFC 1918 private networks
    pub fn rfc1918() -> AddressExclusions {
        let mut excluder = AddressExclusions::new();
        let _ = excluder.add_cidr("10.0.0.0/8");
        let _ = excluder.add_cidr("172.16.0.0/12");
        let _ = excluder.add_cidr("192.168.0.0/16");
        excluder
    }

    /// Localhost and loopback
    pub fn localhost() -> AddressExclusions {
        let mut excluder = AddressExclusions::new();
        let _ = excluder.add_cidr("127.0.0.0/8");
        let _ = excluder.add_cidr("::1/128");
        excluder
    }

    /// Multicast addresses
    pub fn multicast() -> AddressExclusions {
        let mut excluder = AddressExclusions::new();
        let _ = excluder.add_cidr("224.0.0.0/4");
        let _ = excluder.add_cidr("ff00::/8");
        excluder
    }

    /// Link-local addresses
    pub fn link_local() -> AddressExclusions {
        let mut excluder = AddressExclusions::new();
        let _ = excluder.add_cidr("169.254.0.0/16");
        let _ = excluder.add_cidr("fe80::/10");
        excluder
    }

    /// Combine common internal exclusions
    pub fn internal_networks() -> AddressExclusions {
        let mut excluder = AddressExclusions::new();
        
        // RFC 1918 private networks
        let _ = excluder.add_cidr("10.0.0.0/8");
        let _ = excluder.add_cidr("172.16.0.0/12");
        let _ = excluder.add_cidr("192.168.0.0/16");
        
        // Localhost
        let _ = excluder.add_cidr("127.0.0.0/8");
        let _ = excluder.add_cidr("::1/128");
        
        // Link-local
        let _ = excluder.add_cidr("169.254.0.0/16");
        let _ = excluder.add_cidr("fe80::/10");
        
        // Multicast
        let _ = excluder.add_cidr("224.0.0.0/4");
        let _ = excluder.add_cidr("ff00::/8");
        
        excluder
    }
}