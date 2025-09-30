//! Address parsing with CIDR, IPv6, and file support

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;
use anyhow::{anyhow, Result};
use cidr_utils::cidr::{IpCidr, IpInet};

/// Address parser for multiple input formats
#[derive(Debug, Clone)]
pub struct AddressParser {
    exclude_addresses: Vec<IpCidr>,
    custom_resolver: Option<String>,
}

impl Default for AddressParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressParser {
    pub fn new() -> Self {
        Self {
            exclude_addresses: Vec::new(),
            custom_resolver: None,
        }
    }

    /// Set addresses to exclude from scanning
    pub fn with_exclude_addresses(mut self, exclude: Vec<String>) -> Result<Self> {
        self.exclude_addresses = self.parse_excluded_addresses(&exclude)?;
        Ok(self)
    }

    /// Set custom DNS resolver
    pub fn with_resolver(mut self, resolver: String) -> Self {
        self.custom_resolver = Some(resolver);
        self
    }

    /// Parse multiple address formats efficiently
    /// Supports: IP, CIDR, hostname, file paths
    /// Returns deduplicated list for optimal scanning
    pub fn parse_addresses(&self, addresses: &[String]) -> Result<Vec<IpAddr>> {
        let mut all_ips = Vec::new();
        let mut unresolved = Vec::new();

        // First pass: handle direct IPs and CIDRs (fastest)
        for address in addresses {
            match self.parse_single_address(address) {
                Ok(ips) => all_ips.extend(ips),
                Err(_) => unresolved.push(address.as_str()),
            }
        }

        // Second pass: handle files and hostnames (slower operations)
        for address in unresolved {
            if let Ok(file_ips) = self.parse_file_or_hostname(address) {
                all_ips.extend(file_ips);
            } else {
                log::warn!("Could not resolve address: {}", address);
            }
        }

        // Deduplicate and apply exclusions efficiently
        let mut seen = BTreeSet::new();
        all_ips.retain(|ip| {
            seen.insert(*ip) && !self.is_excluded(ip)
        });

        log::info!("Parsed {} unique addresses for scanning", all_ips.len());
        Ok(all_ips)
    }

    /// Parse a single address (IP, CIDR, or hostname)
    fn parse_single_address(&self, address: &str) -> Result<Vec<IpAddr>> {
        // Try IP address first (fastest)
        if let Ok(ip) = IpAddr::from_str(address) {
            return Ok(vec![ip]);
        }

        // Try CIDR notation (very efficient for subnets)
        if let Ok(inet) = IpInet::from_str(address) {
            let network = inet.network();
            let addresses: Vec<IpAddr> = network.into_iter().addresses().collect();
            log::info!("CIDR {} expanded to {} addresses", address, addresses.len());
            return Ok(addresses);
        }

        // Try hostname resolution (slower, so defer to second pass)
        Err(anyhow!("Not a direct IP or CIDR"))
    }

    /// Parse file or resolve hostname
    fn parse_file_or_hostname(&self, address: &str) -> Result<Vec<IpAddr>> {
        let path = Path::new(address);
        
        if path.exists() && path.is_file() {
            // Read from file
            self.parse_file(path)
        } else {
            // Try hostname resolution
            self.resolve_hostname(address)
        }
    }

    /// Parse addresses from file efficiently
    fn parse_file(&self, path: &Path) -> Result<Vec<IpAddr>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut ips = Vec::new();

        for line_result in reader.lines() {
            if let Ok(line) = line_result {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue; // Skip empty lines and comments
                }

                // Try to parse each line as IP/CIDR/hostname
                if let Ok(parsed_ips) = self.parse_single_address(line) {
                    ips.extend(parsed_ips);
                } else if let Ok(resolved) = self.resolve_hostname(line) {
                    ips.extend(resolved);
                }
            }
        }

        log::info!("Loaded {} addresses from file: {}", ips.len(), path.display());
        Ok(ips)
    }

    /// Resolve hostname to IP addresses
    fn resolve_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        // Try standard resolution first
        let socket_str = format!("{}:80", hostname);
        match socket_str.to_socket_addrs() {
            Ok(addrs) => {
                let mut ips = Vec::new();
                for addr in addrs {
                    ips.push(addr.ip());
                }
                if !ips.is_empty() {
                    return Ok(ips);
                }
            }
            Err(_) => {}
        }

        // TODO: Add custom resolver support here if needed
        Err(anyhow!("Could not resolve hostname: {}", hostname))
    }

    /// Parse excluded addresses efficiently
    fn parse_excluded_addresses(&self, exclude: &[String]) -> Result<Vec<IpCidr>> {
        let mut excluded = Vec::new();

        for addr in exclude {
            // Try CIDR first
            if let Ok(cidr) = IpCidr::from_str(addr) {
                excluded.push(cidr);
                continue;
            }

            // Try single IP
            if let Ok(ip) = IpAddr::from_str(addr) {
                excluded.push(IpCidr::new_host(ip));
                continue;
            }

            // Try hostname resolution
            if let Ok(ips) = self.resolve_hostname(addr) {
                for ip in ips {
                    excluded.push(IpCidr::new_host(ip));
                }
            }
        }

        Ok(excluded)
    }

    /// Check if IP should be excluded (very fast check)
    fn is_excluded(&self, ip: &IpAddr) -> bool {
        self.exclude_addresses.iter().any(|cidr| cidr.contains(ip))
    }

    /// Get statistics about parsed addresses
    pub fn get_address_stats(&self, addresses: &[IpAddr]) -> AddressStats {
        let mut ipv4_count = 0;
        let mut ipv6_count = 0;

        for addr in addresses {
            match addr {
                IpAddr::V4(_) => ipv4_count += 1,
                IpAddr::V6(_) => ipv6_count += 1,
            }
        }

        let total_addresses = addresses.len();
        let estimated_scan_time = if total_addresses > 1000 {
            std::time::Duration::from_secs((total_addresses as u64) / 100) // Rough estimate
        } else {
            std::time::Duration::from_secs(10)
        };

        AddressStats {
            total_addresses,
            ipv4_count,
            ipv6_count,
            estimated_scan_time,
        }
    }
}

/// Statistics about parsed addresses
#[derive(Debug, Clone)]
pub struct AddressStats {
    pub total_addresses: usize,
    pub ipv4_count: usize,
    pub ipv6_count: usize,
    pub estimated_scan_time: std::time::Duration,
}

/// Convenience function for quick address parsing
pub fn parse_addresses_simple(addresses: &[String]) -> Result<Vec<IpAddr>> {
    let parser = AddressParser::new();
    parser.parse_addresses(addresses)
}

/// Parse addresses with exclusions
pub fn parse_addresses_with_exclusions(
    addresses: &[String],
    exclude: Vec<String>
) -> Result<Vec<IpAddr>> {
    let parser = AddressParser::new().with_exclude_addresses(exclude)?;
    parser.parse_addresses(addresses)
}

