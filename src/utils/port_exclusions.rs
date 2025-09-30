//! Port exclusion utilities

use std::collections::HashSet;
use std::ops::RangeInclusive;
use anyhow::{anyhow, Result};

/// Port exclusion manager for efficient filtering
#[derive(Debug, Clone)]
pub struct PortExclusionManager {
    excluded_ports: HashSet<u16>,
    excluded_ranges: Vec<RangeInclusive<u16>>,
}

impl Default for PortExclusionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PortExclusionManager {
    pub fn new() -> Self {
        Self {
            excluded_ports: HashSet::new(),
            excluded_ranges: Vec::new(),
        }
    }

    /// Add individual ports to exclusion list
    pub fn exclude_ports(mut self, ports: Vec<u16>) -> Self {
        for port in ports {
            self.excluded_ports.insert(port);
        }
        self
    }

    /// Add port ranges to exclusion list
    pub fn exclude_port_ranges(mut self, ranges: Vec<RangeInclusive<u16>>) -> Self {
        self.excluded_ranges.extend(ranges);
        self
    }

    /// Parse port exclusion string (e.g., "22,80,443,1000-2000")
    pub fn parse_exclusions(exclusions: &str) -> Result<Self> {
        let mut manager = Self::new();

        for part in exclusions.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if part.contains('-') {
                // Handle range (e.g., "1000-2000")
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() != 2 {
                    return Err(anyhow!("Invalid port range format: {}", part));
                }

                let start: u16 = range_parts[0].trim().parse()
                    .map_err(|_| anyhow!("Invalid start port: {}", range_parts[0]))?;
                let end: u16 = range_parts[1].trim().parse()
                    .map_err(|_| anyhow!("Invalid end port: {}", range_parts[1]))?;

                if start > end {
                    return Err(anyhow!("Invalid range: start ({}) > end ({})", start, end));
                }

                manager.excluded_ranges.push(start..=end);
            } else {
                // Handle single port
                let port: u16 = part.parse()
                    .map_err(|_| anyhow!("Invalid port number: {}", part))?;
                manager.excluded_ports.insert(port);
            }
        }

        log::info!("Port exclusions parsed: {} individual ports, {} ranges", 
            manager.excluded_ports.len(), 
            manager.excluded_ranges.len()
        );

        Ok(manager)
    }

    /// Check if a port should be excluded (very fast lookup)
    pub fn is_excluded(&self, port: u16) -> bool {
        // Check individual ports first (O(1) lookup)
        if self.excluded_ports.contains(&port) {
            return true;
        }

        // Check ranges (O(n) but typically very few ranges)
        for range in &self.excluded_ranges {
            if range.contains(&port) {
                return true;
            }
        }

        false
    }

    /// Filter a list of ports, removing excluded ones
    /// This is more efficient than checking each port individually
    pub fn filter_ports(&self, ports: Vec<u16>) -> Vec<u16> {
        if self.excluded_ports.is_empty() && self.excluded_ranges.is_empty() {
            // No exclusions, return original list
            return ports;
        }

        let original_count = ports.len();
        let filtered: Vec<u16> = ports.into_iter()
            .filter(|&port| !self.is_excluded(port))
            .collect();

        let excluded_count = original_count - filtered.len();
        if excluded_count > 0 {
            log::info!("Excluded {} ports from scan ({} remaining)", 
                excluded_count, filtered.len());
        }

        filtered
    }

    /// Get exclusion statistics
    pub fn get_exclusion_stats(&self) -> ExclusionStats {
        let range_port_count: u16 = self.excluded_ranges.iter()
            .map(|range| range.end() - range.start() + 1)
            .sum();

        ExclusionStats {
            individual_ports: self.excluded_ports.len(),
            port_ranges: self.excluded_ranges.len(),
            total_range_ports: range_port_count as usize,
            total_excluded_estimate: self.excluded_ports.len() + range_port_count as usize,
        }
    }

    /// Add common dangerous ports to exclusion list
    pub fn exclude_dangerous_ports(mut self) -> Self {
        // Add commonly dangerous or unwanted ports
        let dangerous_ports = vec![
            135, 136, 137, 138, 139,  // NetBIOS
            445,                       // SMB
            1433, 1434,               // SQL Server
            3389,                     // RDP
            5985, 5986,               // WinRM
        ];

        for port in dangerous_ports {
            self.excluded_ports.insert(port);
        }

        log::info!("Added common dangerous ports to exclusion list");
        self
    }

    /// Add common noisy ports to exclusion list  
    pub fn exclude_noisy_ports(mut self) -> Self {
        // Add ports that generate lots of noise/alerts
        let noisy_ports = vec![
            7,      // Echo
            9,      // Discard
            13,     // Daytime
            19,     // Character Generator
            37,     // Time
            123,    // NTP
            161,    // SNMP
            162,    // SNMP Trap
        ];

        for port in noisy_ports {
            self.excluded_ports.insert(port);
        }

        log::info!("Added common noisy ports to exclusion list");
        self
    }
}

#[derive(Debug, Clone)]
pub struct ExclusionStats {
    pub individual_ports: usize,
    pub port_ranges: usize,
    pub total_range_ports: usize,
    pub total_excluded_estimate: usize,
}

/// Convenience function to parse and apply port exclusions
pub fn apply_port_exclusions(ports: Vec<u16>, exclusions: Option<&str>) -> Result<Vec<u16>> {
    match exclusions {
        Some(excl_str) => {
            let manager = PortExclusionManager::parse_exclusions(excl_str)?;
            Ok(manager.filter_ports(ports))
        }
        None => Ok(ports),
    }
}

/// Generate common port exclusion presets
pub mod presets {
    use super::*;

    /// Exclude Windows-specific ports (useful for Linux-only environments)
    pub fn windows_ports() -> PortExclusionManager {
        PortExclusionManager::new()
            .exclude_ports(vec![
                135, 136, 137, 138, 139, // NetBIOS
                445,                      // SMB
                593,                      // HTTP RPC Ep Map
                1433, 1434,              // SQL Server
                3389,                    // RDP
                5985, 5986,              // WinRM
            ])
    }

    /// Exclude database ports (for security-focused scans)
    pub fn database_ports() -> PortExclusionManager {
        PortExclusionManager::new()
            .exclude_ports(vec![
                1433, 1434,  // SQL Server
                3306,        // MySQL
                5432,        // PostgreSQL
                1521,        // Oracle
                27017,       // MongoDB
                6379,        // Redis
                11211,       // Memcached
            ])
    }

    /// Exclude development/testing ports
    pub fn development_ports() -> PortExclusionManager {
        PortExclusionManager::new()
            .exclude_port_ranges(vec![
                3000..=3999,  // Common dev server range
                8000..=8999,  // Common dev server range
                9000..=9999,  // Common dev server range
            ])
    }

    /// Exclude high ports (above 10000)
    pub fn high_ports() -> PortExclusionManager {
        PortExclusionManager::new()
            .exclude_port_ranges(vec![10001..=65535])
    }
}

