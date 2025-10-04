//! Scan history management and comparison

use crate::scanner::ScanResult;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use colored::*;

/// Scan history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistoryEntry {
    pub id: String,
    pub target: String,
    pub timestamp: DateTime<Utc>,
    pub duration_seconds: f64,
    pub open_ports: Vec<u16>,
    pub closed_ports: Vec<u16>,
    pub filtered_ports: Vec<u16>,
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub service: String,
}

/// Scan comparison result
#[derive(Debug)]
pub struct ScanDiff {
    pub new_open_ports: Vec<u16>,
    pub closed_ports: Vec<u16>,
    pub changed_services: Vec<ServiceChange>,
}

#[derive(Debug)]
pub struct ServiceChange {
    pub port: u16,
    pub old_service: String,
    pub new_service: String,
}

/// History manager
pub struct HistoryManager {
    history_dir: PathBuf,
}

impl HistoryManager {
    /// Create new history manager
    pub fn new() -> io::Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Home directory not found"))?;
        
        let history_dir = home.join(".phobos").join("history");
        fs::create_dir_all(&history_dir)?;
        
        Ok(Self { history_dir })
    }
    
    /// Save scan result to history
    pub fn save(&self, result: &ScanResult) -> io::Result<String> {
        let id = format!("{}_{}", 
            result.target.replace([':', '.', '/'], "_"),
            Utc::now().timestamp()
        );
        
        let entry = ScanHistoryEntry {
            id: id.clone(),
            target: result.target.clone(),
            timestamp: Utc::now(),
            duration_seconds: result.duration.as_secs_f64(),
            open_ports: result.open_ports.clone(),
            closed_ports: result.closed_ports.clone(),
            filtered_ports: result.filtered_ports.clone(),
            services: result.port_results.iter()
                .filter_map(|pr| {
                    pr.service.as_ref().map(|s| ServiceInfo {
                        port: pr.port,
                        service: s.clone(),
                    })
                })
                .collect(),
        };
        
        let file_path = self.history_dir.join(format!("{}.json", id));
        let json = serde_json::to_string_pretty(&entry)?;
        let mut file = File::create(file_path)?;
        file.write_all(json.as_bytes())?;
        
        Ok(id)
    }
    
    /// List all scan history
    pub fn list(&self) -> io::Result<Vec<ScanHistoryEntry>> {
        let mut entries = Vec::new();
        
        for entry in fs::read_dir(&self.history_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(scan_entry) = serde_json::from_str::<ScanHistoryEntry>(&content) {
                        entries.push(scan_entry);
                    }
                }
            }
        }
        
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(entries)
    }
    
    /// Get specific scan by ID
    pub fn get(&self, id: &str) -> io::Result<ScanHistoryEntry> {
        let file_path = self.history_dir.join(format!("{}.json", id));
        let content = fs::read_to_string(file_path)?;
        serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
    
    /// Compare two scans
    pub fn diff(&self, old_id: &str, new_id: &str) -> io::Result<ScanDiff> {
        let old_scan = self.get(old_id)?;
        let new_scan = self.get(new_id)?;
        
        let new_open_ports: Vec<u16> = new_scan.open_ports.iter()
            .filter(|p| !old_scan.open_ports.contains(p))
            .copied()
            .collect();
        
        let closed_ports: Vec<u16> = old_scan.open_ports.iter()
            .filter(|p| !new_scan.open_ports.contains(p))
            .copied()
            .collect();
        
        let mut changed_services = Vec::new();
        for new_service in &new_scan.services {
            if let Some(old_service) = old_scan.services.iter()
                .find(|s| s.port == new_service.port) {
                if old_service.service != new_service.service {
                    changed_services.push(ServiceChange {
                        port: new_service.port,
                        old_service: old_service.service.clone(),
                        new_service: new_service.service.clone(),
                    });
                }
            }
        }
        
        Ok(ScanDiff {
            new_open_ports,
            closed_ports,
            changed_services,
        })
    }
    
    /// Print scan history list
    pub fn print_list(&self) -> io::Result<()> {
        let entries = self.list()?;
        
        if entries.is_empty() {
            println!("{}", "No scan history found.".yellow());
            return Ok(());
        }
        
        println!("{}", "Scan History:".bright_cyan().bold());
        println!();
        
        for entry in entries {
            println!("{} {}", 
                "ID:".bright_white().bold(), 
                entry.id.bright_yellow()
            );
            println!("  Target: {}", entry.target.bright_cyan());
            println!("  Time: {}", entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("  Open Ports: {}", entry.open_ports.len().to_string().bright_green());
            println!("  Duration: {:.2}s", entry.duration_seconds);
            println!();
        }
        
        Ok(())
    }
    
    /// Print scan details
    pub fn print_scan(&self, id: &str) -> io::Result<()> {
        let entry = self.get(id)?;
        
        println!("{}", "Scan Details:".bright_cyan().bold());
        println!();
        println!("{} {}", "ID:".bright_white().bold(), entry.id.bright_yellow());
        println!("{} {}", "Target:".bright_white().bold(), entry.target.bright_cyan());
        println!("{} {}", "Time:".bright_white().bold(), entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("{} {:.2}s", "Duration:".bright_white().bold(), entry.duration_seconds);
        println!();
        
        if !entry.open_ports.is_empty() {
            println!("{}", "Open Ports:".bright_green().bold());
            for port in &entry.open_ports {
                let service = entry.services.iter()
                    .find(|s| s.port == *port)
                    .map(|s| s.service.as_str())
                    .unwrap_or("unknown");
                println!("  {}/tcp - {}", port, service.bright_yellow());
            }
            println!();
        }
        
        Ok(())
    }
    
    /// Print diff between two scans
    pub fn print_diff(&self, old_id: &str, new_id: &str) -> io::Result<()> {
        let old_scan = self.get(old_id)?;
        let new_scan = self.get(new_id)?;
        let diff = self.diff(old_id, new_id)?;
        
        println!("{}", "Scan Comparison:".bright_cyan().bold());
        println!();
        println!("{} {} ({})", 
            "Old Scan:".bright_white().bold(),
            old_scan.id.bright_yellow(),
            old_scan.timestamp.format("%Y-%m-%d %H:%M:%S")
        );
        println!("{} {} ({})", 
            "New Scan:".bright_white().bold(),
            new_scan.id.bright_yellow(),
            new_scan.timestamp.format("%Y-%m-%d %H:%M:%S")
        );
        println!();
        
        if !diff.new_open_ports.is_empty() {
            println!("{}", "✅ Newly Opened Ports:".bright_green().bold());
            for port in &diff.new_open_ports {
                let service = new_scan.services.iter()
                    .find(|s| s.port == *port)
                    .map(|s| s.service.as_str())
                    .unwrap_or("unknown");
                println!("  {} ({}) {}", 
                    port.to_string().bright_green(),
                    service.bright_yellow(),
                    "← NEW".bright_green()
                );
            }
            println!();
        }
        
        if !diff.closed_ports.is_empty() {
            println!("{}", "❌ Closed Ports:".bright_red().bold());
            for port in &diff.closed_ports {
                let service = old_scan.services.iter()
                    .find(|s| s.port == *port)
                    .map(|s| s.service.as_str())
                    .unwrap_or("unknown");
                println!("  {} ({}) {}", 
                    port.to_string().bright_red(),
                    service.bright_yellow(),
                    "← CLOSED".bright_red()
                );
            }
            println!();
        }
        
        if !diff.changed_services.is_empty() {
            println!("{}", "⚠️  Changed Services:".bright_yellow().bold());
            for change in &diff.changed_services {
                println!("  {} {} → {}", 
                    change.port.to_string().bright_yellow(),
                    change.old_service.bright_cyan(),
                    change.new_service.bright_green()
                );
            }
            println!();
        }
        
        if diff.new_open_ports.is_empty() && diff.closed_ports.is_empty() && diff.changed_services.is_empty() {
            println!("{}", "No changes detected.".bright_white());
        }
        
        Ok(())
    }
}
