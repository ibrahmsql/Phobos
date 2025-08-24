//! Output formatting and management

use crate::scanner::ScanResult;
use crate::network::PortResult;
use crate::network::{PortState, Protocol};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Write};
use chrono::{DateTime, Utc};

/// Output format options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    Xml,
    Csv,
    Nmap,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" | "txt" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "xml" => Ok(OutputFormat::Xml),
            "csv" => Ok(OutputFormat::Csv),
            "nmap" => Ok(OutputFormat::Nmap),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}

/// Output configuration
#[derive(Debug, Clone)]
pub struct OutputConfig {
    pub format: OutputFormat,
    pub file: Option<String>,
    pub colored: bool,
    pub verbose: bool,
    pub show_closed: bool,
    pub show_filtered: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            file: None,
            colored: true,
            verbose: false,
            show_closed: false,
            show_filtered: false,
        }
    }
}

/// Main output manager
pub struct OutputManager {
    config: OutputConfig,
}

impl OutputManager {
    pub fn new(config: OutputConfig) -> Self {
        Self { config }
    }
    
    /// Write scan results
    pub fn write_results(&self, results: &ScanResult) -> io::Result<()> {
        let output = match self.config.format {
            OutputFormat::Text => self.format_text(results),
            OutputFormat::Json => self.format_json(results)?,
            OutputFormat::Xml => self.format_xml(results),
            OutputFormat::Csv => self.format_csv(results),
            OutputFormat::Nmap => self.format_nmap(results),
        };
        
        match &self.config.file {
            Some(filename) => {
                let mut file = File::create(filename)?;
                file.write_all(output.as_bytes())?;
            }
            None => {
                print!("{}", output);
            }
        }
        
        Ok(())
    }
    
    /// Format results as text
    fn format_text(&self, results: &ScanResult) -> String {
        let mut output = String::new();
        
        // Header removed - will be replaced with better implementation
        output.push_str("\n");
        
        // Open ports
        let open_port_results: Vec<_> = results.port_results.iter()
            .filter(|pr| matches!(pr.state, crate::network::PortState::Open))
            .collect();
        
        if !open_port_results.is_empty() {
            output.push_str(&self.colorize("🟢 OPEN PORTS:\n", "neon_green"));
            for port_result in open_port_results {
                let service = port_result.service.as_deref().unwrap_or("unknown");
                let protocol = match port_result.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                    _ => "unknown",
                };
                
                let line = format!("  {}/{:<6} {:<15} ({:.1}ms)\n", 
                    port_result.port, 
                    protocol,
                    service,
                    port_result.response_time.as_millis()
                );
                output.push_str(&self.colorize(&line, "neon_green"));
            }
            output.push('\n');
        }
        
        // Closed ports (if requested)
        let closed_port_results: Vec<_> = results.port_results.iter()
            .filter(|pr| matches!(pr.state, crate::network::PortState::Closed))
            .collect();
        
        if self.config.show_closed && !closed_port_results.is_empty() {
            output.push_str(&self.colorize("🔴 CLOSED PORTS:\n", "gray"));
            for port_result in closed_port_results {
                let protocol = match port_result.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                    _ => "unknown",
                };
                let line = format!("  {}/{}\n", port_result.port, protocol);
                output.push_str(&self.colorize(&line, "gray"));
            }
            output.push('\n');
        }
        
        // Filtered ports (if requested)
        let filtered_port_results: Vec<_> = results.port_results.iter()
            .filter(|pr| matches!(pr.state, crate::network::PortState::Filtered | crate::network::PortState::OpenFiltered | crate::network::PortState::ClosedFiltered))
            .collect();
        
        if self.config.show_filtered && !filtered_port_results.is_empty() {
            output.push_str(&self.colorize("🟡 FILTERED PORTS:\n", "gray"));
            for port_result in filtered_port_results {
                let protocol = match port_result.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                    _ => "unknown",
                };
                let line = format!("  {}/{}\n", port_result.port, protocol);
                output.push_str(&self.colorize(&line, "gray"));
            }
            output.push('\n');
        }
        
        // Statistics and summary removed as requested
        
        output
    }
    
    /// Format results as JSON
    fn format_json(&self, results: &ScanResult) -> io::Result<String> {
        let json_result = JsonScanResult::from(results);
        serde_json::to_string_pretty(&json_result)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
    
    /// Format results as XML
    fn format_xml(&self, results: &ScanResult) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<scanresult>\n");
        xml.push_str(&format!("  <target>{}</target>\n", results.target));
        xml.push_str(&format!("  <duration>{:.2}</duration>\n", results.duration.as_secs_f64()));
        xml.push_str(&format!("  <scanrate>{:.2}</scanrate>\n", results.scan_rate()));
        
        xml.push_str("  <ports>\n");
        for port_result in &results.port_results {
            if matches!(port_result.state, crate::network::PortState::Open) {
                xml.push_str(&format!(
                    "    <port number=\"{}\" protocol=\"{}\" state=\"open\" service=\"{}\"/>\n",
                    port_result.port,
                    match port_result.protocol {
                        Protocol::Tcp => "tcp",
                        Protocol::Udp => "udp",
                        _ => "unknown",
                    },
                    port_result.service.as_deref().unwrap_or("unknown")
                ));
            }
        }
        xml.push_str("  </ports>\n");
        
        xml.push_str("  <statistics>\n");
        xml.push_str(&format!("    <packets_sent>{}</packets_sent>\n", results.stats.packets_sent));
        xml.push_str(&format!("    <packets_received>{}</packets_received>\n", results.stats.packets_received));
        xml.push_str(&format!("    <timeouts>{}</timeouts>\n", results.stats.timeouts));
        xml.push_str(&format!("    <errors>{}</errors>\n", results.stats.errors));
        xml.push_str("  </statistics>\n");
        
        xml.push_str("</scanresult>\n");
        xml
    }
    
    /// Format results as CSV
    fn format_csv(&self, results: &ScanResult) -> String {
        let mut csv = String::new();
        csv.push_str("target,port,protocol,state,service,response_time_ms\n");
        
        for port_result in &results.port_results {
            if matches!(port_result.state, crate::network::PortState::Open) {
                csv.push_str(&format!(
                    "{},{},{},open,{},{}\n",
                    results.target,
                    port_result.port,
                    match port_result.protocol {
                        Protocol::Tcp => "tcp",
                        Protocol::Udp => "udp",
                        _ => "unknown",
                    },
                    port_result.service.as_deref().unwrap_or("unknown"),
                    port_result.response_time.as_millis().to_string()
                ));
            }
        }
        
        if self.config.show_closed {
            for port_result in &results.port_results {
                if matches!(port_result.state, crate::network::PortState::Closed) {
                    csv.push_str(&format!(
                        "{},{},{},closed,,\n",
                        results.target,
                        port_result.port,
                        match port_result.protocol {
                            Protocol::Tcp => "tcp",
                            Protocol::Udp => "udp",
                            _ => "unknown",
                        }
                    ));
                }
            }
        }
        
        csv
    }
    
    /// Format results in Nmap-compatible format
    fn format_nmap(&self, results: &ScanResult) -> String {
        let mut output = String::new();
        
        output.push_str(&format!("# Phobos scan report for {}\n", results.target));
        output.push_str(&format!("# Scan completed at {}\n", 
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
        output.push_str(&format!("# {} ports scanned in {:.2} seconds\n\n", 
            results.open_ports.len() + results.closed_ports.len() + results.filtered_ports.len(),
            results.duration.as_secs_f64()));
        
        let open_port_results: Vec<_> = results.port_results.iter()
            .filter(|pr| matches!(pr.state, crate::network::PortState::Open))
            .collect();
        
        if !open_port_results.is_empty() {
            output.push_str("PORT     STATE SERVICE\n");
            for port_result in open_port_results {
                let protocol = match port_result.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                    _ => "unknown",
                };
                output.push_str(&format!(
                    "{}/{:<6} open  {}\n",
                    port_result.port,
                    protocol,
                    port_result.service.as_deref().unwrap_or("unknown")
                ));
            }
        }
        
        output.push_str(&format!("\n# Scan rate: {:.2} ports/sec\n", results.scan_rate()));
        output
    }
    
    /// Apply color formatting if enabled
    fn colorize(&self, text: &str, color: &str) -> String {
        if !self.config.colored {
            return text.to_string();
        }
        
        let color_code = match color {
            "red" => "\x1b[31m",
            "green" => "\x1b[32m",
            "neon_green" => "\x1b[38;2;57;255;20m", // Neon yeşil RGB(57,255,20)
            "yellow" => "\x1b[33m",
            "blue" => "\x1b[34m",
            "magenta" => "\x1b[35m",
            "cyan" => "\x1b[36m",
            "white" => "\x1b[37m",
            "gray" => "\x1b[38;2;128;128;128m", // Gri RGB(128,128,128)
            "bold" => "\x1b[1m",
            _ => "",
        };
        
        format!("{}{}{}", color_code, text, "\x1b[0m")
    }
}

/// JSON-serializable scan result
#[derive(Debug, Serialize, Deserialize)]
struct JsonScanResult {
    target: String,
    scan_time: DateTime<Utc>,
    duration_seconds: f64,
    scan_rate: f64,
    open_ports: Vec<JsonPortResult>,
    closed_ports: Vec<JsonPortResult>,
    filtered_ports: Vec<JsonPortResult>,
    statistics: JsonScanStats,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonPortResult {
    port: u16,
    protocol: String,
    state: String,
    service: Option<String>,
    response_time_ms: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonScanStats {
    packets_sent: u64,
    packets_received: u64,
    timeouts: u64,
    errors: u64,
    avg_response_time_ms: Option<u64>,
}

impl From<&ScanResult> for JsonScanResult {
    fn from(result: &ScanResult) -> Self {
        Self {
            target: result.target.clone(),
            scan_time: chrono::Utc::now(),
            duration_seconds: result.duration.as_secs_f64(),
            scan_rate: result.scan_rate(),
            open_ports: result.port_results.iter()
                .filter(|pr| matches!(pr.state, crate::network::PortState::Open))
                .map(JsonPortResult::from).collect(),
            closed_ports: result.port_results.iter()
                .filter(|pr| matches!(pr.state, crate::network::PortState::Closed))
                .map(JsonPortResult::from).collect(),
            filtered_ports: result.port_results.iter()
                .filter(|pr| matches!(pr.state, crate::network::PortState::Filtered | crate::network::PortState::OpenFiltered | crate::network::PortState::ClosedFiltered))
                .map(JsonPortResult::from).collect(),
            statistics: JsonScanStats::from(&result.stats),
        }
    }
}

impl From<&PortResult> for JsonPortResult {
    fn from(port: &PortResult) -> Self {
        Self {
            port: port.port,
            protocol: match port.protocol {
                Protocol::Tcp => "tcp".to_string(),
                Protocol::Udp => "udp".to_string(),
                _ => "unknown".to_string(),
            },
            state: match port.state {
                PortState::Open => "open".to_string(),
                PortState::Closed => "closed".to_string(),
                PortState::Filtered => "filtered".to_string(),
                PortState::Unfiltered => "unfiltered".to_string(),
                PortState::OpenFiltered => "open|filtered".to_string(),
                PortState::ClosedFiltered => "closed|filtered".to_string(),
            },
            service: port.service.clone(),
            response_time_ms: Some(port.response_time.as_millis() as u64),
        }
    }
}

impl From<&crate::scanner::ScanStats> for JsonScanStats {
    fn from(stats: &crate::scanner::ScanStats) -> Self {
        Self {
            packets_sent: stats.packets_sent,
            packets_received: stats.packets_received,
            timeouts: stats.timeouts,
            errors: stats.errors,
            avg_response_time_ms: Some(stats.avg_response_time.as_millis() as u64),
        }
    }
}

/// Progress display for terminal output
pub struct ProgressDisplay {
    total_ports: usize,
    completed_ports: usize,
    start_time: std::time::Instant,
    last_update: std::time::Instant,
}

impl ProgressDisplay {
    pub fn new(total_ports: usize) -> Self {
        let now = std::time::Instant::now();
        Self {
            total_ports,
            completed_ports: 0,
            start_time: now,
            last_update: now,
        }
    }
    
    /// Update progress and display if needed
    pub fn update(&mut self, completed: usize) {
        self.completed_ports = completed;
        
        // Update every 100ms
        if self.last_update.elapsed().as_millis() >= 100 {
            self.display();
            self.last_update = std::time::Instant::now();
        }
    }
    
    /// Display current progress
    fn display(&self) {
        let percentage = (self.completed_ports as f64 / self.total_ports as f64) * 100.0;
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = self.completed_ports as f64 / elapsed;
        let eta = if rate > 0.0 {
            (self.total_ports - self.completed_ports) as f64 / rate
        } else {
            0.0
        };
        
        let bar_width = 40;
        let filled = (percentage / 100.0 * bar_width as f64) as usize;
        let bar = "█".repeat(filled) + &"░".repeat(bar_width - filled);
        
        print!("\r[{}] {:.1}% ({}/{}) {:.1} ports/sec ETA: {:.0}s",
            bar, percentage, self.completed_ports, self.total_ports, rate, eta);
        io::stdout().flush().unwrap();
    }
    
    /// Finish progress display
    pub fn finish(&self) {
        println!();
    }
}