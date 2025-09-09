//! Nmap Integration Module - Advanced Nmap integration and script execution

use super::*;
use crate::{Result, ScanError};
use log::{debug, info, warn};
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::timeout;

/// Nmap integration engine
pub struct NmapEngine {
    config: NmapConfig,
}

/// Nmap-specific configuration
#[derive(Debug, Clone)]
pub struct NmapConfig {
    /// Path to nmap binary
    pub nmap_path: String,
    /// Default arguments for nmap
    pub default_args: Vec<String>,
    /// Custom NSE script directories
    pub script_dirs: Vec<PathBuf>,
    /// Maximum execution time for nmap
    pub timeout: Duration,
    /// Enable timing optimization
    pub timing_optimization: bool,
    /// Timing template (0-5)
    pub timing_template: u8,
}

impl Default for NmapConfig {
    fn default() -> Self {
        Self {
            nmap_path: "nmap".to_string(),
            default_args: vec![
                "-sV".to_string(),    // Service version detection
                "-sC".to_string(),    // Default scripts
                "-Pn".to_string(),    // Skip host discovery
                "-n".to_string(),     // No DNS resolution
            ],
            script_dirs: vec![
                PathBuf::from("/usr/share/nmap/scripts"),
                PathBuf::from("~/.nmap/scripts"),
            ],
            timeout: Duration::from_secs(600), // 10 minutes
            timing_optimization: true,
            timing_template: 4, // Aggressive timing
        }
    }
}

/// Nmap scan result
#[derive(Debug, Clone)]
pub struct NmapResult {
    pub target: IpAddr,
    pub ports: Vec<u16>,
    pub output: String,
    pub xml_output: Option<String>,
    pub execution_time: Duration,
    pub success: bool,
    pub error: Option<String>,
    pub services: HashMap<u16, ServiceInfo>,
}

/// Service information detected by Nmap
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
    pub confidence: u8,
}

/// Nmap script categories
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NmapScriptCategory {
    Auth,
    Broadcast,
    Brute,
    Default,
    Discovery,
    Dos,
    Exploit,
    External,
    Fuzzer,
    Intrusive,
    Malware,
    Safe,
    Version,
    Vuln,
}

impl NmapScriptCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            NmapScriptCategory::Auth => "auth",
            NmapScriptCategory::Broadcast => "broadcast",
            NmapScriptCategory::Brute => "brute",
            NmapScriptCategory::Default => "default",
            NmapScriptCategory::Discovery => "discovery",
            NmapScriptCategory::Dos => "dos",
            NmapScriptCategory::Exploit => "exploit",
            NmapScriptCategory::External => "external",
            NmapScriptCategory::Fuzzer => "fuzzer",
            NmapScriptCategory::Intrusive => "intrusive",
            NmapScriptCategory::Malware => "malware",
            NmapScriptCategory::Safe => "safe",
            NmapScriptCategory::Version => "version",
            NmapScriptCategory::Vuln => "vuln",
        }
    }
}

impl NmapEngine {
    /// Create new Nmap engine
    pub fn new(config: NmapConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(NmapConfig::default())
    }

    /// Execute comprehensive Nmap scan
    pub async fn execute_comprehensive_scan(
        &self,
        target: IpAddr,
        ports: &[u16],
        custom_args: Option<&[String]>,
    ) -> Result<NmapResult> {
        info!("Starting comprehensive Nmap scan for {} on {} ports", target, ports.len());
        
        let start_time = Instant::now();
        let ports_str = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let mut args = self.config.default_args.clone();
        
        // Add timing optimization
        if self.config.timing_optimization {
            args.push(format!("-T{}", self.config.timing_template));
        }
        
        // Add port specification
        args.push("-p".to_string());
        args.push(ports_str);
        
        // Add XML output for parsing
        args.push("-oX".to_string());
        args.push("-".to_string()); // Output to stdout
        
        // Add custom arguments if provided
        if let Some(custom) = custom_args {
            args.extend_from_slice(custom);
        }
        
        // Add target
        args.push(target.to_string());

        debug!("Executing nmap with args: {:?}", args);

        let result = timeout(
            self.config.timeout,
            self.execute_nmap_command(&args)
        ).await;

        let execution_time = start_time.elapsed();

        match result {
            Ok(Ok(output)) => {
                let services = self.parse_nmap_output(&output.stdout)?;
                
                Ok(NmapResult {
                    target,
                    ports: ports.to_vec(),
                    output: output.stdout.clone(),
                    xml_output: Some(output.stdout),
                    execution_time,
                    success: output.success,
                    error: if output.stderr.is_empty() { None } else { Some(output.stderr) },
                    services,
                })
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ScanError::TimeoutError("Nmap execution timed out".to_string())),
        }
    }

    /// Execute Nmap with specific script categories
    pub async fn execute_script_scan(
        &self,
        target: IpAddr,
        ports: &[u16],
        categories: &[NmapScriptCategory],
    ) -> Result<NmapResult> {
        let script_arg = categories
            .iter()
            .map(|cat| cat.as_str())
            .collect::<Vec<_>>()
            .join(" and ");

        let custom_args = vec![
            "--script".to_string(),
            format!("({})", script_arg),
        ];

        self.execute_comprehensive_scan(target, ports, Some(&custom_args)).await
    }

    /// Execute vulnerability scan
    pub async fn execute_vuln_scan(
        &self,
        target: IpAddr,
        ports: &[u16],
    ) -> Result<NmapResult> {
        info!("Starting vulnerability scan for {}", target);
        
        let custom_args = vec![
            "--script".to_string(),
            "vuln".to_string(),
            "--script-args".to_string(),
            "unsafe=1".to_string(),
        ];

        self.execute_comprehensive_scan(target, ports, Some(&custom_args)).await
    }

    /// Execute service enumeration scan
    pub async fn execute_service_enum(
        &self,
        target: IpAddr,
        ports: &[u16],
    ) -> Result<NmapResult> {
        info!("Starting service enumeration for {}", target);
        
        let custom_args = vec![
            "-sV".to_string(),
            "--version-intensity".to_string(),
            "9".to_string(),
            "--script".to_string(),
            "banner,version".to_string(),
        ];

        self.execute_comprehensive_scan(target, ports, Some(&custom_args)).await
    }

    /// Execute adaptive scan based on detected services
    pub async fn execute_adaptive_scan(
        &self,
        target: IpAddr,
        port_results: &[PortResult],
    ) -> Result<Vec<NmapResult>> {
        info!("Starting adaptive Nmap scan for {}", target);
        
        let mut results = Vec::new();
        let mut service_groups: HashMap<String, Vec<u16>> = HashMap::new();

        // Group ports by likely service types
        for port_result in port_results {
            if port_result.state != PortState::Open {
                continue;
            }

            let service_type = self.classify_port(port_result.port);
            service_groups.entry(service_type).or_default().push(port_result.port);
        }

        // Execute targeted scans for each service group
        for (service_type, ports) in service_groups {
            let custom_args = self.get_service_specific_args(&service_type);
            
            match self.execute_comprehensive_scan(target, &ports, Some(&custom_args)).await {
                Ok(result) => results.push(result),
                Err(e) => warn!("Failed to scan {} ports for {}: {}", service_type, target, e),
            }
        }

        Ok(results)
    }

    /// Execute Nmap command
    async fn execute_nmap_command(&self, args: &[String]) -> Result<CommandOutput> {
        let mut cmd = Command::new(&self.config.nmap_path);
        cmd.args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = cmd.output().await
            .map_err(|e| ScanError::NetworkError(format!("Failed to execute nmap: {}", e)))?;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
            _exit_code: output.status.code(),
        })
    }

    /// Parse Nmap XML output to extract service information
    fn parse_nmap_output(&self, xml_output: &str) -> Result<HashMap<u16, ServiceInfo>> {
        let mut services = HashMap::new();
        
        // Simple XML parsing - in production, use a proper XML parser
        for line in xml_output.lines() {
            if line.contains("<port ") && line.contains("portid=") {
                if let Some(port) = self.extract_port_from_xml(line) {
                    if let Some(service) = self.extract_service_from_xml(line) {
                        services.insert(port, service);
                    }
                }
            }
        }

        Ok(services)
    }

    /// Extract port number from XML line
    fn extract_port_from_xml(&self, line: &str) -> Option<u16> {
        if let Some(start) = line.find("portid=\"") {
            let start = start + 8;
            if let Some(end) = line[start..].find('"') {
                return line[start..start + end].parse().ok();
            }
        }
        None
    }

    /// Extract service information from XML line
    fn extract_service_from_xml(&self, _line: &str) -> Option<ServiceInfo> {
        // Simplified service extraction - implement proper XML parsing
        Some(ServiceInfo {
            name: "unknown".to_string(),
            version: None,
            product: None,
            extra_info: None,
            confidence: 5,
        })
    }

    /// Classify port by likely service type
    fn classify_port(&self, port: u16) -> String {
        match port {
            21 => "ftp".to_string(),
            22 => "ssh".to_string(),
            23 => "telnet".to_string(),
            25 | 465 | 587 => "smtp".to_string(),
            53 => "dns".to_string(),
            80 | 8080 | 8000 | 8008 => "http".to_string(),
            110 | 995 => "pop3".to_string(),
            143 | 993 => "imap".to_string(),
            443 | 8443 => "https".to_string(),
            445 | 139 => "smb".to_string(),
            1433 => "mssql".to_string(),
            3306 => "mysql".to_string(),
            3389 => "rdp".to_string(),
            5432 => "postgresql".to_string(),
            6379 => "redis".to_string(),
            27017 => "mongodb".to_string(),
            _ => "generic".to_string(),
        }
    }

    /// Get service-specific Nmap arguments
    fn get_service_specific_args(&self, service_type: &str) -> Vec<String> {
        match service_type {
            "http" | "https" => vec![
                "--script".to_string(),
                "http-enum,http-headers,http-methods,http-title".to_string(),
            ],
            "ssh" => vec![
                "--script".to_string(),
                "ssh-auth-methods,ssh-hostkey".to_string(),
            ],
            "ftp" => vec![
                "--script".to_string(),
                "ftp-anon,ftp-bounce,ftp-syst".to_string(),
            ],
            "smtp" => vec![
                "--script".to_string(),
                "smtp-commands,smtp-enum-users,smtp-open-relay".to_string(),
            ],
            "smb" => vec![
                "--script".to_string(),
                "smb-enum-shares,smb-enum-users,smb-os-discovery".to_string(),
            ],
            "mysql" => vec![
                "--script".to_string(),
                "mysql-info,mysql-enum".to_string(),
            ],
            "postgresql" => vec![
                "--script".to_string(),
                "pgsql-brute".to_string(),
            ],
            _ => vec![
                "--script".to_string(),
                "default".to_string(),
            ],
        }
    }
}

/// Command execution output
#[derive(Debug)]
struct CommandOutput {
    stdout: String,
    stderr: String,
    success: bool,
    _exit_code: Option<i32>,
}