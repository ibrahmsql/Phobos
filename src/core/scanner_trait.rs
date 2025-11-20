// Phobos Modular Scanner Trait System
// Core trait definitions for extensible scanning architecture

use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Core result types
#[derive(Debug, Clone, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub service: Option<String>,
    pub response_time: Duration,
    pub banner: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanResult<T> {
    pub data: T,
    pub errors: Vec<ScanError>,
}

#[derive(Debug, Clone)]
pub enum ScanError {
    Timeout,
    ConnectionRefused,
    HostUnreachable,
    PermissionDenied,
    TooManyOpenFiles,
    Other(String),
}

/// Scanner capabilities metadata
#[derive(Debug, Clone)]
pub struct ScannerCapabilities {
    /// Requires root/admin privileges
    pub requires_root: bool,
    /// Supports IPv6 addressing
    pub supports_ipv6: bool,
    /// Supports UDP scanning
    pub supports_udp: bool,
    /// Maximum recommended batch size
    pub max_batch_size: Option<usize>,
    /// Scanner technique name
    pub technique_name: &'static str,
}

/// Universal Port Scanner Trait
/// All scanner implementations must implement this trait
#[async_trait]
pub trait PortScanner: Send + Sync {
    /// Scan a single port on a target
    async fn scan_port(&self, target: IpAddr, port: u16) -> Result<PortResult, ScanError>;
    
    /// Scan multiple ports (batch operation)
    /// Default implementation calls scan_port sequentially
    async fn scan_ports(&self, target: IpAddr, ports: &[u16]) -> Vec<Result<PortResult, ScanError>> {
        let mut results = Vec::with_capacity(ports.len());
        for &port in ports {
            results.push(self.scan_port(target, port).await);
        }
        results
    }
    
    /// Get scanner name
    fn name(&self) -> &str;
    
    /// Get scanner capabilities
    fn capabilities(&self) -> ScannerCapabilities;
    
    /// Validate if this scanner can be used
    fn can_run(&self) -> Result<(), String> {
        let caps = self.capabilities();
        
        // Check root privileges if required
        if caps.requires_root {
            #[cfg(unix)]
            {
                if !nix::unistd::geteuid().is_root() {
                    return Err(format!(
                        "{} requires root privileges",
                        self.name()
                    ));
                }
            }
        }
        
        Ok(())
    }
}

/// TCP Connect Scanner - No privileges required
pub struct TcpConnectScanner {
    timeout: Duration,
}

impl TcpConnectScanner {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl PortScanner for TcpConnectScanner {
    async fn scan_port(&self, target: IpAddr, port: u16) -> Result<PortResult, ScanError> {
        let start = std::time::Instant::now();
        let socket_addr = SocketAddr::new(target, port);
        
        match tokio::time::timeout(
            self.timeout,
            tokio::net::TcpStream::connect(socket_addr)
        ).await {
            Ok(Ok(_stream)) => {
                Ok(PortResult {
                    port,
                    state: PortState::Open,
                    service: None,
                    response_time: start.elapsed(),
                    banner: None,
                })
            }
            Ok(Err(_)) => {
                Ok(PortResult {
                    port,
                    state: PortState::Closed,
                    service: None,
                    response_time: start.elapsed(),
                    banner: None,
                })
            }
            Err(_) => Err(ScanError::Timeout),
        }
    }
    
    fn name(&self) -> &str {
        "TCP Connect"
    }
    
    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            requires_root: false,
            supports_ipv6: true,
            supports_udp: false,
            max_batch_size: Some(10000),
            technique_name: "TCP_CONNECT",
        }
    }
}

/// SYN Scanner - Requires raw socket privileges  
pub struct SynScanner {
    timeout: Duration,
}

impl SynScanner {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl PortScanner for SynScanner {
    async fn scan_port(&self, _target: IpAddr, port: u16) -> Result<PortResult, ScanError> {
        // Placeholder - actual raw socket implementation needed
        Ok(PortResult {
            port,
            state: PortState::Unknown,
            service: None,
            response_time: Duration::from_millis(0),
            banner: None,
        })
    }
    
    fn name(&self) -> &str {
        "SYN Stealth"
    }
    
    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            requires_root: true,
            supports_ipv6: true,
            supports_udp: false,
            max_batch_size: Some(50000),
            technique_name: "SYN",
        }
    }
}

/// Scanner factory - Creates appropriate scanner based on requirements
pub struct ScannerFactory;

impl ScannerFactory {
    /// Create a scanner with automatic privilege detection
    pub fn create_best_scanner(timeout: Duration) -> Arc<dyn PortScanner> {
        #[cfg(unix)]
        {
            if nix::unistd::geteuid().is_root() {
                // Use SYN scanner if we have privileges
                Arc::new(SynScanner::new(timeout))
            } else {
                // Fall back to TCP Connect
                Arc::new(TcpConnectScanner::new(timeout))
            }
        }
        
        #[cfg(not(unix))]
        {
            // Always use TCP Connect on non-Unix
            Arc::new(TcpConnectScanner::new(timeout))
        }
    }
    
    /// Create specific scanner by name
    pub fn create_by_name(name: &str, timeout: Duration) -> Option<Arc<dyn PortScanner>> {
        match name.to_lowercase().as_str() {
            "tcp" | "connect" => Some(Arc::new(TcpConnectScanner::new(timeout))),
            "syn" | "stealth" => Some(Arc::new(SynScanner::new(timeout))),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_tcp_connect_scanner() {
        let scanner = TcpConnectScanner::new(Duration::from_secs(1));
        assert_eq!(scanner.name(), "TCP Connect");
        assert!(!scanner.capabilities().requires_root);
    }
    
    #[test]
    fn test_scanner_factory() {
        let scanner = ScannerFactory::create_best_scanner(Duration::from_secs(1));
        assert!(!scanner.name().is_empty());
    }
}
