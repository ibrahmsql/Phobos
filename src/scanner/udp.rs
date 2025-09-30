//! UDP scanning implementation

use crate::error::ScanError;
use crate::utils::scan_options::{ScanOptions, order_ports};
use futures::future::join_all;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpScanResult {
    Open,
    OpenFiltered,
    Closed,
    Filtered,
    Timeout,
}

#[derive(Debug, Clone)]
pub struct UdpScanResponse {
    pub port: u16,
    pub result: UdpScanResult,
    pub response_time: Duration,
    pub service: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UdpScanner {
    options: ScanOptions,
    payloads: UdpPayloads,
}

impl UdpScanner {
    pub fn new(options: ScanOptions) -> Self {
        Self {
            options,
            payloads: UdpPayloads::new(),
        }
    }

    /// Scan multiple UDP ports on a target
    pub async fn scan_ports(&self, target: IpAddr, ports: Vec<u16>) -> Vec<UdpScanResponse> {
        let ordered_ports = order_ports(ports, self.options.scan_order);
        let mut results = Vec::new();

        for chunk in ordered_ports.chunks(self.options.batch_size as usize) {
            let chunk_results = self.scan_batch(target, chunk.to_vec()).await;
            results.extend(chunk_results);
        }

        results
    }

    /// Scan a batch of UDP ports
    async fn scan_batch(&self, target: IpAddr, ports: Vec<u16>) -> Vec<UdpScanResponse> {
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.options.threads as usize));
        let tasks = ports.into_iter().map(|port| {
            let semaphore = semaphore.clone();
            let scanner = self.clone();
            async move {
                let _permit = semaphore.acquire().await.unwrap();
                scanner.scan_single_port(target, port).await
            }
        });

        join_all(tasks).await
    }

    /// Scan a single UDP port
    async fn scan_single_port(&self, target: IpAddr, port: u16) -> UdpScanResponse {
        let start = Instant::now();
        
        let mut attempts = 0;
        let mut result = UdpScanResult::Timeout;
        
        while attempts < self.options.tries {
            match self.probe_port(target, port).await {
                Ok(res) => {
                    result = res;
                    break;
                }
                Err(_) => {
                    attempts += 1;
                    if attempts < self.options.tries {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }

        let response_time = start.elapsed();
        let service = self.identify_service(port, &result);

        UdpScanResponse {
            port,
            result,
            response_time,
            service,
        }
    }

    /// Probe a UDP port
    async fn probe_port(&self, target: IpAddr, port: u16) -> Result<UdpScanResult, ScanError> {
        let socket_addr = SocketAddr::new(target, port);
        let socket = TokioUdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| ScanError::NetworkError(e.to_string()))?;

        // Get appropriate payload for this port
        let payload = self.payloads.get_payload(port);
        
        // Send probe packet
        socket.send_to(&payload, socket_addr).await
            .map_err(|e| ScanError::NetworkError(e.to_string()))?;

        // Wait for response
        let mut buffer = vec![0u8; 1024];
        match timeout(self.options.timeout, socket.recv_from(&mut buffer)).await {
            Ok(Ok((bytes, _))) => {
                if bytes > 0 {
                    Ok(UdpScanResult::Open)
                } else {
                    Ok(UdpScanResult::OpenFiltered)
                }
            }
            Ok(Err(_)) => Ok(UdpScanResult::Filtered),
            Err(_) => {
                // Timeout - could be open or filtered
                Ok(UdpScanResult::OpenFiltered)
            }
        }
    }

    /// Identify service based on port and response
    fn identify_service(&self, port: u16, result: &UdpScanResult) -> Option<String> {
        if matches!(result, UdpScanResult::Open | UdpScanResult::OpenFiltered) {
            self.payloads.get_service_name(port)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
struct UdpPayloads {
    payloads: std::collections::HashMap<u16, Vec<u8>>,
    services: std::collections::HashMap<u16, String>,
}

impl UdpPayloads {
    fn new() -> Self {
        let mut payloads = std::collections::HashMap::new();
        let mut services = std::collections::HashMap::new();

        // DNS
        payloads.insert(53, vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
            0x00, 0x00, 0x01, 0x00, 0x01
        ]);
        services.insert(53, "dns".to_string());

        // DHCP
        payloads.insert(67, vec![
            0x01, 0x01, 0x06, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]);
        services.insert(67, "dhcp".to_string());

        // TFTP
        payloads.insert(69, vec![0x00, 0x01, 0x74, 0x65, 0x73, 0x74, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00]);
        services.insert(69, "tftp".to_string());

        // NTP
        payloads.insert(123, vec![0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        services.insert(123, "ntp".to_string());

        // SNMP
        payloads.insert(161, vec![
            0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
            0xa0, 0x19, 0x02, 0x04, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01,
            0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00
        ]);
        services.insert(161, "snmp".to_string());

        // SIP
        payloads.insert(5060, b"OPTIONS sip:test@example.com SIP/2.0\r\n\r\n".to_vec());
        services.insert(5060, "sip".to_string());

        Self { payloads, services }
    }

    fn get_payload(&self, port: u16) -> Vec<u8> {
        self.payloads.get(&port).cloned().unwrap_or_else(|| b"TEST".to_vec())
    }

    fn get_service_name(&self, port: u16) -> Option<String> {
        self.services.get(&port).cloned()
    }
}

/// Common UDP ports for scanning
pub struct UdpPorts;

impl UdpPorts {
    pub fn top_100() -> Vec<u16> {
        vec![
            53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1900,
            4500, 5353, 5060, 1434, 1701, 4569, 5004, 5005, 2049, 111, 2000, 5432, 1433, 1521,
            3389, 5984, 6379, 11211, 25826, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007,
            1812, 1813, 1645, 1646, 3478, 5349, 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888,
            1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037,
            1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051,
            1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065
        ]
    }

    pub fn common_services() -> Vec<u16> {
        vec![53, 67, 69, 123, 135, 137, 138, 161, 500, 514, 520, 1900, 5060, 5353]
    }

    pub fn database_ports() -> Vec<u16> {
        vec![1433, 1521, 3306, 5432, 6379, 27017, 9042, 7000, 7001]
    }

    pub fn voip_ports() -> Vec<u16> {
        vec![5060, 5061, 4569, 1720, 1719]
    }
}