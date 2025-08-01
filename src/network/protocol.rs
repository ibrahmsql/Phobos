//! Protocol-specific implementations and utilities

use crate::network::{PortState, ScanTechnique};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Common service ports mapping
#[derive(Clone)]
pub struct ServiceDatabase {
    tcp_services: HashMap<u16, &'static str>,
    udp_services: HashMap<u16, &'static str>,
}

impl ServiceDatabase {
    pub fn new() -> Self {
        let mut tcp_services = HashMap::new();
        let mut udp_services = HashMap::new();
        
        // Common TCP services
        tcp_services.insert(21, "ftp");
        tcp_services.insert(22, "ssh");
        tcp_services.insert(23, "telnet");
        tcp_services.insert(25, "smtp");
        tcp_services.insert(53, "domain");
        tcp_services.insert(80, "http");
        tcp_services.insert(110, "pop3");
        tcp_services.insert(143, "imap");
        tcp_services.insert(443, "https");
        tcp_services.insert(993, "imaps");
        tcp_services.insert(995, "pop3s");
        tcp_services.insert(3389, "rdp");
        tcp_services.insert(5432, "postgresql");
        tcp_services.insert(3306, "mysql");
        tcp_services.insert(1433, "mssql");
        tcp_services.insert(5984, "couchdb");
        tcp_services.insert(6379, "redis");
        tcp_services.insert(27017, "mongodb");
        tcp_services.insert(8080, "http-proxy");
        tcp_services.insert(8443, "https-alt");
        
        // Common UDP services
        udp_services.insert(53, "domain");
        udp_services.insert(67, "dhcps");
        udp_services.insert(68, "dhcpc");
        udp_services.insert(69, "tftp");
        udp_services.insert(123, "ntp");
        udp_services.insert(161, "snmp");
        udp_services.insert(162, "snmptrap");
        udp_services.insert(514, "syslog");
        udp_services.insert(1194, "openvpn");
        udp_services.insert(4500, "ipsec-nat-t");
        
        Self {
            tcp_services,
            udp_services,
        }
    }
    
    pub fn get_tcp_service(&self, port: u16) -> Option<&'static str> {
        self.tcp_services.get(&port).copied()
    }
    
    pub fn get_udp_service(&self, port: u16) -> Option<&'static str> {
        self.udp_services.get(&port).copied()
    }
    
    /// Get the top N most common TCP ports
    pub fn get_top_tcp_ports(n: usize) -> Vec<u16> {
        let mut ports = vec![
            80, 23, 443, 21, 22, 25, 53, 110, 111, 995, 993, 143, 993, 995, 587, 8080, 8443,
            465, 631, 993, 995, 1723, 3389, 5432, 5984, 6379, 8080, 8443, 27017, 3306, 1433,
            139, 445, 135, 1025, 1026, 1027, 1028, 1029, 1110, 4444, 5000, 5001, 5002, 5003,
            5004, 5005, 5006, 5007, 5008, 5009, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007,
            1234, 1337, 1433, 1521, 1723, 2049, 2121, 2717, 3128, 3306, 3389, 4899, 5060, 5432,
            5631, 5666, 5800, 5900, 5984, 6379, 6667, 7000, 7001, 7002, 8000, 8001, 8008, 8080,
            8443, 8888, 9000, 9001, 9090, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
            49157, 1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42,
            43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111,
            113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255,
            256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443,
            444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545,
            548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683,
            687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808,
            843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
            999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026,
            1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040,
            1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054,
            1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068,
            1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082,
            1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096,
            1097, 1098, 1099, 1100
        ];
        
        ports.truncate(n);
        ports
    }
    
    /// Get the top N most common UDP ports
    pub fn get_top_udp_ports(n: usize) -> Vec<u16> {
        let mut ports = vec![
            53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434,
            1900, 4500, 49152, 49153, 49154, 49155, 49156, 49157, 1, 7, 9, 13, 17, 19, 37, 42,
            49, 53, 67, 68, 69, 80, 88, 111, 120, 123, 135, 136, 137, 138, 139, 158, 161, 162,
            177, 427, 443, 497, 500, 514, 515, 518, 520, 593, 623, 626, 631, 996, 997, 998, 999,
            1022, 1023, 1025, 1026, 1027, 1028, 1029, 1030, 1433, 1434, 1645, 1646, 1701, 1718,
            1719, 1812, 1813, 1900, 2000, 2048, 2049, 2222, 2223, 4444, 4500, 5000, 5060, 5353,
            5632, 9200, 10000, 17185, 20031, 30718, 31337, 32768, 32769, 32770, 32771, 32772,
            32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784,
            49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49162, 49163,
            49164, 49165, 49166, 49167, 49168, 49169, 49170, 49171, 49172, 49173, 49174, 49175,
            49176, 49177, 49178, 49179, 49180, 49181, 49182, 49183, 49184, 49185, 49186, 49187,
            49188, 49189, 49190, 49191, 49192, 49193, 49194, 49195, 49196, 49197, 49198, 49199,
            49200, 65024
        ];
        
        ports.truncate(n);
        ports
    }
}

/// Response analyzer for determining port states
pub struct ResponseAnalyzer {
    technique: ScanTechnique,
}

impl ResponseAnalyzer {
    pub fn new(technique: ScanTechnique) -> Self {
        Self { technique }
    }
    
    /// Analyze TCP response and determine port state
    pub fn analyze_tcp_response(
        &self,
        response: Option<&crate::network::packet::TcpResponse>,
        timeout: bool,
    ) -> PortState {
        match self.technique {
            ScanTechnique::Syn => {
                match response {
                    Some(resp) if resp.is_syn_ack() => PortState::Open,
                    Some(resp) if resp.is_rst() => PortState::Closed,
                    None if timeout => PortState::Filtered,
                    _ => PortState::Filtered,
                }
            }
            ScanTechnique::Connect => {
                // This is handled differently in the connect scanner
                PortState::Closed
            }
            ScanTechnique::Fin | ScanTechnique::Null | ScanTechnique::Xmas => {
                match response {
                    Some(resp) if resp.is_rst() => PortState::Closed,
                    None if timeout => PortState::OpenFiltered,
                    _ => PortState::OpenFiltered,
                }
            }
            ScanTechnique::Ack | ScanTechnique::Window => {
                match response {
                    Some(resp) if resp.is_rst() => PortState::Unfiltered,
                    None if timeout => PortState::Filtered,
                    _ => PortState::Filtered,
                }
            }
            ScanTechnique::Udp => {
                // UDP analysis is different
                PortState::OpenFiltered
            }
        }
    }
    
    /// Analyze UDP response and determine port state
    pub fn analyze_udp_response(
        &self,
        response: Option<&crate::network::packet::UdpResponse>,
        icmp_unreachable: bool,
        timeout: bool,
    ) -> PortState {
        if icmp_unreachable {
            PortState::Closed
        } else if response.is_some() {
            PortState::Open
        } else if timeout {
            PortState::OpenFiltered
        } else {
            PortState::OpenFiltered
        }
    }
}

/// Rate limiter for controlling packet sending rate
pub struct RateLimiter {
    rate: u64,
    last_send: std::time::Instant,
    tokens: f64,
    max_tokens: f64,
}

impl RateLimiter {
    pub fn new(packets_per_second: u64) -> Self {
        Self {
            rate: packets_per_second,
            last_send: std::time::Instant::now(),
            tokens: packets_per_second as f64,
            max_tokens: packets_per_second as f64,
        }
    }
    
    /// Check if we can send a packet (token bucket algorithm)
    pub fn can_send(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_send).as_secs_f64();
        
        // Prevent division by zero and overflow
        if self.rate == 0 {
            return false;
        }
        
        // Add tokens based on elapsed time with overflow protection
        let tokens_to_add = elapsed * self.rate as f64;
        if tokens_to_add.is_finite() && tokens_to_add >= 0.0 {
            self.tokens += tokens_to_add;
            if self.tokens > self.max_tokens {
                self.tokens = self.max_tokens;
            }
        }
        
        self.last_send = now;
        
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
    
    /// Calculate delay needed before next send
    pub fn delay_until_next(&self) -> Duration {
        if self.tokens >= 1.0 || self.rate == 0 {
            Duration::from_millis(0)
        } else {
            let needed_tokens = 1.0 - self.tokens;
            let delay_secs = needed_tokens / self.rate as f64;
            
            // Ensure delay is finite and reasonable
            if delay_secs.is_finite() && delay_secs >= 0.0 && delay_secs <= 60.0 {
                Duration::from_secs_f64(delay_secs)
            } else {
                Duration::from_secs(1) // Fallback to 1 second
            }
        }
    }
}

/// Network utilities
pub struct NetworkUtils;

impl NetworkUtils {
    /// Get local IP address for source IP spoofing
    pub fn get_local_ip() -> crate::Result<Ipv4Addr> {
        // Try to connect to a remote address to determine local IP
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| crate::ScanError::NetworkError(e.to_string()))?;
        socket.connect("8.8.8.8:80")
            .map_err(|e| crate::ScanError::NetworkError(e.to_string()))?;
        
        let local_addr = socket.local_addr()
            .map_err(|e| crate::ScanError::NetworkError(e.to_string()))?;
        
        match local_addr.ip() {
            std::net::IpAddr::V4(ipv4) => Ok(ipv4),
            std::net::IpAddr::V6(_) => {
                Err(crate::ScanError::InvalidTarget("IPv6 not supported".to_string()))
            }
        }
    }
    
    /// Generate a random source port
    pub fn random_source_port() -> u16 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(32768..65535)
    }
    
    /// Parse CIDR notation (e.g., 192.168.1.0/24)
    pub fn parse_cidr(cidr: &str) -> crate::Result<Vec<Ipv4Addr>> {
        if !cidr.contains('/') {
            // Single IP address
            let ip: Ipv4Addr = cidr.parse()
                .map_err(|_| crate::ScanError::InvalidTarget(format!("Invalid IP: {}", cidr)))?;
            return Ok(vec![ip]);
        }
        
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(crate::ScanError::InvalidTarget(format!("Invalid CIDR: {}", cidr)));
        }
        
        let base_ip: Ipv4Addr = parts[0].parse()
            .map_err(|_| crate::ScanError::InvalidTarget(format!("Invalid IP: {}", parts[0])))?;
        
        let prefix_len: u8 = parts[1].parse()
            .map_err(|_| crate::ScanError::InvalidTarget(format!("Invalid prefix: {}", parts[1])))?;
        
        if prefix_len > 32 {
            return Err(crate::ScanError::InvalidTarget("Prefix length must be <= 32".to_string()));
        }
        
        let mut ips = Vec::new();
        let base = u32::from(base_ip);
        let mask = !((1u32 << (32 - prefix_len)) - 1);
        let network = base & mask;
        let broadcast = network | ((1u32 << (32 - prefix_len)) - 1);
        
        for ip_int in network..=broadcast {
            ips.push(Ipv4Addr::from(ip_int));
        }
        
        Ok(ips)
    }
}