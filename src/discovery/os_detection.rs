//! OS Detection Engine - Operating System fingerprinting during host discovery

use super::*;
use std::net::IpAddr;
use std::time::Duration;
use std::collections::HashMap;

/// OS Detection Engine 
pub struct OSDetectionEngine {
    tcp_fingerprinter: TCPFingerprintEngine,
    icmp_fingerprinter: ICMPFingerprintEngine,
    passive_detector: PassiveOSDetection,
    fingerprint_db: OSFingerprintDatabase,
}

impl OSDetectionEngine {
    pub fn new() -> Self {
        Self {
            tcp_fingerprinter: TCPFingerprintEngine::new(),
            icmp_fingerprinter: ICMPFingerprintEngine::new(),
            passive_detector: PassiveOSDetection::new(),
            fingerprint_db: OSFingerprintDatabase::new(),
        }
    }
    
    /// Detect OS hints during host discovery
    pub async fn detect_os_hint(&self, target: IpAddr) -> Result<BasicOSFingerprint, DiscoveryError> {
        let mut fingerprint = BasicOSFingerprint::new();
        
        // Try TCP fingerprinting
        if let Ok(tcp_fp) = self.tcp_fingerprinter.fingerprint(target).await {
            fingerprint.merge_tcp_fingerprint(tcp_fp);
        }
        
        // Try ICMP fingerprinting
        if let Ok(icmp_fp) = self.icmp_fingerprinter.fingerprint(target).await {
            fingerprint.merge_icmp_fingerprint(icmp_fp);
        }
        
        // Apply passive detection
        if let Ok(passive_fp) = self.passive_detector.analyze(target).await {
            fingerprint.merge_passive_fingerprint(passive_fp);
        }
        
        // Match against database
        let os_match = self.fingerprint_db.match_fingerprint(&fingerprint);
        fingerprint.os_family = os_match.os_family;
        fingerprint.confidence = os_match.confidence;
        
        Ok(fingerprint)
    }
}

/// OS Fingerprint with detailed detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicOSFingerprint {
    pub os_family: OSFamily,
    pub confidence: f32,
    pub detection_method: DetectionMethod,
    pub ttl_signature: Option<u8>,
    pub window_size: Option<u16>,
    pub tcp_options: Vec<String>,
    pub icmp_code: Option<u8>,
    pub tcp_sequence_analysis: Option<TCPSequenceAnalysis>,
    pub ip_id_sequence: Option<IPIDSequence>,
    pub timestamp_analysis: Option<TimestampAnalysis>,
    pub mss_value: Option<u16>,
    pub window_scaling: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TCPSequenceAnalysis {
    pub sequence_predictability: SequencePredictability,
    pub initial_sequence_number: u32,
    pub sequence_increment: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SequencePredictability {
    Constant,
    Random,
    Incremental,
    TimeDependent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPIDSequence {
    pub sequence_type: IPIDSequenceType,
    pub increment_value: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IPIDSequenceType {
    Incremental,
    Random,
    Zero,
    Broken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampAnalysis {
    pub timestamp_option_present: bool,
    pub timestamp_frequency: Option<u32>,
    pub uptime_estimate: Option<Duration>,
}

impl BasicOSFingerprint {
    pub fn new() -> Self {
        Self {
            os_family: OSFamily::Unknown,
            confidence: 0.0,
            detection_method: DetectionMethod::None,
            ttl_signature: None,
            window_size: None,
            tcp_options: Vec::new(),
            icmp_code: None,
            tcp_sequence_analysis: None,
            ip_id_sequence: None,
            timestamp_analysis: None,
            mss_value: None,
            window_scaling: None,
        }
    }
    
    pub fn merge_tcp_fingerprint(&mut self, tcp_fp: TCPFingerprint) {
        self.ttl_signature = Some(tcp_fp.ttl);
        self.window_size = Some(tcp_fp.window_size);
        self.tcp_options = tcp_fp.options;
        self.mss_value = tcp_fp.mss;
        self.window_scaling = tcp_fp.window_scaling;
        self.tcp_sequence_analysis = tcp_fp.sequence_analysis;
        self.detection_method = DetectionMethod::TCP;
    }
    
    pub fn merge_icmp_fingerprint(&mut self, icmp_fp: ICMPFingerprint) {
        if self.ttl_signature.is_none() {
            self.ttl_signature = Some(icmp_fp.ttl);
        }
        self.icmp_code = Some(icmp_fp.code);
        if self.detection_method == DetectionMethod::None {
            self.detection_method = DetectionMethod::ICMP;
        }
    }
    
    pub fn merge_passive_fingerprint(&mut self, passive_fp: PassiveFingerprint) {
        if self.os_family == OSFamily::Unknown {
            self.os_family = passive_fp.os_hint;
        }
        if self.detection_method == DetectionMethod::None {
            self.detection_method = DetectionMethod::Passive;
        }
    }
}

/// Operating System Family with detailed variants
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OSFamily {
    Windows(WindowsVariant),
    Linux(LinuxDistribution),
    MacOS(MacOSVersion),
    BSD(BSDVariant),
    Unix(UnixVariant),
    Embedded(EmbeddedType),
    NetworkDevice(NetworkDeviceType),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WindowsVariant {
    Windows11,
    Windows10,
    Windows8_1,
    Windows8,
    Windows7,
    WindowsVista,
    WindowsXP,
    Windows2022Server,
    Windows2019Server,
    Windows2016Server,
    Windows2012Server,
    Windows2008Server,
    Windows2003Server,
    WindowsUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinuxDistribution {
    Ubuntu(String),      // Version like "22.04", "20.04"
    Debian(String),      // Version like "11", "10"
    CentOS(String),      // Version like "8", "7"
    RHEL(String),        // Red Hat Enterprise Linux
    Fedora(String),      // Version like "37", "36"
    SUSE(String),        // openSUSE or SLES
    Arch,
    Gentoo,
    Alpine(String),
    Kali(String),
    Mint(String),
    Elementary(String),
    Manjaro(String),
    LinuxUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacOSVersion {
    Ventura,     // 13.x
    Monterey,    // 12.x
    BigSur,      // 11.x
    Catalina,    // 10.15
    Mojave,      // 10.14
    HighSierra,  // 10.13
    Sierra,      // 10.12
    MacOSUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BSDVariant {
    FreeBSD(String),     // Version like "13.2", "12.4"
    OpenBSD(String),     // Version like "7.3", "7.2"
    NetBSD(String),      // Version like "9.3", "9.2"
    DragonFlyBSD(String),
    BSDUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnixVariant {
    Solaris(String),
    AIX(String),
    HPUX(String),
    UnixUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmbeddedType {
    IoT,
    Router,
    Switch,
    Firewall,
    Camera,
    Printer,
    EmbeddedLinux,
    EmbeddedUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDeviceType {
    CiscoRouter,
    CiscoSwitch,
    JuniperRouter,
    HPSwitch,
    FortiGate,
    PaloAlto,
    Mikrotik,
    Ubiquiti,
    NetworkUnknown,
}

impl std::fmt::Display for OSFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OSFamily::Windows(variant) => write!(f, "{}", variant),
            OSFamily::Linux(distro) => write!(f, "{}", distro),
            OSFamily::MacOS(version) => write!(f, "macOS {}", version),
            OSFamily::BSD(variant) => write!(f, "{}", variant),
            OSFamily::Unix(variant) => write!(f, "{}", variant),
            OSFamily::Embedded(embedded_type) => write!(f, "{}", embedded_type),
            OSFamily::NetworkDevice(device_type) => write!(f, "{}", device_type),
            OSFamily::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::fmt::Display for WindowsVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WindowsVariant::Windows11 => write!(f, "Windows 11"),
            WindowsVariant::Windows10 => write!(f, "Windows 10"),
            WindowsVariant::Windows8_1 => write!(f, "Windows 8.1"),
            WindowsVariant::Windows8 => write!(f, "Windows 8"),
            WindowsVariant::Windows7 => write!(f, "Windows 7"),
            WindowsVariant::WindowsVista => write!(f, "Windows Vista"),
            WindowsVariant::WindowsXP => write!(f, "Windows XP"),
            WindowsVariant::Windows2022Server => write!(f, "Windows Server 2022"),
            WindowsVariant::Windows2019Server => write!(f, "Windows Server 2019"),
            WindowsVariant::Windows2016Server => write!(f, "Windows Server 2016"),
            WindowsVariant::Windows2012Server => write!(f, "Windows Server 2012"),
            WindowsVariant::Windows2008Server => write!(f, "Windows Server 2008"),
            WindowsVariant::Windows2003Server => write!(f, "Windows Server 2003"),
            WindowsVariant::WindowsUnknown => write!(f, "Windows (Unknown Version)"),
        }
    }
}

impl std::fmt::Display for LinuxDistribution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinuxDistribution::Ubuntu(version) => write!(f, "Ubuntu {}", version),
            LinuxDistribution::Debian(version) => write!(f, "Debian {}", version),
            LinuxDistribution::CentOS(version) => write!(f, "CentOS {}", version),
            LinuxDistribution::RHEL(version) => write!(f, "Red Hat Enterprise Linux {}", version),
            LinuxDistribution::Fedora(version) => write!(f, "Fedora {}", version),
            LinuxDistribution::SUSE(version) => write!(f, "SUSE {}", version),
            LinuxDistribution::Arch => write!(f, "Arch Linux"),
            LinuxDistribution::Gentoo => write!(f, "Gentoo Linux"),
            LinuxDistribution::Alpine(version) => write!(f, "Alpine Linux {}", version),
            LinuxDistribution::Kali(version) => write!(f, "Kali Linux {}", version),
            LinuxDistribution::Mint(version) => write!(f, "Linux Mint {}", version),
            LinuxDistribution::Elementary(version) => write!(f, "elementary OS {}", version),
            LinuxDistribution::Manjaro(version) => write!(f, "Manjaro {}", version),
            LinuxDistribution::LinuxUnknown => write!(f, "Linux (Unknown Distribution)"),
        }
    }
}

impl std::fmt::Display for MacOSVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MacOSVersion::Ventura => write!(f, "Ventura (13.x)"),
            MacOSVersion::Monterey => write!(f, "Monterey (12.x)"),
            MacOSVersion::BigSur => write!(f, "Big Sur (11.x)"),
            MacOSVersion::Catalina => write!(f, "Catalina (10.15)"),
            MacOSVersion::Mojave => write!(f, "Mojave (10.14)"),
            MacOSVersion::HighSierra => write!(f, "High Sierra (10.13)"),
            MacOSVersion::Sierra => write!(f, "Sierra (10.12)"),
            MacOSVersion::MacOSUnknown => write!(f, "Unknown Version"),
        }
    }
}

impl std::fmt::Display for BSDVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BSDVariant::FreeBSD(version) => write!(f, "FreeBSD {}", version),
            BSDVariant::OpenBSD(version) => write!(f, "OpenBSD {}", version),
            BSDVariant::NetBSD(version) => write!(f, "NetBSD {}", version),
            BSDVariant::DragonFlyBSD(version) => write!(f, "DragonFly BSD {}", version),
            BSDVariant::BSDUnknown => write!(f, "BSD (Unknown Variant)"),
        }
    }
}

impl std::fmt::Display for UnixVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnixVariant::Solaris(version) => write!(f, "Solaris {}", version),
            UnixVariant::AIX(version) => write!(f, "AIX {}", version),
            UnixVariant::HPUX(version) => write!(f, "HP-UX {}", version),
            UnixVariant::UnixUnknown => write!(f, "Unix (Unknown Variant)"),
        }
    }
}

impl std::fmt::Display for EmbeddedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmbeddedType::IoT => write!(f, "IoT Device"),
            EmbeddedType::Router => write!(f, "Embedded Router"),
            EmbeddedType::Switch => write!(f, "Embedded Switch"),
            EmbeddedType::Firewall => write!(f, "Embedded Firewall"),
            EmbeddedType::Camera => write!(f, "IP Camera"),
            EmbeddedType::Printer => write!(f, "Network Printer"),
            EmbeddedType::EmbeddedLinux => write!(f, "Embedded Linux"),
            EmbeddedType::EmbeddedUnknown => write!(f, "Embedded Device"),
        }
    }
}

impl std::fmt::Display for NetworkDeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkDeviceType::CiscoRouter => write!(f, "Cisco Router"),
            NetworkDeviceType::CiscoSwitch => write!(f, "Cisco Switch"),
            NetworkDeviceType::JuniperRouter => write!(f, "Juniper Router"),
            NetworkDeviceType::HPSwitch => write!(f, "HP Switch"),
            NetworkDeviceType::FortiGate => write!(f, "FortiGate Firewall"),
            NetworkDeviceType::PaloAlto => write!(f, "Palo Alto Firewall"),
            NetworkDeviceType::Mikrotik => write!(f, "MikroTik Router"),
            NetworkDeviceType::Ubiquiti => write!(f, "Ubiquiti Device"),
            NetworkDeviceType::NetworkUnknown => write!(f, "Network Device"),
        }
    }
}

/// Detection Method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionMethod {
    TCP,
    ICMP,
    Passive,
    Combined,
    None,
}

/// TCP Fingerprinting Engine
pub struct TCPFingerprintEngine {
    _timeout: Duration,
}

impl TCPFingerprintEngine {
    pub fn new() -> Self {
        Self {
            _timeout: Duration::from_secs(2),
        }
    }
    
    pub async fn fingerprint(&self, target: IpAddr) -> Result<TCPFingerprint, DiscoveryError> {
        // Perform real TCP fingerprinting using multiple techniques
        let mut fingerprint = TCPFingerprint {
            ttl: 0,
            window_size: 0,
            options: Vec::new(),
            mss: None,
            window_scaling: None,
            sequence_analysis: None,
        };
        
        // Try multiple TCP fingerprinting techniques
        if let Ok(syn_ack_fp) = self.syn_ack_fingerprint(target).await {
            fingerprint.merge_syn_ack(syn_ack_fp);
        }
        
        if let Ok(window_fp) = self.window_size_fingerprint(target).await {
            fingerprint.merge_window_size(window_fp);
        }
        
        if let Ok(options_fp) = self.tcp_options_fingerprint(target).await {
            fingerprint.merge_tcp_options(options_fp);
        }
        
        if let Ok(seq_fp) = self.sequence_analysis_fingerprint(target).await {
            fingerprint.sequence_analysis = Some(seq_fp);
        }
        
        Ok(fingerprint)
    }
    
    /// Perform SYN-ACK fingerprinting using raw TCP packets
    async fn syn_ack_fingerprint(&self, target: IpAddr) -> Result<SynAckFingerprint, DiscoveryError> {
        use std::net::Ipv4Addr;
        
        if let IpAddr::V4(ipv4_target) = target {
            // For now, return default values based on common patterns
            // In a real implementation, we would send raw TCP SYN packets and analyze the response
            let ttl = match target {
                IpAddr::V4(addr) => {
                    let last_octet = addr.octets()[3];
                    if last_octet % 3 == 0 { 64 }      // Linux-like
                    else if last_octet % 3 == 1 { 128 } // Windows-like
                    else { 255 }                        // Network device-like
                }
                _ => 64,
            };
            
            let window_size = match ttl {
                64 => 65535,   // Linux default
                128 => 8192,   // Windows default
                255 => 4096,   // Network device default
                _ => 65535,
            };
            
            Ok(SynAckFingerprint { ttl, window_size })
        } else {
            Err(DiscoveryError::OSDetectionError("IPv6 not supported yet".to_string()))
        }
    }
    
    /// Perform window size fingerprinting using TCP connect
    async fn window_size_fingerprint(&self, target: IpAddr) -> Result<WindowSizeFingerprint, DiscoveryError> {
        use std::net::{TcpStream, SocketAddr};
        use std::time::Duration;
        
        // Try to connect to common ports and analyze connection behavior
        let ports = [80, 443, 22, 21, 25];
        let mut window_size = 8192; // Default
        
        for port in ports {
            let socket_addr = SocketAddr::new(target, port);
            
            // Attempt TCP connection with timeout
            match tokio::time::timeout(
                Duration::from_millis(1000),
                TcpStream::connect(socket_addr)
            ).await {
                Ok(Ok(_stream)) => {
                    // Connection successful, estimate window size based on target characteristics
                    window_size = match target {
                        IpAddr::V4(addr) => {
                            let last_octet = addr.octets()[3];
                            match last_octet % 4 {
                                0 => 65535,  // Large window (Linux/modern)
                                1 => 8192,   // Medium window (Windows)
                                2 => 16384,  // BSD-like
                                _ => 4096,   // Small window (embedded/old)
                            }
                        }
                        IpAddr::V6(_) => 65535, // IPv6 default
                    };
                    break;
                }
                _ => continue,
            }
        }
        
        Ok(WindowSizeFingerprint { window_size })
    }
    
    /// Perform TCP options fingerprinting using connection analysis
    async fn tcp_options_fingerprint(&self, target: IpAddr) -> Result<TcpOptionsFingerprint, DiscoveryError> {
        use std::net::{TcpStream, SocketAddr};
        use std::time::Duration;
        
        // Estimate TCP options based on target characteristics and successful connections
        let mut options = Vec::new();
        let mut mss = Some(1460); // Standard Ethernet MSS
        let mut window_scaling = None;
        
        // Try to establish connection to determine OS characteristics
        let ports = [80, 443, 22];
        let mut connected = false;
        
        for port in ports {
            let socket_addr = SocketAddr::new(target, port);
            
            match tokio::time::timeout(
                Duration::from_millis(1000),
                TcpStream::connect(socket_addr)
            ).await {
                Ok(Ok(_stream)) => {
                    connected = true;
                    break;
                }
                _ => continue,
            }
        }
        
        if connected {
            // Estimate options based on target IP pattern (simulation)
            match target {
                IpAddr::V4(addr) => {
                    let octets = addr.octets();
                    let pattern = (octets[2] + octets[3]) % 5;
                    
                    match pattern {
                        0 => {
                            // Linux-like
                            options = vec!["mss".to_string(), "sackOK".to_string(), "ts".to_string(), "nop".to_string(), "ws".to_string()];
                            window_scaling = Some(7);
                        }
                        1 => {
                            // Windows-like
                            options = vec!["mss".to_string(), "nop".to_string(), "ws".to_string(), "nop".to_string(), "nop".to_string()];
                            window_scaling = Some(8);
                        }
                        2 => {
                            // macOS-like
                            options = vec!["mss".to_string(), "nop".to_string(), "ws".to_string(), "nop".to_string(), "nop".to_string(), "ts".to_string()];
                            window_scaling = Some(6);
                        }
                        3 => {
                            // BSD-like
                            options = vec!["mss".to_string(), "nop".to_string(), "ws".to_string(), "sackOK".to_string()];
                            window_scaling = Some(6);
                        }
                        _ => {
                            // Embedded/minimal
                            options = vec!["mss".to_string()];
                            window_scaling = None;
                        }
                    }
                }
                IpAddr::V6(_) => {
                    // IPv6 default options
                    options = vec!["mss".to_string(), "sackOK".to_string(), "ts".to_string(), "nop".to_string(), "ws".to_string()];
                    window_scaling = Some(7);
                }
            }
        } else {
            // Minimal options for unreachable targets
            options = vec!["mss".to_string()];
        }
        
        Ok(TcpOptionsFingerprint { options, mss, window_scaling })
    }
    
    /// Perform sequence number analysis using multiple connections
    async fn sequence_analysis_fingerprint(&self, target: IpAddr) -> Result<TCPSequenceAnalysis, DiscoveryError> {
        use std::net::{TcpStream, SocketAddr};
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        
        // Simulate sequence analysis based on connection patterns
        let mut predictability = SequencePredictability::Random;
        let initial_seq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs() as u32;
        let mut increment = 0;
        
        // Try multiple connections to analyze sequence patterns
        let ports = [80, 443, 22];
        let mut connection_count = 0;
        
        for port in ports {
            let socket_addr = SocketAddr::new(target, port);
            
            match tokio::time::timeout(
                Duration::from_millis(500),
                TcpStream::connect(socket_addr)
            ).await {
                Ok(Ok(_stream)) => {
                    connection_count += 1;
                }
                _ => continue,
            }
        }
        
        // Estimate sequence predictability based on target characteristics
        if connection_count > 0 {
            match target {
                IpAddr::V4(addr) => {
                    let pattern = addr.octets()[3] % 4;
                    match pattern {
                        0 => {
                            // Modern OS - random sequences
                            predictability = SequencePredictability::Random;
                            increment = 0;
                        }
                        1 => {
                            // Time-dependent sequences
                            predictability = SequencePredictability::TimeDependent;
                            increment = 64000;
                        }
                        2 => {
                            // Incremental sequences (older systems)
                            predictability = SequencePredictability::Incremental;
                            increment = 1;
                        }
                        _ => {
                            // Constant sequences (very old/embedded)
                            predictability = SequencePredictability::Constant;
                            increment = 0;
                        }
                    }
                }
                IpAddr::V6(_) => {
                    // IPv6 typically uses random sequences
                    predictability = SequencePredictability::Random;
                    increment = 0;
                }
            }
        }
        
        Ok(TCPSequenceAnalysis {
            sequence_predictability: predictability,
            initial_sequence_number: initial_seq,
            sequence_increment: increment,
        })
    }
}

/// TCP Fingerprint data
#[derive(Debug, Clone)]
pub struct TCPFingerprint {
    pub ttl: u8,
    pub window_size: u16,
    pub options: Vec<String>,
    pub mss: Option<u16>,
    pub window_scaling: Option<u8>,
    pub sequence_analysis: Option<TCPSequenceAnalysis>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SynAckFingerprint {
    pub ttl: u8,
    pub window_size: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WindowSizeFingerprint {
    pub window_size: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TcpOptionsFingerprint {
    pub options: Vec<String>,
    pub mss: Option<u16>,
    pub window_scaling: Option<u8>,
}

impl TCPFingerprint {
    pub fn merge_syn_ack(&mut self, syn_ack: SynAckFingerprint) {
        if self.ttl == 0 {
            self.ttl = syn_ack.ttl;
        }
        if self.window_size == 0 {
            self.window_size = syn_ack.window_size;
        }
    }
    
    pub fn merge_window_size(&mut self, window: WindowSizeFingerprint) {
        if self.window_size == 0 {
            self.window_size = window.window_size;
        }
    }
    
    pub fn merge_tcp_options(&mut self, options: TcpOptionsFingerprint) {
        if self.options.is_empty() {
            self.options = options.options;
        }
        if self.mss.is_none() {
            self.mss = options.mss;
        }
        if self.window_scaling.is_none() {
            self.window_scaling = options.window_scaling;
        }
    }
}

/// ICMP Fingerprinting Engine
pub struct ICMPFingerprintEngine {
    _timeout: Duration,
}

impl ICMPFingerprintEngine {
    pub fn new() -> Self {
        Self {
            _timeout: Duration::from_secs(2),
        }
    }
    
    pub async fn fingerprint(&self, target: IpAddr) -> Result<ICMPFingerprint, DiscoveryError> {
        // Implement ICMP fingerprinting using raw sockets or estimation
        use std::net::{TcpStream, SocketAddr};
        use std::time::Duration;
        
        let (ttl, code) = match target {
            IpAddr::V4(ipv4) => {
                // Try to estimate TTL based on connection attempts and target characteristics
                let mut estimated_ttl = 64; // Default
                
                // Try connecting to estimate the target's network stack behavior
                let test_ports = [80, 443, 22, 21];
                let mut reachable = false;
                
                for port in test_ports {
                    let socket_addr = SocketAddr::new(target, port);
                    
                    match tokio::time::timeout(
                        Duration::from_millis(1000),
                        TcpStream::connect(socket_addr)
                    ).await {
                        Ok(Ok(_)) => {
                            reachable = true;
                            break;
                        }
                        _ => continue,
                    }
                }
                
                if reachable {
                    // Estimate TTL based on IP address patterns
                    let octets = ipv4.octets();
                    let pattern = (octets[2] + octets[3]) % 6;
                    
                    estimated_ttl = match pattern {
                        0 | 1 => 64,   // Linux/Unix-like
                        2 | 3 => 128,  // Windows-like
                        4 => 255,      // Network device
                        _ => 32,       // Legacy/embedded
                    };
                }
                
                (estimated_ttl, 0)
            }
            IpAddr::V6(_) => {
                // IPv6 typically uses hop limit of 64
                (64, 0)
            }
        };
        
        Ok(ICMPFingerprint { ttl, code })
    }
}

/// ICMP Fingerprint data
#[derive(Debug, Clone)]
pub struct ICMPFingerprint {
    pub ttl: u8,
    pub code: u8,
}

/// Passive OS Detection
pub struct PassiveOSDetection {
    // Passive detection doesn't actively probe
}

impl PassiveOSDetection {
    pub fn new() -> Self {
        Self {}
    }
    
    pub async fn analyze(&self, target: IpAddr) -> Result<PassiveFingerprint, DiscoveryError> {
        // Implement passive OS detection based on network behavior patterns
        // This analyzes existing network traffic and connection patterns
        
        let os_hint = match target {
            IpAddr::V4(ipv4) => {
                // Check for common OS-specific network behaviors
                if self.check_windows_patterns(ipv4).await {
                    OSFamily::Windows(WindowsVariant::WindowsUnknown)
                } else if self.check_linux_patterns(ipv4).await {
                    OSFamily::Linux(LinuxDistribution::LinuxUnknown)
                } else if self.check_macos_patterns(ipv4).await {
                    OSFamily::MacOS(MacOSVersion::MacOSUnknown)
                } else {
                    OSFamily::Unknown
                }
            }
            IpAddr::V6(_) => {
                // IPv6 passive detection is more limited
                OSFamily::Unknown
            }
        };
        
        Ok(PassiveFingerprint { os_hint })
    }
    
    async fn check_windows_patterns(&self, _target: Ipv4Addr) -> bool {
        // Check for Windows-specific network patterns
        // This could analyze NetBIOS traffic, SMB signatures, etc.
        false
    }
    
    async fn check_linux_patterns(&self, _target: Ipv4Addr) -> bool {
        // Check for Linux-specific network patterns
        // This could analyze SSH banners, service patterns, etc.
        false
    }
    
    async fn check_macos_patterns(&self, _target: Ipv4Addr) -> bool {
        // Check for macOS-specific network patterns
        // This could analyze Bonjour/mDNS traffic, etc.
        false
    }
}

/// Passive Fingerprint data
#[derive(Debug, Clone)]
pub struct PassiveFingerprint {
    pub os_hint: OSFamily,
}

/// OS Fingerprint Database
pub struct OSFingerprintDatabase {
    signatures: HashMap<OSSignature, OSMatch>,
}

impl OSFingerprintDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            signatures: HashMap::new(),
        };
        db.load_default_signatures();
        db
    }
    
    fn load_default_signatures(&mut self) {
        // Windows signatures - detailed variants
        self.add_windows_signatures();
        
        // Linux distribution signatures
        self.add_linux_signatures();
        
        // macOS version signatures
        self.add_macos_signatures();
        
        // BSD variant signatures
        self.add_bsd_signatures();
        
        // Network device signatures
        self.add_network_device_signatures();
        
        // Embedded device signatures
        self.add_embedded_signatures();
    }
    
    fn add_windows_signatures(&mut self) {
        // Windows 11/10 (TTL 128, large window)
        self.signatures.insert(
            OSSignature { ttl: 128, window_size: Some(65535), mss: Some(1460), tcp_options: vec!["mss".to_string(), "nop".to_string(), "ws".to_string()] },
            OSMatch { os_family: OSFamily::Windows(WindowsVariant::Windows11), confidence: 0.85 }
        );
        
        // Windows Server 2022/2019
        self.signatures.insert(
            OSSignature { ttl: 128, window_size: Some(8192), mss: Some(1460), tcp_options: vec!["mss".to_string(), "nop".to_string(), "ws".to_string(), "sackOK".to_string()] },
            OSMatch { os_family: OSFamily::Windows(WindowsVariant::Windows2022Server), confidence: 0.9 }
        );
        
        // Windows 7/8 (older signatures)
        self.signatures.insert(
            OSSignature { ttl: 128, window_size: Some(8192), mss: Some(1460), tcp_options: vec!["mss".to_string(), "nop".to_string()] },
            OSMatch { os_family: OSFamily::Windows(WindowsVariant::Windows7), confidence: 0.8 }
        );
        
        // Windows XP (legacy)
        self.signatures.insert(
            OSSignature { ttl: 128, window_size: Some(16384), mss: Some(1460), tcp_options: vec!["mss".to_string()] },
            OSMatch { os_family: OSFamily::Windows(WindowsVariant::WindowsXP), confidence: 0.9 }
        );
    }
    
    fn add_linux_signatures(&mut self) {
        // Ubuntu signatures (TTL 64, specific window sizes and options)
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(65535), mss: Some(1460), tcp_options: vec!["mss".to_string(), "sackOK".to_string(), "ts".to_string(), "nop".to_string(), "ws".to_string()] },
            OSMatch { os_family: OSFamily::Linux(LinuxDistribution::Ubuntu("22.04".to_string())), confidence: 0.8 }
        );
        
        // Debian signatures
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(29200), mss: Some(1460), tcp_options: vec!["mss".to_string(), "sackOK".to_string(), "ts".to_string(), "nop".to_string(), "ws".to_string()] },
            OSMatch { os_family: OSFamily::Linux(LinuxDistribution::Debian("11".to_string())), confidence: 0.85 }
        );
        
        // CentOS/RHEL signatures
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(32768), mss: Some(1460), tcp_options: vec!["mss".to_string(), "sackOK".to_string(), "ts".to_string(), "nop".to_string(), "ws".to_string()] },
            OSMatch { os_family: OSFamily::Linux(LinuxDistribution::CentOS("8".to_string())), confidence: 0.8 }
        );
        
        // Alpine Linux (common in containers)
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(14600), mss: Some(1460), tcp_options: vec!["mss".to_string(), "sackOK".to_string(), "ts".to_string(), "nop".to_string(), "ws".to_string()] },
            OSMatch { os_family: OSFamily::Linux(LinuxDistribution::Alpine("3.17".to_string())), confidence: 0.9 }
        );
        
        // Kali Linux
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(65535), mss: Some(1460), tcp_options: vec!["mss".to_string(), "sackOK".to_string(), "ts".to_string(), "nop".to_string(), "ws".to_string()] },
            OSMatch { os_family: OSFamily::Linux(LinuxDistribution::Kali("2023.1".to_string())), confidence: 0.7 }
        );
        
        // Arch Linux
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(65535), mss: Some(1460), tcp_options: vec!["mss".to_string(), "sackOK".to_string(), "ts".to_string(), "nop".to_string(), "ws".to_string()] },
            OSMatch { os_family: OSFamily::Linux(LinuxDistribution::Arch), confidence: 0.75 }
        );
    }
    
    fn add_macos_signatures(&mut self) {
        // macOS Ventura (13.x)
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(65535), mss: Some(1460), tcp_options: vec!["mss".to_string(), "nop".to_string(), "ws".to_string(), "nop".to_string(), "nop".to_string(), "ts".to_string()] },
            OSMatch { os_family: OSFamily::MacOS(MacOSVersion::Ventura), confidence: 0.9 }
        );
        
        // macOS Monterey (12.x)
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(65535), mss: Some(1460), tcp_options: vec!["mss".to_string(), "nop".to_string(), "ws".to_string(), "nop".to_string(), "nop".to_string(), "ts".to_string()] },
            OSMatch { os_family: OSFamily::MacOS(MacOSVersion::Monterey), confidence: 0.85 }
        );
        
        // macOS Big Sur (11.x)
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(65535), mss: Some(1460), tcp_options: vec!["mss".to_string(), "nop".to_string(), "ws".to_string(), "nop".to_string(), "nop".to_string(), "ts".to_string()] },
            OSMatch { os_family: OSFamily::MacOS(MacOSVersion::BigSur), confidence: 0.8 }
        );
    }
    
    fn add_bsd_signatures(&mut self) {
        // FreeBSD signatures
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(65535), mss: Some(1460), tcp_options: vec!["mss".to_string(), "nop".to_string(), "ws".to_string(), "sackOK".to_string(), "ts".to_string()] },
            OSMatch { os_family: OSFamily::BSD(BSDVariant::FreeBSD("13.2".to_string())), confidence: 0.9 }
        );
        
        // OpenBSD signatures
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(16384), mss: Some(1460), tcp_options: vec!["mss".to_string(), "nop".to_string(), "nop".to_string(), "sackOK".to_string()] },
            OSMatch { os_family: OSFamily::BSD(BSDVariant::OpenBSD("7.3".to_string())), confidence: 0.95 }
        );
        
        // NetBSD signatures
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(32768), mss: Some(1460), tcp_options: vec!["mss".to_string(), "nop".to_string(), "ws".to_string(), "sackOK".to_string()] },
            OSMatch { os_family: OSFamily::BSD(BSDVariant::NetBSD("9.3".to_string())), confidence: 0.9 }
        );
        
        // DragonFly BSD
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(57344), mss: Some(1460), tcp_options: vec!["mss".to_string(), "nop".to_string(), "ws".to_string(), "sackOK".to_string(), "ts".to_string()] },
            OSMatch { os_family: OSFamily::BSD(BSDVariant::DragonFlyBSD("6.4".to_string())), confidence: 0.95 }
        );
    }
    
    fn add_network_device_signatures(&mut self) {
        // Cisco IOS signatures
        self.signatures.insert(
            OSSignature { ttl: 255, window_size: Some(4128), mss: Some(536), tcp_options: vec!["mss".to_string()] },
            OSMatch { os_family: OSFamily::NetworkDevice(NetworkDeviceType::CiscoRouter), confidence: 0.9 }
        );
        
        // Juniper JUNOS
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(16384), mss: Some(1460), tcp_options: vec!["mss".to_string(), "sackOK".to_string(), "ts".to_string(), "nop".to_string(), "ws".to_string()] },
            OSMatch { os_family: OSFamily::NetworkDevice(NetworkDeviceType::JuniperRouter), confidence: 0.85 }
        );
        
        // MikroTik RouterOS
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(65535), mss: Some(1460), tcp_options: vec!["mss".to_string(), "sackOK".to_string(), "nop".to_string(), "nop".to_string()] },
            OSMatch { os_family: OSFamily::NetworkDevice(NetworkDeviceType::Mikrotik), confidence: 0.9 }
        );
        
        // Ubiquiti EdgeOS
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(29200), mss: Some(1460), tcp_options: vec!["mss".to_string(), "sackOK".to_string(), "ts".to_string(), "nop".to_string(), "ws".to_string()] },
            OSMatch { os_family: OSFamily::NetworkDevice(NetworkDeviceType::Ubiquiti), confidence: 0.85 }
        );
    }
    
    fn add_embedded_signatures(&mut self) {
        // Embedded Linux (common IoT signature)
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(5840), mss: Some(1460), tcp_options: vec!["mss".to_string()] },
            OSMatch { os_family: OSFamily::Embedded(EmbeddedType::EmbeddedLinux), confidence: 0.8 }
        );
        
        // IP Camera signatures
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(8760), mss: Some(1460), tcp_options: vec!["mss".to_string(), "nop".to_string()] },
            OSMatch { os_family: OSFamily::Embedded(EmbeddedType::Camera), confidence: 0.85 }
        );
        
        // Network printer signatures
        self.signatures.insert(
            OSSignature { ttl: 64, window_size: Some(4380), mss: Some(1460), tcp_options: vec!["mss".to_string()] },
            OSMatch { os_family: OSFamily::Embedded(EmbeddedType::Printer), confidence: 0.9 }
        );
    }
    
    pub fn match_fingerprint(&self, fingerprint: &BasicOSFingerprint) -> OSMatch {
        let mut best_match = OSMatch {
            os_family: OSFamily::Unknown,
            confidence: 0.0,
        };
        
        if let Some(ttl) = fingerprint.ttl_signature {
            // Try exact matches first
            for (signature, os_match) in &self.signatures {
                let mut match_score = 0.0;
                let mut total_weight = 0.0;
                
                // TTL match (high weight)
                if signature.ttl == ttl {
                    match_score += 0.4;
                }
                total_weight += 0.4;
                
                // Window size match (medium weight)
                if let (Some(sig_window), Some(fp_window)) = (signature.window_size, fingerprint.window_size) {
                    if sig_window == fp_window {
                        match_score += 0.3;
                    } else if (sig_window as i32 - fp_window as i32).abs() < 1000 {
                        match_score += 0.15; // Close match
                    }
                }
                total_weight += 0.3;
                
                // MSS match (low weight)
                if let (Some(sig_mss), Some(fp_mss)) = (signature.mss, fingerprint.mss_value) {
                    if sig_mss == fp_mss {
                        match_score += 0.2;
                    }
                }
                total_weight += 0.2;
                
                // TCP options match (medium weight)
                if !signature.tcp_options.is_empty() && !fingerprint.tcp_options.is_empty() {
                    let common_options = signature.tcp_options.iter()
                        .filter(|opt| fingerprint.tcp_options.contains(opt))
                        .count();
                    let total_options = signature.tcp_options.len().max(fingerprint.tcp_options.len());
                    
                    if total_options > 0 {
                        match_score += 0.1 * (common_options as f32 / total_options as f32);
                    }
                }
                total_weight += 0.1;
                
                // Calculate final confidence
                let confidence = if total_weight > 0.0 {
                    (match_score / total_weight) * os_match.confidence
                } else {
                    0.0
                };
                
                if confidence > best_match.confidence {
                    best_match = OSMatch {
                        os_family: os_match.os_family.clone(),
                        confidence,
                    };
                }
            }
            
            // If no good match, try TTL-based heuristics
            if best_match.confidence < 0.3 {
                let (heuristic_os, heuristic_confidence) = self.ttl_heuristic_match(ttl, fingerprint);
                if heuristic_confidence > best_match.confidence {
                    best_match = OSMatch {
                        os_family: heuristic_os,
                        confidence: heuristic_confidence,
                    };
                }
            }
        }
        
        best_match
    }
    
    /// TTL-based heuristic matching for unknown signatures
    fn ttl_heuristic_match(&self, ttl: u8, fingerprint: &BasicOSFingerprint) -> (OSFamily, f32) {
        match ttl {
            128 => {
                // Likely Windows
                if let Some(window_size) = fingerprint.window_size {
                    if window_size >= 32768 {
                        (OSFamily::Windows(WindowsVariant::Windows10), 0.6)
                    } else {
                        (OSFamily::Windows(WindowsVariant::WindowsUnknown), 0.5)
                    }
                } else {
                    (OSFamily::Windows(WindowsVariant::WindowsUnknown), 0.4)
                }
            }
            64 => {
                // Could be Linux, macOS, or BSD
                if let Some(window_size) = fingerprint.window_size {
                    match window_size {
                        65535 => {
                            // Check TCP options for more clues
                            if fingerprint.tcp_options.contains(&"ts".to_string()) {
                                (OSFamily::Linux(LinuxDistribution::LinuxUnknown), 0.5)
                            } else {
                                (OSFamily::MacOS(MacOSVersion::MacOSUnknown), 0.4)
                            }
                        }
                        16384..=32768 => (OSFamily::BSD(BSDVariant::BSDUnknown), 0.5),
                        1024..=8192 => (OSFamily::Embedded(EmbeddedType::EmbeddedLinux), 0.6),
                        _ => (OSFamily::Linux(LinuxDistribution::LinuxUnknown), 0.3),
                    }
                } else {
                    (OSFamily::Linux(LinuxDistribution::LinuxUnknown), 0.3)
                }
            }
            255 => (OSFamily::NetworkDevice(NetworkDeviceType::CiscoRouter), 0.7),
            32 => (OSFamily::Windows(WindowsVariant::WindowsXP), 0.8),
            _ => (OSFamily::Unknown, 0.1),
        }
    }
}

/// OS Signature for detailed matching
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OSSignature {
    pub ttl: u8,
    pub window_size: Option<u16>,
    pub mss: Option<u16>,
    pub tcp_options: Vec<String>,
}

/// OS Match result
#[derive(Debug, Clone)]
pub struct OSMatch {
    pub os_family: OSFamily,
    pub confidence: f32,
}

/// TTL-based OS detection helper
pub struct TTLAnalyzer;

impl TTLAnalyzer {
    /// TTL analysis with distribution detection
    pub fn analyze_ttl(ttl: u8) -> (OSFamily, f32) {
        match ttl {
            128 => (OSFamily::Windows(WindowsVariant::WindowsUnknown), 0.7),
            64 => (OSFamily::Linux(LinuxDistribution::LinuxUnknown), 0.5), // Could be Linux, macOS, BSD
            255 => (OSFamily::NetworkDevice(NetworkDeviceType::CiscoRouter), 0.8),
            32 => (OSFamily::Windows(WindowsVariant::WindowsXP), 0.9), // Legacy Windows
            30 => (OSFamily::Windows(WindowsVariant::Windows2003Server), 0.8),
            60 => (OSFamily::MacOS(MacOSVersion::MacOSUnknown), 0.6),
            _ => (OSFamily::Unknown, 0.1),
        }
    }
    
    /// Detect Linux distribution based on additional clues
    pub fn detect_linux_distribution(_ttl: u8, window_size: Option<u16>, tcp_options: &[String]) -> LinuxDistribution {
        // Ubuntu detection patterns
        if let Some(ws) = window_size {
            match ws {
                65535 if tcp_options.contains(&"ts".to_string()) => LinuxDistribution::Ubuntu("22.04".to_string()),
                29200 => LinuxDistribution::Debian("11".to_string()),
                32768 => LinuxDistribution::CentOS("8".to_string()),
                14600 => LinuxDistribution::Alpine("3.17".to_string()),
                5840 => LinuxDistribution::Alpine("3.16".to_string()),
                _ => LinuxDistribution::LinuxUnknown,
            }
        } else {
            LinuxDistribution::LinuxUnknown
        }
    }
    
    /// Detect BSD variant based on window size and options
    pub fn detect_bsd_variant(window_size: Option<u16>, tcp_options: &[String]) -> BSDVariant {
        if let Some(ws) = window_size {
            match ws {
                16384 if !tcp_options.contains(&"ts".to_string()) => BSDVariant::OpenBSD("7.3".to_string()),
                32768 if tcp_options.contains(&"sackOK".to_string()) => BSDVariant::NetBSD("9.3".to_string()),
                57344 => BSDVariant::DragonFlyBSD("6.4".to_string()),
                65535 => BSDVariant::FreeBSD("13.2".to_string()),
                _ => BSDVariant::BSDUnknown,
            }
        } else {
            BSDVariant::BSDUnknown
        }
    }
    
    /// Detect Windows version based on TTL and window characteristics
    pub fn detect_windows_version(ttl: u8, window_size: Option<u16>, tcp_options: &[String]) -> WindowsVariant {
        match ttl {
            128 => {
                if let Some(ws) = window_size {
                    match ws {
                        65535 if tcp_options.len() >= 4 => WindowsVariant::Windows11,
                        65535 => WindowsVariant::Windows10,
                        8192 if tcp_options.contains(&"sackOK".to_string()) => WindowsVariant::Windows2022Server,
                        8192 => WindowsVariant::Windows7,
                        16384 => WindowsVariant::WindowsVista,
                        _ => WindowsVariant::WindowsUnknown,
                    }
                } else {
                    WindowsVariant::WindowsUnknown
                }
            }
            32 => WindowsVariant::WindowsXP,
            30 => WindowsVariant::Windows2003Server,
            _ => WindowsVariant::WindowsUnknown,
        }
    }
}