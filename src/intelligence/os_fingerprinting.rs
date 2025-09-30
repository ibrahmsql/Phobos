//! Advanced OS fingerprinting system for Phobos
//! Uses multiple techniques to identify target operating systems

use crate::network::{PortResult, PortState, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Operating system detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSDetectionResult {
    pub primary_os: Option<OperatingSystem>,
    pub confidence: f64,
    pub secondary_matches: Vec<OSMatch>,
    pub detection_methods: Vec<DetectionMethod>,
    pub fingerprint_data: FingerprintData,
}

/// Detected operating system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatingSystem {
    pub family: OSFamily,
    pub name: String,
    pub version: Option<String>,
    pub architecture: Option<String>,
    pub vendor: String,
}

/// OS family categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OSFamily {
    Windows,
    Linux,
    MacOS,
    FreeBSD,
    OpenBSD,
    NetBSD,
    Solaris,
    AIX,
    HPUX,
    Cisco,
    Juniper,
    Unknown,
}

/// Secondary OS match with confidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSMatch {
    pub os: OperatingSystem,
    pub confidence: f64,
    pub reason: String,
}

/// Detection methods used
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionMethod {
    PortPattern,
    ServiceBanner,
    TTLAnalysis,
    TCPFingerprint,
    TimingAnalysis,
    WindowSize,
}

/// Raw fingerprint data collected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintData {
    pub ttl_values: Vec<u8>,
    pub window_sizes: Vec<u16>,
    pub open_ports: Vec<u16>,
    pub service_banners: HashMap<u16, String>,
    pub response_times: HashMap<u16, Duration>,
    pub tcp_options: Vec<String>,
}

/// Advanced OS fingerprinting engine
pub struct OSFingerprinter {
    port_signatures: HashMap<OSFamily, Vec<PortSignature>>,
    banner_patterns: HashMap<OSFamily, Vec<BannerPattern>>,
    ttl_signatures: HashMap<OSFamily, TTLSignature>,
}

/// Port signature for OS detection
#[derive(Debug, Clone)]
struct PortSignature {
    common_ports: Vec<u16>,
    #[allow(dead_code)]
    rare_ports: Vec<u16>,
    service_combinations: Vec<Vec<u16>>,
    confidence_weight: f64,
}

/// Banner pattern matching
#[derive(Debug, Clone)]
struct BannerPattern {
    pattern: String,
    #[allow(dead_code)]
    os_indicator: String,
    confidence: f64,
}

/// TTL signature for OS detection
#[derive(Debug, Clone)]
struct TTLSignature {
    typical_ttl: u8,
    variance: u8,
    confidence: f64,
}

impl OSFingerprinter {
    pub fn new() -> Self {
        let mut fingerprinter = Self {
            port_signatures: HashMap::new(),
            banner_patterns: HashMap::new(),
            ttl_signatures: HashMap::new(),
        };
        
        fingerprinter.initialize_signatures();
        fingerprinter
    }
    
    /// Initialize OS signatures database
    fn initialize_signatures(&mut self) {
        // Windows signatures
        self.port_signatures.insert(OSFamily::Windows, vec![
            PortSignature {
                common_ports: vec![135, 139, 445, 3389, 5985, 5986],
                rare_ports: vec![1433, 1434, 593, 49152, 49153, 49154],
                service_combinations: vec![
                    vec![135, 139, 445], // Classic Windows SMB
                    vec![80, 443, 3389], // Windows Server with RDP
                    vec![53, 88, 389, 636], // Domain Controller
                ],
                confidence_weight: 0.9,
            }
        ]);
        
        // Linux signatures
        self.port_signatures.insert(OSFamily::Linux, vec![
            PortSignature {
                common_ports: vec![22, 80, 443, 25, 53, 110, 143],
                rare_ports: vec![111, 2049, 6000, 6001, 6002],
                service_combinations: vec![
                    vec![22, 80, 443], // Typical Linux server
                    vec![22, 25, 53, 80], // Mail/DNS server
                    vec![111, 2049], // NFS server
                ],
                confidence_weight: 0.8,
            }
        ]);
        
        // macOS signatures
        self.port_signatures.insert(OSFamily::MacOS, vec![
            PortSignature {
                common_ports: vec![22, 80, 443, 548, 631, 5900],
                rare_ports: vec![88, 311, 625, 3283, 5353],
                service_combinations: vec![
                    vec![22, 548, 631], // macOS Server
                    vec![5900, 3283], // Screen sharing + Apple Remote Desktop
                ],
                confidence_weight: 0.85,
            }
        ]);
        
        // TTL signatures
        self.ttl_signatures.insert(OSFamily::Windows, TTLSignature {
            typical_ttl: 128,
            variance: 2,
            confidence: 0.7,
        });
        
        self.ttl_signatures.insert(OSFamily::Linux, TTLSignature {
            typical_ttl: 64,
            variance: 1,
            confidence: 0.7,
        });
        
        self.ttl_signatures.insert(OSFamily::MacOS, TTLSignature {
            typical_ttl: 64,
            variance: 1,
            confidence: 0.6,
        });
        
        // Banner patterns
        self.banner_patterns.insert(OSFamily::Windows, vec![
            BannerPattern {
                pattern: "Microsoft".to_string(),
                os_indicator: "Windows Server".to_string(),
                confidence: 0.9,
            },
            BannerPattern {
                pattern: "IIS".to_string(),
                os_indicator: "Windows IIS".to_string(),
                confidence: 0.85,
            },
        ]);
        
        self.banner_patterns.insert(OSFamily::Linux, vec![
            BannerPattern {
                pattern: "Apache".to_string(),
                os_indicator: "Linux Apache".to_string(),
                confidence: 0.6,
            },
            BannerPattern {
                pattern: "nginx".to_string(),
                os_indicator: "Linux nginx".to_string(),
                confidence: 0.6,
            },
            BannerPattern {
                pattern: "OpenSSH".to_string(),
                os_indicator: "Linux OpenSSH".to_string(),
                confidence: 0.7,
            },
        ]);
    }
    
    /// Perform OS detection on scan results
    pub fn detect_os(&self, _target: IpAddr, port_results: &[PortResult]) -> OSDetectionResult {
        let mut detection_methods = Vec::new();
        let mut confidence_scores: HashMap<OSFamily, f64> = HashMap::new();
        
        // Collect fingerprint data
        let fingerprint_data = self.collect_fingerprint_data(port_results);
        
        // Port pattern analysis
        let port_scores = self.analyze_port_patterns(port_results);
        for (os_family, score) in port_scores {
            *confidence_scores.entry(os_family).or_insert(0.0) += score;
        }
        detection_methods.push(DetectionMethod::PortPattern);
        
        // Service banner analysis
        let banner_scores = self.analyze_service_banners(&fingerprint_data.service_banners);
        for (os_family, score) in banner_scores {
            *confidence_scores.entry(os_family).or_insert(0.0) += score;
        }
        if !fingerprint_data.service_banners.is_empty() {
            detection_methods.push(DetectionMethod::ServiceBanner);
        }
        
        // TTL analysis (simulated - would need actual packet capture)
        if let Some(ttl_scores) = self.analyze_ttl_patterns(&fingerprint_data.ttl_values) {
            for (os_family, score) in ttl_scores {
                *confidence_scores.entry(os_family).or_insert(0.0) += score;
            }
            detection_methods.push(DetectionMethod::TTLAnalysis);
        }
        
        // Find best match
        let (primary_os, confidence) = self.determine_primary_os(&confidence_scores);
        let secondary_matches = self.get_secondary_matches(&confidence_scores, &primary_os);
        
        OSDetectionResult {
            primary_os,
            confidence,
            secondary_matches,
            detection_methods,
            fingerprint_data,
        }
    }
    
    fn collect_fingerprint_data(&self, port_results: &[PortResult]) -> FingerprintData {
        let open_ports: Vec<u16> = port_results
            .iter()
            .filter(|p| p.state == PortState::Open)
            .map(|p| p.port)
            .collect();
        
        let mut service_banners = HashMap::new();
        let mut response_times = HashMap::new();
        
        for result in port_results {
            if let Some(ref service) = result.service {
                service_banners.insert(result.port, service.clone());
            }
            response_times.insert(result.port, result.response_time);
        }
        
        FingerprintData {
            ttl_values: vec![64, 128], // Simulated - would come from actual packets
            window_sizes: vec![65535, 8192], // Simulated
            open_ports,
            service_banners,
            response_times,
            tcp_options: vec![], // Would be populated from actual TCP analysis
        }
    }
    
    fn analyze_port_patterns(&self, port_results: &[PortResult]) -> HashMap<OSFamily, f64> {
        let mut scores = HashMap::new();
        let open_ports: Vec<u16> = port_results
            .iter()
            .filter(|p| p.state == PortState::Open)
            .map(|p| p.port)
            .collect();
        
        for (os_family, signatures) in &self.port_signatures {
            let mut total_score = 0.0;
            
            for signature in signatures {
                let mut signature_score = 0.0;
                
                // Check common ports
                let common_matches = signature.common_ports
                    .iter()
                    .filter(|&&port| open_ports.contains(&port))
                    .count();
                
                signature_score += (common_matches as f64 / signature.common_ports.len() as f64) * 0.6;
                
                // Check service combinations
                for combination in &signature.service_combinations {
                    let combo_matches = combination
                        .iter()
                        .filter(|&&port| open_ports.contains(&port))
                        .count();
                    
                    if combo_matches == combination.len() {
                        signature_score += 0.4; // Bonus for complete service combination
                    }
                }
                
                total_score += signature_score * signature.confidence_weight;
            }
            
            scores.insert(*os_family, total_score);
        }
        
        scores
    }
    
    fn analyze_service_banners(&self, banners: &HashMap<u16, String>) -> HashMap<OSFamily, f64> {
        let mut scores = HashMap::new();
        
        for (os_family, patterns) in &self.banner_patterns {
            let mut total_score = 0.0;
            
            for (_port, banner) in banners {
                for pattern in patterns {
                    if banner.to_lowercase().contains(&pattern.pattern.to_lowercase()) {
                        total_score += pattern.confidence;
                    }
                }
            }
            
            if total_score > 0.0 {
                scores.insert(*os_family, total_score);
            }
        }
        
        scores
    }
    
    fn analyze_ttl_patterns(&self, ttl_values: &[u8]) -> Option<HashMap<OSFamily, f64>> {
        if ttl_values.is_empty() {
            return None;
        }
        
        let mut scores = HashMap::new();
        let avg_ttl = ttl_values.iter().map(|&x| x as f64).sum::<f64>() / ttl_values.len() as f64;
        
        for (os_family, signature) in &self.ttl_signatures {
            let diff = (avg_ttl - signature.typical_ttl as f64).abs();
            if diff <= signature.variance as f64 {
                let score = signature.confidence * (1.0 - (diff / signature.variance as f64));
                scores.insert(*os_family, score);
            }
        }
        
        Some(scores)
    }
    
    fn determine_primary_os(&self, scores: &HashMap<OSFamily, f64>) -> (Option<OperatingSystem>, f64) {
        if let Some((os_family, &confidence)) = scores.iter().max_by(|a, b| a.1.partial_cmp(b.1).unwrap()) {
            let os = self.create_os_from_family(*os_family);
            (Some(os), confidence)
        } else {
            (None, 0.0)
        }
    }
    
    fn get_secondary_matches(&self, scores: &HashMap<OSFamily, f64>, primary: &Option<OperatingSystem>) -> Vec<OSMatch> {
        let mut matches = Vec::new();
        
        for (os_family, &confidence) in scores {
            if let Some(ref primary_os) = primary {
                if primary_os.family != *os_family && confidence > 0.3 {
                    matches.push(OSMatch {
                        os: self.create_os_from_family(*os_family),
                        confidence,
                        reason: "Port pattern analysis".to_string(),
                    });
                }
            }
        }
        
        matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        matches.truncate(3); // Top 3 secondary matches
        matches
    }
    
    fn create_os_from_family(&self, family: OSFamily) -> OperatingSystem {
        match family {
            OSFamily::Windows => OperatingSystem {
                family,
                name: "Microsoft Windows".to_string(),
                version: None,
                architecture: None,
                vendor: "Microsoft".to_string(),
            },
            OSFamily::Linux => OperatingSystem {
                family,
                name: "Linux".to_string(),
                version: None,
                architecture: None,
                vendor: "Various".to_string(),
            },
            OSFamily::MacOS => OperatingSystem {
                family,
                name: "macOS".to_string(),
                version: None,
                architecture: None,
                vendor: "Apple".to_string(),
            },
            _ => OperatingSystem {
                family,
                name: "Unknown".to_string(),
                version: None,
                architecture: None,
                vendor: "Unknown".to_string(),
            },
        }
    }
}

impl Default for OSFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_windows_detection() {
        let fingerprinter = OSFingerprinter::new();
        let port_results = vec![
            PortResult {
                port: 135,
                state: PortState::Open,
                service: Some("msrpc".to_string()),
                protocol: Protocol::Tcp,
                response_time: Duration::from_millis(10),
            },
            PortResult {
                port: 139,
                state: PortState::Open,
                service: Some("netbios-ssn".to_string()),
                protocol: Protocol::Tcp,
                response_time: Duration::from_millis(15),
            },
            PortResult {
                port: 445,
                state: PortState::Open,
                service: Some("microsoft-ds".to_string()),
                protocol: Protocol::Tcp,
                response_time: Duration::from_millis(12),
            },
        ];
        
        let result = fingerprinter.detect_os("192.168.1.100".parse().unwrap(), &port_results);
        
        assert!(result.primary_os.is_some());
        let os = result.primary_os.unwrap();
        assert_eq!(os.family, OSFamily::Windows);
        assert!(result.confidence > 0.5);
    }
    
    #[test]
    fn test_linux_detection() {
        let fingerprinter = OSFingerprinter::new();
        let port_results = vec![
            PortResult {
                port: 22,
                state: PortState::Open,
                service: Some("OpenSSH 8.0".to_string()),
                protocol: Protocol::Tcp,
                response_time: Duration::from_millis(5),
            },
            PortResult {
                port: 80,
                state: PortState::Open,
                service: Some("Apache/2.4.41".to_string()),
                protocol: Protocol::Tcp,
                response_time: Duration::from_millis(8),
            },
        ];
        
        let result = fingerprinter.detect_os("10.0.0.1".parse().unwrap(), &port_results);
        
        assert!(result.primary_os.is_some());
        let os = result.primary_os.unwrap();
        assert_eq!(os.family, OSFamily::Linux);
    }
}