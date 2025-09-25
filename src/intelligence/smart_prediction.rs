//! Smart port prediction based on service fingerprinting and ML

use crate::network::{PortResult, PortState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Smart port predictor using service patterns
#[derive(Debug, Clone)]
pub struct SmartPredictor {
    service_patterns: HashMap<String, Vec<u16>>,
    port_correlations: HashMap<u16, Vec<u16>>,
}

/// Prediction result with confidence score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortPrediction {
    pub port: u16,
    pub confidence: f64,
    pub reason: String,
    pub related_services: Vec<String>,
}

impl SmartPredictor {
    pub fn new() -> Self {
        let mut service_patterns = HashMap::new();
        
        // Common service patterns
        service_patterns.insert("web".to_string(), vec![80, 443, 8080, 8443, 3000, 8000]);
        service_patterns.insert("database".to_string(), vec![3306, 5432, 1433, 27017, 6379]);
        service_patterns.insert("mail".to_string(), vec![25, 110, 143, 993, 995, 587]);
        service_patterns.insert("ftp".to_string(), vec![21, 22, 990]);
        service_patterns.insert("dns".to_string(), vec![53, 853]);
        service_patterns.insert("admin".to_string(), vec![22, 3389, 5900, 5901]);
        
        let mut port_correlations = HashMap::new();
        
        // Port correlations - if one is open, others might be too
        port_correlations.insert(80, vec![443, 8080, 8443]);
        port_correlations.insert(443, vec![80, 8080, 8443]);
        port_correlations.insert(22, vec![2222, 2200]);
        port_correlations.insert(3306, vec![3307, 33060]);
        port_correlations.insert(5432, vec![5433]);
        
        Self {
            service_patterns,
            port_correlations,
        }
    }
    
    /// Predict likely open ports based on discovered services
    pub fn predict_ports(&self, discovered_ports: &[PortResult]) -> Vec<PortPrediction> {
        let mut predictions = Vec::new();
        let open_ports: Vec<u16> = discovered_ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .map(|p| p.port)
            .collect();
        
        // Service-based predictions
        for (service, ports) in &self.service_patterns {
            let matching_ports: Vec<u16> = ports.iter()
                .filter(|&&p| open_ports.contains(&p))
                .copied()
                .collect();
            
            if !matching_ports.is_empty() {
                let confidence = matching_ports.len() as f64 / ports.len() as f64;
                
                for &port in ports {
                    if !open_ports.contains(&port) && confidence > 0.3 {
                        predictions.push(PortPrediction {
                            port,
                            confidence: confidence * 0.8, // Reduce confidence for predictions
                            reason: format!("Service pattern: {}", service),
                            related_services: vec![service.clone()],
                        });
                    }
                }
            }
        }
        
        // Correlation-based predictions
        for &open_port in &open_ports {
            if let Some(related_ports) = self.port_correlations.get(&open_port) {
                for &related_port in related_ports {
                    if !open_ports.contains(&related_port) {
                        predictions.push(PortPrediction {
                            port: related_port,
                            confidence: 0.6,
                            reason: format!("Correlated with port {}", open_port),
                            related_services: vec!["correlation".to_string()],
                        });
                    }
                }
            }
        }
        
        // Sort by confidence
        predictions.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        predictions.truncate(20); // Limit to top 20 predictions
        
        predictions
    }
    
    /// Get recommended scan order based on target type
    pub fn get_scan_order(&self, target: IpAddr) -> Vec<u16> {
        let mut priority_ports = Vec::new();
        
        // High-priority ports (most common services)
        priority_ports.extend_from_slice(&[22, 80, 443, 21, 25, 53, 110, 143]);
        
        // Add service-specific ports based on IP range heuristics
        if target.is_loopback() {
            // Local development ports
            priority_ports.extend_from_slice(&[3000, 8000, 8080, 9000, 5000]);
        } else if self.is_likely_server(target) {
            // Server ports
            priority_ports.extend_from_slice(&[3306, 5432, 6379, 27017, 1433]);
        }
        
        priority_ports.sort_unstable();
        priority_ports.dedup();
        priority_ports
    }
    
    fn is_likely_server(&self, target: IpAddr) -> bool {
        match target {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Common server IP patterns
                matches!(octets[0], 10 | 172 | 192) || 
                matches!((octets[0], octets[1]), (172, 16..=31)) ||
                matches!((octets[0], octets[1], octets[2]), (192, 168, _))
            }
            IpAddr::V6(_) => false, // Simple heuristic for now
        }
    }
}

impl Default for SmartPredictor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Protocol;
    use std::time::Duration;
    
    #[test]
    fn test_web_service_prediction() {
        let predictor = SmartPredictor::new();
        let discovered = vec![
            PortResult {
                port: 80,
                state: PortState::Open,
                service: Some("http".to_string()),
                protocol: Protocol::Tcp,
                response_time: Duration::from_millis(10),
            }
        ];
        
        let predictions = predictor.predict_ports(&discovered);
        assert!(!predictions.is_empty());
        
        // Should predict HTTPS port
        let https_prediction = predictions.iter().find(|p| p.port == 443);
        assert!(https_prediction.is_some());
        assert!(https_prediction.unwrap().confidence > 0.0);
    }
    
    #[test]
    fn test_scan_order() {
        let predictor = SmartPredictor::new();
        let localhost = "127.0.0.1".parse().unwrap();
        
        let order = predictor.get_scan_order(localhost);
        assert!(!order.is_empty());
        assert!(order.contains(&22)); // SSH should be in priority
        assert!(order.contains(&80)); // HTTP should be in priority
    }
}