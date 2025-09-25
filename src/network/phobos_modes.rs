//! Phobos-specific scanning modes that embody the god of fear

use crate::config::ScanConfig;
use serde::{Deserialize, Serialize};
use rand::Rng;

/// Simplified mode levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FearLevel {
    Normal = 3,     // Balanced approach (default)
}

impl From<u8> for FearLevel {
    fn from(_level: u8) -> Self {
        FearLevel::Normal
    }
}



/// Wrath mode configuration for maximum aggression
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrathConfig {
    pub enabled: bool,
    pub max_threads: usize,
    pub burst_rate: u64,
    pub evasion_techniques: Vec<EvasionTechnique>,
    pub decoy_count: usize,
}

/// Shadow scanning configuration for stealth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowConfig {
    pub enabled: bool,
    pub randomize_timing: bool,
    pub fragment_packets: bool,
    pub spoof_source: bool,
    pub use_proxies: bool,
    pub minimal_footprint: bool,
}



/// Evasion techniques for advanced stealth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvasionTechnique {
    PacketFragmentation,
    TimingRandomization,
    SourceSpoofing,
    DecoyScanning,
    IdleScanning,
    ZombieScanning,
}

/// Phobos mode manager that applies configurations
pub struct PhobosModeManager {
    fear_level: FearLevel,

    wrath: Option<WrathConfig>,
    shadow: Option<ShadowConfig>,

}

impl PhobosModeManager {
    pub fn new(fear_level: FearLevel) -> Self {
        Self {
            fear_level,

            wrath: None,
            shadow: None,

        }
    }



    /// Enable Wrath mode for maximum aggression
    pub fn enable_wrath(&mut self) -> &mut Self {
        let max_threads = 2000; // Fixed reasonable number

        self.wrath = Some(WrathConfig {
            enabled: true,
            max_threads,
            burst_rate: 6_000_000, // 6M PPS - good balance
            evasion_techniques: vec![
                EvasionTechnique::PacketFragmentation,
                EvasionTechnique::DecoyScanning,
            ],
            decoy_count: 4, // Fixed reasonable number
        });
        self
    }

    /// Enable Shadow mode for maximum stealth
    pub fn enable_shadow(&mut self) -> &mut Self {
        self.shadow = Some(ShadowConfig {
            enabled: true,
            randomize_timing: true,
            fragment_packets: true,
            spoof_source: false, // Keep it simple
            use_proxies: false,
            minimal_footprint: true,
        });
        self
    }



    /// Apply Phobos modes to scan configuration
    pub fn apply_to_config(&self, mut config: ScanConfig) -> ScanConfig {
        // Apply fear level base settings
        config = self.apply_fear_level(config);



        // Apply Wrath mode aggression
        if let Some(wrath) = &self.wrath {
            config = self.apply_wrath(config, wrath);
        }

        // Apply Shadow mode stealth
        if let Some(shadow) = &self.shadow {
            config = self.apply_shadow(config, shadow);
        }



        config
    }

    fn apply_fear_level(&self, config: ScanConfig) -> ScanConfig {
        // Just return config as-is since we only have Normal level
        config
    }



    fn apply_wrath(&self, mut config: ScanConfig, wrath: &WrathConfig) -> ScanConfig {
        config.threads = wrath.max_threads;
        config.rate_limit = wrath.burst_rate;
        
        // Apply evasion techniques to stealth options
        let mut stealth = config.stealth_options.unwrap_or_default();
        
        for technique in &wrath.evasion_techniques {
            match technique {
                EvasionTechnique::PacketFragmentation => {
                    stealth.fragment_packets = true;
                }
                EvasionTechnique::DecoyScanning => {
                    stealth.decoy_addresses = self.generate_decoy_addresses(wrath.decoy_count);
                }
                _ => {} // Other techniques handled elsewhere
            }
        }
        
        config.stealth_options = Some(stealth);
        config
    }

    fn apply_shadow(&self, mut config: ScanConfig, shadow: &ShadowConfig) -> ScanConfig {
        let mut stealth = config.stealth_options.unwrap_or_default();
        
        if shadow.fragment_packets {
            stealth.fragment_packets = true;
        }
        
        if shadow.spoof_source {
            stealth.spoof_source_ip = Some("192.168.1.100".parse().unwrap());
        }
        
        if shadow.minimal_footprint {
            // Reduce threads and rate for stealth
            config.threads = config.threads.min(100);
            config.rate_limit = config.rate_limit.min(1000);
        }
        
        config.stealth_options = Some(stealth);
        config
    }



    fn generate_decoy_addresses(&self, count: usize) -> Vec<std::net::IpAddr> {
        let mut rng = rand::thread_rng();
        let mut decoys = Vec::new();
        
        for _ in 0..count {
            let ip = format!("192.168.{}.{}", 
                rng.gen_range(1..255), 
                rng.gen_range(1..255)
            );
            if let Ok(addr) = ip.parse() {
                decoys.push(addr);
            }
        }
        
        decoys
    }

    /// Get a description of the current mode configuration
    pub fn get_mode_description(&self) -> String {
        let mut desc = format!("Fear Level: {:?}", self.fear_level);
        

        if self.wrath.is_some() {
            desc.push_str(" | Wrath: UNLEASHED");
        }
        if self.shadow.is_some() {
            desc.push_str(" | Shadow: ENGAGED");
        }

        
        desc
    }
}

impl Default for PhobosModeManager {
    fn default() -> Self {
        Self::new(FearLevel::Normal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fear_levels() {
        assert_eq!(FearLevel::from(1), FearLevel::Normal);
        assert_eq!(FearLevel::from(5), FearLevel::Normal);
        assert_eq!(FearLevel::from(99), FearLevel::Normal); // Always Normal
    }

    #[test]
    fn test_mode_combinations() {
        let mut manager = PhobosModeManager::new(FearLevel::Normal);
        manager.enable_wrath()
               .enable_shadow();
        
        let desc = manager.get_mode_description();
        assert!(desc.contains("Wrath"));
        assert!(desc.contains("Shadow"));
    }
}