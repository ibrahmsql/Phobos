//! Scan profile management system

use crate::config::ScanConfig;
use crate::network::{ScanTechnique, stealth::StealthOptions};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use colored::*;

/// Predefined scan profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProfile {
    pub name: String,
    pub description: String,
    pub technique: ScanTechnique,
    pub threads: usize,
    pub timeout: u64,
    pub rate_limit: u64,
    pub timing_template: u8,
    pub stealth_level: u8,
    pub max_retries: u32,
    pub batch_size: Option<usize>,
    pub adaptive: bool,
    pub source_port: Option<u16>,
    pub interface: Option<String>,
}

impl ScanProfile {
    /// Apply profile to scan configuration
    pub fn apply_to_config(&self, mut config: ScanConfig) -> ScanConfig {
        config.technique = self.technique;
        config.threads = self.threads;
        config.timeout = self.timeout;
        config.rate_limit = self.rate_limit;
        config.timing_template = self.timing_template;
        
        // Apply stealth options
        let mut stealth_options = config.stealth_options.unwrap_or_default();
        stealth_options.randomize_source_port = self.stealth_level >= 2;
        stealth_options.fragment_packets = self.stealth_level >= 3;
        stealth_options.decoy_addresses = if self.stealth_level >= 4 {
            vec!["192.168.1.1".parse().unwrap(), "10.0.0.1".parse().unwrap()]
        } else {
            vec![]
        };
        stealth_options.spoof_source_ip = if self.stealth_level >= 5 {
            Some("192.168.1.100".parse().unwrap())
        } else {
            None
        };
        config.stealth_options = Some(stealth_options);
        
        // Apply other settings
        if let Some(batch_size) = self.batch_size {
            config.batch_size = Some(batch_size);
        }
        
        config.adaptive_learning = self.adaptive;
        
        config
    }
}

/// Profile manager for handling scan profiles
pub struct ProfileManager {
    profiles_dir: PathBuf,
    profiles: HashMap<String, ScanProfile>,
}

impl ProfileManager {
    /// Create a new profile manager
    pub fn new() -> crate::Result<Self> {
        let profiles_dir = Self::get_profiles_dir()?;
        
        // Create profiles directory if it doesn't exist
        if !profiles_dir.exists() {
            fs::create_dir_all(&profiles_dir)
                .map_err(|e| crate::ScanError::NetworkError(format!("Failed to create profiles directory: {}", e)))?;
        }
        
        let mut manager = Self {
            profiles_dir,
            profiles: HashMap::new(),
        };
        
        // Load built-in profiles
        manager.load_builtin_profiles();
        
        // Load user profiles
        manager.load_user_profiles()?;
        
        Ok(manager)
    }
    
    /// Get profiles directory path
    fn get_profiles_dir() -> crate::Result<PathBuf> {
        let home_dir = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| crate::ScanError::NetworkError("Cannot determine home directory".to_string()))?;
        
        Ok(Path::new(&home_dir).join(".phobos").join("profiles"))
    }
    
    /// Load built-in profiles
    fn load_builtin_profiles(&mut self) {
        // Quick profile - fast scanning with minimal accuracy
        self.profiles.insert("quick".to_string(), ScanProfile {
            name: "quick".to_string(),
            description: "Fast scanning with minimal accuracy - good for quick reconnaissance".to_string(),
            technique: ScanTechnique::Connect,
            threads: 2000,
            timeout: 500,
            rate_limit: 50_000_000,
            timing_template: 5, // Insane timing
            stealth_level: 0,
            max_retries: 1,
            batch_size: Some(10000),
            adaptive: false,
            source_port: None,
            interface: None,
        });
        
        // Stealth profile - slow but undetectable
        self.profiles.insert("stealth".to_string(), ScanProfile {
            name: "stealth".to_string(),
            description: "Slow and stealthy scanning to avoid detection".to_string(),
            technique: ScanTechnique::Syn,
            threads: 10,
            timeout: 10000,
            rate_limit: 100,
            timing_template: 0, // Paranoid timing
            stealth_level: 5,
            max_retries: 5,
            batch_size: Some(10),
            adaptive: true,
            source_port: None,
            interface: None,
        });
        
        // Aggressive profile - maximum speed and accuracy
        self.profiles.insert("aggressive".to_string(), ScanProfile {
            name: "aggressive".to_string(),
            description: "Maximum speed scanning with high resource usage".to_string(),
            technique: ScanTechnique::Syn,
            threads: 5000,
            timeout: 1000,
            rate_limit: 100_000_000,
            timing_template: 4, // Aggressive timing
            stealth_level: 0,
            max_retries: 2,
            batch_size: Some(20000),
            adaptive: true,
            source_port: None,
            interface: None,
        });
        
        // Comprehensive profile - thorough scanning
        self.profiles.insert("comprehensive".to_string(), ScanProfile {
            name: "comprehensive".to_string(),
            description: "Thorough scanning with multiple techniques and high accuracy".to_string(),
            technique: ScanTechnique::Syn,
            threads: 1000,
            timeout: 5000,
            rate_limit: 10_000_000,
            timing_template: 3, // Normal timing
            stealth_level: 2,
            max_retries: 3,
            batch_size: Some(5000),
            adaptive: true,
            source_port: None,
            interface: None,
        });
    }
    
    /// Load user-defined profiles from disk
    fn load_user_profiles(&mut self) -> crate::Result<()> {
        if !self.profiles_dir.exists() {
            return Ok(());
        }
        
        let entries = fs::read_dir(&self.profiles_dir)
            .map_err(|e| crate::ScanError::NetworkError(format!("Failed to read profiles directory: {}", e)))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| crate::ScanError::NetworkError(e.to_string()))?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                if let Ok(profile) = self.load_profile_from_file(&path) {
                    self.profiles.insert(profile.name.clone(), profile);
                }
            }
        }
        
        Ok(())
    }
    
    /// Load a single profile from file
    fn load_profile_from_file(&self, path: &Path) -> crate::Result<ScanProfile> {
        let content = fs::read_to_string(path)
            .map_err(|e| crate::ScanError::NetworkError(format!("Failed to read profile file: {}", e)))?;
        
        toml::from_str(&content)
            .map_err(|e| crate::ScanError::InvalidTarget(format!("Invalid profile format: {}", e)))
    }
    
    /// Save a profile to disk
    pub fn save_profile(&self, profile: &ScanProfile) -> crate::Result<()> {
        let filename = format!("{}.toml", profile.name);
        let path = self.profiles_dir.join(filename);
        
        let content = toml::to_string_pretty(profile)
            .map_err(|e| crate::ScanError::InvalidTarget(format!("Failed to serialize profile: {}", e)))?;
        
        fs::write(&path, content)
            .map_err(|e| crate::ScanError::NetworkError(format!("Failed to save profile: {}", e)))?;
        
        println!("{} {}", 
            "[✓] Profile saved:".bright_green().bold(),
            path.display().to_string().bright_cyan()
        );
        
        Ok(())
    }
    
    /// Get a profile by name
    pub fn get_profile(&self, name: &str) -> Option<&ScanProfile> {
        self.profiles.get(name)
    }
    
    /// Load a profile and convert it to ScanConfig
    pub fn load_profile(&self, name: &str) -> crate::Result<ScanConfig> {
        let profile = self.get_profile(name)
            .ok_or_else(|| crate::ScanError::InvalidTarget(format!("Profile '{}' not found", name)))?;
        
        let base_config = ScanConfig::default();
        Ok(profile.apply_to_config(base_config))
    }
    
    /// List all available profiles
    pub fn list_profiles(&self) {
        println!("{}", "Available Scan Profiles:".bright_yellow().bold());
        println!();
        
        // Sort profiles by name
        let mut profiles: Vec<_> = self.profiles.values().collect();
        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        
        for profile in profiles {
            let profile_type = if ["quick", "stealth", "aggressive", "comprehensive"].contains(&profile.name.as_str()) {
                "[Built-in]".bright_blue()
            } else {
                "[User]".bright_green()
            };
            
            println!("{} {} {}", 
                profile_type,
                profile.name.bright_white().bold(),
                format!("- {}", profile.description).bright_cyan()
            );
            
            println!("    {} {} {} {} {} {}",
                format!("Technique: {}", format!("{:?}", profile.technique)).bright_yellow(),
                format!("Threads: {}", profile.threads).bright_magenta(),
                format!("Timeout: {}ms", profile.timeout).bright_blue(),
                format!("Timing: T{}", profile.timing_template).bright_green(),
                format!("Stealth: {}", profile.stealth_level).bright_red(),
                if profile.adaptive { "Adaptive".bright_cyan() } else { "Static".bright_white() }
            );
            println!();
        }
    }
    
    /// Create profile from current scan configuration
    pub fn create_profile_from_config(&self, name: String, description: String, config: &ScanConfig) -> ScanProfile {
        let default_stealth = StealthOptions::default();
        let stealth_options = config.stealth_options.as_ref().unwrap_or(&default_stealth);
        
        let stealth_level = if stealth_options.spoof_source_ip.is_some() {
            5
        } else if !stealth_options.decoy_addresses.is_empty() {
            4
        } else if stealth_options.fragment_packets {
            3
        } else if stealth_options.randomize_source_port {
            2
        } else if stealth_options.timing_randomization {
            1
        } else {
            0
        };
        
        ScanProfile {
            name,
            description,
            technique: config.technique,
            threads: config.threads,
            timeout: config.timeout,
            rate_limit: config.rate_limit,
            timing_template: config.timing_template,
            stealth_level,
            max_retries: 3, // Default value
            batch_size: config.batch_size,
            adaptive: config.adaptive_learning,
            source_port: None, // Not stored in ScanConfig currently
            interface: None,   // Not stored in ScanConfig currently
        }
    }
    
    /// Delete a user profile
    pub fn delete_profile(&mut self, name: &str) -> crate::Result<()> {
        // Don't allow deletion of built-in profiles
        if ["quick", "stealth", "aggressive", "comprehensive"].contains(&name) {
            return Err(crate::ScanError::InvalidTarget("Cannot delete built-in profiles".to_string()));
        }
        
        if self.profiles.remove(name).is_some() {
            let filename = format!("{}.toml", name);
            let path = self.profiles_dir.join(filename);
            
            if path.exists() {
                fs::remove_file(&path)
                    .map_err(|e| crate::ScanError::NetworkError(format!("Failed to delete profile file: {}", e)))?;
            }
            
            println!("{} {}", 
                "[✓] Profile deleted:".bright_green().bold(),
                name.bright_cyan()
            );
        } else {
            return Err(crate::ScanError::InvalidTarget(format!("Profile '{}' not found", name)));
        }
        
        Ok(())
    }
}

impl Default for ProfileManager {
    fn default() -> Self {
        Self::new().expect("Failed to create profile manager")
    }
}