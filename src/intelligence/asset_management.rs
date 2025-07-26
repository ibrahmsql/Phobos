//! Asset management and classification system
//! Intelligent device classification and risk assessment

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::core::IntelligenceResult;
use super::network_discovery::DeviceType;
use super::performance::MemoryPool;
use super::service_detection::ServiceInfo;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
pub struct AssetId(Uuid);

impl AssetId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: AssetId,
    pub ip_address: IpAddr,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub device_type: DeviceType,
    pub operating_system: Option<OSInfo>,
    pub services: Vec<ServiceInfo>,
    pub risk_score: RiskScore,
    pub last_seen: DateTime<Utc>,
    pub first_discovered: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSInfo {
    pub name: String,
    pub version: String,
    pub architecture: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskScore {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetUpdates {
    pub hostname: Option<String>,
    pub device_type: Option<DeviceType>,
    pub operating_system: Option<OSInfo>,
    pub services: Option<Vec<ServiceInfo>>,
    pub risk_score: Option<RiskScore>,
}

impl AssetUpdates {
    pub fn from_asset(asset: &Asset) -> Self {
        Self {
            hostname: asset.hostname.clone(),
            device_type: Some(asset.device_type.clone()),
            operating_system: asset.operating_system.clone(),
            services: Some(asset.services.clone()),
            risk_score: Some(asset.risk_score.clone()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetQuery {
    pub ip_address: Option<IpAddr>,
    pub hostname: Option<String>,
    pub device_type: Option<DeviceType>,
    pub risk_score: Option<RiskScore>,
}

pub struct AssetManager {
    assets: HashMap<AssetId, Asset>,
    #[allow(dead_code)]
    memory_pool: Arc<MemoryPool>,
}

impl AssetManager {
    pub async fn new(memory_pool: Arc<MemoryPool>) -> IntelligenceResult<Self> {
        Ok(Self {
            assets: HashMap::new(),
            memory_pool,
        })
    }
}

#[allow(async_fn_in_trait)]
pub trait AssetManagement {
    async fn add_asset(&mut self, asset: Asset) -> IntelligenceResult<AssetId>;
    async fn update_asset(&mut self, id: AssetId, updates: AssetUpdates) -> IntelligenceResult<()>;
    async fn classify_asset(&self, asset: &Asset) -> IntelligenceResult<Asset>;
    async fn assess_risk(&self, asset: &Asset) -> RiskScore;
    async fn search_assets(&self, query: AssetQuery) -> Vec<Asset>;
}

impl AssetManagement for AssetManager {
    async fn add_asset(&mut self, asset: Asset) -> IntelligenceResult<AssetId> {
        let id = asset.id.clone();
        self.assets.insert(id.clone(), asset);
        Ok(id)
    }
    
    async fn update_asset(&mut self, id: AssetId, updates: AssetUpdates) -> IntelligenceResult<()> {
        if let Some(asset) = self.assets.get_mut(&id) {
            if let Some(hostname) = updates.hostname {
                asset.hostname = Some(hostname);
            }
            if let Some(device_type) = updates.device_type {
                asset.device_type = device_type;
            }
            if let Some(os) = updates.operating_system {
                asset.operating_system = Some(os);
            }
            if let Some(services) = updates.services {
                asset.services = services;
            }
            if let Some(risk_score) = updates.risk_score {
                asset.risk_score = risk_score;
            }
            asset.last_seen = Utc::now();
        }
        Ok(())
    }
    
    async fn classify_asset(&self, asset: &Asset) -> IntelligenceResult<Asset> {
        let mut classified_asset = asset.clone();
        
        // If device type is already set and not Unknown, keep it
        if classified_asset.device_type != DeviceType::Unknown {
            classified_asset.risk_score = self.assess_risk(&classified_asset).await;
            return Ok(classified_asset);
        }
        
        // Simple classification based on services
        classified_asset.device_type = if asset.services.iter().any(|s| s.port == 22 || s.port == 80 || s.port == 443) {
            DeviceType::Server
        } else if asset.services.iter().any(|s| s.port == 135 || s.port == 445) {
            DeviceType::Workstation
        } else if asset.services.iter().any(|s| s.port == 161 || s.port == 23) {
            DeviceType::NetworkDevice
        } else {
            DeviceType::Unknown
        };
        
        classified_asset.risk_score = self.assess_risk(&classified_asset).await;
        
        Ok(classified_asset)
    }
    
    async fn assess_risk(&self, asset: &Asset) -> RiskScore {
        let mut risk_factors = 0;
        
        // Check for high-risk services
        for service in &asset.services {
            match service.port {
                21 | 23 | 135 | 139 | 445 => risk_factors += 2, // High-risk ports
                22 | 80 | 443 => risk_factors += 1, // Medium-risk ports
                _ => {}
            }
            
            // Check for vulnerabilities
            if !service.vulnerabilities.is_empty() {
                risk_factors += service.vulnerabilities.len() * 3;
            }
        }
        
        match risk_factors {
            0..=2 => RiskScore::Low,
            3..=5 => RiskScore::Medium,
            6..=10 => RiskScore::High,
            _ => RiskScore::Critical,
        }
    }
    
    async fn search_assets(&self, query: AssetQuery) -> Vec<Asset> {
        self.assets.values()
            .filter(|asset| {
                if let Some(ip) = query.ip_address {
                    if asset.ip_address != ip {
                        return false;
                    }
                }
                if let Some(hostname) = &query.hostname {
                    if asset.hostname.as_ref() != Some(hostname) {
                        return false;
                    }
                }
                if let Some(device_type) = &query.device_type {
                    if &asset.device_type != device_type {
                        return false;
                    }
                }
                if let Some(risk_score) = &query.risk_score {
                    if &asset.risk_score != risk_score {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }
}

pub struct DeviceClassifier;
pub struct RiskAssessor;