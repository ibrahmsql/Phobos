//! Tests for the Network Intelligence System
//! Validates ultra-fast performance targets

#[cfg(test)]
mod tests {
    use crate::intelligence::*;
    use crate::intelligence::core::*;
    use crate::intelligence::performance::*;
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_intelligence_engine_creation() {
        let config = IntelligenceConfig::default();
        let engine = IntelligenceEngine::new(config).await;
        assert!(engine.is_ok(), "Intelligence engine should be created successfully");
    }
    
    #[tokio::test]
    async fn test_performance_targets() {
        let config = PerformanceConfig::default();
        
        // Verify our performance targets are ambitious
        assert_eq!(config.nmap_speed_multiplier, 10.0, "Should be 10x faster than Nmap");
        assert_eq!(config.rustscan_speed_multiplier, 3.0, "Should be 3x faster than RustScan");
        assert_eq!(config.masscan_memory_divisor, 5.0, "Should use 5x less memory than Masscan");
        
        assert!(config.enable_zero_copy, "Zero-copy optimizations should be enabled");
        assert!(config.enable_memory_pooling, "Memory pooling should be enabled");
        assert!(config.enable_simd, "SIMD optimizations should be enabled");
    }
    
    #[tokio::test]
    async fn test_memory_pool_performance() {
        let pool = MemoryPool::new(1024 * 1024, true); // 1MB pool
        
        let start = std::time::Instant::now();
        
        // Allocate and deallocate many buffers to test performance
        for _ in 0..1000 {
            if let Some(buffer) = pool.get_buffer(256) {
                pool.return_buffer(buffer);
            }
        }
        
        let duration = start.elapsed();
        
        // Should be very fast (under 1ms for 1000 allocations)
        assert!(duration < Duration::from_millis(1), 
                "Memory pool should be ultra-fast: {:?}", duration);
    }
    
    #[tokio::test]
    async fn test_thread_pool_performance() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        
        let memory_pool = Arc::new(MemoryPool::new(1024, true));
        let thread_pool = UltraFastThreadPool::new(4, memory_pool);
        
        let counter = Arc::new(AtomicUsize::new(0));
        let start = std::time::Instant::now();
        
        // Execute many tasks to test throughput
        for _ in 0..1000 {
            let counter_clone = counter.clone();
            thread_pool.execute(move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
            }).await;
        }
        
        // Wait for tasks to complete
        while counter.load(Ordering::Relaxed) < 1000 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        
        let duration = start.elapsed();
        
        // Should complete 1000 tasks very quickly
        assert!(duration < Duration::from_millis(100), 
                "Thread pool should be ultra-fast: {:?}", duration);
        assert_eq!(counter.load(Ordering::Relaxed), 1000);
    }
    
    #[tokio::test]
    async fn test_service_detection_stub() {
        use std::net::SocketAddr;
        use std::sync::Arc;
        
        let memory_pool = Arc::new(MemoryPool::new(1024, true));
        let thread_pool = Arc::new(UltraFastThreadPool::new(2, memory_pool.clone()));
        
        let detector = ServiceDetectionEngine::new(
            Duration::from_millis(100),
            thread_pool,
            memory_pool,
        ).await.unwrap();
        
        let target: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let result = detector.detect_service(target).await;
        
        assert!(result.is_ok(), "Service detection should work");
        let service_info = result.unwrap();
        assert_eq!(service_info.port, 80);
        assert_eq!(service_info.protocol, "tcp");
    }
    
    #[test]
    fn test_simd_optimizations() {
        let data1 = b"Hello, World!";
        
        let checksum = SIMDOptimizations::fast_checksum(data1);
        assert!(checksum > 0, "Checksum should be calculated");
    }
    
    #[tokio::test]
    async fn test_asset_management_stub() {
        use std::net::IpAddr;
        use std::sync::Arc;
        
        let memory_pool = Arc::new(MemoryPool::new(1024, true));
        let mut asset_manager = AssetManager::new(memory_pool).await.unwrap();
        
        let asset = Asset {
            id: AssetId::new(),
            ip_address: "192.168.1.100".parse::<IpAddr>().unwrap(),
            mac_address: None,
            hostname: Some("test-host".to_string()),
            device_type: DeviceType::Server,
            operating_system: None,
            services: Vec::new(),
            risk_score: RiskScore::Low,
            last_seen: chrono::Utc::now(),
            first_discovered: chrono::Utc::now(),
        };
        
        let asset_id = asset_manager.add_asset(asset.clone()).await.unwrap();
        assert_eq!(asset_id, asset.id);
        
        let classified = asset_manager.classify_asset(&asset).await.unwrap();
        // Since we don't have services, it should remain as Server (as we set it)
        assert_eq!(classified.device_type, DeviceType::Server);
    }
}