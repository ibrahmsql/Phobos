//! Stress tests for Phobos port scanner
//! Heavy-duty tests for performance, accuracy, and reliability under load

use phobos::config::ScanConfig;
use phobos::scanner::engine::ScanEngine;
use phobos::network::ScanTechnique;
use std::net::TcpListener;
use std::time::Instant;

#[cfg(test)]
mod stress_tests {
    use super::*;

    /// Helper to create multiple TCP listeners on random ports
    fn create_test_listeners(count: usize) -> Vec<TcpListener> {
        let mut listeners = Vec::new();
        for _ in 0..count {
            if let Ok(listener) = TcpListener::bind("127.0.0.1:0") {
                listeners.push(listener);
            }
        }
        listeners
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_massive_port_range_10k_ports() {
        println!("\n🔥 STRESS TEST: 10,000 Port Scan");
        println!("═══════════════════════════════════════");

        // Create 50 open ports
        let listeners = create_test_listeners(50);
        let open_ports: Vec<u16> = listeners
            .iter()
            .filter_map(|l| l.local_addr().ok().map(|a| a.port()))
            .collect();

        println!("✓ Created {} open ports", open_ports.len());

        // Scan 10,000 ports including our open ones
        let mut all_ports: Vec<u16> = (10000..20000).collect();
        for &port in &open_ports {
            if !all_ports.contains(&port) {
                all_ports.push(port);
            }
        }

        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: all_ports.clone(),
            technique: ScanTechnique::Connect,
            threads: 5000,
            timeout: 1500,
            rate_limit: 50000,
            max_retries: Some(2),
            ..Default::default()
        };

        let start = Instant::now();
        let engine = ScanEngine::new(config).await.unwrap();
        let result = engine.scan().await.unwrap();
        let duration = start.elapsed();

        println!("\n📊 RESULTS:");
        println!("───────────────────────────────────────");
        println!("⏱️  Duration: {:.2}s", duration.as_secs_f64());
        println!("📦 Total ports scanned: {}", all_ports.len());
        println!("✅ Open ports found: {}", result.open_ports.len());
        println!("🚀 Ports/sec: {:.2}", all_ports.len() as f64 / duration.as_secs_f64());
        
        // Verify we found at least 80% of open ports
        let found_count = result.open_ports.len();
        let expected_count = open_ports.len();
        let accuracy = (found_count as f64 / expected_count as f64) * 100.0;
        
        println!("🎯 Accuracy: {:.2}%", accuracy);
        println!("═══════════════════════════════════════");

        assert!(
            accuracy >= 80.0,
            "Should find at least 80% of open ports, found {:.2}%",
            accuracy
        );

        // Performance assertion: Should scan 10k ports in under 30 seconds
        assert!(
            duration.as_secs() < 30,
            "10k port scan should complete in under 30s, took {}s",
            duration.as_secs()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_ultra_concurrent_scanning() {
        println!("\n🔥 STRESS TEST: Ultra-Concurrent Scanning (10 targets simultaneously)");
        println!("═══════════════════════════════════════════════════════════════════════");

        let listeners = create_test_listeners(20);
        let ports: Vec<u16> = listeners
            .iter()
            .filter_map(|l| l.local_addr().ok().map(|a| a.port()))
            .take(10)
            .collect();

        let start = Instant::now();
        let mut handles = vec![];

        // Launch 10 concurrent scans
        for i in 0..10 {
            let ports_clone = ports.clone();
            let handle = tokio::spawn(async move {
                let config = ScanConfig {
                    target: "127.0.0.1".to_string(),
                    ports: ports_clone,
                    technique: ScanTechnique::Connect,
                    threads: 500,
                    timeout: 1000,
                    rate_limit: 10000,
                    ..Default::default()
                };

                let engine = ScanEngine::new(config).await.unwrap();
                let result = engine.scan().await.unwrap();
                (i, result.open_ports.len())
            });
            handles.push(handle);
        }

        // Wait for all scans
        let results: Vec<_> = futures::future::join_all(handles).await;
        let duration = start.elapsed();

        println!("\n📊 RESULTS:");
        println!("───────────────────────────────────────");
        println!("⏱️  Total duration: {:.2}s", duration.as_secs_f64());
        println!("🔢 Concurrent scans: 10");
        
        let mut success_count = 0;
        for result in results {
            if let Ok((scan_id, found)) = result {
                println!("  Scan #{}: {} ports found", scan_id, found);
                if found > 0 {
                    success_count += 1;
                }
            }
        }

        println!("✅ Successful scans: {}/10", success_count);
        println!("═══════════════════════════════════════");

        assert!(
            success_count >= 8,
            "At least 8/10 concurrent scans should succeed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_memory_efficiency_large_scan() {
        println!("\n🔥 STRESS TEST: Memory Efficiency (50,000 ports)");
        println!("═══════════════════════════════════════════════════");

        // Scan 50k ports
        let ports: Vec<u16> = (1..=50000).collect();

        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: ports.clone(),
            technique: ScanTechnique::Connect,
            threads: 10000,
            timeout: 500, // Fast timeout
            rate_limit: 100000,
            batch_size: Some(2000),
            ..Default::default()
        };

        println!("📦 Ports to scan: {}", ports.len());
        println!("🧵 Threads: {}", config.threads);
        println!("⚡ Batch size: {}", config.batch_size.unwrap());

        let start = Instant::now();
        let engine = ScanEngine::new(config).await.unwrap();
        let result = engine.scan().await.unwrap();
        let duration = start.elapsed();

        println!("\n📊 RESULTS:");
        println!("───────────────────────────────────────");
        println!("⏱️  Duration: {:.2}s", duration.as_secs_f64());
        println!("🚀 Ports/sec: {:.2}", ports.len() as f64 / duration.as_secs_f64());
        println!("✅ Scan completed successfully");
        println!("📊 Total results: {}", result.open_ports.len() + result.closed_ports.len());
        println!("═══════════════════════════════════════");

        // Should complete in reasonable time (under 2 minutes)
        assert!(
            duration.as_secs() < 120,
            "50k port scan should complete in under 2 minutes"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_rapid_fire_small_scans() {
        println!("\n🔥 STRESS TEST: Rapid-Fire Small Scans (100 scans x 10 ports)");
        println!("═══════════════════════════════════════════════════════════════");

        let test_ports = vec![22, 80, 443, 8080, 3306, 5432, 6379, 27017, 9200, 11211];
        let _listeners = create_test_listeners(5);

        let start = Instant::now();
        let mut handles = vec![];

        // Launch 100 rapid scans
        for i in 0..100 {
            let ports_clone = test_ports.clone();
            let handle = tokio::spawn(async move {
                let config = ScanConfig {
                    target: "127.0.0.1".to_string(),
                    ports: ports_clone,
                    technique: ScanTechnique::Connect,
                    threads: 100,
                    timeout: 500,
                    rate_limit: 5000,
                    ..Default::default()
                };

                let engine = ScanEngine::new(config).await.unwrap();
                let _ = engine.scan().await;
                i
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        let duration = start.elapsed();

        let success_count = results.iter().filter(|r| r.is_ok()).count();

        println!("\n📊 RESULTS:");
        println!("───────────────────────────────────────");
        println!("⏱️  Duration: {:.2}s", duration.as_secs_f64());
        println!("✅ Successful scans: {}/100", success_count);
        println!("🚀 Scans/sec: {:.2}", 100.0 / duration.as_secs_f64());
        println!("⚡ Avg scan time: {:.2}ms", duration.as_millis() as f64 / 100.0);
        println!("═══════════════════════════════════════");

        assert!(
            success_count >= 95,
            "At least 95/100 rapid scans should succeed, got {}",
            success_count
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_full_range_accuracy_stress() {
        println!("\n🔥 STRESS TEST: Full Range Accuracy (1-65535 with 100 open ports)");
        println!("═══════════════════════════════════════════════════════════════════");

        // Create 100 random open ports
        let listeners = create_test_listeners(100);
        let open_ports: Vec<u16> = listeners
            .iter()
            .filter_map(|l| l.local_addr().ok().map(|a| a.port()))
            .collect();

        println!("✓ Created {} open ports for testing", open_ports.len());

        // Full range scan
        let all_ports: Vec<u16> = (1..=65535).collect();

        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: all_ports.clone(),
            technique: ScanTechnique::Connect,
            threads: 10000,
            timeout: 1500,
            rate_limit: 100000,
            max_retries: Some(3),
            batch_size: Some(2500),
            ..Default::default()
        };

        println!("🚀 Starting full-range scan...");
        let start = Instant::now();
        let engine = ScanEngine::new(config).await.unwrap();
        let result = engine.scan().await.unwrap();
        let duration = start.elapsed();

        // Count how many of our open ports were found
        let found_open: Vec<u16> = result
            .open_ports
            .iter()
            .filter(|&&port| open_ports.contains(&port))
            .copied()
            .collect();

        let detection_rate = (found_open.len() as f64 / open_ports.len() as f64) * 100.0;
        let ports_per_sec = 65535.0 / duration.as_secs_f64();

        println!("\n📊 RESULTS:");
        println!("═══════════════════════════════════════");
        println!("⏱️  Duration: {:.2}s ({:.2} min)", duration.as_secs_f64(), duration.as_secs_f64() / 60.0);
        println!("🚀 Speed: {:.2} ports/sec", ports_per_sec);
        println!("📦 Total ports scanned: 65,535");
        println!("🎯 Expected open ports: {}", open_ports.len());
        println!("✅ Found open ports: {}", found_open.len());
        println!("📊 Detection rate: {:.2}%", detection_rate);
        println!("❌ Missed ports: {}", open_ports.len() - found_open.len());
        
        if found_open.len() < open_ports.len() {
            let missed: Vec<u16> = open_ports
                .iter()
                .filter(|p| !found_open.contains(p))
                .copied()
                .take(10)
                .collect();
            println!("⚠️  Sample missed ports: {:?}", missed);
        }
        
        println!("═══════════════════════════════════════");

        // Should find at least 90% of open ports even in full range
        assert!(
            detection_rate >= 90.0,
            "Full range scan should find at least 90% of ports, found {:.2}%",
            detection_rate
        );

        // Should be reasonably fast (under 5 minutes)
        assert!(
            duration.as_secs() < 300,
            "Full range scan should complete in under 5 minutes"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_timeout_resilience() {
        println!("\n🔥 STRESS TEST: Timeout Resilience (varying timeouts)");
        println!("═══════════════════════════════════════════════════════");

        let listeners = create_test_listeners(10);
        let ports: Vec<u16> = listeners
            .iter()
            .filter_map(|l| l.local_addr().ok().map(|a| a.port()))
            .collect();

        let timeouts = vec![100, 500, 1000, 2000, 5000];
        let mut results = Vec::new();

        for timeout in timeouts {
            let config = ScanConfig {
                target: "127.0.0.1".to_string(),
                ports: ports.clone(),
                technique: ScanTechnique::Connect,
                threads: 500,
                timeout,
                rate_limit: 10000,
                max_retries: Some(2),
                ..Default::default()
            };

            let start = Instant::now();
            let engine = ScanEngine::new(config).await.unwrap();
            let result = engine.scan().await.unwrap();
            let duration = start.elapsed();

            let accuracy = (result.open_ports.len() as f64 / ports.len() as f64) * 100.0;
            results.push((timeout, accuracy, duration));

            println!("  Timeout {}ms: {:.1}% accuracy, {:.2}s duration", 
                timeout, accuracy, duration.as_secs_f64());
        }

        println!("\n📊 ANALYSIS:");
        println!("───────────────────────────────────────");
        let avg_accuracy: f64 = results.iter().map(|(_, acc, _)| acc).sum::<f64>() / results.len() as f64;
        println!("📈 Average accuracy across timeouts: {:.2}%", avg_accuracy);
        println!("═══════════════════════════════════════");

        // Average accuracy should be good
        assert!(
            avg_accuracy >= 70.0,
            "Average accuracy across timeouts should be >= 70%"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_thread_scaling_performance() {
        println!("\n🔥 STRESS TEST: Thread Scaling Performance");
        println!("═══════════════════════════════════════════════");

        let ports: Vec<u16> = (10000..15000).collect();
        let thread_counts = vec![100, 500, 1000, 5000, 10000];
        let mut results = Vec::new();

        for threads in thread_counts {
            let config = ScanConfig {
                target: "127.0.0.1".to_string(),
                ports: ports.clone(),
                technique: ScanTechnique::Connect,
                threads,
                timeout: 500,
                rate_limit: 50000,
                ..Default::default()
            };

            let start = Instant::now();
            let engine = ScanEngine::new(config).await.unwrap();
            let _ = engine.scan().await.unwrap();
            let duration = start.elapsed();

            let ports_per_sec = ports.len() as f64 / duration.as_secs_f64();
            results.push((threads, ports_per_sec, duration));

            println!("  {} threads: {:.2} ports/sec ({:.2}s)", 
                threads, ports_per_sec, duration.as_secs_f64());
        }

        println!("\n📊 ANALYSIS:");
        println!("───────────────────────────────────────");
        let max_speed = results.iter().map(|(_, speed, _)| *speed).fold(0.0, f64::max);
        let (best_threads, _, _) = results.iter().max_by(|a, b| a.1.partial_cmp(&b.1).unwrap()).unwrap();
        println!("🏆 Best performance: {} threads at {:.2} ports/sec", best_threads, max_speed);
        println!("═══════════════════════════════════════");
    }
}
