//! Performance benchmarks for the phobos scanner

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;
use tokio::runtime::Runtime;
use phobos::{
    config::ScanConfig,
    network::{ScanTechnique, packet::TcpPacketBuilder},
    scanner::engine::ScanEngine,
    utils::timing::AdaptiveTimer,
};

/// Benchmark packet crafting performance
fn bench_packet_crafting(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_crafting");
    
    // TCP packet crafting
    group.bench_function("tcp_syn_packet", |b| {
        b.iter(|| {
            let builder = TcpPacketBuilder::new(
                black_box("192.168.1.1".parse().unwrap()),
                black_box("192.168.1.100".parse().unwrap()),
                black_box(12345),
                black_box(80),
            );
            
            let packet = builder
                .syn()
                .sequence_number(black_box(0x12345678))
                .window_size(black_box(65535))
                .build();
            
            black_box(packet)
        })
    });
    
    // Batch packet crafting
    group.bench_function("tcp_batch_1000", |b| {
        b.iter(|| {
            let src_ip = "192.168.1.1".parse().unwrap();
            let dst_ip = "192.168.1.100".parse().unwrap();
            
            for port in black_box(1..=1000) {
                let builder = TcpPacketBuilder::new(src_ip, dst_ip, 12345, port);
                let packet = builder
                    .syn()
                    .sequence_number(0x12345678)
                    .window_size(65535)
                    .build();
                black_box(packet);
            }
        })
    });
    
    group.finish();
}

/// Benchmark port parsing performance
fn bench_port_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("port_parsing");
    
    group.bench_function("parse_range_1-65535", |b| {
        b.iter(|| {
            phobos::utils::parse_ports(black_box("1-65535"))
        })
    });
    
    group.bench_function("parse_list_common_ports", |b| {
        b.iter(|| {
            phobos::utils::parse_ports(black_box("21,22,23,25,53,80,110,111,135,139,143,443,993,995"))
        })
    });
    
    group.bench_function("parse_mixed_complex", |b| {
        b.iter(|| {
            phobos::utils::parse_ports(black_box("1-100,443,8000-8100,9000,9443"))
        })
    });
    
    group.finish();
}

/// Benchmark timing algorithms
fn bench_timing(c: &mut Criterion) {
    let mut group = c.benchmark_group("timing");
    
    group.bench_function("adaptive_timer_update", |b| {
        let mut timer = AdaptiveTimer::new(1000.0);
        b.iter(|| {
            timer.record_response(black_box(Duration::from_millis(10)));
        })
    });
    
    group.bench_function("rate_limiter_acquire", |b| {
        let mut rate_limiter = phobos::network::protocol::RateLimiter::new(1_000_000);
        b.iter(|| {
            rate_limiter.acquire(black_box(1))
        })
    });
    
    group.finish();
}

/// Benchmark concurrent scanning
fn bench_concurrent_scan(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("concurrent_scan");
    group.sample_size(10); // Reduce sample size for expensive operations
    
    for thread_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("connect_scan", thread_count),
            thread_count,
            |b, &thread_count| {
                b.to_async(&rt).iter(|| async {
                    let config = ScanConfig {
                        target: "127.0.0.1".to_string(),
                        ports: (1..=100).collect(),
                        technique: ScanTechnique::ConnectScan,
                        threads: thread_count,
                        timeout: 100,
                        rate_limit: 10000,
                    };
                    
                    let engine = ScanEngine::new(config).await.unwrap();
                    let result = engine.scan().await;
                    black_box(result)
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_memory_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_patterns");
    
    group.bench_function("vec_allocation_1000", |b| {
        b.iter(|| {
            let mut vec = Vec::new();
            for i in 0..1000 {
                vec.push(black_box(i));
            }
            black_box(vec)
        })
    });
    
    group.bench_function("vec_with_capacity_1000", |b| {
        b.iter(|| {
            let mut vec = Vec::with_capacity(1000);
            for i in 0..1000 {
                vec.push(black_box(i));
            }
            black_box(vec)
        })
    });
    
    group.bench_function("batch_processing_1000", |b| {
        b.iter(|| {
            let ports: Vec<u16> = (1..=1000).collect();
            let batches = phobos::scanner::create_batches(
                black_box(&ports),
                black_box(100)
            );
            black_box(batches)
        })
    });
    
    group.finish();
}

/// Benchmark network utilities
fn bench_network_utils(c: &mut Criterion) {
    let mut group = c.benchmark_group("network_utils");
    
    group.bench_function("cidr_parsing_24", |b| {
        b.iter(|| {
            phobos::network::protocol::NetworkUtils::parse_cidr(
                black_box("192.168.1.0/24")
            )
        })
    });
    
    group.bench_function("cidr_parsing_16", |b| {
        b.iter(|| {
            phobos::network::protocol::NetworkUtils::parse_cidr(
                black_box("192.168.0.0/16")
            )
        })
    });
    
    group.bench_function("random_port_generation", |b| {
        b.iter(|| {
            phobos::network::protocol::NetworkUtils::random_source_port()
        })
    });
    
    group.finish();
}

/// Benchmark service detection
fn bench_service_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("service_detection");
    
    let service_db = phobos::network::protocol::ServiceDatabase::new();
    
    group.bench_function("tcp_service_lookup", |b| {
        b.iter(|| {
            service_db.get_tcp_service(black_box(80))
        })
    });
    
    group.bench_function("udp_service_lookup", |b| {
        b.iter(|| {
            service_db.get_udp_service(black_box(53))
        })
    });
    
    group.bench_function("top_ports_tcp_1000", |b| {
        b.iter(|| {
            service_db.get_top_tcp_ports(black_box(1000))
        })
    });
    
    group.finish();
}

/// Full scan benchmark
fn bench_full_scan(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("full_scan");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    
    // Benchmark against localhost to avoid network dependencies
    group.bench_function("localhost_top_100_ports", |b| {
        b.to_async(&rt).iter(|| async {
            let service_db = phobos::network::protocol::ServiceDatabase::new();
            let top_ports = service_db.get_top_tcp_ports(100);
            
            let config = ScanConfig {
                target: "127.0.0.1".to_string(),
                ports: top_ports,
                technique: ScanTechnique::ConnectScan,
                threads: 100,
                timeout: 1000,
                rate_limit: 10000,
            };
            
            let engine = ScanEngine::new(config).await.unwrap();
            let result = engine.scan().await;
            black_box(result)
        })
    });
    
    group.finish();
}

/// Performance regression tests
fn bench_performance_targets(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("performance_targets");
    group.sample_size(10);
    
    // Target: 65K ports in 1 second
    group.bench_function("target_65k_ports_1sec", |b| {
        b.to_async(&rt).iter(|| async {
            let ports: Vec<u16> = (1..=65535).collect();
            
            let config = ScanConfig {
                target: "127.0.0.1".to_string(),
                ports,
                technique: ScanTechnique::ConnectScan,
                threads: 1000,
                timeout: 100,
                rate_limit: 100000,
            };
            
            let start = std::time::Instant::now();
            let engine = ScanEngine::new(config).await.unwrap();
            let result = engine.scan().await;
            let duration = start.elapsed();
            
            // Assert performance target
            assert!(duration <= Duration::from_secs(2), 
                "Scan took {:?}, target is 1-2 seconds", duration);
            
            black_box(result)
        })
    });
    
    group.finish();
}

/// Benchmark large scale scanning
fn benchmark_large_scan(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("large_scale_scan");
    group.sample_size(5);
    group.measurement_time(Duration::from_secs(60));
    
    group.bench_function("scan_65535_ports", |b| {
        b.to_async(&rt).iter(|| async {
            let ports: Vec<u16> = (1..=65535).collect();
            
            let config = ScanConfig {
                target: "127.0.0.1".to_string(),
                ports,
                technique: ScanTechnique::ConnectScan,
                threads: 1000,
                timeout: 50,
                rate_limit: 100000,
            };
            
            let engine = ScanEngine::new(config).await.unwrap();
            let result = engine.scan().await;
            black_box(result)
        })
    });
    
    group.bench_function("scan_10k_ports_optimized", |b| {
        b.to_async(&rt).iter(|| async {
            let ports: Vec<u16> = (1..=10000).collect();
            
            let config = ScanConfig {
                target: "127.0.0.1".to_string(),
                ports,
                technique: ScanTechnique::ConnectScan,
                threads: 500,
                timeout: 100,
                rate_limit: 50000,
            };
            
            let engine = ScanEngine::new(config).await.unwrap();
            let result = engine.scan().await;
            black_box(result)
        })
    });
    
    group.finish();
}

/// Benchmark network scanning
fn benchmark_network_scan(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("network_scan");
    group.sample_size(5);
    group.measurement_time(Duration::from_secs(45));
    
    group.bench_function("scan_network_24", |b| {
        b.to_async(&rt).iter(|| async {
            // Simulate /24 network scan (256 hosts)
            let mut scan_results = Vec::new();
            
            for host in 1..=10 { // Limited to 10 hosts for benchmark
                let target = format!("127.0.0.{}", host);
                let config = ScanConfig {
                    target,
                    ports: vec![22, 80, 443],
                    technique: ScanTechnique::ConnectScan,
                    threads: 10,
                    timeout: 1000,
                    rate_limit: 1000,
                };
                
                let engine = ScanEngine::new(config).await.unwrap();
                let result = engine.scan().await;
                scan_results.push(result);
            }
            
            black_box(scan_results)
        })
    });
    
    group.bench_function("scan_network_common_ports", |b| {
        b.to_async(&rt).iter(|| async {
            let common_ports = vec![21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995];
            
            let config = ScanConfig {
                target: "127.0.0.1".to_string(),
                ports: common_ports,
                technique: ScanTechnique::ConnectScan,
                threads: 50,
                timeout: 1000,
                rate_limit: 5000,
            };
            
            let engine = ScanEngine::new(config).await.unwrap();
            let result = engine.scan().await;
            black_box(result)
        })
    });
    
    group.finish();
}

/// Benchmark stealth scanning techniques
fn benchmark_stealth_scan(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("stealth_scan");
    group.sample_size(10);
    
    group.bench_function("stealth_fragmented_scan", |b| {
        b.to_async(&rt).iter(|| async {
            use phobos::network::stealth::StealthOptions;
            
            let mut config = ScanConfig {
                target: "127.0.0.1".to_string(),
                ports: vec![80, 443, 8080],
                technique: ScanTechnique::ConnectScan,
                threads: 10,
                timeout: 1000,
                rate_limit: 1000,
            };
            
            config.stealth_options = Some(StealthOptions {
                fragment_packets: true,
                randomize_source_port: true,
                spoof_source_ip: None,
                decoy_addresses: vec![],
                randomize_timing: true,
                packet_padding: Some(64),
                custom_mtu: Some(1500),
                randomize_ip_id: true,
                randomize_sequence: true,
                bad_checksum: false,
            });
            
            let engine = ScanEngine::new(config).await.unwrap();
            let result = engine.scan().await;
            black_box(result)
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_packet_crafting,
    bench_port_parsing,
    bench_timing,
    bench_concurrent_scan,
    bench_memory_patterns,
    bench_network_utils,
    bench_service_detection,
    bench_full_scan,
    bench_performance_targets,
    benchmark_large_scan,
    benchmark_network_scan,
    benchmark_stealth_scan
);

criterion_main!(benches);