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
            // Simple port range parsing for benchmark
            let range = "1-65535";
            let parts: Vec<&str> = range.split('-').collect();
            let start: u16 = parts[0].parse().unwrap_or(1);
            let end: u16 = parts[1].parse().unwrap_or(65535);
            let ports: Vec<u16> = (start..=end).collect();
            black_box(ports)
        })
    });
    
    group.bench_function("parse_list_common_ports", |b| {
        b.iter(|| {
            // Simple port list parsing for benchmark
            let port_list = "21,22,23,25,53,80,110,111,135,139,143,443,993,995";
            let ports: Vec<u16> = port_list.split(',').map(|p| p.parse().unwrap_or(80)).collect();
            black_box(ports)
        })
    });
    
    group.bench_function("parse_mixed_complex", |b| {
        b.iter(|| {
            // Complex port parsing for benchmark
            let complex = "1-100,443,8000-8100,9000-9010";
            let mut ports = Vec::new();
            for part in complex.split(',') {
                if part.contains('-') {
                    let range: Vec<&str> = part.split('-').collect();
                    let start: u16 = range[0].parse().unwrap_or(1);
                    let end: u16 = range[1].parse().unwrap_or(100);
                    ports.extend(start..=end);
                } else {
                    ports.push(part.parse().unwrap_or(80));
                }
            }
            black_box(ports)
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
            rate_limiter.can_send()
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
                b.iter(|| {
                    rt.block_on(async {
                        let config = ScanConfig {
                            target: "127.0.0.1".to_string(),
                            ports: (1..=100).collect(),
                            technique: ScanTechnique::Connect,
                            threads: thread_count,
                            timeout: 100,
                            rate_limit: 10000,
                            stealth_options: None,
                            timing_template: 3,
                            top_ports: None,
                            batch_size: None,
                            realtime_notifications: false,
                            notification_color: "orange".to_string(),
                            adaptive_learning: false,
                            min_response_time: 50,
                            max_response_time: 3000,
                        };
                        
                        let engine = ScanEngine::new(config).await.unwrap();
                        let result = engine.scan().await;
                        black_box(result)
                    })
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
            let target = std::net::Ipv4Addr::new(127, 0, 0, 1);
            let batches = phobos::scanner::create_batches(
                black_box(ports),
                black_box(target),
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
            phobos::network::protocol::ServiceDatabase::get_top_tcp_ports(black_box(1000))
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
        b.iter(|| {
            rt.block_on(async {
                let top_ports: Vec<u16> = (1..=100).collect();
                
                let config = ScanConfig {
                    target: "127.0.0.1".to_string(),
                    ports: top_ports,
                    technique: ScanTechnique::Connect,
                    threads: 100,
                    timeout: 1000,
                    rate_limit: 10000,
                    stealth_options: None,
                    timing_template: 3,
                    top_ports: None,
                    batch_size: None,
                    realtime_notifications: false,
                    notification_color: "orange".to_string(),
                    adaptive_learning: false,
                    min_response_time: 50,
                    max_response_time: 3000,
                };
                
                let engine = ScanEngine::new(config).await.unwrap();
                let result = engine.scan().await;
                black_box(result)
            })
        })
    });
    
    group.finish();
}

/// Performance regression tests
fn bench_performance_targets(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("performance_targets");
    group.sample_size(10);
    
    // Target: 1K ports for realistic testing
    group.bench_function("target_1k_ports_fast", |b| {
        b.iter(|| {
            rt.block_on(async {
                let ports: Vec<u16> = (1..=1000).collect();
                
                let config = ScanConfig {
                    target: "127.0.0.1".to_string(),
                    ports,
                    technique: ScanTechnique::Connect,
                    threads: 1000,
                    timeout: 100,
                    rate_limit: 100000,
                    stealth_options: None,
                    timing_template: 3,
                    top_ports: None,
                    batch_size: None,
                    realtime_notifications: false,
                    notification_color: "orange".to_string(),
                    adaptive_learning: false,
                    min_response_time: 50,
                    max_response_time: 3000,
                };
                
                let start = std::time::Instant::now();
                let engine = ScanEngine::new(config).await.unwrap();
                let result = engine.scan().await;
                let duration = start.elapsed();
                
                println!("1K ports scan took: {:?}", duration);
                
                black_box(result)
            })
        })
    });
    
    group.finish();
}

/// Benchmark large scale scanning
fn benchmark_large_scan(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("large_scale_scan");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    
    group.bench_function("scan_5k_ports", |b| {
        b.iter(|| {
            rt.block_on(async {
                let ports: Vec<u16> = (1..=5000).collect();
                
                let config = ScanConfig {
                    target: "127.0.0.1".to_string(),
                    ports,
                    technique: ScanTechnique::Connect,
                    threads: 1000,
                    timeout: 50,
                    rate_limit: 100000,
                    stealth_options: None,
                    timing_template: 3,
                    top_ports: None,
                    batch_size: None,
                    realtime_notifications: false,
                    notification_color: "orange".to_string(),
                    adaptive_learning: false,
                    min_response_time: 50,
                    max_response_time: 3000,
                };
                
                let start = std::time::Instant::now();
                let engine = ScanEngine::new(config).await.unwrap();
                let result = engine.scan().await;
                let duration = start.elapsed();
                
                println!("5K ports scan took: {:?}", duration);
                black_box(result)
            })
        })
    });
    
    group.bench_function("scan_1k_ports_optimized", |b| {
        b.iter(|| {
            rt.block_on(async {
                let ports: Vec<u16> = (1..=1000).collect();
                
                let config = ScanConfig {
                    target: "127.0.0.1".to_string(),
                    ports,
                    technique: ScanTechnique::Connect,
                    threads: 500,
                    timeout: 100,
                    rate_limit: 50000,
                    stealth_options: None,
                    timing_template: 3,
                    top_ports: None,
                    batch_size: None,
                    realtime_notifications: false,
                    notification_color: "orange".to_string(),
                    adaptive_learning: false,
                    min_response_time: 50,
                    max_response_time: 3000,
                };
                
                let start = std::time::Instant::now();
                let engine = ScanEngine::new(config).await.unwrap();
                let result = engine.scan().await;
                let duration = start.elapsed();
                
                println!("1K ports optimized scan took: {:?}", duration);
                black_box(result)
            })
        })
    });
    
    group.finish();
}

/// Benchmark network scanning
fn benchmark_network_scan(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("network_scan");
    group.sample_size(5);
    group.measurement_time(Duration::from_secs(20));
    
    group.bench_function("scan_common_ports", |b| {
        b.iter(|| {
            rt.block_on(async {
                let common_ports = vec![21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995];
                
                let config = ScanConfig {
                    target: "127.0.0.1".to_string(),
                    ports: common_ports,
                    technique: ScanTechnique::Connect,
                    threads: 50,
                    timeout: 1000,
                    rate_limit: 5000,
                    stealth_options: None,
                    timing_template: 3,
                    top_ports: None,
                    batch_size: None,
                    realtime_notifications: false,
                    notification_color: "orange".to_string(),
                    adaptive_learning: false,
                    min_response_time: 50,
                    max_response_time: 3000,
                };
                
                let start = std::time::Instant::now();
                let engine = ScanEngine::new(config).await.unwrap();
                let result = engine.scan().await;
                let duration = start.elapsed();
                
                println!("Common ports scan took: {:?}", duration);
                black_box(result)
            })
        })
    });
    
    group.finish();
}

/// Benchmark stealth scanning techniques
fn benchmark_stealth_scan(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("stealth_scan");
    group.sample_size(10);
    
    group.bench_function("stealth_scan", |b| {
        b.iter(|| {
            rt.block_on(async {
                use phobos::network::stealth::StealthOptions;
                
                let config = ScanConfig {
                    target: "127.0.0.1".to_string(),
                    ports: vec![80, 443, 8080],
                    technique: ScanTechnique::Connect,
                    threads: 10,
                    timeout: 1000,
                    rate_limit: 1000,
                    stealth_options: Some(StealthOptions {
                        fragment_packets: true,
                        randomize_source_port: true,
                        spoof_source_ip: None,
                        decoy_addresses: vec![],
                        timing_randomization: true,
                        packet_padding: Some(64),
                        custom_mtu: Some(1500),
                        randomize_ip_id: true,
                        randomize_sequence: true,
                        use_bad_checksum: false,
                    }),
                    timing_template: 3,
                    top_ports: None,
                    batch_size: None,
                    realtime_notifications: false,
                    notification_color: "orange".to_string(),
                    adaptive_learning: false,
                    min_response_time: 50,
                    max_response_time: 3000,
                };
                
                let start = std::time::Instant::now();
                let engine = ScanEngine::new(config).await.unwrap();
                let result = engine.scan().await;
                let duration = start.elapsed();
                
                println!("Stealth scan took: {:?}", duration);
                black_box(result)
            })
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