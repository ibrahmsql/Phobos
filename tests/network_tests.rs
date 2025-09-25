//! Network layer tests

use phobos::network::{
    socket::{TcpConnectScanner, UdpScanner, SocketPool},
    icmp::IcmpPinger,
    packet::{TcpPacketBuilder, TcpResponse, UdpResponse},
    protocol::NetworkUtils,
    ScanTechnique,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use tokio::time::timeout;

#[tokio::test]
async fn test_tcp_connect_scanner() {
    let scanner = TcpConnectScanner::new(Duration::from_millis(1000));
    let target_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let target_port = 22;
    
    let start = Instant::now();
    let result = timeout(
        Duration::from_secs(5),
        scanner.scan_port(target_ip, target_port)
    ).await;
    
    assert!(result.is_ok());
    let scan_result = result.unwrap();
    
    // Should complete quickly for localhost
    let duration = start.elapsed();
    assert!(duration < Duration::from_secs(2));
    
    // Result should be boolean for connect scanner
    assert!(scan_result.is_ok());
}

#[tokio::test]
async fn test_udp_scanner() {
    let scanner = UdpScanner::new(Duration::from_millis(1000));
    let target_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let target_port = 53;
    
    let start = Instant::now();
    let result = timeout(
        Duration::from_secs(5),
        scanner.scan_port(target_ip, target_port)
    ).await;
    
    assert!(result.is_ok());
    let scan_result = result.unwrap();
    
    // Should complete within reasonable time
    let duration = start.elapsed();
    assert!(duration < Duration::from_secs(3));
    
    // UDP scanning should return a boolean result
    assert!(scan_result.is_ok());
}

#[tokio::test]
async fn test_socket_pool() {
    let pool_result = SocketPool::new(5, 5); // 5 TCP, 5 UDP sockets
    
    match pool_result {
        Ok(pool) => {
            // Test socket acquisition
            let tcp_socket = pool.get_tcp_socket();
            assert!(tcp_socket.is_some());
            
            let udp_socket = pool.get_udp_socket();
            assert!(udp_socket.is_some());
            
            println!("Socket pool test passed");
        },
        Err(_) => {
            // May fail due to permissions for raw sockets
            println!("Socket pool requires root privileges - skipping test");
        }
    }
}

#[tokio::test]
async fn test_icmp_pinger() {
    let pinger_result = IcmpPinger::new();
    
    match pinger_result {
        Ok(pinger) => {
            let target = Ipv4Addr::new(127, 0, 0, 1);
            
            let start = Instant::now();
            let result = timeout(
                Duration::from_secs(5),
                pinger.ping(target, Duration::from_millis(1000))
            ).await;
            
            assert!(result.is_ok());
            let ping_result = result.unwrap();
            
            // Should complete quickly for localhost
            let duration = start.elapsed();
            assert!(duration < Duration::from_secs(2));
            
            // Check ping result structure
            assert_eq!(ping_result.target, target);
        },
        Err(_) => {
            // May fail due to permissions for ICMP
            println!("ICMP pinger requires root privileges - skipping test");
        }
    }
}

#[tokio::test]
async fn test_packet_building() {
    let builder = TcpPacketBuilder::new(
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(192, 168, 1, 1),
        12345,
        80
    );
    
    // Test SYN packet
    let syn_packet = builder.syn().build();
    assert!(!syn_packet.is_empty());
    
    // Test packet response structure
    let response = TcpResponse {
        source_ip: Ipv4Addr::new(192, 168, 1, 1),
        dest_ip: Ipv4Addr::new(192, 168, 1, 100),
        source_port: 80,
        dest_port: 12345,
        flags: 0x12, // SYN+ACK
        seq_num: 1000,
        ack_num: 2000,
        window_size: 65535,
    };
    
    assert!(response.is_syn_ack());
    assert!(!response.is_rst());
}

#[tokio::test]
async fn test_udp_response() {
    let response = UdpResponse {
        source_ip: Ipv4Addr::new(8, 8, 8, 8),
        dest_ip: Ipv4Addr::new(192, 168, 1, 100),
        source_port: 53,
        dest_port: 12345,
        length: 32,
        payload: vec![0x12, 0x34, 0x81, 0x80], // DNS response
    };
    
    assert_eq!(response.source_port, 53);
    assert_eq!(response.length, 32);
    assert!(!response.payload.is_empty());
}

#[tokio::test]
async fn test_network_utilities() {
    // Test random port generation
    let random_port = NetworkUtils::random_source_port();
    assert!(random_port > 1024);
    assert!(random_port <= 65535);
    
    // Test local IP retrieval
    let local_ip = NetworkUtils::get_local_ip();
    assert!(local_ip.is_ok());
}

#[tokio::test]
async fn test_scan_techniques() {
    // Test scan technique properties
    assert!(ScanTechnique::Syn.is_tcp());
    assert!(ScanTechnique::Connect.is_tcp());
    assert!(!ScanTechnique::Udp.is_tcp());
    
    assert!(ScanTechnique::Syn.requires_raw_socket());
    assert!(!ScanTechnique::Connect.requires_raw_socket());
    
    // Test TCP flags
    assert_eq!(ScanTechnique::Syn.tcp_flags(), 0x02); // SYN flag
    assert_eq!(ScanTechnique::Fin.tcp_flags(), 0x01); // FIN flag
    assert_eq!(ScanTechnique::Null.tcp_flags(), 0x00); // No flags
}

#[tokio::test]
async fn test_concurrent_scanning() {
    let scanner = TcpConnectScanner::new(Duration::from_millis(500));
    let targets = vec![
        (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22),
        (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
        (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443),
    ];
    
    let start = Instant::now();
    
    // Run concurrent scans
    let mut handles = vec![];
    for (ip, port) in targets {
        let scanner_clone = scanner.clone();
        let handle = tokio::spawn(async move {
            scanner_clone.scan_port(ip, port).await
        });
        handles.push(handle);
    }
    
    // Wait for all scans to complete
    for handle in handles {
        let result = handle.await;
        assert!(result.is_ok());
    }
    
    let duration = start.elapsed();
    
    // Concurrent scans should be faster than sequential
    assert!(duration < Duration::from_secs(5));
}

#[tokio::test]
async fn test_network_performance() {
    let scanner = TcpConnectScanner::new(Duration::from_millis(100));
    let target_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    
    let start = Instant::now();
    
    // Test multiple rapid scans
    for port in 20..30 {
        let _ = scanner.scan_port(target_ip, port).await;
    }
    
    let duration = start.elapsed();
    
    // Should complete 10 scans quickly
    assert!(duration < Duration::from_secs(3));
    
    println!("Completed 10 scans in {:?}", duration);
}

#[tokio::test]
async fn test_network_error_handling() {
    let scanner = TcpConnectScanner::new(Duration::from_millis(50)); // Very short timeout
    
    // Test timeout handling with unreachable address
    let unreachable_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)); // RFC 5737 test address
    let result = scanner.scan_port(unreachable_ip, 80).await;
    
    // Should handle timeout gracefully
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_network_protocols() {
    // Test protocol detection capabilities
    let tcp_techniques = vec![
        ScanTechnique::Syn,
        ScanTechnique::Connect,
        ScanTechnique::Fin,
        ScanTechnique::Null,
        ScanTechnique::Xmas,
        ScanTechnique::Ack,
        ScanTechnique::Window,
    ];
    
    for technique in tcp_techniques {
        assert!(technique.is_tcp());
        assert_ne!(technique.description(), "");
    }
    
    // Test UDP technique
    assert!(!ScanTechnique::Udp.is_tcp());
    assert_eq!(ScanTechnique::Udp.description(), "UDP scan");
}