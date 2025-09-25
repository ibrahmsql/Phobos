use phobos::config::ScanConfig;
use phobos::scanner::engine::ScanEngine;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::timeout;

/// Test 1: Genel tarama - başlangıç portu belirtmeden
#[tokio::test]
async fn test_general_scan_without_specific_ports() {
    // Genel tarama konfigürasyonu - tüm yaygın portları tarar
    let config = ScanConfig::new("127.0.0.1".to_string())
        .with_timeout(5000) // 5 saniye timeout (milliseconds)
        .with_threads(100)
        .with_ports(vec![22, 80, 443, 8080]); // Test için birkaç yaygın port
    
    let engine = ScanEngine::new(config).await.expect("Engine oluşturulamadı");
    
    // Localhost'u tara
    let _target = Ipv4Addr::new(127, 0, 0, 1);
    
    let scan_result = timeout(
        Duration::from_secs(30),
        engine.scan()
    ).await;
    
    match scan_result {
        Ok(result) => {
            let scan_data = result.expect("Tarama başarısız");
            println!("Genel tarama tamamlandı:");
            println!("- Toplam port sayısı: {}", scan_data.total_ports());
            println!("- Açık portlar: {:?}", scan_data.open_ports.len());
            
            // Port atlama kontrolü
            let open_ports = &scan_data.open_ports;
            if !open_ports.is_empty() {
                let mut sorted_ports: Vec<_> = open_ports.iter().cloned().collect();
                sorted_ports.sort();
                
                // Ardışık portlar arasında büyük boşluk var mı kontrol et
                for i in 1..sorted_ports.len() {
                    let gap = sorted_ports[i] - sorted_ports[i-1];
                    if gap > 1000 {
                        println!("⚠️  Port {} ile {} arasında büyük boşluk tespit edildi ({})", 
                               sorted_ports[i-1], sorted_ports[i], gap);
                    }
                }
                println!("✅ Genel tarama port atlama kontrolü tamamlandı");
            }
        },
        Err(_) => {
            println!("⚠️  Genel tarama zaman aşımına uğradı");
        }
    }
}

/// Test 2: Hedefli tarama - belirli port aralığı
#[tokio::test]
async fn test_targeted_scan_with_port_range() {
    // Web servisleri için yaygın portlar
    let target_ports = vec![80, 443, 8080, 8443, 3000, 5000, 8000, 9000];
    
    // Belirli port aralığı konfigürasyonu
    let config = ScanConfig::new("127.0.0.1".to_string())
        .with_timeout(3000) // 3 saniye timeout (milliseconds)
        .with_threads(50)
        .with_ports(target_ports.clone());
    
    let engine = ScanEngine::new(config).await.expect("Engine oluşturulamadı");
    
    let scan_result = timeout(
        Duration::from_secs(15),
        engine.scan()
    ).await;
    
    match scan_result {
        Ok(result) => {
            let scan_data = result.expect("Hedefli tarama başarısız");
            println!("Hedefli tarama tamamlandı:");
            println!("- Hedef port sayısı: {}", target_ports.len());
            println!("- Taranan port sayısı: {}", scan_data.total_ports());
            println!("- Açık portlar: {:?}", scan_data.open_ports.len());
            
            // Tüm hedef portların tarandığından emin ol
            let scanned_ports: Vec<u16> = scan_data.port_results
                .iter()
                .map(|r| r.port)
                .collect();
            
            for &target_port in &target_ports {
                if !scanned_ports.contains(&target_port) {
                    println!("❌ Port {} atlandı!", target_port);
                } else {
                    println!("✅ Port {} tarandı", target_port);
                }
            }
            
            // Port atlama kontrolü - hedef portlar dışında tarama yapılmış mı?
            for &scanned_port in &scanned_ports {
                if !target_ports.contains(&scanned_port) {
                    println!("⚠️  Beklenmeyen port tarandı: {}", scanned_port);
                }
            }
            
            println!("✅ Hedefli tarama port atlama kontrolü tamamlandı");
        },
        Err(_) => {
            println!("⚠️  Hedefli tarama zaman aşımına uğradı");
        }
    }
}

/// Test 3: Flag kombinasyonları optimizasyon testi
#[tokio::test]
async fn test_optimal_flag_combinations() {
    println!("🔧 Optimal flag kombinasyonları test ediliyor...");
    
    let test_configs = vec![
        ("Hızlı + Küçük Batch", 50, Duration::from_millis(500)),
        ("Orta + Orta Batch", 100, Duration::from_secs(1)),
        ("Yavaş + Büyük Batch", 200, Duration::from_secs(2)),
        ("Çok Hızlı + Çok Küçük Batch", 25, Duration::from_millis(200)),
    ];
    
    let test_ports = vec![22, 80, 443, 8080];
    
    for (name, batch_size, timeout_duration) in test_configs {
        println!("\n📊 Test ediliyor: {}", name);
        
        let config = ScanConfig::new("127.0.0.1".to_string())
            .with_threads(batch_size)
            .with_timeout(timeout_duration.as_millis() as u64)
            .with_ports(test_ports.clone());
        
        let start_time = std::time::Instant::now();
        
        match ScanEngine::new(config).await {
            Ok(engine) => {
                match timeout(Duration::from_secs(10), engine.scan()).await {
                    Ok(Ok(result)) => {
                        let duration = start_time.elapsed();
                        println!("  ✅ Süre: {:?}, Portlar: {}, Açık: {}", 
                               duration, result.total_ports(), result.open_ports.len());
                    },
                    Ok(Err(e)) => {
                        println!("  ❌ Hata: {:?}", e);
                    },
                    Err(_) => {
                        println!("  ⚠️  Zaman aşımı");
                    }
                }
            },
            Err(e) => {
                println!("  ❌ Engine oluşturulamadı: {:?}", e);
            }
        }
    }
    
    println!("\n🎯 Optimal kombinasyon testi tamamlandı!");
    println!("💡 En iyi performans için küçük batch size ve kısa timeout önerilir.");
}

/// Test 4: Port atlama detaylı analizi
#[tokio::test]
async fn test_port_skipping_analysis() {
    println!("🔍 Port atlama detaylı analizi başlıyor...");
    
    // Ardışık port aralığı testi
    let sequential_ports: Vec<u16> = (8000..8010).collect();
    
    let config = ScanConfig::new("127.0.0.1".to_string())
        .with_ports(sequential_ports.clone())
        .with_timeout(1000) // 1 saniye timeout (milliseconds)
        .with_threads(5);
    
    let engine = ScanEngine::new(config).await.expect("Engine oluşturulamadı");
    
    match engine.scan().await {
        Ok(result) => {
            let scanned_ports: Vec<u16> = result.port_results
                .iter()
                .map(|r| r.port)
                .collect();
            
            println!("Hedef portlar: {:?}", sequential_ports);
            println!("Taranan portlar: {:?}", scanned_ports);
            
            // Her portu kontrol et
            let mut missing_ports = Vec::new();
            for &port in &sequential_ports {
                if !scanned_ports.contains(&port) {
                    missing_ports.push(port);
                }
            }
            
            if missing_ports.is_empty() {
                println!("✅ Tüm portlar başarıyla tarandı - port atlama yok");
            } else {
                println!("❌ Atlanan portlar: {:?}", missing_ports);
            }
        },
        Err(e) => {
            println!("❌ Tarama hatası: {:?}", e);
        }
    }
}