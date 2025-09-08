use phobos::config::ScanConfig;
use phobos::scanner::engine::ScanEngine;
use std::time::{Duration, Instant};
use tokio::time::timeout;

/// Kapsamlı performans testi - farklı port aralıkları ve konfigürasyonlar
#[tokio::test]
async fn test_comprehensive_performance_analysis() {
    println!("🚀 Kapsamlı performans analizi başlıyor...");
    
    let test_scenarios = vec![
        (
            "Hızlı Tarama - Az Port",
            vec![22, 80, 443, 8080],
            50,   // threads
            1000, // timeout ms
        ),
        (
            "Orta Tarama - Orta Port",
            (1..=100).collect::<Vec<u16>>(),
            100,  // threads
            2000, // timeout ms
        ),
        (
            "Yoğun Tarama - Çok Port",
            (1..=1000).collect::<Vec<u16>>(),
            200,  // threads
            3000, // timeout ms
        ),
        (
            "Web Servisleri Tarama",
            vec![80, 443, 8080, 8443, 3000, 5000, 8000, 9000, 3001, 8001],
            75,   // threads
            1500, // timeout ms
        ),
    ];
    
    for (scenario_name, ports, threads, timeout_ms) in test_scenarios {
        println!("\n📊 Senaryo: {}", scenario_name);
        println!("   - Port sayısı: {}", ports.len());
        println!("   - Thread sayısı: {}", threads);
        println!("   - Timeout: {}ms", timeout_ms);
        
        let config = ScanConfig::new("127.0.0.1".to_string())
            .with_ports(ports.clone())
            .with_threads(threads)
            .with_timeout(timeout_ms);
        
        let start_time = Instant::now();
        
        match ScanEngine::new(config).await {
            Ok(engine) => {
                match timeout(Duration::from_secs(30), engine.scan()).await {
                    Ok(Ok(result)) => {
                        let duration = start_time.elapsed();
                        let scan_rate = result.scan_rate();
                        
                        println!("   ✅ Başarılı!");
                        println!("   - Süre: {:?}", duration);
                        println!("   - Taranan portlar: {}", result.total_ports());
                        println!("   - Açık portlar: {}", result.open_ports.len());
                        println!("   - Kapalı portlar: {}", result.closed_ports.len());
                        println!("   - Filtrelenmiş portlar: {}", result.filtered_ports.len());
                        println!("   - Tarama hızı: {:.2} port/saniye", scan_rate);
                        
                        // Port atlama kontrolü
                        let scanned_ports: Vec<u16> = result.port_results
                            .iter()
                            .map(|r| r.port)
                            .collect();
                        
                        let mut missing_ports = Vec::new();
                        for &expected_port in &ports {
                            if !scanned_ports.contains(&expected_port) {
                                missing_ports.push(expected_port);
                            }
                        }
                        
                        if missing_ports.is_empty() {
                            println!("   ✅ Port atlama yok - tüm portlar tarandı");
                        } else {
                            println!("   ⚠️  Atlanan portlar: {:?}", missing_ports);
                        }
                        
                        // Performans değerlendirmesi
                        if scan_rate > 1000.0 {
                            println!("   🏆 Mükemmel performans!");
                        } else if scan_rate > 500.0 {
                            println!("   👍 İyi performans");
                        } else if scan_rate > 100.0 {
                            println!("   👌 Kabul edilebilir performans");
                        } else {
                            println!("   ⚠️  Yavaş performans");
                        }
                    },
                    Ok(Err(e)) => {
                        println!("   ❌ Tarama hatası: {:?}", e);
                    },
                    Err(_) => {
                        println!("   ⏰ Zaman aşımı (30s)");
                    }
                }
            },
            Err(e) => {
                println!("   ❌ Engine oluşturulamadı: {:?}", e);
            }
        }
    }
    
    println!("\n🎯 Kapsamlı performans analizi tamamlandı!");
}

/// Farklı flag kombinasyonlarının optimizasyon testi
#[tokio::test]
async fn test_flag_optimization_combinations() {
    println!("⚙️  Flag optimizasyon kombinasyonları test ediliyor...");
    
    let base_ports = vec![22, 80, 443, 8080, 3000];
    
    let flag_combinations = vec![
        ("Ultra Hızlı", 25, 500),   // az thread, kısa timeout
        ("Hızlı", 50, 1000),        // orta thread, orta timeout
        ("Dengeli", 100, 2000),     // çok thread, uzun timeout
        ("Yoğun", 200, 3000),       // çok thread, çok uzun timeout
        ("Konservatif", 10, 5000),  // az thread, çok uzun timeout
    ];
    
    let mut best_combination = ("None", 0, 0, 0.0, Duration::from_secs(0));
    
    for (name, threads, timeout_ms) in flag_combinations {
        println!("\n🔧 Test: {} (threads: {}, timeout: {}ms)", name, threads, timeout_ms);
        
        let config = ScanConfig::new("127.0.0.1".to_string())
            .with_ports(base_ports.clone())
            .with_threads(threads)
            .with_timeout(timeout_ms);
        
        let start_time = Instant::now();
        
        match ScanEngine::new(config).await {
            Ok(engine) => {
                match timeout(Duration::from_secs(15), engine.scan()).await {
                    Ok(Ok(result)) => {
                        let duration = start_time.elapsed();
                        let scan_rate = result.scan_rate();
                        
                        println!("  ✅ Süre: {:?}, Hız: {:.2} port/s, Portlar: {}", 
                               duration, scan_rate, result.total_ports());
                        
                        // En iyi kombinasyonu bul (hız ve güvenilirlik dengesi)
                        let score = scan_rate * (result.total_ports() as f64 / base_ports.len() as f64);
                        if score > best_combination.3 {
                            best_combination = (name, threads, timeout_ms, score, duration);
                        }
                    },
                    Ok(Err(e)) => {
                        println!("  ❌ Hata: {:?}", e);
                    },
                    Err(_) => {
                        println!("  ⏰ Zaman aşımı");
                    }
                }
            },
            Err(e) => {
                println!("  ❌ Engine hatası: {:?}", e);
            }
        }
    }
    
    println!("\n🏆 EN OPTIMAL KOMBİNASYON:");
    println!("   - İsim: {}", best_combination.0);
    println!("   - Thread sayısı: {}", best_combination.1);
    println!("   - Timeout: {}ms", best_combination.2);
    println!("   - Performans skoru: {:.2}", best_combination.3);
    println!("   - Süre: {:?}", best_combination.4);
    
    println!("\n💡 ÖNERİLER:");
    if best_combination.1 <= 50 {
        println!("   - Düşük thread sayısı optimal - sistem kaynaklarını verimli kullanıyor");
    } else {
        println!("   - Yüksek thread sayısı gerekli - yoğun paralel işlem");
    }
    
    if best_combination.2 <= 1000 {
        println!("   - Kısa timeout optimal - hızlı yanıt");
    } else {
        println!("   - Uzun timeout gerekli - güvenilir sonuç");
    }
}

/// Gerçek dünya senaryoları testi
#[tokio::test]
async fn test_real_world_scenarios() {
    println!("🌍 Gerçek dünya senaryoları test ediliyor...");
    
    let scenarios = vec![
        (
            "Web Sunucu Tarama",
            vec![80, 443, 8080, 8443, 8000, 8001, 8888, 9000, 9001, 9080],
        ),
        (
            "Veritabanı Servisleri",
            vec![3306, 5432, 1433, 1521, 27017, 6379, 11211, 5984],
        ),
        (
            "Sistem Servisleri",
            vec![22, 23, 21, 25, 53, 110, 143, 993, 995],
        ),
        (
            "Geliştirme Portları",
            vec![3000, 3001, 4000, 4200, 5000, 5173, 8080, 8081, 9000, 9001],
        ),
    ];
    
    for (scenario_name, ports) in scenarios {
        println!("\n📋 Senaryo: {}", scenario_name);
        
        let config = ScanConfig::new("127.0.0.1".to_string())
            .with_ports(ports.clone())
            .with_threads(75)
            .with_timeout(2000);
        
        let start_time = Instant::now();
        
        match ScanEngine::new(config).await {
            Ok(engine) => {
                match timeout(Duration::from_secs(20), engine.scan()).await {
                    Ok(Ok(result)) => {
                        let duration = start_time.elapsed();
                        
                        println!("   ✅ Tamamlandı: {:?}", duration);
                        println!("   - Hedef portlar: {}", ports.len());
                        println!("   - Taranan portlar: {}", result.total_ports());
                        println!("   - Tarama oranı: {:.1}%", 
                               (result.total_ports() as f64 / ports.len() as f64) * 100.0);
                        
                        if result.total_ports() == ports.len() {
                            println!("   🎯 Mükemmel - tüm portlar tarandı!");
                        } else {
                            println!("   ⚠️  Bazı portlar atlandı");
                        }
                    },
                    Ok(Err(e)) => {
                        println!("   ❌ Hata: {:?}", e);
                    },
                    Err(_) => {
                        println!("   ⏰ Zaman aşımı");
                    }
                }
            },
            Err(e) => {
                println!("   ❌ Engine hatası: {:?}", e);
            }
        }
    }
    
    println!("\n🎉 Gerçek dünya senaryoları testi tamamlandı!");
}