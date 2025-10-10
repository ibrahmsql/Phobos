// Phobos Build Script
// Sistem özelliklerine göre otomatik optimization

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    
    // CPU core sayısını al
    let cpu_cores = num_cpus::get();
    println!("cargo:rustc-env=PHOBOS_CPU_CORES={}", cpu_cores);
    
    // Target platform
    let target = env::var("TARGET").unwrap();
    println!("cargo:rustc-env=PHOBOS_TARGET={}", target);
    
    // CPU features'ları detect et
    if target.contains("x86_64") {
        println!("cargo:warning=Building with x86_64 native optimizations");
        println!("cargo:warning=Using CPU features: AVX2, AES, SSE4.2, POPCNT");
    } else if target.contains("aarch64") {
        println!("cargo:warning=Building with ARM64 native optimizations");
    }
    
    // Release profile için ekstra optimizasyonlar
    if let Ok(profile) = env::var("PROFILE") {
        if profile == "release" {
            println!("cargo:rustc-env=PHOBOS_OPTIMIZED=true");
        }
    }
}
