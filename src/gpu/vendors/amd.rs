//! AMD GPU Optimizations
//! RDNA/GCN architecture specific optimizations

/// AMD-specific OpenCL kernel optimizations
pub const AMD_CHECKSUM_KERNEL: &str = r#"
// AMD-optimized TCP checksum calculation
// Optimized for RDNA/GCN wavefront size (64 threads)

__kernel void calculate_tcp_checksum_amd(
    __global const uchar* packets,
    __global ushort* checksums,
    const uint packet_size
) {
    int gid = get_global_id(0);
    int lid = get_local_id(0);
    int offset = gid * packet_size;
    
    // AMD wavefront-optimized memory access
    uint sum = 0;
    
    // Use vector loads for better memory bandwidth
    // AMD GPUs have excellent vector performance
    for (int i = 0; i < packet_size / 8; i++) {
        ulong data = ((__global ulong*)(packets + offset))[i];
        sum += (data & 0xFFFFFFFF) + (data >> 32);
    }
    
    // Handle remaining bytes
    int remaining = packet_size % 8;
    if (remaining > 0) {
        int base = (packet_size / 8) * 8;
        for (int i = 0; i < remaining; i++) {
            sum += packets[offset + base + i];
        }
    }
    
    // Fold to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    checksums[gid] = (ushort)(~sum);
}
"#;

/// AMD GPU architecture info
#[derive(Debug, Clone)]
pub struct AmdInfo {
    /// GPU architecture (e.g., "RDNA 3", "RDNA 2", "GCN")
    pub architecture: String,
    /// Number of Compute Units
    pub compute_units: u32,
    /// Number of Stream Processors
    pub stream_processors: u32,
    /// Memory bandwidth (GB/s)
    pub memory_bandwidth: f32,
    /// Wavefront size (typically 64 for RDNA)
    pub wavefront_size: u32,
}

impl AmdInfo {
    /// Detect AMD GPU architecture from device name
    pub fn from_device_name(device_name: &str) -> Self {
        let device_lower = device_name.to_lowercase();
        
        let (architecture, sp_per_cu, wavefront_size) = if device_lower.contains("rx 7") {
            ("RDNA 3", 128, 64) // RX 7900 XTX, 7800 XT
        } else if device_lower.contains("rx 6") {
            ("RDNA 2", 128, 64) // RX 6900 XT, 6800 XT
        } else if device_lower.contains("rx 5") {
            ("RDNA", 128, 64) // RX 5700 XT
        } else if device_lower.contains("vega") {
            ("GCN 5", 64, 64) // Vega 64, Vega 56
        } else {
            ("GCN", 64, 64) // Older architectures
        };
        
        let compute_units = 60; // Placeholder, will be updated
        let stream_processors = compute_units * sp_per_cu;
        
        // Memory bandwidth estimates (GB/s)
        let memory_bandwidth = if device_lower.contains("7900 xtx") {
            960.0
        } else if device_lower.contains("6900 xt") {
            512.0
        } else if device_lower.contains("6800 xt") {
            512.0
        } else {
            400.0 // Conservative
        };
        
        Self {
            architecture: architecture.to_string(),
            compute_units,
            stream_processors,
            memory_bandwidth,
            wavefront_size,
        }
    }
    
    /// Get optimal configuration for this AMD GPU
    pub fn optimal_config(&self) -> AmdOptimalConfig {
        AmdOptimalConfig {
            work_group_size: 256, // Multiple of wavefront size (64)
            batch_size: (self.compute_units as usize) * 64,
            use_lds: true, // Local Data Share
            async_compute: true,
            prefer_wave64: self.wavefront_size == 64,
        }
    }
}

/// Optimal configuration for AMD GPUs
#[derive(Debug, Clone)]
pub struct AmdOptimalConfig {
    pub work_group_size: usize,
    pub batch_size: usize,
    pub use_lds: bool, // Local Data Share
    pub async_compute: bool,
    pub prefer_wave64: bool,
}

/// AMD-specific performance tips
pub fn performance_tips() -> Vec<&'static str> {
    vec![
        "Use wavefront size (64) multiples for work groups",
        "Utilize LDS (Local Data Share) for shared data",
        "Optimize for memory bandwidth on RDNA",
        "Enable async compute engines",
        "Use wave64 mode for better occupancy",
        "Leverage Infinity Cache on RDNA 2/3",
        "Profile with Radeon GPU Profiler",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_amd_architecture_detection() {
        let rx7900 = AmdInfo::from_device_name("AMD Radeon RX 7900 XTX");
        assert_eq!(rx7900.architecture, "RDNA 3");
        assert_eq!(rx7900.wavefront_size, 64);
        
        let rx6800 = AmdInfo::from_device_name("AMD Radeon RX 6800 XT");
        assert_eq!(rx6800.architecture, "RDNA 2");
    }
}
