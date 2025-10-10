//! Intel GPU Optimizations
//! Arc/Iris Xe/UHD Graphics optimizations

/// Intel-specific OpenCL kernel
pub const INTEL_CHECKSUM_KERNEL: &str = r#"
// Intel-optimized TCP checksum calculation
// Optimized for EU (Execution Unit) architecture

__kernel void calculate_tcp_checksum_intel(
    __global const uchar* packets,
    __global ushort* checksums,
    const uint packet_size
) {
    int gid = get_global_id(0);
    int offset = gid * packet_size;
    
    // Intel EU-optimized access pattern
    uint sum = 0;
    
    // Use 32-bit loads (Intel GPUs prefer aligned access)
    for (int i = 0; i < packet_size / 4; i++) {
        uint data = ((__global uint*)(packets + offset))[i];
        sum += (data & 0xFFFF) + (data >> 16);
    }
    
    // Handle remaining bytes
    int remaining = packet_size % 4;
    if (remaining > 0) {
        int base = (packet_size / 4) * 4;
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

/// Intel GPU architecture info
#[derive(Debug, Clone)]
pub struct IntelInfo {
    /// GPU architecture
    pub architecture: String,
    /// Number of Execution Units (EUs)
    pub execution_units: u32,
    /// Subslice count
    pub subslices: u32,
    /// Memory bandwidth (GB/s)
    pub memory_bandwidth: f32,
}

impl IntelInfo {
    /// Detect Intel GPU from device name
    pub fn from_device_name(device_name: &str) -> Self {
        let device_lower = device_name.to_lowercase();
        
        let (architecture, eu_count) = if device_lower.contains("arc") {
            if device_lower.contains("a770") {
                ("Alchemist (Arc)", 512) // Arc A770
            } else if device_lower.contains("a750") {
                ("Alchemist (Arc)", 448) // Arc A750
            } else {
                ("Alchemist (Arc)", 256) // Other Arc
            }
        } else if device_lower.contains("iris xe") {
            ("Xe-LP (Iris Xe)", 96) // Tiger Lake / Alder Lake
        } else if device_lower.contains("uhd") {
            ("Gen 11/12", 32) // UHD Graphics
        } else {
            ("Unknown", 24) // Conservative
        };
        
        let subslices = eu_count / 8; // Approximate
        
        let memory_bandwidth = if device_lower.contains("arc a770") {
            560.0
        } else if device_lower.contains("iris xe") {
            68.0
        } else {
            50.0 // Integrated graphics
        };
        
        Self {
            architecture: architecture.to_string(),
            execution_units: eu_count,
            subslices,
            memory_bandwidth,
        }
    }
    
    /// Get optimal configuration
    pub fn optimal_config(&self) -> IntelOptimalConfig {
        IntelOptimalConfig {
            work_group_size: 128, // Good for EU architecture
            batch_size: (self.execution_units as usize) * 32,
            use_subgroups: true,
            async_compute: true,
        }
    }
}

/// Optimal configuration for Intel GPUs
#[derive(Debug, Clone)]
pub struct IntelOptimalConfig {
    pub work_group_size: usize,
    pub batch_size: usize,
    pub use_subgroups: bool,
    pub async_compute: bool,
}

/// Intel-specific performance tips
pub fn performance_tips() -> Vec<&'static str> {
    vec![
        "Use aligned memory access (32-bit preferred)",
        "Leverage Intel subgroups for SIMD operations",
        "Optimize for EU thread dispatch",
        "Use shared local memory efficiently",
        "Profile with Intel VTune or Graphics Performance Analyzers",
        "Arc GPUs: Use ray tracing acceleration when available",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_intel_architecture_detection() {
        let arc_a770 = IntelInfo::from_device_name("Intel Arc A770");
        assert_eq!(arc_a770.architecture, "Alchemist (Arc)");
        
        let iris_xe = IntelInfo::from_device_name("Intel Iris Xe Graphics");
        assert_eq!(iris_xe.architecture, "Xe-LP (Iris Xe)");
    }
}
