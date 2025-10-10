//! GPU Vendor-Specific Optimizations
//! Each vendor has different characteristics and optimal settings

pub mod nvidia;
pub mod amd;
pub mod intel;
pub mod apple;

use super::GpuCapabilities;

/// GPU Vendor type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuVendor {
    Nvidia,
    AMD,
    Intel,
    Apple,
    Unknown,
}

impl GpuVendor {
    /// Detect vendor from vendor string
    pub fn from_vendor_string(vendor: &str) -> Self {
        let vendor_lower = vendor.to_lowercase();
        
        if vendor_lower.contains("nvidia") {
            GpuVendor::Nvidia
        } else if vendor_lower.contains("amd") || vendor_lower.contains("advanced micro devices") {
            GpuVendor::AMD
        } else if vendor_lower.contains("intel") {
            GpuVendor::Intel
        } else if vendor_lower.contains("apple") {
            GpuVendor::Apple
        } else {
            GpuVendor::Unknown
        }
    }
    
    /// Get optimal batch size for this vendor
    pub fn optimal_batch_size(&self, compute_units: u32) -> usize {
        match self {
            GpuVendor::Nvidia => (compute_units as usize) * 128, // CUDA cores work best with large batches
            GpuVendor::AMD => (compute_units as usize) * 64,     // GCN/RDNA architecture
            GpuVendor::Intel => (compute_units as usize) * 32,   // EU (Execution Units)
            GpuVendor::Apple => (compute_units as usize) * 64,   // Metal/OpenCL hybrid
            GpuVendor::Unknown => (compute_units as usize) * 32, // Conservative default
        }
    }
    
    /// Get optimal work group size for this vendor
    pub fn optimal_work_group_size(&self) -> usize {
        match self {
            GpuVendor::Nvidia => 256,  // Warp size is 32, use multiples
            GpuVendor::AMD => 256,     // Wavefront size is 64 for RDNA
            GpuVendor::Intel => 128,   // EU configuration
            GpuVendor::Apple => 256,   // Metal thread group size
            GpuVendor::Unknown => 128, // Safe default
        }
    }
    
    /// Check if this vendor supports specific features
    pub fn supports_async_transfer(&self) -> bool {
        match self {
            GpuVendor::Nvidia => true,  // CUDA streams
            GpuVendor::AMD => true,     // ROCm queues
            GpuVendor::Intel => true,   // OneAPI
            GpuVendor::Apple => true,   // Metal command buffers
            GpuVendor::Unknown => false,
        }
    }
    
    /// Get vendor-specific optimization hints
    pub fn optimization_hints(&self) -> Vec<&'static str> {
        match self {
            GpuVendor::Nvidia => vec![
                "Use warp-aligned memory access",
                "Maximize occupancy with large work groups",
                "Utilize shared memory for frequently accessed data",
                "Enable async compute for overlap",
            ],
            GpuVendor::AMD => vec![
                "Optimize for wavefront size (64 threads)",
                "Use LDS (Local Data Share) effectively",
                "Balance compute and memory bandwidth",
                "Leverage async compute engines",
            ],
            GpuVendor::Intel => vec![
                "Optimize for EU thread dispatch",
                "Use subgroups for SIMD operations",
                "Balance across execution units",
                "Minimize memory latency",
            ],
            GpuVendor::Apple => vec![
                "Leverage unified memory architecture",
                "Use Metal best practices",
                "Optimize for tile-based architecture",
                "Minimize CPU-GPU transfers",
            ],
            GpuVendor::Unknown => vec![
                "Use conservative settings",
                "Test performance on target hardware",
            ],
        }
    }
}

/// Vendor-specific GPU configuration
pub struct VendorConfig {
    pub vendor: GpuVendor,
    pub optimal_batch_size: usize,
    pub optimal_work_group: usize,
    pub supports_async: bool,
}

impl VendorConfig {
    pub fn from_capabilities(caps: &GpuCapabilities) -> Self {
        let vendor = GpuVendor::from_vendor_string(&caps.vendor);
        
        Self {
            optimal_batch_size: vendor.optimal_batch_size(caps.max_compute_units),
            optimal_work_group: vendor.optimal_work_group_size(),
            supports_async: vendor.supports_async_transfer(),
            vendor,
        }
    }
}
