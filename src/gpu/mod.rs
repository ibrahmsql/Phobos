//! GPU Acceleration Module for Phobos
//! OpenCL-based GPU acceleration for high-performance port scanning
//!
//! ## Features
//! - Parallel packet checksum calculation
//! - GPU-accelerated port filtering
//! - Batch packet processing
//! - Automatic GPU detection and fallback
//! - Vendor-specific optimizations (NVIDIA, AMD, Intel, Apple)

#[cfg(feature = "gpu")]
pub mod opencl;

#[cfg(feature = "gpu")]
pub mod vendors;

#[cfg(feature = "gpu")]
pub use opencl::*;

#[cfg(feature = "gpu")]
pub use vendors::{GpuVendor, VendorConfig};

/// GPU acceleration status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuStatus {
    /// GPU is available and initialized
    Available,
    /// GPU is not available (no OpenCL support)
    NotAvailable,
    /// GPU is disabled by configuration
    Disabled,
}

/// GPU capabilities
#[derive(Debug, Clone)]
pub struct GpuCapabilities {
    /// GPU device name
    pub device_name: String,
    /// GPU vendor
    pub vendor: String,
    /// Maximum work group size
    pub max_work_group_size: usize,
    /// Maximum compute units
    pub max_compute_units: u32,
    /// Global memory size (bytes)
    pub global_mem_size: u64,
    /// GPU status
    pub status: GpuStatus,
}

impl Default for GpuCapabilities {
    fn default() -> Self {
        Self {
            device_name: "CPU".to_string(),
            vendor: "None".to_string(),
            max_work_group_size: 1,
            max_compute_units: 1,
            global_mem_size: 0,
            status: GpuStatus::NotAvailable,
        }
    }
}

/// Mock GPU module when feature is disabled
#[cfg(not(feature = "gpu"))]
pub mod mock {
    use super::*;

    pub struct GpuAccelerator;

    impl GpuAccelerator {
        pub fn new() -> crate::Result<Self> {
            Ok(Self)
        }

        pub fn is_available(&self) -> bool {
            false
        }

        pub fn capabilities(&self) -> GpuCapabilities {
            GpuCapabilities::default()
        }

        pub fn calculate_checksums(&self, _packets: &[Vec<u8>]) -> crate::Result<Vec<u16>> {
            Err(crate::error::ScanError::ConfigError(
                "GPU acceleration not compiled in".to_string(),
            ))
        }
    }
}
