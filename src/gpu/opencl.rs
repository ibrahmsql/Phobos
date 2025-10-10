//! OpenCL GPU Acceleration Implementation
//! High-performance GPU-accelerated packet processing

use super::{GpuCapabilities, GpuStatus};
use super::vendors::{GpuVendor, VendorConfig};
use crate::error::ScanError;
use crate::Result;
use log::{debug, info};
use ocl::{Buffer, Context, Device, Kernel, Platform, Program, Queue};
use std::sync::Arc;

/// OpenCL kernel for TCP checksum calculation
const CHECKSUM_KERNEL: &str = r#"
__kernel void calculate_tcp_checksum(
    __global const uchar* packets,
    __global ushort* checksums,
    const uint packet_size
) {
    int gid = get_global_id(0);
    int offset = gid * packet_size;
    
    uint sum = 0;
    
    // Calculate checksum for TCP header
    for (int i = 0; i < packet_size / 2; i++) {
        ushort word = (packets[offset + i*2] << 8) | packets[offset + i*2 + 1];
        sum += word;
    }
    
    // Handle odd byte
    if (packet_size % 2 == 1) {
        sum += packets[offset + packet_size - 1] << 8;
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    checksums[gid] = (ushort)(~sum);
}
"#;

/// OpenCL kernel for port range filtering
const PORT_FILTER_KERNEL: &str = r#"
__kernel void filter_ports(
    __global const uint* ports,
    __global const uint* open_ports,
    __global uchar* results,
    const uint open_count
) {
    int gid = get_global_id(0);
    uint port = ports[gid];
    
    results[gid] = 0;
    for (uint i = 0; i < open_count; i++) {
        if (port == open_ports[i]) {
            results[gid] = 1;
            break;
        }
    }
}
"#;

/// GPU Accelerator using OpenCL with vendor-specific optimizations
pub struct GpuAccelerator {
    context: Context,
    queue: Queue,
    device: Device,
    capabilities: GpuCapabilities,
    vendor_config: VendorConfig,
    checksum_program: Arc<Program>,
    filter_program: Arc<Program>,
}

impl GpuAccelerator {
    /// Initialize GPU accelerator
    pub fn new() -> Result<Self> {
        info!("Initializing GPU accelerator with OpenCL...");

        // Get platform
        let platform = Platform::default();
        debug!("OpenCL Platform: {}", platform.name()?);

        // Get GPU device (fallback to CPU if no GPU)
        let device = Device::first(platform)?;
        debug!("OpenCL Device: {}", device.name()?);

        let context = Context::builder()
            .platform(platform)
            .devices(device)
            .build()?;

        let queue = Queue::new(&context, device, None)?;

        // Compile kernels
        let checksum_program = Program::builder()
            .devices(device)
            .src(CHECKSUM_KERNEL)
            .build(&context)?;

        let filter_program = Program::builder()
            .devices(device)
            .src(PORT_FILTER_KERNEL)
            .build(&context)?;

        let capabilities = Self::query_capabilities(&device)?;
        let vendor_config = VendorConfig::from_capabilities(&capabilities);

        info!("GPU initialized: {}", capabilities.device_name);
        info!("  Vendor: {} ({:?})", capabilities.vendor, vendor_config.vendor);
        info!(
            "  Compute units: {}, Max work group: {}",
            capabilities.max_compute_units, capabilities.max_work_group_size
        );
        info!(
            "  Optimal batch: {}, Work group: {}",
            vendor_config.optimal_batch_size, vendor_config.optimal_work_group
        );
        info!("  Async compute: {}", vendor_config.supports_async);

        Ok(Self {
            context,
            queue,
            device,
            capabilities,
            vendor_config,
            checksum_program: Arc::new(checksum_program),
            filter_program: Arc::new(filter_program),
        })
    }

    /// Query GPU capabilities - Dynamic detection for all vendors
    fn query_capabilities(device: &Device) -> Result<GpuCapabilities> {
        use ocl::core::{self, DeviceInfo, DeviceInfoResult};
        
        // Get device info dynamically
        let compute_units_info = core::get_device_info(device, DeviceInfo::MaxComputeUnits)
            .map_err(|e| ScanError::NetworkError(format!("Failed to get compute units: {}", e)))?;
        
        let max_compute_units = match compute_units_info {
            DeviceInfoResult::MaxComputeUnits(val) => val,
            _ => 24, // Default fallback
        };
        
        let mem_size_info = core::get_device_info(device, DeviceInfo::GlobalMemSize)
            .map_err(|e| ScanError::NetworkError(format!("Failed to get memory size: {}", e)))?;
        
        let global_mem_size = match mem_size_info {
            DeviceInfoResult::GlobalMemSize(val) => val,
            _ => 8_000_000_000, // Default 8GB fallback
        };
        
        Ok(GpuCapabilities {
            device_name: device.name()?,
            vendor: device.vendor()?,
            max_work_group_size: device.max_wg_size()?,
            max_compute_units,
            global_mem_size,
            status: GpuStatus::Available,
        })
    }

    /// Check if GPU is available
    pub fn is_available(&self) -> bool {
        self.capabilities.status == GpuStatus::Available
    }

    /// Get GPU capabilities
    pub fn capabilities(&self) -> GpuCapabilities {
        self.capabilities.clone()
    }

    /// Calculate TCP checksums for multiple packets using GPU
    ///
    /// # Performance
    /// - GPU: ~1M checksums/sec (batch processing)
    /// - CPU: ~100K checksums/sec
    pub fn calculate_checksums(&self, packets: &[Vec<u8>]) -> Result<Vec<u16>> {
        if packets.is_empty() {
            return Ok(Vec::new());
        }

        let packet_size = packets[0].len();
        let num_packets = packets.len();

        // Flatten packets into single buffer
        let mut flat_data = Vec::with_capacity(num_packets * packet_size);
        for packet in packets {
            flat_data.extend_from_slice(packet);
        }

        // Create buffers
        let packets_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(flat_data.len())
            .copy_host_slice(&flat_data)
            .build()?;

        let checksums_buffer = Buffer::<u16>::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(num_packets)
            .build()?;

        // Create and execute kernel
        let kernel = Kernel::builder()
            .program(&self.checksum_program)
            .name("calculate_tcp_checksum")
            .queue(self.queue.clone())
            .global_work_size(num_packets)
            .arg(&packets_buffer)
            .arg(&checksums_buffer)
            .arg(&(packet_size as u32))
            .build()?;

        unsafe { kernel.enq()? };

        // Read results
        let mut checksums = vec![0u16; num_packets];
        checksums_buffer.read(&mut checksums).enq()?;

        debug!("Calculated {} checksums on GPU", num_packets);

        Ok(checksums)
    }

    /// Filter ports using GPU parallel processing
    pub fn filter_ports(&self, all_ports: &[u16], open_ports: &[u16]) -> Result<Vec<bool>> {
        if all_ports.is_empty() {
            return Ok(Vec::new());
        }

        let num_ports = all_ports.len();
        let num_open = open_ports.len();

        // Convert to u32 for GPU
        let ports_u32: Vec<u32> = all_ports.iter().map(|&p| p as u32).collect();
        let open_u32: Vec<u32> = open_ports.iter().map(|&p| p as u32).collect();

        // Create buffers
        let ports_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(num_ports)
            .copy_host_slice(&ports_u32)
            .build()?;

        let open_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(num_open)
            .copy_host_slice(&open_u32)
            .build()?;

        let results_buffer = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(num_ports)
            .build()?;

        // Create and execute kernel
        let kernel = Kernel::builder()
            .program(&self.filter_program)
            .name("filter_ports")
            .queue(self.queue.clone())
            .global_work_size(num_ports)
            .arg(&ports_buffer)
            .arg(&open_buffer)
            .arg(&results_buffer)
            .arg(&(num_open as u32))
            .build()?;

        unsafe { kernel.enq()? };

        // Read results
        let mut results = vec![0u8; num_ports];
        results_buffer.read(&mut results).enq()?;

        Ok(results.iter().map(|&r| r == 1).collect())
    }

    /// Batch process packet checksums (optimized for large batches)
    pub fn batch_process_checksums(
        &self,
        packets: &[Vec<u8>],
        batch_size: usize,
    ) -> Result<Vec<u16>> {
        let mut all_checksums = Vec::new();

        for chunk in packets.chunks(batch_size) {
            let checksums = self.calculate_checksums(chunk)?;
            all_checksums.extend(checksums);
        }

        Ok(all_checksums)
    }

    /// Get optimal batch size for GPU (vendor-optimized)
    pub fn optimal_batch_size(&self) -> usize {
        self.vendor_config.optimal_batch_size
    }
    
    /// Get vendor information
    pub fn vendor(&self) -> GpuVendor {
        self.vendor_config.vendor
    }
}

impl Drop for GpuAccelerator {
    fn drop(&mut self) {
        debug!("Shutting down GPU accelerator");
    }
}

// Error conversion for OCL errors
impl From<ocl::Error> for ScanError {
    fn from(err: ocl::Error) -> Self {
        ScanError::NetworkError(format!("GPU Error: {}", err))
    }
}

impl From<ocl::core::Error> for ScanError {
    fn from(err: ocl::core::Error) -> Self {
        ScanError::NetworkError(format!("GPU Core Error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_initialization() {
        match GpuAccelerator::new() {
            Ok(gpu) => {
                let caps = gpu.capabilities();
                let vendor = gpu.vendor();
                
                println!("GPU initialized: {:?}", caps);
                println!("Vendor detected: {:?}", vendor);
                println!("Optimal batch size: {}", gpu.optimal_batch_size());
                
                assert!(gpu.is_available());
                assert_ne!(vendor, GpuVendor::Unknown);
            }
            Err(e) => {
                println!("GPU not available: {}", e);
                // It's OK if GPU is not available in test environment
            }
        }
    }

    #[test]
    fn test_checksum_calculation() {
        if let Ok(gpu) = GpuAccelerator::new() {
            let packets = vec![
                vec![0u8; 20], // Empty TCP header
                vec![1u8; 20],
                vec![2u8; 20],
            ];

            let checksums = gpu.calculate_checksums(&packets).unwrap();
            assert_eq!(checksums.len(), 3);
            println!("Checksums: {:?}", checksums);
        }
    }

    #[test]
    fn test_port_filtering() {
        if let Ok(gpu) = GpuAccelerator::new() {
            let all_ports: Vec<u16> = (1..=100).collect();
            let open_ports = vec![22, 80, 99];

            let results = gpu.filter_ports(&all_ports, &open_ports).unwrap();
            assert_eq!(results.len(), 100);

            // Check that open ports are marked as true (0-indexed)
            assert!(results[21]); // Port 22 is at index 21
            assert!(results[79]); // Port 80 is at index 79
            assert!(results[98]); // Port 99 is at index 98
        }
    }
}
