//! Scan options and configurations

use rand::seq::SliceRandom;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOrder {
    Serial,
    Random,
}

impl Default for ScanOrder {
    fn default() -> Self {
        Self::Serial
    }
}

impl ScanOrder {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "serial" | "seq" | "sequential" => Some(Self::Serial),
            "random" | "rand" | "shuffle" => Some(Self::Random),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub scan_order: ScanOrder,
    pub tries: u8,
    pub timeout: Duration,
    pub batch_size: u16,
    pub threads: u16,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            scan_order: ScanOrder::Serial,
            tries: 1,
            timeout: Duration::from_millis(2000),
            batch_size: 1000,
            threads: 100,
        }
    }
}

impl ScanOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_scan_order(mut self, order: ScanOrder) -> Self {
        self.scan_order = order;
        self
    }

    pub fn with_tries(mut self, tries: u8) -> Self {
        self.tries = tries.max(1);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_batch_size(mut self, batch_size: u16) -> Self {
        self.batch_size = batch_size;
        self
    }

    pub fn with_threads(mut self, threads: u16) -> Self {
        self.threads = threads;
        self
    }
}

/// Order ports according to scan strategy
pub fn order_ports(ports: Vec<u16>, scan_order: ScanOrder) -> Vec<u16> {
    match scan_order {
        ScanOrder::Serial => ports,
        ScanOrder::Random => {
            let mut rng = rand::thread_rng();
            let mut shuffled = ports;
            shuffled.shuffle(&mut rng);
            shuffled
        }
    }
}

/// Retry mechanism for failed scans
pub async fn retry_operation<F, T, E>(
    mut operation: F,
    max_tries: u8,
    delay_ms: u64,
) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
{
    let mut attempts = 0;
    let max_attempts = max_tries.max(1);

    loop {
        attempts += 1;
        
        match operation() {
            Ok(result) => return Ok(result),
            Err(error) => {
                if attempts >= max_attempts {
                    return Err(error);
                }
                
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }
}