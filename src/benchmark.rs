//! Provides functionality to capture timing information for scans.
//!
//! # Usage
//!
//! ```rust
//! // Initiate Benchmark vector
//! # use phobos::benchmark::{Benchmark, NamedTimer};
//! let mut bm = Benchmark::init();
//! // Start named timer with name
//! let mut example_bench = NamedTimer::start("Example Bench");
//! // Stop named timer
//! example_bench.end();
//! // Add named timer to Benchmarks
//! bm.push(example_bench);
//! // Print Benchmark Summary
//! println!("{}", bm.summary());
//! ```
use std::time::Instant;

/// A Benchmark struct to hold NamedTimers with name, start and end Instants,
#[derive(Debug)]
pub struct Benchmark {
    timers: Vec<NamedTimer>,
}

impl Default for Benchmark {
    fn default() -> Self {
        Self {
            timers: Vec::new(),
        }
    }
}

impl Benchmark {
    pub fn init() -> Self {
        Self::default()
    }
    
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn push(&mut self, timer: NamedTimer) {
        self.timers.push(timer);
    }
    
    pub fn add_timer(&mut self, timer: NamedTimer) {
        self.push(timer);
    }

    /// Summary of the benchmarks will destruct the vector,
    /// formats every element the same way and return
    /// a single String with all the available information
    /// for easy printing
    pub fn summary(&self) -> String {
        let mut summary = String::from("\nPhobos Benchmark Summary");

        for timer in &self.timers {
            if timer.start.is_some() && timer.end.is_some() {
                let runtime_secs = timer
                    .end
                    .unwrap()
                    .saturating_duration_since(timer.start.unwrap())
                    .as_secs_f32();
                summary.push_str(&format!("\n{0: <10} | {1: <10}s", timer.name, runtime_secs));
            }
        }
        summary
    }
    
    pub fn print_summary(&self) {
        println!("{}", self.summary());
    }
}

/// The purpose of NamedTimer is to hold a name,
/// start Instant and end Instant for a specific timer.
/// The given name will be presented in the benchmark summary,
/// start and end Instants will be used for calculating runtime.
#[derive(Debug)]
pub struct NamedTimer {
    name: &'static str,
    start: Option<Instant>,
    end: Option<Instant>,
}

impl NamedTimer {
    pub fn start(name: &'static str) -> Self {
        Self {
            name,
            start: Some(Instant::now()),
            end: None,
        }
    }
    
    pub fn end(&mut self) {
        self.end = Some(Instant::now());
    }
    
    pub fn stop(&mut self) {
        self.end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn benchmark() {
        let mut benchmarks = Benchmark::init();
        let mut test_timer = NamedTimer::start("test");
        std::thread::sleep(std::time::Duration::from_millis(100));
        test_timer.end();
        benchmarks.push(test_timer);
        benchmarks.push(NamedTimer::start("only_start"));
        assert!(benchmarks
            .summary()
            .contains("\nPhobos Benchmark Summary\ntest       | 0."));
        assert!(!benchmarks.summary().contains("only_start"));
    }
}