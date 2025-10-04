use phobos::{HistoryManager, scanner::ScanResult};
use std::time::Duration;

#[test]
fn test_history_save_and_load() {
    let history = HistoryManager::new().expect("Failed to create history manager");
    
    // Create a mock scan result
    let result = ScanResult {
        target: "127.0.0.1".to_string(),
        open_ports: vec![22, 80, 443],
        closed_ports: vec![],
        filtered_ports: vec![],
        port_results: vec![],
        duration: Duration::from_secs(5),
        stats: phobos::scanner::ScanStats::default(),
    };
    
    // Save scan
    let id = history.save(&result).expect("Failed to save scan");
    assert!(!id.is_empty());
    
    // Load scan
    let loaded = history.get(&id).expect("Failed to load scan");
    assert_eq!(loaded.target, "127.0.0.1");
    assert_eq!(loaded.open_ports, vec![22, 80, 443]);
}

#[test]
fn test_history_list() {
    let history = HistoryManager::new().expect("Failed to create history manager");
    let entries = history.list().expect("Failed to list history");
    // Should not fail even if empty
    assert!(entries.len() >= 0);
}

#[test]
fn test_scan_diff() {
    let history = HistoryManager::new().expect("Failed to create history manager");
    
    // Create first scan
    let result1 = ScanResult {
        target: "127.0.0.1".to_string(),
        open_ports: vec![22, 80],
        closed_ports: vec![],
        filtered_ports: vec![],
        port_results: vec![],
        duration: Duration::from_secs(5),
        stats: phobos::scanner::ScanStats::default(),
    };
    
    // Create second scan with changes
    let result2 = ScanResult {
        target: "127.0.0.1".to_string(),
        open_ports: vec![22, 443], // 80 closed, 443 opened
        closed_ports: vec![],
        filtered_ports: vec![],
        port_results: vec![],
        duration: Duration::from_secs(5),
        stats: phobos::scanner::ScanStats::default(),
    };
    
    let id1 = history.save(&result1).expect("Failed to save first scan");
    let id2 = history.save(&result2).expect("Failed to save second scan");
    
    // Compare scans
    let diff = history.diff(&id1, &id2).expect("Failed to diff scans");
    
    assert_eq!(diff.new_open_ports, vec![443]);
    assert_eq!(diff.closed_ports, vec![80]);
}
