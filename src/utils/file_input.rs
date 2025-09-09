//! File input utilities for reading targets from files
//!
//! This module provides functionality to read scan targets from various file formats:
//! - Plain text files with one target per line
//! - CSV files with target information
//! - JSON files with structured target data
//! - Nmap XML output files for target extraction

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use crate::utils::target_parser::{TargetParser, ParsedTarget};

/// File input handler for various target file formats
pub struct FileInputHandler {
    parser: TargetParser,
    max_targets: usize,
    deduplicate: bool,
}

/// Supported file formats for target input
#[derive(Debug, Clone, PartialEq)]
pub enum FileFormat {
    PlainText,
    Csv,
    Json,
    NmapXml,
    Auto, // Auto-detect format
}

/// Target information from file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTarget {
    pub target: String,
    pub ports: Option<Vec<u16>>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// File input statistics
#[derive(Debug, Clone)]
pub struct FileInputStats {
    pub total_lines: usize,
    pub valid_targets: usize,
    pub invalid_targets: usize,
    pub duplicates_removed: usize,
    pub file_format: FileFormat,
}

impl Default for FileInputHandler {
    fn default() -> Self {
        Self {
            parser: TargetParser::default(),
            max_targets: 10000,
            deduplicate: true,
        }
    }
}

impl FileInputHandler {
    /// Create a new file input handler
    pub fn new(max_targets: usize, deduplicate: bool) -> Self {
        Self {
            parser: TargetParser::default(),
            max_targets,
            deduplicate,
        }
    }

    /// Read targets from a file with auto-format detection
    pub fn read_targets_from_file<P: AsRef<Path>>(
        &self,
        file_path: P,
    ) -> Result<(Vec<ParsedTarget>, FileInputStats)> {
        let format = self.detect_file_format(&file_path)?;
        self.read_targets_with_format(file_path, format)
    }

    /// Read targets from a file with specified format
    pub fn read_targets_with_format<P: AsRef<Path>>(
        &self,
        file_path: P,
        format: FileFormat,
    ) -> Result<(Vec<ParsedTarget>, FileInputStats)> {
        let file = File::open(&file_path)
            .with_context(|| format!("Failed to open file: {:?}", file_path.as_ref()))?;

        match format {
            FileFormat::PlainText => self.read_plain_text(file),
            FileFormat::Csv => self.read_csv(file),
            FileFormat::Json => self.read_json(file),
            FileFormat::NmapXml => self.read_nmap_xml(file),
            FileFormat::Auto => {
                let detected_format = self.detect_file_format(&file_path)?;
                self.read_targets_with_format(file_path, detected_format)
            }
        }
    }

    /// Detect file format based on extension and content
    fn detect_file_format<P: AsRef<Path>>(&self, file_path: P) -> Result<FileFormat> {
        let path = file_path.as_ref();
        
        // Check file extension first
        if let Some(extension) = path.extension().and_then(|ext| ext.to_str()) {
            match extension.to_lowercase().as_str() {
                "txt" | "list" => return Ok(FileFormat::PlainText),
                "csv" => return Ok(FileFormat::Csv),
                "json" => return Ok(FileFormat::Json),
                "xml" => return Ok(FileFormat::NmapXml),
                _ => {}
            }
        }

        // Try to detect by content
        let mut file = File::open(path)?;
        let mut buffer = [0; 1024];
        let bytes_read = file.read(&mut buffer)?;
        let content = String::from_utf8_lossy(&buffer[..bytes_read]);

        if content.trim_start().starts_with('{') || content.trim_start().starts_with('[') {
            Ok(FileFormat::Json)
        } else if content.contains("<?xml") || content.contains("<nmaprun") {
            Ok(FileFormat::NmapXml)
        } else if content.contains(',') && content.lines().count() > 1 {
            Ok(FileFormat::Csv)
        } else {
            Ok(FileFormat::PlainText)
        }
    }

    /// Read plain text file (one target per line)
    fn read_plain_text(&self, file: File) -> Result<(Vec<ParsedTarget>, FileInputStats)> {
        let reader = BufReader::new(file);
        let mut targets = Vec::new();
        let mut seen_targets = HashSet::new();
        let mut stats = FileInputStats {
            total_lines: 0,
            valid_targets: 0,
            invalid_targets: 0,
            duplicates_removed: 0,
            file_format: FileFormat::PlainText,
        };

        for line in reader.lines() {
            stats.total_lines += 1;
            
            if targets.len() >= self.max_targets {
                break;
            }

            let line = line?;
            let target_str = line.trim();
            
            // Skip empty lines and comments
            if target_str.is_empty() || target_str.starts_with('#') {
                continue;
            }

            // Check for duplicates
            if self.deduplicate && seen_targets.contains(target_str) {
                stats.duplicates_removed += 1;
                continue;
            }

            // Parse target
            match self.parser.parse_target(target_str) {
                Ok(parsed_target) => {
                    if self.deduplicate {
                        seen_targets.insert(target_str.to_string());
                    }
                    targets.push(parsed_target);
                    stats.valid_targets += 1;
                }
                Err(_) => {
                    stats.invalid_targets += 1;
                    eprintln!("Warning: Invalid target format: {}", target_str);
                }
            }
        }

        Ok((targets, stats))
    }

    /// Read CSV file with target information
    fn read_csv(&self, file: File) -> Result<(Vec<ParsedTarget>, FileInputStats)> {
        let mut reader = csv::Reader::from_reader(file);
        let mut targets = Vec::new();
        let mut seen_targets = HashSet::new();
        let mut stats = FileInputStats {
            total_lines: 0,
            valid_targets: 0,
            invalid_targets: 0,
            duplicates_removed: 0,
            file_format: FileFormat::Csv,
        };

        for result in reader.deserialize() {
            stats.total_lines += 1;
            
            if targets.len() >= self.max_targets {
                break;
            }

            let file_target: FileTarget = match result {
                Ok(target) => target,
                Err(_) => {
                    stats.invalid_targets += 1;
                    continue;
                }
            };

            // Check for duplicates
            if self.deduplicate && seen_targets.contains(&file_target.target) {
                stats.duplicates_removed += 1;
                continue;
            }

            // Parse target
            match self.parser.parse_target(&file_target.target) {
                Ok(parsed_target) => {
                    if self.deduplicate {
                        seen_targets.insert(file_target.target.clone());
                    }
                    targets.push(parsed_target);
                    stats.valid_targets += 1;
                }
                Err(_) => {
                    stats.invalid_targets += 1;
                    eprintln!("Warning: Invalid target format: {}", file_target.target);
                }
            }
        }

        Ok((targets, stats))
    }

    /// Read JSON file with structured target data
    fn read_json(&self, mut file: File) -> Result<(Vec<ParsedTarget>, FileInputStats)> {
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        
        let file_targets: Vec<FileTarget> = serde_json::from_str(&content)
            .context("Failed to parse JSON file")?;

        let mut targets = Vec::new();
        let mut seen_targets = HashSet::new();
        let mut stats = FileInputStats {
            total_lines: file_targets.len(),
            valid_targets: 0,
            invalid_targets: 0,
            duplicates_removed: 0,
            file_format: FileFormat::Json,
        };

        for file_target in file_targets {
            if targets.len() >= self.max_targets {
                break;
            }

            // Check for duplicates
            if self.deduplicate && seen_targets.contains(&file_target.target) {
                stats.duplicates_removed += 1;
                continue;
            }

            // Parse target
            match self.parser.parse_target(&file_target.target) {
                Ok(parsed_target) => {
                    if self.deduplicate {
                        seen_targets.insert(file_target.target.clone());
                    }
                    targets.push(parsed_target);
                    stats.valid_targets += 1;
                }
                Err(_) => {
                    stats.invalid_targets += 1;
                    eprintln!("Warning: Invalid target format: {}", file_target.target);
                }
            }
        }

        Ok((targets, stats))
    }

    /// Read Nmap XML output file and extract targets
    fn read_nmap_xml(&self, mut file: File) -> Result<(Vec<ParsedTarget>, FileInputStats)> {
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        
        let mut targets = Vec::new();
        let mut seen_targets = HashSet::new();
        let mut stats = FileInputStats {
            total_lines: 0,
            valid_targets: 0,
            invalid_targets: 0,
            duplicates_removed: 0,
            file_format: FileFormat::NmapXml,
        };

        // Simple XML parsing for host addresses
        // This is a basic implementation - for production use, consider using a proper XML parser
        for line in content.lines() {
            stats.total_lines += 1;
            
            if targets.len() >= self.max_targets {
                break;
            }

            if let Some(addr) = self.extract_address_from_xml_line(line) {
                // Check for duplicates
                if self.deduplicate && seen_targets.contains(&addr) {
                    stats.duplicates_removed += 1;
                    continue;
                }

                // Parse target
                match self.parser.parse_target(&addr) {
                    Ok(parsed_target) => {
                        if self.deduplicate {
                            seen_targets.insert(addr);
                        }
                        targets.push(parsed_target);
                        stats.valid_targets += 1;
                    }
                    Err(_) => {
                        stats.invalid_targets += 1;
                    }
                }
            }
        }

        Ok((targets, stats))
    }

    /// Extract IP address from Nmap XML line
    fn extract_address_from_xml_line(&self, line: &str) -> Option<String> {
        if line.contains("<address") && line.contains("addr=") {
            if let Some(start) = line.find("addr=\"") {
                let start = start + 6; // Length of 'addr="'
                if let Some(end) = line[start..].find('"') {
                    return Some(line[start..start + end].to_string());
                }
            }
        }
        None
    }

    /// Validate file before processing
    pub fn validate_file<P: AsRef<Path>>(&self, file_path: P) -> Result<()> {
        let path = file_path.as_ref();
        
        if !path.exists() {
            return Err(anyhow::anyhow!("File does not exist: {:?}", path));
        }

        if !path.is_file() {
            return Err(anyhow::anyhow!("Path is not a file: {:?}", path));
        }

        let metadata = std::fs::metadata(path)?;
        if metadata.len() == 0 {
            return Err(anyhow::anyhow!("File is empty: {:?}", path));
        }

        // Check file size (warn if > 100MB)
        if metadata.len() > 100 * 1024 * 1024 {
            eprintln!("Warning: Large file detected ({} MB). Processing may take time.", 
                     metadata.len() / 1024 / 1024);
        }

        Ok(())
    }

    /// Get supported file extensions
    pub fn supported_extensions() -> Vec<&'static str> {
        vec!["txt", "list", "csv", "json", "xml"]
    }
}

/// Utility function to create target list from file
pub fn targets_from_file<P: AsRef<Path>>(
    file_path: P,
    max_targets: Option<usize>,
) -> Result<Vec<ParsedTarget>> {
    let handler = FileInputHandler::new(
        max_targets.unwrap_or(10000),
        true, // deduplicate by default
    );
    
    handler.validate_file(&file_path)?;
    let (targets, stats) = handler.read_targets_from_file(file_path)?;
    
    println!("File input statistics:");
    println!("  Format: {:?}", stats.file_format);
    println!("  Total lines: {}", stats.total_lines);
    println!("  Valid targets: {}", stats.valid_targets);
    println!("  Invalid targets: {}", stats.invalid_targets);
    println!("  Duplicates removed: {}", stats.duplicates_removed);
    
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_plain_text_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "192.168.1.1").unwrap();
        writeln!(temp_file, "10.0.0.0/24").unwrap();
        writeln!(temp_file, "# Comment line").unwrap();
        writeln!(temp_file, "example.com").unwrap();
        
        let handler = FileInputHandler::default();
        let (targets, stats) = handler.read_targets_from_file(temp_file.path()).unwrap();
        
        assert_eq!(stats.valid_targets, 3);
        assert_eq!(targets.len(), 3);
    }

    #[test]
    fn test_json_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let json_content = r#"[
            {"target": "192.168.1.1", "description": "Test target"},
            {"target": "10.0.0.0/24", "ports": [80, 443]}
        ]"#;
        write!(temp_file, "{}", json_content).unwrap();
        
        let handler = FileInputHandler::default();
        let (targets, stats) = handler.read_targets_with_format(
            temp_file.path(),
            FileFormat::Json,
        ).unwrap();
        
        assert_eq!(stats.valid_targets, 2);
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn test_duplicate_removal() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "192.168.1.1").unwrap();
        writeln!(temp_file, "192.168.1.1").unwrap(); // Duplicate
        writeln!(temp_file, "192.168.1.2").unwrap();
        
        let handler = FileInputHandler::new(1000, true); // Enable deduplication
        let (targets, stats) = handler.read_targets_from_file(temp_file.path()).unwrap();
        
        assert_eq!(stats.duplicates_removed, 1);
        assert_eq!(targets.len(), 2);
    }
}