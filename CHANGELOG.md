# Changelog

All notable changes to Phobos will be documented in this file.

## [Unreleased]

### Added
- **Scan History & Comparison**: Automatic scan history tracking with comparison capabilities
  - All scans are automatically saved to `~/.phobos/history/`
  - `--history list` - List all previous scans
  - `--history show --history-id <ID>` - View specific scan details
  - `--history diff --history-id <ID1> --compare-with <ID2>` - Compare two scans
  - `--no-history` - Disable automatic history saving
  - Detects newly opened ports, closed ports, and service changes
  - Timeline tracking for monitoring changes over time

### Changed
- Scan results now include automatic history saving by default

### Fixed
- N/A

## [1.1.1] - Previous Release

See README.md for previous features and capabilities.
