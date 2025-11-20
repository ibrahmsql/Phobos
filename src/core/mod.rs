// Core module - Fundamental traits and types
pub mod scanner_trait;

pub use scanner_trait::{
    PortScanner,
    PortResult,
    PortState,
    ScanError,
    ScanResult,
    ScannerCapabilities,
    ScannerFactory,
    TcpConnectScanner,
    SynScanner,
};
