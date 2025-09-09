use crate::modules::db::ThreatDatabase;

use std::path::PathBuf;

pub mod config;
pub mod hashes;
pub mod scanner;

#[derive(Debug, Clone)]
pub struct ProcessScanResult {
    pub pid: u32,
    pub name: String,
    pub path: PathBuf,
    pub result: ScanResult,
}

#[derive(Debug, Clone)]
pub enum ScanResult {
    Clean(PathBuf),
    Threat {
        path: PathBuf,
        malware: ThreatDatabase,
    },
    YaraThreat {
        path: PathBuf,
        matching_rules: Vec<String>,
    },
    Error {
        path: PathBuf,
        error: String,
    },
}
