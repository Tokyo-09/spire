use av_db::models::MalwareDB;

use std::path::PathBuf;

pub mod analysis;
pub mod hashes;

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
        malware: MalwareDB,
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
