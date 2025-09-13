use heuristic_engine::types::FileContainer;
use heuristic_engine::utils::parse_file;
use heuristic_engine::{
    HeuristicEngine,
    types::{FileData, FileType, HeuristicResult},
};
use std::path::PathBuf;

pub mod core;
pub mod modules;

#[derive(clap::Subcommand, Debug)]
pub enum ScanModes {
    Fast {
        // Directory or file to scan
        #[arg(long)]
        path: PathBuf,
        // Generate report
        #[arg(long)]
        report: Option<PathBuf>,
    },
    Full {
        //Path with yara rules
        #[arg(long)]
        rules: PathBuf,
        //Path to scan
        #[arg(long)]
        path: PathBuf,
        // Report
        #[clap(long, value_parser)]
        report: Option<PathBuf>,
    },
}

pub struct SpireAVCore {}

impl SpireAVCore {
    pub fn heuristic_scan(path: &PathBuf) {
        let engine = HeuristicEngine::new();

        let file_path = path;
        let bytes = std::fs::read(file_path).expect("Не удалось прочитать файл");

        // Parse the file
        let file_data = match parse_file(&bytes) {
            Ok(data) => data,
            Err(_) => {
                // If parsing fails, fall back to string-based heuristics
                let strings = heuristic_engine::utils::extract_ascii_strings(&bytes, 4);
                FileData {
                    bytes,
                    file_type: FileType::Unknown,
                    strings,
                    container: FileContainer::None,
                }
            }
        };

        match engine.scan(&file_data) {
            HeuristicResult::Safe => println!("✅ Безопасно"),
            HeuristicResult::Suspicious { score, reason } => {
                println!("⚠️ Подозрительно (балл: {})", score);
                println!("   Причина: {}", reason);
            }
            HeuristicResult::Malicious { score, reason } => {
                println!("❌ Вредоносный (балл: {})", score);
                println!("   Причина: {}", reason);
            }
        }
    }
}
