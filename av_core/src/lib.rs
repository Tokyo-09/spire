use heuristic_engine::{
    HeuristicEngine,
    types::{FileData, FileType, HeuristicResult},
};

pub mod core;
pub mod modules;

pub enum ScanModes {
    Static,
    Dynamic,
}

pub struct SpireAVCore {}

impl SpireAVCore {
    pub fn heuristic_scan() {
        let engine = HeuristicEngine::new();

        let file_path = "../../test_files/malware.py";
        let bytes = std::fs::read(file_path).expect("Не удалось прочитать файл");

        // Определи тип файла (можно через magic bytes)
        let file_type = if bytes.starts_with(&[0x4D, 0x5A]) {
            // MZ header
            FileType::PE
        } else if bytes.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
            // ELF
            FileType::ELF
        } else if file_path.ends_with(".ps1") || file_path.ends_with(".bat") {
            FileType::Script
        } else {
            FileType::Unknown
        };

        let strings = heuristic_engine::rules::strings::extract_ascii_strings(&bytes, 4);

        let file_data = FileData {
            bytes,
            file_type,
            strings,
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
