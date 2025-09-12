pub mod rules;
pub mod types;

use crate::rules::*;
use crate::types::*;

pub struct HeuristicEngine {
    rules: Vec<HeuristicRule>,
}

impl HeuristicEngine {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        HeuristicEngine {
            rules: vec![
                HeuristicRule {
                    name: "suspicious_strings",
                    description: "Поиск подозрительных команд в строках файла",
                    severity: Severity::High,
                    check_fn: strings::scan_suspicious_strings,
                },
                /*                 HeuristicRule {
                    name: "pe_rwx_section",
                    description: "Проверка наличия RWX-секций в PE-файле",
                    severity: Severity::High,
                    #[cfg(target_os = "windows")]
                    check_fn: file_struct::scan_pe_structure,
                    #[cfg(target_os = "linux")]
                    check_fn: file_struct::scan_elf_struct,
                },
                */
                HeuristicRule {
                    name: "xor_obfuscation",
                    description: "Обнаружение обфускации через нечитаемые байты",
                    severity: Severity::Medium,
                    check_fn: obfuscation::detect_xor_obfuscation,
                },
                // Добавляй новые правила по мере развития!
            ],
        }
    }

    pub fn scan(&self, file_data: &FileData) -> HeuristicResult {
        let mut total_score = 0;
        let mut reasons = Vec::new();

        for rule in &self.rules {
            if let Some(reason) = (rule.check_fn)(file_data) {
                total_score += rule.severity.to_score();
                reasons.push(reason);
            }
        }

        if total_score >= 15 {
            HeuristicResult::Malicious {
                score: total_score,
                reason: reasons.join("; "),
            }
        } else if total_score >= 8 {
            HeuristicResult::Suspicious {
                score: total_score,
                reason: reasons.join("; "),
            }
        } else {
            HeuristicResult::Safe
        }
    }
}
