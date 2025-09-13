pub mod rules;
pub mod types;
pub mod utils;

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
                #[cfg(target_os = "windows")]
                HeuristicRule {
                    name: "elf_rwx_section",
                    description: "Проверка наличия RWX-секций в PE-файле",
                    severity: Severity::High,
                    check_fn: file_struct::scan_pe_structure,
                },
                HeuristicRule {
                    name: "pe_rwx_section",
                    description: "Проверка наличия RWX-секций в PE-файле",
                    severity: Severity::High,
                    check_fn: file_struct::scan_elf_structure,
                },
                HeuristicRule {
                    name: "xor_obfuscation",
                    description: "Obfuscation detection",
                    severity: Severity::Medium,
                    check_fn: obfuscation::detect_xor_obfuscation,
                },
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
