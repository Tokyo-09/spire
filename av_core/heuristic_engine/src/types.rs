// heuristic_engine/types.rs

use goblin::{elf::Elf, mach::MachO, pe::PE};

#[derive(Debug, Clone, PartialEq)]
pub enum HeuristicResult {
    Safe,
    Suspicious { score: u8, reason: String },
    Malicious { score: u8, reason: String },
}

#[derive(Debug, Clone)]
pub struct HeuristicRule {
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub check_fn: fn(&FileData) -> Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn to_score(&self) -> u8 {
        match self {
            Severity::Low => 2,
            Severity::Medium => 5,
            Severity::High => 8,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FileType {
    PE,     // Windows executable
    ELF,    // Linux executable
    MachO,  // macOS executable
    Script, // .bat, .ps1, .sh
    Unknown,
}

// Enum to hold parsed file structures, parameterized by lifetime 'a
#[derive(Debug)]
pub enum FileContainer<'a> {
    Elf(Box<Elf<'a>>),
    Pe(Box<PE<'a>>),
    MachO(Box<MachO<'a>>),
    None,
}

#[derive(Debug)]
pub struct FileData<'a> {
    pub bytes: Vec<u8>,
    pub file_type: FileType,
    pub strings: Vec<String>,         // Extracted strings
    pub container: FileContainer<'a>, // Use lifetime 'a
}
