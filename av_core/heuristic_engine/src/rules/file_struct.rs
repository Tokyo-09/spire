// heuristic_engine/rules/file_structure.rs

use crate::types::{FileContainer, FileData};
use goblin::elf;

#[cfg(target_os = "windows")]
use goblin::pe;

#[cfg(target_os = "windows")]
pub fn scan_pe_structure(data: &FileData) -> Option<String> {
    let pe = match &data.container {
        FileContainer::Pe(pe) => pe,
        _ => return None, // Not a PE file
    };

    // 🔍 1. Check for RWX sections
    for section in &pe.sections {
        let characteristics = section.characteristics;
        if characteristics & pe::section_table::IMAGE_SCN_MEM_READ != 0
            && characteristics & pe::section_table::IMAGE_SCN_MEM_WRITE != 0
            && characteristics & pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0
        {
            return Some("Detected section with RWX permissions (read+write+execute)".to_string());
        }
    }

    // 🔍 2. Check for suspicious imports
    let suspicious_imports = [
        "VirtualAlloc",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "ShellExecute",
        "WinExec",
        "LoadLibrary",
        "GetProcAddress",
    ];

    for import in &pe.imports {
        let name = import.name.clone();
        if suspicious_imports.iter().any(|&s| name.contains(s)) {
            return Some(format!("Suspicious import: {}", name));
        }
    }

    // 🔍 3. No authenticode signature check (not supported in goblin 0.10)
    None
}

// --- ELF Analysis ---
pub fn scan_elf_structure(data: &FileData) -> Option<String> {
    let elf = match &data.container {
        FileContainer::Elf(elf) => elf,
        _ => return None, // Not an ELF file
    };

    // 🔍 1. Check for RWX segments
    for ph in &elf.program_headers {
        let flags = ph.p_flags;
        let is_read = flags & elf::program_header::PF_R != 0;
        let is_write = flags & elf::program_header::PF_W != 0;
        let is_exec = flags & elf::program_header::PF_X != 0;

        if is_read && is_write && is_exec {
            return Some("Detected segment with RWX permissions (read+write+execute)".to_string());
        }
    }

    // 🔍 2. Check for suspicious interpreter
    if let Some(interp) = elf.interpreter {
        let common_interp = [
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "/usr/lib64/ld-linux-x86-64.so.2",
            "/lib/ld-linux-armhf.so.3", // ARM
        ];
        if !common_interp.iter().any(|&s| interp.contains(s)) {
            return Some(format!("Suspicious interpreter: {}", interp));
        }
    }

    // 🔍 3. Check for suspicious dynamic libraries
    let suspicious_libs = [
        "libsystemd.so",
        "libdl.so",
        "libpthread.so",
        "libm.so",
        "libncurses.so",
    ];

    if let Some(dynamic) = &elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag == elf::dynamic::DT_NEEDED
                && let Some(name) = elf.strtab.get_at(dyn_entry.d_val as usize)
                && suspicious_libs.iter().any(|&s| name.contains(s))
            {
                return Some(format!("Suspicious library in DT_NEEDED: {}", name));
            }
        }
    }

    // 🔍 4. Check for suspicious sections
    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name)
            && (name.starts_with(".gob") || name.starts_with(".crypt") || name.starts_with(".xor"))
        {
            return Some(format!("Detected suspicious section: {}", name));
        }
    }

    // 🔍 5. Check for large file size (>5MB)
    if data.bytes.len() > 5 * 1024 * 1024 {
        return Some("File is very large (>5MB), may contain embedded shellcode".to_string());
    }

    None
}

// --- Mach-O Analysis ---
pub fn scan_macho_structure(data: &FileData) -> Option<String> {
    let _macho = match &data.container {
        FileContainer::MachO(macho) => macho,
        _ => return None, // Not a Mach-O file
    };

    // 🔍 Basic check for large file size (>5MB)
    if data.bytes.len() > 5 * 1024 * 1024 {
        return Some("File is very large (>5MB), may contain embedded shellcode".to_string());
    }

    // TODO: Add more Mach-O specific checks if needed
    None
}
