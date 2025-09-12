// heuristic_engine/utils.rs

use crate::types::{FileContainer, FileData, FileType};
use goblin::{elf::Elf, mach::MachO, pe::PE};

pub fn parse_file<'a>(bytes: &'a [u8]) -> Result<FileData<'a>, Box<dyn std::error::Error>> {
    let (file_type, container) = if bytes.len() >= 4 && &bytes[0..4] == b"\x7FELF" {
        let elf = Elf::parse(bytes)?;
        (FileType::ELF, FileContainer::Elf(Box::new(elf)))
    } else if bytes.len() >= 2 && &bytes[0..2] == b"MZ" {
        let pe = PE::parse(bytes)?;
        (FileType::PE, FileContainer::Pe(Box::new(pe)))
    } else if bytes.len() >= 4
        && (&bytes[0..4] == b"\xFE\xED\xFA\xCE" || &bytes[0..4] == b"\xCE\xFA\xED\xFE")
    {
        let macho = MachO::parse(bytes, 0)?;
        (FileType::MachO, FileContainer::MachO(Box::new(macho)))
    } else {
        (FileType::Unknown, FileContainer::None)
    };

    let strings = extract_ascii_strings(bytes, 4);

    Ok(FileData {
        bytes: bytes.to_vec(),
        file_type,
        strings,
        container,
    })
}

pub fn extract_ascii_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            current.push(b);
        } else {
            if current.len() >= min_len
                && let Ok(s) = String::from_utf8(current.clone())
            {
                strings.push(s);
            }

            current.clear();
        }
    }

    if current.len() >= min_len
        && let Ok(s) = String::from_utf8(current)
    {
        strings.push(s);
    }

    strings
}
