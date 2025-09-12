#[cfg(target_os = "windows")]
use pe::PeImage; // Добавь в Cargo.toml: pe = "0.6"

#[cfg(target_os = "windows")]
pub fn scan_pe_structure(data: &FileData) -> Option<String> {
    if data.file_type != crate::types::FileType::PE {
        return None;
    }

    // Попробуем распарсить как PE
    match PeImage::parse(&data.bytes) {
        Ok(pe) => {
            // 1. Есть ли секция с правами RWX? (очень подозрительно)
            for section in pe.sections() {
                if section.characteristics().contains(
                    pe::SectionCharacteristics::MEM_READ
                        | pe::SectionCharacteristics::MEM_WRITE
                        | pe::SectionCharacteristics::MEM_EXECUTE,
                ) {
                    return Some(
                        "Обнаружена секция с правами RWX (выполнение + запись)".to_string(),
                    );
                }
            }

            // 2. Подозрительные импорты
            let suspicious_imports = [
                "VirtualAlloc",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "ShellExecute",
            ];
            for imp in pe.imports() {
                for lib in imp.dll_name().to_str().unwrap_or("") {
                    if suspicious_imports.iter().any(|&s| lib.contains(s)) {
                        return Some(format!("Подозрительный импорт: {}", lib));
                    }
                }
            }

            // 3. Нет цифровой подписи?
            if !pe.has_authenticode_signature() {
                return Some("Файл не подписан".to_string());
            }
        }
        Err(_) => return None, // Не PE — пропускаем
    }

    None
}

// Для ELF — можно использовать crate `elf`
// Пример: проверка, есть ли `.got.plt`, `.text` с RWX, странные программы-интерпретаторы
pub fn scan_elf_struct() -> Option<String> {
    unimplemented!();
}
