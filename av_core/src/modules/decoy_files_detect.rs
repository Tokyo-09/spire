use std::fs;
#[cfg(target_os = "windows")]
use std::path::Path;
use walkdir::WalkDir;

// Структура для хранения подозрительного файла
#[derive(Debug)]
pub struct SuspiciousFile {
    pub path: String,
    pub reason: Reason,
}

#[derive(Debug)]
pub enum Reason {
    Hidden,
    Symlink,
    DoubleExtension,
}

pub fn detect_decoy_files(start_path: &str) -> Vec<SuspiciousFile> {
    let mut suspicious = Vec::new();

    for entry in WalkDir::new(start_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            // Пропускаем директории и другие типы
            continue;
        }

        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let metadata = fs::metadata(path);
        match metadata {
            Ok(meta) => {
                let file_type = meta.file_type();

                // Проверка на symlink
                if file_type.is_symlink() {
                    suspicious.push(SuspiciousFile {
                        path: path.to_string_lossy().to_string(),
                        reason: Reason::Symlink,
                    });
                    continue;
                }

                // Проверка на hidden
                if is_hidden_file(
                    &file_name,
                    #[cfg(target_os = "windows")]
                    &meta,
                    #[cfg(target_os = "windows")]
                    path,
                ) {
                    suspicious.push(SuspiciousFile {
                        path: path.to_string_lossy().to_string(),
                        reason: Reason::Hidden,
                    });
                }

                // Проверка на двойные расширения
                if has_double_extension(&file_name) {
                    suspicious.push(SuspiciousFile {
                        path: path.to_string_lossy().to_string(),
                        reason: Reason::DoubleExtension,
                    });
                }
            }
            Err(_) => continue, // Пропускаем файлы без доступа
        }
    }

    suspicious
}

fn is_hidden_file(
    file_name: &str,
    #[cfg(target_os = "windows")] meta: &fs::Metadata,
    #[cfg(target_os = "windows")] _path: &Path,
) -> bool {
    if file_name.starts_with('.') {
        return true;
    }

    // Для Windows: проверка атрибута hidden (требует cfg)
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        if (meta.file_attributes() & FILE_ATTRIBUTE_HIDDEN) != 0 {
            return true;
        }
    }

    false
}

// Проверка на двойные расширения (простая эвристика)
fn has_double_extension(file_name: &str) -> bool {
    let parts: Vec<&str> = file_name.rsplitn(2, '.').collect();
    if parts.len() < 2 {
        return false;
    }

    let extension = parts[0].to_lowercase();
    let base_name = parts[1];

    // Подозрительно, если базовое имя тоже имеет расширение (двойная точка) или комбинация вроде .txt.exe
    base_name.contains('.')
        || (extension == "exe" || extension == "bat" || extension == "js")
            && (base_name.ends_with("txt")
                || base_name.ends_with("doc")
                || base_name.ends_with("jpg"))
}
