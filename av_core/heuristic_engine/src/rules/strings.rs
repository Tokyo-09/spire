use crate::types::FileData;

pub fn scan_suspicious_strings(data: &FileData) -> Option<String> {
    let suspicious_patterns = [
        "cmd.exe /c",
        "powershell -enc",
        "powershell -nop -c",
        "rm -rf /",
        "wget http://",
        "curl http://",
        "base64 -d",
        "exec ",
        "system(",
        "eval(",
        "shell_exec(",
        "CreateRemoteThread",
        "VirtualAlloc",
        "WriteProcessMemory",
        "RegSetValueEx",
        "/etc/passwd",
        "/root/.ssh/",
        "id_rsa",
    ];

    for s in &data.strings {
        for pattern in &suspicious_patterns {
            if s.contains(pattern) {
                return Some(format!("Обнаружена подозрительная строка: '{}'", pattern));
            }
        }
    }

    None
}

// Функция для извлечения ASCII-строк из байтов
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
