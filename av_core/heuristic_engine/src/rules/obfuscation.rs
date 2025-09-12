use crate::types::FileData;

pub fn detect_xor_obfuscation(data: &FileData) -> Option<String> {
    // Простая эвристика: если >50% байтов в файле — не ASCII и не нулевые
    let non_ascii_count = data.bytes.iter().filter(|&&b| !b.is_ascii()).count();
    let total = data.bytes.len();

    if total == 0 {
        return None;
    }

    let ratio = non_ascii_count as f64 / total as f64;

    // Если >70% байтов — нечитаемы, возможно, обфусцировано
    if ratio > 0.7 {
        return Some(
            "Файл содержит высокий уровень нечитаемых байтов (возможная обфускация)".to_string(),
        );
    }

    // Также можно искать повторяющиеся XOR-паттерны — но это сложнее
    // Пример: найти последовательности, где байты отличаются на постоянную величину

    None
}
