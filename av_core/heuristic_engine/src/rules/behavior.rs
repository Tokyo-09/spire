// Эта функция вызывается при запуске процесса, а не при сканировании файла
pub fn analyze_process_behavior(command_line: &str, env_vars: &[&str]) -> Option<String> {
    if command_line.contains("powershell -enc") && env_vars.iter().any(|e| e.contains("TEMP")) {
        return Some(
            "Запущен PowerShell с зашифрованным кодом из временной директории".to_string(),
        );
    }

    if command_line.contains("curl")
        && command_line.contains("http://")
        && !command_line.contains("github.com")
    {
        return Some("Подозрительный исходящий HTTP-запрос через curl".to_string());
    }

    None
}
