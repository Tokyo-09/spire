use crate::{
    core::{ScanResult, config::Config, hashes::Hasher},
    modules::{db::ThreatDatabase, quarantine::Quarantine},
};

use indicatif::{ProgressBar, ProgressStyle};
use log::error;
use rusqlite::{Connection, Result};
use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;
use yara_x::{Compiler, Scanner as yara_Scanner};

pub enum IocMarksLevel {
    High,
    Medium,
    Low,
}

#[allow(dead_code)]
pub struct Scanner {
    conn: Connection,
    path: PathBuf,
    md5hash: String,
    sha256hash: String,
    config: Config,
}

impl Scanner {
    pub fn check_file(
        conn: &Connection,
        md5hash: String,
        sha256hash: String,
    ) -> Result<Option<ThreatDatabase>, anyhow::Error> {
        let mut stmt =
            conn.prepare("SELECT md5hash, sha256hash, name FROM default_db WHERE md5hash = ?1")?;
        let mut malware_iter = stmt.query_map([md5hash], |row| {
            let md5hash: String = row.get(0)?;
            let sha256hash: String = row.get(1)?;
            let name: String = row.get(2)?;
            Ok(ThreatDatabase {
                name,
                md5hash,
                sha256hash,
            })
        })?;

        if let Some(malware) = malware_iter.next() {
            let malware = malware?;
            return Ok(Some(malware));
        }

        let mut stmt =
            conn.prepare("SELECT md5hash, sha256hash, name FROM default_db WHERE sha256hash = ?1")?;
        let mut malware_iter = stmt.query_map([sha256hash], |row| {
            let md5hash: String = row.get(0)?;
            let sha256hash: String = row.get(1)?;
            let name: String = row.get(2)?;
            Ok(ThreatDatabase {
                name,
                sha256hash,
                md5hash,
            })
        })?;

        if let Some(malware) = malware_iter.next() {
            let malware = malware?;
            return Ok(Some(malware));
        }
        Ok(None)
    }

    pub fn scan_path(conn: &Connection, path: &PathBuf) -> anyhow::Result<Vec<ScanResult>> {
        let mut results: Vec<ScanResult> = Vec::new();

        if path.is_file() {
            // Handle single file
            if !path.exists() {
                anyhow::bail!("File does not exist: {}", path.display());
            }

            let path_display = path.display();
            let pb = ProgressBar::new(1);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
                    .progress_chars("#>-"),
            );
            pb.set_message(format!("Scanning file: {path_display}"));

            let md5hash = Hasher::calculate_md5(path.to_path_buf())?
                .trim()
                .to_lowercase();
            let sha256hash = Hasher::calculate_sha256(path.to_path_buf())?
                .trim()
                .to_lowercase();

            match Scanner::check_file(conn, md5hash.clone(), sha256hash.clone()) {
                Ok(Some(malware)) => {
                    pb.println(format!(
                        "Threat detected in {}: {} (MD5: {}, SHA256: {})",
                        path_display, malware.name, malware.md5hash, malware.sha256hash
                    ));
                    Quarantine::quarantine_file(
                        conn,
                        &ScanResult::Threat {
                            path: path.to_path_buf(),
                            malware: malware.clone(),
                        },
                    )?;
                    pb.println(format!(
                        "Quarantined file {} (MD5: {}, SHA256: {})",
                        malware.name, malware.md5hash, malware.sha256hash
                    ));
                    results.push(ScanResult::Threat {
                        path: path.to_path_buf(),
                        malware,
                    });
                }
                Ok(None) => {
                    pb.println(format!("File clean: {path_display}",));
                    results.push(ScanResult::Clean(path.to_path_buf()));
                }
                Err(e) => {
                    pb.println(format!("Error scanning {path_display}: {e}"));
                    error!("Error: {e}");
                    results.push(ScanResult::Error {
                        path: path.to_path_buf(),
                        error: e.to_string(),
                    });
                }
            }
            pb.inc(1);
            pb.finish_with_message("File scan completed.");
        } else if path.is_dir() {
            // Handle directory
            let total_files: u64 = WalkDir::new(path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .count() as u64;

            let pb = ProgressBar::new(total_files);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
                    .progress_chars("#>-"),
            );
            pb.set_message(format!("Scanning directory: {}", path.display()));

            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let path_display = entry.path().display();
                    pb.set_message(format!("Scanning: {path_display}"));

                    let md5hash = Hasher::calculate_md5(entry.path().to_path_buf())?
                        .trim()
                        .to_lowercase();
                    let sha256hash = Hasher::calculate_sha256(entry.path().to_path_buf())?
                        .trim()
                        .to_lowercase();

                    match Scanner::check_file(conn, md5hash.clone(), sha256hash.clone()) {
                        Ok(Some(malware)) => {
                            pb.println(format!(
                                "Threat detected in {}: {} (MD5: {}, SHA256: {})",
                                path_display, malware.name, malware.md5hash, malware.sha256hash
                            ));
                            Quarantine::quarantine_file(
                                conn,
                                &ScanResult::Threat {
                                    path: entry.path().to_path_buf(),
                                    malware: malware.clone(),
                                },
                            )?;
                            pb.println(format!(
                                "Quarantined file {} (MD5: {}, SHA256: {})",
                                malware.name, malware.md5hash, malware.sha256hash
                            ));
                            results.push(ScanResult::Threat {
                                path: entry.path().to_path_buf(),
                                malware,
                            });
                        }
                        Ok(None) => {
                            pb.println(format!("File clean: {path_display}"));
                            results.push(ScanResult::Clean(entry.path().to_path_buf()));
                        }
                        Err(e) => {
                            pb.println(format!("Error scanning {path_display}: {e}"));
                            error!("Error: {e}");
                            results.push(ScanResult::Error {
                                path: entry.path().to_path_buf(),
                                error: e.to_string(),
                            });
                        }
                    }
                    pb.inc(1);
                }
            }
            pb.finish_with_message("Directory scan completed.");
        } else {
            anyhow::bail!("Path is neither a file nor a directory: {}", path.display());
        }

        Ok(results)
    }

    pub fn scan_yara(
        conn: &Connection,
        rules_path: &PathBuf,
        target_path: &PathBuf,
    ) -> anyhow::Result<Vec<ScanResult>> {
        let mut compiler = Compiler::new();

        // Handle rules_path as file or directory
        if rules_path.is_file() {
            if !rules_path.exists() {
                anyhow::bail!("YARA rules file does not exist: {}", rules_path.display());
            }
            let rules_src = fs::read_to_string(rules_path)?;
            compiler.add_source(&*rules_src).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to compile YARA rules from {}: {}",
                    rules_path.display(),
                    e
                )
            })?;
        } else if rules_path.is_dir() {
            for entry in WalkDir::new(rules_path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_type().is_file()
                        && e.path()
                            .extension()
                            .map(|ext| ext == "yara" || ext == "yar")
                            .unwrap_or(false)
                })
            {
                let rule_file = entry.path();
                let rules_src = fs::read_to_string(rule_file)?;
                compiler.add_source(&*rules_src).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to compile YARA rules from {}: {}",
                        rule_file.display(),
                        e
                    )
                })?;
            }
        } else {
            anyhow::bail!(
                "Rules path is neither a file nor a directory: {}",
                rules_path.display()
            );
        }

        let rules = compiler.build();
        let mut scanner = yara_Scanner::new(&rules);

        let mut results: Vec<ScanResult> = Vec::new();

        if target_path.is_file() {
            match fs::read(target_path) {
                Ok(data) => match scanner.scan(&data) {
                    Ok(scan_results) => {
                        let matching = scan_results.matching_rules();
                        let matching_rules: Vec<String> =
                            matching.map(|rule| rule.identifier().to_string()).collect();
                        if !matching_rules.is_empty() {
                            results.push(ScanResult::YaraThreat {
                                path: target_path.clone(),
                                matching_rules,
                            });
                        } else {
                            results.push(ScanResult::Clean(target_path.clone()));
                        }
                    }
                    Err(e) => {
                        results.push(ScanResult::Error {
                            path: target_path.clone(),
                            error: e.to_string(),
                        });
                    }
                },
                Err(e) => {
                    results.push(ScanResult::Error {
                        path: target_path.clone(),
                        error: format!("Failed to read file: {e}"),
                    });
                }
            }
        } else if target_path.is_dir() {
            let total_files: u64 = WalkDir::new(target_path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .count() as u64;

            let pb = ProgressBar::new(total_files);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
                    .progress_chars("#>-"),
            );
            pb.set_message(format!(
                "YARA scanning directory: {}",
                target_path.display()
            ));

            for entry in WalkDir::new(target_path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let path_display = entry.path().display();
                    pb.set_message(format!("Scanning: {path_display}"));

                    match fs::read(entry.path()) {
                        Ok(data) => match scanner.scan(&data) {
                            Ok(scan_results) => {
                                let matching = scan_results.matching_rules();
                                let matching_rules: Vec<String> =
                                    matching.map(|rule| rule.identifier().to_string()).collect();
                                if !matching_rules.is_empty() {
                                    pb.println(format!(
                                        "Threat detected in {}: YARA matches - {}",
                                        path_display,
                                        matching_rules.join(", ")
                                    ));
                                    Quarantine::quarantine_file(
                                        conn,
                                        &ScanResult::YaraThreat {
                                            path: entry.path().to_path_buf(),
                                            matching_rules: matching_rules.clone(),
                                        },
                                    )?;
                                    pb.println(format!(
                                        "Quarantined file {}: YARA matches - {}",
                                        path_display,
                                        matching_rules.join(", ")
                                    ));
                                    results.push(ScanResult::YaraThreat {
                                        path: entry.path().to_path_buf(),
                                        matching_rules,
                                    });
                                } else {
                                    pb.println(format!("File clean: {path_display}"));
                                    results.push(ScanResult::Clean(entry.path().to_path_buf()));
                                }
                            }
                            Err(e) => {
                                pb.println(format!("Error scanning {path_display}: {e}"));
                                error!("Error: {e}");
                                results.push(ScanResult::Error {
                                    path: entry.path().to_path_buf(),
                                    error: e.to_string(),
                                });
                            }
                        },
                        Err(e) => {
                            pb.println(format!("Error reading {path_display}: {e}"));
                            error!("Error: {e}");
                            results.push(ScanResult::Error {
                                path: entry.path().to_path_buf(),
                                error: format!("Failed to read file: {e}"),
                            });
                        }
                    }
                    pb.inc(1);
                }
            }

            pb.finish_with_message("YARA directory scan completed.");
        } else {
            anyhow::bail!(
                "Target path is neither a file nor a directory: {}",
                target_path.display()
            );
        }

        Ok(results)
    }
}
