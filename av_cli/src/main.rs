use clap::Parser;
use indicatif::MultiProgress;
use log::{debug, error, info};
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use rusqlite::Connection;
use std::{
    env,
    fs::DirBuilder,
    path::{Path, PathBuf},
    sync::mpsc::channel,
    time::Duration,
};
use sysinfo::System;

use av_core::{
    ScanModes,
    core::{models::ScanResult, scanner::Scanner},
    modules::{db::ThreatDatabase, quarantine::Quarantine},
};
use cli::{
    QuarantineAction,
    commands::{Cli, Command},
};

use generate_report::generate_html_report;

mod cli;
mod generate_report;
mod generated;

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Cli::parse();

    let home_dir = env::var("HOME")?;
    let spire_dir = format!("{}/.spire", home_dir);
    let db_path = format!("{}/database.db", spire_dir);
    let yara_db_path = format!("{}/yara_rules/yara", spire_dir);

    // Проверяем существование директории ~/.spire
    // Cоздаем ее если нет
    if !Path::new(&spire_dir).exists() {
        DirBuilder::new().create(&spire_dir)?;
        debug!("Created directory: {}", spire_dir);
    }

    // Проверяем существование файла database.db
    if !Path::new(&yara_db_path).exists() {
        debug!("Database not found, downloading...");
        ThreatDatabase::new(&spire_dir, &yara_db_path)?;
    } else {
        debug!("Database already exists at: {}", yara_db_path);
    }

    if !Path::new(&db_path).exists() {
        debug!("Database not found, downloading...");
        ThreatDatabase::new(&spire_dir, &db_path)?;
    } else {
        debug!("Database already exists at: {}", db_path);
    }

    let m = MultiProgress::new();

    let conn = Connection::open(&db_path)?;

    match args.command {
        Command::Scan { scan_type } => match scan_type {
            av_core::ScanModes::Full {
                rules,
                path,
                report,
            } => {
                if !path.exists() {
                    anyhow::bail!("Scan path does not exist: {}", path.display());
                }

                let results = Scanner::scan_yara(&conn, &rules, &path)?;
                if let Some(report_path) = report {
                    generate_html_report(&results, &report_path, None)?;
                    m.println(format!("Report generated at: {}", report_path.display()))?;
                }
                // SpireAVCore::heuristic_scan(&path);
                // SpireAVCore::ProcessScan
            }
            av_core::ScanModes::Fast {
                rules,
                path,
                report,
            } => {
                info!("{:?}", rules);
                let results = Scanner::scan_path(&conn, &path)?;
                if let Some(report_path) = report {
                    generate_html_report(&results, &report_path, None)?;
                    m.println(format!("Report generated at: {}", report_path.display()))?;
                }
            }
        },
        Command::YaraScan {
            rules,
            path,
            report,
        } => {
            let results = Scanner::scan_yara(&conn, &rules, &path)?;
            if let Some(report_path) = report {
                generate_html_report(&results, &report_path, None)?;
                m.println(format!("Report generated at: {}", report_path.display()))?;
            }
        }
        Command::ProcessScan { scan_type } => {
            process_scan(&conn, &m, scan_type)?;
        }
        Command::Config { action } => {
            dbg!(action);
            unimplemented!("Not yet working");
        }
        Command::Quarantine { action } => match action {
            QuarantineAction::List {} => {
                let items = Quarantine::list_quarantined(&conn)?;
                for (id, original_path, malware_name, timestamp) in items {
                    let datetime = chrono::DateTime::<chrono::Utc>::from(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64),
                    );
                    let cest_offset =
                        chrono::FixedOffset::east_opt(2 * 3600).expect("Invalid timezone offset");
                    let datetime_cest = datetime.with_timezone(&cest_offset);
                    println!(
                        "ID: {} | Original Path: {} | Malware: {} | Quarantined On: {}",
                        id,
                        original_path,
                        malware_name,
                        datetime_cest.format("%Y-%m-%d %H:%M:%S %Z")
                    );
                }
            }
            QuarantineAction::Restore { id } => {
                Quarantine::restore_quarantined(&conn, id)?;
                println!("Restored item with ID: {id}");
            }
            QuarantineAction::Delete { id } => {
                Quarantine::delete_quarantined(&conn, id)?;
                println!("Deleted item with ID: {id}");
            }
        },
        Command::Monitor { path } => {
            if !path.exists() {
                anyhow::bail!("Monitor path does not exist: {}", path.display());
            }
            monitor_directory(&conn, &path, &m)?;
        }
        Command::UpdateDB { ip } => {
            m.println(format!("Database update not implemented: ip={ip:?}"))?;
            unimplemented!("Database update is not yet implemented");
        }
    }

    Ok(())
}

fn monitor_directory(conn: &Connection, path: &Path, m: &MultiProgress) -> anyhow::Result<()> {
    // Create a channel to receive filesystem events
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            let _ = tx.send(res);
        },
        Config::default().with_poll_interval(Duration::from_secs(1)),
    )?;

    // Watch the directory recursively
    watcher.watch(path, RecursiveMode::Recursive)?;
    m.println(format!("Monitoring directory: {}", path.display()))?;

    // Process filesystem events
    for res in rx {
        match res {
            Ok(event) => {
                // Handle create and modify events
                if event.kind.is_create() || event.kind.is_modify() {
                    for file_path in event.paths {
                        if file_path.is_file() {
                            m.println(format!("Detected change in file: {}", file_path.display()))?;
                            Scanner::scan_path(conn, &file_path)?;
                            // SpireAVCore::heuristic_scan(&file_path)?;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Filesystem watch error: {}", e);
            }
        }
    }

    Ok(())
}

fn process_scan(conn: &Connection, m: &MultiProgress, scan_type: ScanModes) -> anyhow::Result<()> {
    info!("Starting process scan...");

    // Refresh system information
    let mut system = System::new_all();
    system.refresh_all();

    let total_processes = system.processes().len() as u64;

    // Create a progress bar for scanning processes
    let pb = m.add(indicatif::ProgressBar::new(total_processes));
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .expect("Invalid progress style")
            .progress_chars("#>-"),
    );
    pb.set_message("Scanning processes...");

    match scan_type {
        av_core::ScanModes::Full {
            rules,
            path,
            report,
        } => {
            let mut results: Vec<ScanResult> = Vec::new();

            for (pid, process) in system.processes() {
                if let Some(exe_path) = process.exe() {
                    let path_buf = exe_path.to_path_buf();
                    pb.set_message(format!(
                        "Scanning process {:?} (PID: {}): {}",
                        process.name(),
                        pid,
                        exe_path.display()
                    ));

                    let scan_results = Scanner::scan_yara(conn, &rules, &path_buf);

                    match scan_results {
                        Ok(mut res) => {
                            for result in &res {
                                if let ScanResult::Threat { path: _, malware } = result {
                                    // For threats, attempt to kill the process and quarantine the executable
                                    if process.kill() {
                                        info!(
                                            "Terminated malicious process {:?} (PID: {}), malware: {}",
                                            process.name(),
                                            pid,
                                            malware.name,
                                        );
                                        match Quarantine::quarantine_file(conn, result) {
                                            Ok(id) => {
                                                pb.println(format!(
                                                    "Quarantined threat ID: {:?} from process {:?} (PID: {}), malware: {}",
                                                    id,
                                                    process.name(),
                                                    pid,
                                                    malware.name,
                                                ));
                                            }
                                            Err(e) => {
                                                error!(
                                                    "Failed to quarantine {}: {}",
                                                    exe_path.display(),
                                                    e
                                                );
                                            }
                                        }
                                    } else {
                                        error!(
                                            "Failed to terminate process {:?} (PID: {})",
                                            process.name(),
                                            pid
                                        );
                                    }
                                }
                            }
                            results.append(&mut res);
                        }
                        Err(e) => {
                            error!(
                                "Failed to scan process {:?} (PID: {}): {}",
                                process.name(),
                                pid,
                                e
                            );
                        }
                    }
                } else {
                    debug!(
                        "No executable path for process {:?} (PID: {})",
                        process.name(),
                        pid
                    );
                }
                pb.inc(1);
            }

            pb.finish_with_message("Process scan completed.");
        }
        av_core::ScanModes::Fast {
            rules,
            path,
            report,
        } => {
            let mut results: Vec<ScanResult> = Vec::new();

            for (pid, process) in system.processes() {
                if let Some(exe_path) = process.exe() {
                    let path_buf = exe_path.to_path_buf();
                    pb.set_message(format!(
                        "Scanning process {:?} (PID: {}): {}",
                        process.name(),
                        pid,
                        exe_path.display()
                    ));

                    let scan_results = Scanner::scan_path(conn, &path_buf);

                    match scan_results {
                        Ok(mut res) => {
                            for result in &res {
                                if let ScanResult::Threat { path: _, malware } = result {
                                    // For threats, attempt to kill the process and quarantine the executable
                                    if process.kill() {
                                        info!(
                                            "Terminated malicious process {:?} (PID: {}), malware: {}",
                                            process.name(),
                                            pid,
                                            malware.name,
                                        );
                                        match Quarantine::quarantine_file(conn, result) {
                                            Ok(id) => {
                                                pb.println(format!(
                                                    "Quarantined threat ID: {:?} from process {:?} (PID: {}), malware: {}",
                                                    id,
                                                    process.name(),
                                                    pid,
                                                    malware.name,
                                                ));
                                            }
                                            Err(e) => {
                                                error!(
                                                    "Failed to quarantine {}: {}",
                                                    exe_path.display(),
                                                    e
                                                );
                                            }
                                        }
                                    } else {
                                        error!(
                                            "Failed to terminate process {:?} (PID: {})",
                                            process.name(),
                                            pid
                                        );
                                    }
                                }
                            }
                            results.append(&mut res);
                        }
                        Err(e) => {
                            error!(
                                "Failed to scan process {:?} (PID: {}): {}",
                                process.name(),
                                pid,
                                e
                            );
                        }
                    }
                } else {
                    debug!(
                        "No executable path for process {:?} (PID: {})",
                        process.name(),
                        pid
                    );
                }
                pb.inc(1);
            }

            pb.finish_with_message("Process scan completed.");
        }
    }

    // Optionally generate a report if needed
    // generate_html_report(&results, &some_report_path, None)?;

    Ok(())
}
