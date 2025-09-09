use clap::Parser;
use indicatif::MultiProgress;
use rusqlite::Connection;
use std::env;
use std::fs::DirBuilder;
use std::path::Path;

use av_core::core::scanner::{scan_path, scan_yara};
use av_core::modules::db::MalwareDB;
use av_core::modules::quarantine::Quarantine;

use crate::cli::QuarantineAction;
use cli::commands::{Cli, Command};
use generate_report::generate_html_report;

mod cli;
mod generate_report;

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let home_dir = env::var("HOME")?;
    let spire_dir = format!("{}/.spire", home_dir);
    let db_path = format!("{}/database.db", spire_dir);

    // Проверяем существование директории ~/.spire
    if !Path::new(&spire_dir).exists() {
        // Создаем директорию, если ее нет
        DirBuilder::new().create(&spire_dir)?;
        println!("Created directory: {}", spire_dir);
    }

    // Проверяем существование файла database.db
    if !Path::new(&db_path).exists() {
        println!("Database not found, downloading...");
        MalwareDB::new(&spire_dir, &db_path)?;
    } else {
        println!("Database already exists at: {}", db_path);
    }

    let m = MultiProgress::new();

    match args.command {
        Command::Scan { path, report } => {
            let conn = Connection::open(&db_path)?;
            let results = scan_path(&conn, &path)?;
            if let Some(report_path) = report {
                generate_html_report(&results, &report_path, None)?;
                m.println(format!("Report generated at: {}", report_path.display()))?;
            }
        }
        Command::YaraScan {
            rules,
            path,
            report,
        } => {
            if !path.exists() {
                anyhow::bail!("Scan path does not exist: {}", path.display());
            }
            let conn = Connection::open(&db_path)?;
            let results = scan_yara(&conn, &rules, &path)?;
            if let Some(report_path) = report {
                generate_html_report(&results, &report_path, None)?;
                m.println(format!("Report generated at: {}", report_path.display()))?;
            }
        }
        Command::ProcessScan { yara_rules } => {
            dbg!(yara_rules);
            unimplemented!("Not yet working");
        }
        Command::Config { action } => {
            dbg!(action);
            unimplemented!("Not yet working");
        }
        Command::Quarantine { action } => match action {
            QuarantineAction::List {} => {
                let conn = Connection::open(&db_path)?;
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
                let conn = Connection::open(&db_path)?;
                Quarantine::restore_quarantined(&conn, id)?;
                println!("Restored item with ID: {id}");
            }
            QuarantineAction::Delete { id } => {
                let conn = Connection::open(&db_path)?;
                Quarantine::delete_quarantined(&conn, id)?;
                println!("Deleted item with ID: {id}");
            }
        },
        Command::Monitor {
            excluded_dirs,
            excluded_extensions,
            scan_time,
        } => {
            m.println(format!(
                "Monitor not implemented: excluded_dirs={excluded_dirs:?}, excluded_extensions={excluded_extensions:?}, scan_time={scan_time:?}"
            ))?;
            unimplemented!("Monitor functionality is not yet implemented");
        }
        Command::UpdateDB { ip } => {
            m.println(format!("Database update not implemented: ip={ip:?}"))?;
            unimplemented!("Database update is not yet implemented");
        }
    }

    Ok(())
}
