use clap::Parser;
use indicatif::MultiProgress;
use log::debug;
use rusqlite::Connection;

use std::{env, fs::DirBuilder, path::Path};

use av_core::SpireAVCore;
use av_core::{
    core::scanner::Scanner,
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

    //    let heuristic_scan = SpireAVCore::heuristic_scan();
    //    dbg!(heuristic_scan);

    // Проверяем существование директории ~/.spire
    // Cоздаем ее если нет
    if !Path::new(&spire_dir).exists() {
        DirBuilder::new().create(&spire_dir)?;
        debug!("Created directory: {}", spire_dir);
    }

    // Проверяем существование файла database.db
    if !Path::new(&db_path).exists() {
        debug!("Database not found, downloading...");
        ThreatDatabase::new(&spire_dir, &db_path)?;
    } else {
        debug!("Database already exists at: {}", db_path);
    }

    let m = MultiProgress::new();

    let conn = Connection::open(&db_path)?;

    match args.command {
        Command::Scan { path, report } => {
            let results = Scanner::scan_path(&conn, &path)?;
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
            let results = Scanner::scan_yara(&conn, &rules, &path)?;
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
        Command::Monitor {} => {
            "Monitor not implemented".to_string();
            unimplemented!("Monitor functionality is not yet implemented");
        }
        Command::UpdateDB { ip } => {
            m.println(format!("Database update not implemented: ip={ip:?}"))?;
            unimplemented!("Database update is not yet implemented");
        }
    }

    Ok(())
}
