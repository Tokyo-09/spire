use clap::Parser;
use rusqlite::Connection;
use indicatif::MultiProgress;

use av_core::actions::quarantine::Quarantine;
use av_core::scanner::analysis::{scan_path, scan_yara};

use crate::cli::QuarantineAction;
use cli::commands::{Cli, Command};
use generate_report::generate_html_report;

mod cli;
mod generate_report;

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Cli::parse();
    let m = MultiProgress::new();

    match args.command {
        Command::Scan { db, path, report } => {
            let conn = Connection::open(&db)?;
            let results = scan_path(&conn, &path)?;
            if let Some(report_path) = report {
                generate_html_report(&results, &report_path, None)?;
                m.println(format!("Report generated at: {}", report_path.display()))?;
            }
        }
        Command::YaraScan {
            db,
            rules,
            path,
            report,
        } => {
            if !path.exists() {
                anyhow::bail!("Scan path does not exist: {}", path.display());
            }
            let conn = Connection::open(&db)?;
            let results = scan_yara(&conn, &rules, &path)?;
            if let Some(report_path) = report {
                generate_html_report(&results, &report_path, None)?;
                m.println(format!("Report generated at: {}", report_path.display()))?;
            }
        }
        Command::ProcessScan { db, yara_rules } => {
            dbg!(db, yara_rules);
            unimplemented!("Not yet working");
        }
        Command::Config { action } => {
            dbg!(action);
            unimplemented!("Not yet working");
        }
        Command::Quarantine { action } => match action {
            QuarantineAction::List { db } => {
                let conn = Connection::open(&db)?;
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
            QuarantineAction::Restore { db, id } => {
                let conn = Connection::open(&db)?;
                Quarantine::restore_quarantined(&conn, id)?;
                println!("Restored item with ID: {id}");
            }
            QuarantineAction::Delete { db, id } => {
                let conn = Connection::open(&db)?;
                Quarantine::delete_quarantined(&conn, id)?;
                println!("Deleted item with ID: {id}");
            }
        },
        Command::Monitor {
            db,
            excluded_dirs,
            excluded_extensions,
            scan_time,
        } => {
            m.println(format!(
                "Monitor not implemented: db={db:?}, excluded_dirs={excluded_dirs:?}, excluded_extensions={excluded_extensions:?}, scan_time={scan_time:?}"
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
