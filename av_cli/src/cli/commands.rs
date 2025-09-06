use clap::{Parser, Subcommand};
use std::{net::Ipv4Addr, path::PathBuf};

use crate::cli::QuarantineAction;

#[derive(Parser, Debug)]
#[command(
    version = "0.0.3",
    name = "Rust Sentinel",
    about = "Simple rust AntiVirus"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Scan {
        // Path to database
        #[arg(long)]
        db: PathBuf,
        // Directory or file to scan
        #[arg(long)]
        path: PathBuf,
        // Generate report
        #[arg(long)]
        report: Option<PathBuf>,
    },
    YaraScan {
        #[arg(long)]
        db: PathBuf,
        //Path with yara rules
        #[arg(long)]
        rules: PathBuf,
        //Path to scan
        #[arg(long)]
        path: PathBuf,
        // Report
        #[clap(long, value_parser)]
        report: Option<PathBuf>,
    },
    ProcessScan {
        #[arg(long)]
        db: PathBuf,

        #[clap(long)]
        yara_rules: Option<PathBuf>,
    },
    Quarantine {
        #[clap(subcommand)]
        action: QuarantineAction,
    },
    Config {
        #[clap(subcommand)]
        action: QuarantineAction,
    },
    Monitor {
        // Database
        #[arg(long)]
        db: PathBuf,

        // Excluded directories
        #[arg(long)]
        excluded_dirs: Vec<PathBuf>,

        // Excluded file extensions
        #[arg(long)]
        excluded_extensions: Vec<String>,

        // Periodic scan time
        #[arg(long)]
        scan_time: String,
    },
    UpdateDB {
        // Server ip address
        ip: Ipv4Addr,
    },
}
