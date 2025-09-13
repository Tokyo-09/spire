use clap::{Parser, Subcommand};
use std::{net::Ipv4Addr, path::PathBuf};

use crate::cli::QuarantineAction;
use av_core::ScanModes;

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
        #[clap(subcommand)]
        scan_type: ScanModes,
    },
    YaraScan {
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
        #[clap(long)]
        yara_rules: PathBuf,
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
        path: PathBuf,
    },
    UpdateDB {
        // Server ip address
        ip: Option<Ipv4Addr>,
    },
}
