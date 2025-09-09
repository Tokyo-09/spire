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
        // Directory or file to scan
        #[arg(long)]
        path: PathBuf,
        // Generate report
        #[arg(long)]
        report: Option<PathBuf>,
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
    Monitor {},
    UpdateDB {
        // Server ip address
        ip: Option<Ipv4Addr>,
    },
}
