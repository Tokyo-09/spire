use std::path::PathBuf;

pub mod commands;

#[derive(clap::Subcommand, Debug)]
pub enum QuarantineAction {
    // List quarantined files
    List {
        #[clap(long, value_parser)]
        db: PathBuf,
    },
    Restore {
        #[clap(long, value_parser)]
        db: PathBuf,
        #[clap(long, value_parser)]
        id: i64,
    },
    Delete {
        #[clap(long, value_parser)]
        db: PathBuf,
        #[clap(long, value_parser)]
        id: i64,
    },
}

#[derive(clap::Subcommand)]
pub enum ConfigAction {
    List {
        // List current config
        db: PathBuf,
    },
    Add {
        db: PathBuf,

        exclude_dir: Option<PathBuf>,

        exclude_extensions: Option<Vec<String>>,

        exclude_processes: Option<Vec<String>>,
    },
    Delete {
        db: PathBuf,

        rule_id: Option<i64>,
    },
}
