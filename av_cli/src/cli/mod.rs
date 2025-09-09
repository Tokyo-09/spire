use std::path::PathBuf;

pub mod commands;

#[derive(clap::Subcommand, Debug)]
pub enum QuarantineAction {
    // List quarantined files
    List {},
    Restore {
        #[clap(long, value_parser)]
        id: i64,
    },
    Delete {
        #[clap(long, value_parser)]
        id: i64,
    },
}

#[derive(clap::Subcommand)]
pub enum ConfigAction {
    List {},
    Add {
        exclude_dir: Option<PathBuf>,

        exclude_extensions: Option<Vec<String>>,

        exclude_processes: Option<Vec<String>>,
    },
    Delete {
        rule_id: Option<i64>,
    },
}
