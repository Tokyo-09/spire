use rusqlite::{Connection, Statement};

use install::download_database;

pub mod install;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MalwareDB {
    pub malware_name: String,
    pub md5hash: String,
    pub sha256hash: String,
}

impl MalwareDB {
    pub fn query_db(conn: &Connection) -> anyhow::Result<()> {
        let mut stmt: Statement = conn.prepare("SELECT * FROM default_db")?;
        let ioc_iter = stmt.query_map([], |row| {
            Ok(MalwareDB {
                malware_name: row.get(1)?,
                md5hash: row.get(0)?,
                sha256hash: row.get(3)?,
            })
        })?;

        for ioc in ioc_iter {
            println!("{:?}", ioc?);
        }
        Ok(())
    }

    #[allow(clippy::new_ret_no_self)]
    pub fn new(spire_dir: &str, db_path: &str) -> anyhow::Result<()> {
        download_database(spire_dir, db_path)?;
        Ok(())
    }

    pub fn update_db() -> anyhow::Result<()> {
        unimplemented!();
    }
}
