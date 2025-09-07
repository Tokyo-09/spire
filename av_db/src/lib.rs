use crate::models::MalwareDB;
use update::update::fetch_updates;

use rusqlite::{Connection, Statement};

pub mod models;
pub mod update;

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

    pub fn new() -> Self {
        unimplemented!();
    }

    pub fn update_db() -> anyhow::Result<()> {
        fetch_updates()?;

        unimplemented!();
    }
}
