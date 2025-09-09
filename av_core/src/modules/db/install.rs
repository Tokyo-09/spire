use anyhow::{Context, Result};
use reqwest::blocking::Client;
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn download_database(_spire_dir: &str, db_path: &str) -> Result<()> {
    let client = Client::new();
    // Change in prod!!!!!
    let db_url = "http://127.0.0.1:8080/database.db";

    // Ensure parent directory exists
    if let Some(parent) = Path::new(db_path).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory '{}'", parent.display()))?;
    }

    // Perform request
    let response = client
        .get(db_url)
        .send()
        .with_context(|| format!("failed to send GET request to {}", db_url))?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("unexpected HTTP status {} when fetching {}", status, db_url);
    }

    // Read bytes with context
    let bytes = response
        .bytes()
        .with_context(|| format!("failed to read response body from {}", db_url))?;

    // Write to temp file first then atomically rename
    let tmp_path = format!("{}.part", db_path);
    {
        let mut tmp_file = fs::File::create(&tmp_path)
            .with_context(|| format!("failed to create temporary file '{}'", tmp_path))?;
        tmp_file
            .write_all(&bytes)
            .with_context(|| format!("failed to write to temporary file '{}'", tmp_path))?;
        tmp_file.flush().context("failed to flush temporary file")?;
    }

    fs::rename(&tmp_path, db_path)
        .with_context(|| format!("failed to rename '{}' -> '{}'", tmp_path, db_path))?;

    println!("Database downloaded successfully to: {}", db_path);
    Ok(())
}
