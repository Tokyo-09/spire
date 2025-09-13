use anyhow::{Context, Result};
use reqwest::blocking::Client;
use std::fs;
use std::io::Write;
use std::path::Path;
use zip::ZipArchive;

pub fn download_database(spire_dir: &str, db_path: &str) -> Result<()> {
    let client = Client::new();
    // Change in prod!!!!!
    let db_url = "http://127.0.0.1:8080/database.db";
    let yara_url = "http://127.0.0.1:8080/yara.zip";

    // Ensure parent directory exists
    if let Some(parent) = Path::new(db_path).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create parent directory '{}'", parent.display()))?;
    }

    // Create yara_rules directory
    let yara_rules_dir = format!("{}/yara_rules", spire_dir);
    fs::create_dir_all(&yara_rules_dir)
        .with_context(|| format!("Failed to create YARA rules directory '{}'", yara_rules_dir))?;

    // Download database.db
    let response = client
        .get(db_url)
        .send()
        .with_context(|| format!("Failed to send GET request to {}", db_url))?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("Unexpected HTTP status {} when fetching {}", status, db_url);
    }

    // Read database bytes
    let db_bytes = response
        .bytes()
        .with_context(|| format!("Failed to read response body from {}", db_url))?;

    // Write database to temp file then rename atomically
    let db_tmp_path = format!("{}.part", db_path);
    {
        let mut tmp_file = fs::File::create(&db_tmp_path)
            .with_context(|| format!("Failed to create temporary file '{}'", db_tmp_path))?;
        tmp_file
            .write_all(&db_bytes)
            .with_context(|| format!("Failed to write to temporary file '{}'", db_tmp_path))?;
        tmp_file
            .flush()
            .context("Failed to flush temporary database file")?;
    }

    fs::rename(&db_tmp_path, db_path)
        .with_context(|| format!("Failed to rename '{}' -> '{}'", db_tmp_path, db_path))?;

    println!("Database downloaded successfully to: {}", db_path);

    // Download yara.zip
    let yara_response = client
        .get(yara_url)
        .send()
        .with_context(|| format!("Failed to send GET request to {}", yara_url))?;

    let yara_status = yara_response.status();
    if !yara_status.is_success() {
        anyhow::bail!(
            "Unexpected HTTP status {} when fetching {}",
            yara_status,
            yara_url
        );
    }

    // Read yara.zip bytes
    let yara_bytes = yara_response
        .bytes()
        .with_context(|| format!("Failed to read response body from {}", yara_url))?;

    // Write yara.zip to temp file
    let yara_tmp_path = format!("{}/yara.zip.part", spire_dir);
    {
        let mut yara_tmp_file = fs::File::create(&yara_tmp_path)
            .with_context(|| format!("Failed to create temporary file '{}'", yara_tmp_path))?;
        yara_tmp_file
            .write_all(&yara_bytes)
            .with_context(|| format!("Failed to write to temporary file '{}'", yara_tmp_path))?;
        yara_tmp_file
            .flush()
            .context("Failed to flush temporary YARA file")?;
    }

    // Extract yara.zip to yara_rules directory
    let yara_file = fs::File::open(&yara_tmp_path)
        .with_context(|| format!("Failed to open temporary YARA file '{}'", yara_tmp_path))?;
    let mut archive = ZipArchive::new(yara_file)
        .with_context(|| format!("Failed to read ZIP archive from '{}'", yara_tmp_path))?;

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .with_context(|| format!("Failed to read file {} from ZIP archive", i))?;
        let file_path = file
            .enclosed_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid file path in ZIP archive"))?;

        // Only extract .yara or .yar files
        if file_path
            .extension()
            .map(|ext| ext == "yara" || ext == "yar")
            .unwrap_or(false)
        {
            let dest_path = Path::new(&yara_rules_dir).join(file_path);
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create parent directory '{}'", parent.display())
                })?;
            }

            let mut dest_file = fs::File::create(&dest_path)
                .with_context(|| format!("Failed to create file '{}'", dest_path.display()))?;
            std::io::copy(&mut file, &mut dest_file)
                .with_context(|| format!("Failed to extract file '{}'", dest_path.display()))?;
            dest_file
                .flush()
                .context("Failed to flush extracted YARA file")?;
        }
    }

    // Clean up temporary yara.zip file
    fs::remove_file(&yara_tmp_path)
        .with_context(|| format!("Failed to remove temporary file '{}'", yara_tmp_path))?;

    println!("YARA rules extracted successfully to: {}", yara_rules_dir);
    Ok(())
}
