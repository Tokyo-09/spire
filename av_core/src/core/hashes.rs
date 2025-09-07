use hex;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

#[allow(dead_code)]
pub struct Hasher {
    file: PathBuf,
}

impl Hasher {
    pub fn calculate_md5(file: PathBuf) -> anyhow::Result<String> {
        let mut file = File::open(file).expect("File not found!");
        let mut buffer = Vec::new();

        file.read_to_end(&mut buffer).expect("Failed to read file!");

        let hash = md5::compute(&buffer);

        Ok(format!("{hash:x}"))
    }
    pub fn calculate_sha256(file: PathBuf) -> anyhow::Result<String> {
        let mut file = File::open(file)?;
        let mut hasher = Sha256::new();
        let mut buffer: [u8; 1024] = [0; 1024];

        loop {
            let bytes_read: usize = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[0..bytes_read]);
        }

        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }
}
