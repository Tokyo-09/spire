#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MalwareDB {
    pub malware_name: String,
    pub md5hash: String,
    pub sha256hash: String,
}
