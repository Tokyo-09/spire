#[allow(dead_code)]
pub struct Logs {
    date: String,
    info: Vec<String>,
}

impl Logs {
    pub fn collect_logs() -> Self {
        unimplemented!();
    }

    pub fn write_logs_to_file(&self) -> anyhow::Result<()> {
        unimplemented!();
    }

    pub fn send_logs_to_server(&self) -> anyhow::Result<()> {
        unimplemented!();
    }
}
