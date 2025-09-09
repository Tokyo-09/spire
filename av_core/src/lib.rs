pub mod core;
pub mod db;
pub mod modules;
mod rules;

pub fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}
