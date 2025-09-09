use std::io::prelude::*;

pub fn list_zip_contents(reader: impl Read + Seek) -> zip::result::ZipResult<()> {
    let mut zip = zip::ZipArchive::new(reader)?;

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        println!("Filename: {}", file.name());
        std::io::copy(&mut file, &mut std::io::stdout())?;
    }

    Ok(())
}
