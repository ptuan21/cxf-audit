use std::fs;
use std::io::Cursor;

pub fn extract_unsafe(bytes: &[u8], dest_dir: &str) {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let name = file.name().to_string();
        let outpath = std::path::Path::new(dest_dir).join(&name);
        // ruleid: zip-slip-taint-rust
        let mut outfile = fs::File::create(&outpath).unwrap();
        std::io::copy(&mut file, &mut outfile).unwrap();
    }
}

pub fn extract_safe(bytes: &[u8], dest_dir: &str) {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let name = file.name().to_string();
        if name.contains("..") {
            continue;
        }
        let outpath = std::path::Path::new(dest_dir).join(&name);
        // ok: zip-slip-taint-rust
        let mut outfile = fs::File::create(&outpath).unwrap();
        std::io::copy(&mut file, &mut outfile).unwrap();
    }
}

pub fn write_log(dest_dir: &str) {
    let outpath = std::path::Path::new(dest_dir).join("app.log");
    // ok: zip-slip-taint-rust
    let _ = fs::File::create(&outpath).unwrap();
}
