use std::io::{Cursor, Read, Write};

use crate::findings::{Finding, Severity};

/// Builds a zip archive from raw (entry_name, content) pairs. Entry names are
/// written verbatim, including path-traversal sequences, so this can be used
/// to construct zip-slip proof-of-concept archives (see threat-model.md §2.4).
pub fn build_archive(entries: &[(&str, &[u8])]) -> zip::result::ZipResult<Vec<u8>> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buf);
        let options = zip::write::SimpleFileOptions::default();
        for (name, content) in entries {
            writer.start_file(*name, options)?;
            writer.write_all(content)?;
        }
        writer.finish()?;
    }
    Ok(buf.into_inner())
}

fn traversal_reason(name: &str) -> Option<&'static str> {
    if name.contains("..") {
        Some("chứa \"..\" (parent directory reference)")
    } else if name.starts_with('/') {
        Some("đường dẫn tuyệt đối kiểu Unix (bắt đầu bằng \"/\")")
    } else if name.as_bytes().get(1) == Some(&b':') {
        Some("đường dẫn tuyệt đối kiểu Windows (ổ đĩa X:)")
    } else if name.contains('\\') {
        Some("chứa \"\\\" (Windows path separator lẫn trong tên entry)")
    } else {
        None
    }
}

/// Scans a zip archive's stated entry names for zip-slip (path traversal)
/// patterns. Only inspects names — never extracts — so it is safe to run
/// against untrusted input.
pub fn scan_archive(bytes: &[u8]) -> zip::result::ZipResult<Vec<Finding>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    let mut findings = Vec::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        let name = file.name().to_string();
        if let Some(reason) = traversal_reason(&name) {
            findings.push(Finding {
                severity: Severity::Critical,
                message: format!(
                    "Tên entry {reason} — có thể ghi đè file ngoài thư mục giải nén dự kiến"
                ),
                entry_name: name,
            });
        }
    }
    Ok(findings)
}

/// Reads a specific entry's contents by index, for manual inspection.
pub fn read_entry(bytes: &[u8], index: usize) -> zip::result::ZipResult<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    let mut file = archive.by_index(index)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(content)
}
