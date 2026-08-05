use std::path::Path;

use cxf_audit::{scan_source, Severity};

#[test]
fn unrecognized_extension_returns_none() {
    assert!(scan_source(Path::new("README.md"), "# hello").is_none());
}

mod rust_rule {
    use super::*;

    #[test]
    fn flags_raw_by_index_extraction() {
        let source = r#"
fn extract(bytes: &[u8]) {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let outpath = std::path::Path::new("/tmp/out").join(file.name());
        let mut outfile = std::fs::File::create(outpath).unwrap();
        std::io::copy(&mut file, &mut outfile).unwrap();
    }
}
"#;
        let findings = scan_source(Path::new("src/importer.rs"), source).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].line > 0);
    }

    #[test]
    fn downgrades_severity_when_cxf_audit_referenced_in_file() {
        let source = r#"
fn extract(bytes: &[u8]) {
    cxf_audit::assert_safe_archive(bytes).unwrap();
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut file = archive.by_index(0).unwrap();
}
"#;
        let findings = scan_source(Path::new("src/importer.rs"), source).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn does_not_flag_unrelated_method_calls() {
        let source = r#"
fn greet(name: &str) -> String {
    name.to_uppercase().trim().to_string()
}
"#;
        let findings = scan_source(Path::new("src/lib.rs"), source).unwrap();
        assert!(findings.is_empty());
    }
}

mod kotlin_rule {
    use super::*;

    #[test]
    fn flags_file_constructed_from_entry_name() {
        let source = r#"
fun extract(zipFile: File, destDir: File) {
    ZipInputStream(FileInputStream(zipFile)).use { zis ->
        var entry = zis.nextEntry
        while (entry != null) {
            val outFile = File(destDir, entry.name)
            FileOutputStream(outFile).use { fos -> zis.copyTo(fos) }
            entry = zis.nextEntry
        }
    }
}
"#;
        let findings = scan_source(Path::new("Importer.kt"), source).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn does_not_flag_file_constructed_from_fixed_name() {
        let source = r#"
fun makeConfig(destDir: File): File {
    return File(destDir, "config.json")
}
"#;
        let findings = scan_source(Path::new("Config.kt"), source).unwrap();
        assert!(findings.is_empty());
    }
}

mod swift_rule {
    use super::*;

    #[test]
    fn flags_archive_extract_call() {
        let source = r#"
func extract(archive: Archive, to destDir: URL) {
    for entry in archive {
        let destinationURL = destDir.appendingPathComponent(entry.path)
        try? archive.extract(entry, to: destinationURL)
    }
}
"#;
        let findings = scan_source(Path::new("Importer.swift"), source).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn does_not_flag_unrelated_calls() {
        let source = r#"
func greet(name: String) -> String {
    return name.uppercased()
}
"#;
        let findings = scan_source(Path::new("Greet.swift"), source).unwrap();
        assert!(findings.is_empty());
    }
}
