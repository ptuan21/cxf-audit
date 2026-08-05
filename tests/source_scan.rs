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
        // 1 zip-slip finding (by_index) + 1 companion zip-bomb finding (no
        // resource-limit guard anywhere in the file).
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].message.contains("by_index"));
        assert_eq!(findings[1].severity, Severity::Info);
        assert!(findings[1].message.contains("zip-bomb"));
        assert!(findings[0].line > 0 && findings[1].line > 0);
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
        // Still 2 findings: cxf_audit reference in file only downgrades the
        // zip-slip finding's severity — it does not imply a resource-limit
        // guard (that requires assert_within_limits/check_resource_limits/
        // ZipLimits specifically), so the zip-bomb finding still fires.
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[1].severity, Severity::Info);
    }

    /// Real-world case, not synthetic: georust/transitfeed's
    /// `sanitize_filename` uses exactly this idiom (Path::components()
    /// filtered to Component::Normal) to strip `..`/absolute-path segments
    /// before joining an untrusted zip entry name onto an output dir — a
    /// legitimate, textbook-safe guard our own `.contains("..")`-based
    /// detection previously didn't recognize (found by running scan-source
    /// against that repo and checking the flagged code by hand).
    #[test]
    fn downgrades_severity_when_component_normal_filtering_present() {
        let source = r#"
fn extract_zip(archive: &mut zip::ZipArchive<impl std::io::Read + std::io::Seek>, output: &std::path::Path) {
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let outpath = output.join(sanitize_filename(file.name()));
        write_file(&mut file, &outpath);
    }
}

fn sanitize_filename(filename: &str) -> std::path::PathBuf {
    std::path::Path::new(filename)
        .components()
        .filter(|c| matches!(*c, std::path::Component::Normal(..)))
        .fold(std::path::PathBuf::new(), |mut p, c| { p.push(c.as_os_str()); p })
}
"#;
        let findings = scan_source(Path::new("src/archive.rs"), source).unwrap();
        let slip_finding = findings
            .iter()
            .find(|f| f.rule_id == "rust-zip-raw-extraction")
            .expect("expected a zip-slip finding");
        assert_eq!(slip_finding.severity, Severity::Info);
    }

    #[test]
    fn downgrades_severity_when_dotdot_contains_check_present() {
        let source = r#"
fn extract(bytes: &[u8]) {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut file = archive.by_index(0).unwrap();
    let name = file.name().to_string();
    if name.contains("..") {
        return;
    }
}
"#;
        let findings = scan_source(Path::new("src/importer.rs"), source).unwrap();
        let slip_finding = findings
            .iter()
            .find(|f| f.rule_id == "rust-zip-raw-extraction")
            .expect("expected a zip-slip finding");
        assert_eq!(slip_finding.severity, Severity::Info);
    }

    #[test]
    fn no_bomb_finding_when_resource_limits_checked() {
        let source = r#"
fn extract(bytes: &[u8]) {
    cxf_audit::assert_within_limits(bytes, &cxf_audit::ZipLimits::default()).unwrap();
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut file = archive.by_index(0).unwrap();
}
"#;
        let findings = scan_source(Path::new("src/importer.rs"), source).unwrap();
        assert_eq!(
            findings.len(),
            1,
            "expected only the zip-slip finding: {findings:?}"
        );
        assert!(!findings[0].message.contains("zip-bomb"));
    }

    #[test]
    fn flags_unauthenticated_hpke_mode() {
        let source = r#"
fn build_params() -> HpkeParameters {
    HpkeParameters {
        mode: HpkeMode::Base,
        kem: HpkeKem::DhX25519,
        kdf: HpkeKdf::HkdfSha256,
        aead: HpkeAead::Aes256Gcm,
        key: None,
    }
}
"#;
        let findings = scan_source(Path::new("src/protocol.rs"), source).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].message.contains("HpkeMode::Base"));
    }

    #[test]
    fn does_not_flag_authenticated_hpke_mode() {
        let source = r#"
fn build_params() -> HpkeParameters {
    HpkeParameters {
        mode: HpkeMode::Auth,
        kem: HpkeKem::DhX25519,
        kdf: HpkeKdf::HkdfSha256,
        aead: HpkeAead::Aes256Gcm,
        key: None,
    }
}
"#;
        let findings = scan_source(Path::new("src/protocol.rs"), source).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_unrelated_enum_variant_named_base() {
        let source = r#"
fn pick(color: ColorMode) -> ColorMode {
    ColorMode::Base
}
"#;
        let findings = scan_source(Path::new("src/color.rs"), source).unwrap();
        assert!(findings.is_empty());
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

    /// Real-world case: pass-with-high-score/blockads-android's `ZipUtils.kt`
    /// uses exactly this canonicalPath+startsWith containment check and is
    /// safe (found by scanning that repo, then reading the flagged code by
    /// hand — the string `.canonicalPath` includes `canonicalPath` as a
    /// substring, matching the marker).
    #[test]
    fn downgrades_severity_when_canonical_path_and_starts_with_present() {
        let source = r#"
fun extract(destDir: File, canonicalDest: String, entry: ZipEntry) {
    val entryFile = File(destDir, entry.name)
    if (!entryFile.canonicalPath.startsWith(canonicalDest)) {
        throw ZipExtractionException("Zip-slip detected")
    }
}
"#;
        let findings = scan_source(Path::new("ZipUtils.kt"), source).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// Real-world case: vayun-mathur/Modern-Apps's `UnzipWorker.kt` uses the
    /// same containment check but via `canonicalFile` instead of
    /// `canonicalPath` (both are standard `java.io.File` members) — the
    /// first version of this guard marker only recognized `canonicalPath`
    /// and still flagged this equally-safe variant as Critical.
    #[test]
    fn downgrades_severity_when_canonical_file_and_starts_with_present() {
        let source = r#"
fun extract(destDir: File, destDirCanonical: File, entry: ZipEntry) {
    val entryFile = File(destDir, entry.name).canonicalFile
    if (!entryFile.path.startsWith(destDirCanonical.path)) {
        return
    }
}
"#;
        let findings = scan_source(Path::new("UnzipWorker.kt"), source).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
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

    /// Real-world case: ZIPFoundation's own `unzipItem(at:to:...)` calls
    /// `.extract` internally but only after `entryURL.isContained(in:
    /// destinationURL)` — found by scanning ZIPFoundation's own
    /// `FileManager+ZIP.swift` and reading the flagged code by hand.
    #[test]
    fn downgrades_severity_when_is_contained_in_check_present() {
        let source = r#"
func unzipItem(at sourceURL: URL, to destinationURL: URL) throws {
    for entry in archive {
        let entryURL = destinationURL.appendingPathComponent(entry.path)
        guard entryURL.isContained(in: destinationURL) else {
            throw CocoaError(.fileReadInvalidFileName)
        }
        _ = try archive.extract(entry, to: entryURL)
    }
}
"#;
        let findings = scan_source(Path::new("FileManager+ZIP.swift"), source).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
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
