use cxf_audit::{build_archive, scan_archive, zipslip_poc_archive, Severity};

#[test]
fn flags_parent_directory_traversal() {
    let archive = build_archive(&[(
        "../../../etc/cron.d/evil",
        b"* * * * * root touch /tmp/pwned",
    )])
    .unwrap();
    let findings = scan_archive(&archive).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Critical);
    assert!(findings[0].entry_name.contains(".."));
}

#[test]
fn flags_absolute_unix_path() {
    let archive = build_archive(&[("/etc/passwd", b"data")]).unwrap();
    let findings = scan_archive(&archive).unwrap();
    assert_eq!(findings.len(), 1);
}

#[test]
fn flags_windows_drive_absolute_path() {
    let archive = build_archive(&[("C:\\Windows\\System32\\evil.dll", b"data")]).unwrap();
    let findings = scan_archive(&archive).unwrap();
    assert_eq!(findings.len(), 1);
}

#[test]
fn flags_windows_style_separator_without_drive_letter() {
    let archive = build_archive(&[("subdir\\..\\..\\evil", b"data")]).unwrap();
    let findings = scan_archive(&archive).unwrap();
    assert_eq!(findings.len(), 1);
}

#[test]
fn does_not_flag_legitimate_nested_relative_path() {
    let archive = build_archive(&[
        ("a1b2c3d4e5f6.jwe", b"data"),
        ("documents/f7g8h9.jwe", b"data"),
    ])
    .unwrap();
    let findings = scan_archive(&archive).unwrap();
    assert!(findings.is_empty(), "false positive: {findings:?}");
}

#[test]
fn empty_archive_has_no_findings() {
    let archive = build_archive(&[]).unwrap();
    let findings = scan_archive(&archive).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn multiple_entries_only_flags_malicious_one() {
    let archive = build_archive(&[("legit.jwe", b"data"), ("../evil.jwe", b"data")]).unwrap();
    let findings = scan_archive(&archive).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].entry_name, "../evil.jwe");
}

#[test]
fn scan_rejects_bytes_that_are_not_a_zip_archive() {
    let result = scan_archive(b"this is not a zip file");
    assert!(result.is_err());
}

#[test]
fn zipslip_poc_archive_is_flagged_by_scan_archive() {
    let poc = zipslip_poc_archive("../../../../tmp/cxf-audit-poc-marker").unwrap();
    let findings = scan_archive(&poc).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].entry_name,
        "../../../../tmp/cxf-audit-poc-marker"
    );
}

#[test]
fn zipslip_poc_archive_carries_cxf_shaped_content() {
    let poc = zipslip_poc_archive("../evil").unwrap();
    let content = cxf_audit::read_entry(&poc, 0).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&content).unwrap();
    assert_eq!(json["exporterRpId"], "cxf-audit.research");
    assert!(json["accounts"].is_array());
}
