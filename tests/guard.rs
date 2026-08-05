use cxf_audit::{assert_safe_archive, build_archive, GuardError};

#[test]
fn accepts_clean_archive() {
    let archive = build_archive(&[("legit.jwe", b"data")]).unwrap();
    assert!(assert_safe_archive(&archive).is_ok());
}

#[test]
fn rejects_traversal_entry() {
    let archive = build_archive(&[("../../etc/passwd", b"data")]).unwrap();
    match assert_safe_archive(&archive) {
        Err(GuardError::UnsafeEntries(findings)) => {
            assert_eq!(findings.len(), 1);
        }
        other => panic!("expected UnsafeEntries, got {other:?}"),
    }
}

#[test]
fn rejects_bytes_that_are_not_a_zip_archive() {
    match assert_safe_archive(b"not a zip") {
        Err(GuardError::InvalidArchive(_)) => {}
        other => panic!("expected InvalidArchive, got {other:?}"),
    }
}

#[test]
fn error_display_lists_offending_entries() {
    let archive = build_archive(&[("../evil", b"data")]).unwrap();
    let err = assert_safe_archive(&archive).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("../evil"), "message was: {msg}");
}
