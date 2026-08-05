use cxf_audit::{
    assert_within_limits, build_archive, check_resource_limits, GuardError, ZipLimits,
};

fn tiny_limits() -> ZipLimits {
    ZipLimits {
        max_entries: 2,
        max_total_uncompressed_bytes: 10,
    }
}

#[test]
fn accepts_archive_within_limits() {
    let archive = build_archive(&[("a", b"1"), ("b", b"2")]).unwrap();
    let findings = check_resource_limits(&archive, &tiny_limits()).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn flags_too_many_entries() {
    let archive = build_archive(&[("a", b"1"), ("b", b"1"), ("c", b"1")]).unwrap();
    let findings = check_resource_limits(&archive, &tiny_limits()).unwrap();
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("Số lượng entry"));
}

#[test]
fn flags_declared_uncompressed_size_over_limit() {
    let big_content = vec![b'x'; 50];
    let archive = build_archive(&[("a", &big_content)]).unwrap();
    let findings = check_resource_limits(&archive, &tiny_limits()).unwrap();
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("kích thước giải nén"));
}

#[test]
fn flags_both_when_both_exceeded() {
    let big_content = vec![b'x'; 50];
    let archive = build_archive(&[
        ("a", &big_content),
        ("b", &big_content),
        ("c", &big_content),
    ])
    .unwrap();
    let findings = check_resource_limits(&archive, &tiny_limits()).unwrap();
    assert_eq!(findings.len(), 2);
}

#[test]
fn default_limits_accept_small_archive() {
    let archive = build_archive(&[("a", b"small")]).unwrap();
    let findings = check_resource_limits(&archive, &ZipLimits::default()).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn assert_within_limits_rejects_oversized_archive() {
    let big_content = vec![b'x'; 50];
    let archive = build_archive(&[("a", &big_content)]).unwrap();
    match assert_within_limits(&archive, &tiny_limits()) {
        Err(GuardError::UnsafeEntries(findings)) => assert_eq!(findings.len(), 1),
        other => panic!("expected UnsafeEntries, got {other:?}"),
    }
}
