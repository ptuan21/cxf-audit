use cxf_audit::{check_version_downgrade, Version};

#[test]
fn same_version_is_not_flagged() {
    assert!(check_version_downgrade(Version::V0, Version::V0).is_none());
}

#[test]
fn responded_version_lower_than_requested_is_flagged() {
    let requested = Version::from(5u8);
    let responded = Version::from(2u8);
    let finding = check_version_downgrade(requested, responded).expect("expected a finding");
    assert!(finding.message.contains("downgrade") || finding.message.contains("thấp hơn"));
}

#[test]
fn responded_version_higher_than_requested_is_not_flagged() {
    let requested = Version::from(1u8);
    let responded = Version::from(3u8);
    assert!(check_version_downgrade(requested, responded).is_none());
}

#[test]
fn unknown_responded_version_equal_is_not_flagged() {
    let requested = Version::from(7u8);
    let responded = Version::from(7u8);
    assert!(check_version_downgrade(requested, responded).is_none());
}
