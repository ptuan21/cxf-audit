use std::fmt;

use crate::{check_resource_limits, scan_archive, Finding, ZipLimits};

/// Error returned by [`assert_safe_archive`] / [`assert_within_limits`].
#[derive(Debug)]
pub enum GuardError {
    /// The bytes could not be parsed as a zip archive at all.
    InvalidArchive(zip::result::ZipError),
    /// The archive parsed, but one or more findings (zip-slip entry names,
    /// or resource limits exceeded) were flagged.
    UnsafeEntries(Vec<Finding>),
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardError::InvalidArchive(e) => write!(f, "archive không hợp lệ: {e}"),
            GuardError::UnsafeEntries(findings) => {
                write!(f, "{} entry đáng ngờ:", findings.len())?;
                for finding in findings {
                    write!(f, " [{}] {}", finding.entry_name, finding.message)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for GuardError {}

/// Embeddable guard for CXF importers: call this on received archive bytes
/// *before* extracting them, and reject on `Err`. This is the integration
/// point meant for third-party code — see README.md.
pub fn assert_safe_archive(bytes: &[u8]) -> Result<(), GuardError> {
    let findings = scan_archive(bytes).map_err(GuardError::InvalidArchive)?;
    if findings.is_empty() {
        Ok(())
    } else {
        Err(GuardError::UnsafeEntries(findings))
    }
}

/// Embeddable guard for CXF importers: call this on received archive bytes
/// *before* extracting them, and reject on `Err` if entry count or declared
/// uncompressed size exceeds `limits` (zip-bomb check).
pub fn assert_within_limits(bytes: &[u8], limits: &ZipLimits) -> Result<(), GuardError> {
    let findings = check_resource_limits(bytes, limits).map_err(GuardError::InvalidArchive)?;
    if findings.is_empty() {
        Ok(())
    } else {
        Err(GuardError::UnsafeEntries(findings))
    }
}
