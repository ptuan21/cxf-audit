mod archive;
mod findings;
mod guard;
mod limits;
mod sample;
mod source_scan;
mod version;

pub use archive::{build_archive, read_entry, scan_archive};
pub use findings::{Finding, Severity};
pub use guard::{assert_safe_archive, assert_within_limits, GuardError};
pub use limits::{check_resource_limits, ZipLimits};
pub use sample::sample_header;
pub use source_scan::{scan_source, SourceFinding};
pub use version::check_version_downgrade;

pub use credential_exchange_protocol::Version;

/// Builds a zip-slip proof-of-concept archive: a single entry whose name is a
/// path-traversal string, with CXF-shaped (but unencrypted) placeholder
/// content. See threat-model.md §2.4 for the underlying question this probes.
pub fn zipslip_poc_archive(traversal_entry_name: &str) -> zip::result::ZipResult<Vec<u8>> {
    let header = sample_header();
    let content = serde_json::to_vec_pretty(&header).expect("Header serialization cannot fail");
    build_archive(&[(traversal_entry_name, &content)])
}
