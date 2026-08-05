mod archive;
mod findings;
mod sample;

pub use archive::{build_archive, read_entry, scan_archive};
pub use findings::{Finding, Severity};
pub use sample::sample_header;

/// Builds a zip-slip proof-of-concept archive: a single entry whose name is a
/// path-traversal string, with CXF-shaped (but unencrypted) placeholder
/// content. See threat-model.md §2.4 for the underlying question this probes.
pub fn zipslip_poc_archive(traversal_entry_name: &str) -> zip::result::ZipResult<Vec<u8>> {
    let header = sample_header();
    let content = serde_json::to_vec_pretty(&header).expect("Header serialization cannot fail");
    build_archive(&[(traversal_entry_name, &content)])
}
