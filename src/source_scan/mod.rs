mod kotlin;
mod rust;
mod swift;

use std::path::Path;

use crate::Severity;

/// A finding from scanning a developer's *source code* (not CXF archive/protocol
/// data — see [`crate::Finding`] for that). Points at a specific file/line so
/// editors and CI can surface it inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFinding {
    pub file: String,
    pub line: usize,
    pub severity: Severity,
    pub message: String,
    /// Stable identifier for the rule that produced this finding — e.g.
    /// `"rust-zip-raw-extraction"`. Constant across runs/versions of the
    /// same rule, unlike `message` (free text). Needed for SARIF output
    /// (`ruleId`), where tools like GitHub Code Scanning use it to group
    /// and deduplicate results.
    pub rule_id: &'static str,
}

/// Scans one source file's content for CXF/CXP-relevant unsafe patterns
/// (currently: zip-extraction sinks known to enable zip-slip in each
/// ecosystem). Returns `None` if the file extension isn't a recognized
/// language — callers scanning a directory tree should skip those, not
/// treat them as clean.
pub fn scan_source(file: &Path, content: &str) -> Option<Vec<SourceFinding>> {
    let file_str = file.display().to_string();
    match file.extension().and_then(|e| e.to_str()) {
        Some("rs") => Some(rust::scan(content, &file_str)),
        Some("kt") | Some("kts") => Some(kotlin::scan(content, &file_str)),
        Some("swift") => Some(swift::scan(content, &file_str)),
        _ => None,
    }
}
