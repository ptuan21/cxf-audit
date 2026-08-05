use std::io::Cursor;

use crate::findings::{Finding, Severity};

/// Thresholds for [`check_resource_limits`]. Declared (not actual) sizes are
/// checked — see function docs for why that is still meaningful.
#[derive(Debug, Clone, Copy)]
pub struct ZipLimits {
    pub max_entries: u64,
    pub max_total_uncompressed_bytes: u64,
}

impl Default for ZipLimits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_total_uncompressed_bytes: 500 * 1024 * 1024,
        }
    }
}

/// Flags archives whose entry count or *declared* total uncompressed size
/// exceeds `limits` — a static zip-bomb check (see threat-model.md §2.4's
/// open question on archive limits). This reads zip central-directory
/// metadata only; it never decompresses entries, so it is cheap to run
/// against untrusted input. Note the declared size is attacker-controlled
/// in the sense that a lying header is itself the signal callers should
/// reject before extracting — this function does not need to trust it any
/// further than that.
pub fn check_resource_limits(bytes: &[u8], limits: &ZipLimits) -> zip::result::ZipResult<Vec<Finding>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    let mut findings = Vec::new();

    let count = archive.len() as u64;
    if count > limits.max_entries {
        findings.push(Finding {
            severity: Severity::Critical,
            entry_name: format!("<archive: {count} entries>"),
            message: format!(
                "Số lượng entry ({count}) vượt giới hạn {} — nguy cơ resource exhaustion khi giải nén",
                limits.max_entries
            ),
        });
    }

    let mut total: u64 = 0;
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        total = total.saturating_add(file.size());
    }
    if total > limits.max_total_uncompressed_bytes {
        findings.push(Finding {
            severity: Severity::Critical,
            entry_name: format!("<archive: {total} bytes uncompressed khai báo>"),
            message: format!(
                "Tổng kích thước giải nén khai báo ({total} bytes) vượt giới hạn {} — nguy cơ zip bomb",
                limits.max_total_uncompressed_bytes
            ),
        });
    }

    Ok(findings)
}
