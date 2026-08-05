use credential_exchange_protocol::Version;

use crate::findings::{Finding, Severity};

fn version_number(v: Version) -> u8 {
    v.into()
}

/// Flags a downgraded protocol version: CXP's "Importer MAY refuse this
/// version downgrade" clause permits refusal but does not require it (see
/// threat-model.md §2.6), so silent acceptance is opt-out, not opt-in, in
/// most implementations unless they add this check themselves.
pub fn check_version_downgrade(requested: Version, responded: Version) -> Option<Finding> {
    let requested_num = version_number(requested);
    let responded_num = version_number(responded);
    if responded_num < requested_num {
        Some(Finding {
            severity: Severity::Critical,
            entry_name: "<protocol version>".into(),
            message: format!(
                "ExportResponse dùng version {responded_num}, thấp hơn version {requested_num} \
                 đã yêu cầu trong ExportRequest — spec cho phép Importer từ chối downgrade \
                 (\"MAY refuse\") nhưng không bắt buộc; nếu ứng dụng không tự kiểm tra, \
                 downgrade sẽ được chấp nhận âm thầm"
            ),
        })
    } else {
        None
    }
}
