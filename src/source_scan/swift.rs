use tree_sitter::{Query, QueryCursor};

use super::SourceFinding;
use crate::Severity;

const QUERY: &str = r#"
(call_expression
  (navigation_expression
    suffix: (navigation_suffix
      suffix: (simple_identifier) @method))
) @call
"#;

/// Same-file marker that downgrades severity: `isContained(in:` is
/// ZIPFoundation's own containment-check API (used internally by its
/// `unzipItem(at:to:...)` convenience method right before calling
/// `.extract` — confirmed by reading ZIPFoundation's own
/// `FileManager+ZIP.swift`, not guessed) — a strong, specific signal the
/// destination path has already been validated.
const GUARD_MARKER: &str = "isContained(in:";

/// Flags calls to `.extract(...)` — ZIPFoundation's `Archive.extract(_:to:...)`,
/// the raw extraction API. Contrast `cxf_audit::assert_safe_archive`, which
/// validates entry names for path traversal before extraction is ever
/// attempted; Swift/ZIPFoundation code that calls `.extract` directly is on
/// the hook for doing that itself. Matches on method name only (not receiver
/// type), so it will also flag unrelated `.extract()` calls on other types —
/// documented false-positive risk, see README.
pub fn scan(source: &str, file: &str) -> Vec<SourceFinding> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(tree_sitter_swift::language())
        .expect("tree-sitter-swift grammar is statically linked and must load");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let query = Query::new(tree_sitter_swift::language(), QUERY)
        .expect("QUERY is a fixed, tested string — must compile");
    let mut cursor = QueryCursor::new();
    let call_idx = query.capture_index_for_name("call").unwrap();
    let method_idx = query.capture_index_for_name("method").unwrap();

    let looks_guarded = source.contains(GUARD_MARKER);
    let mut findings = Vec::new();
    for m in cursor.matches(&query, tree.root_node(), source.as_bytes()) {
        let method_node = m.captures.iter().find(|c| c.index == method_idx);
        let call_node = m.captures.iter().find(|c| c.index == call_idx);
        let (Some(method_node), Some(call_node)) = (method_node, call_node) else {
            continue;
        };
        let Ok(method_name) = method_node.node.utf8_text(source.as_bytes()) else {
            continue;
        };
        if method_name != "extract" {
            continue;
        }
        findings.push(SourceFinding {
            file: file.to_string(),
            line: call_node.node.start_position().row + 1,
            severity: if looks_guarded {
                Severity::Info
            } else {
                Severity::Critical
            },
            message: format!(
                "Gọi `.extract(` trực tiếp (kiểu ZIPFoundation Archive.extract) — API thô, \
                 tự bạn phải validate đường dẫn đích chống path traversal trước khi giải nén.{}",
                if looks_guarded {
                    " (file này có tham chiếu isContained(in: ở đâu đó — có thể đã guard, hạ \
                       severity)"
                } else {
                    ""
                }
            ),
            rule_id: "swift-archive-extract-raw",
        });
    }
    findings
}
