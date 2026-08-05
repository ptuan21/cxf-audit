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
            severity: Severity::Critical,
            message:
                "Gọi `.extract(` trực tiếp (kiểu ZIPFoundation Archive.extract) — API thô, \
                       tự bạn phải validate đường dẫn đích chống path traversal trước khi giải nén."
                    .to_string(),
            rule_id: "swift-archive-extract-raw",
        });
    }
    findings
}
