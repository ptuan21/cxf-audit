use tree_sitter::{Parser, Query, QueryCursor};

use super::SourceFinding;
use crate::Severity;

const DANGEROUS_METHODS: &[&str] = &["by_index", "by_name"];

const QUERY: &str = r#"
(call_expression
  function: (field_expression
    field: (field_identifier) @method)
) @call
"#;

/// Flags calls to `ZipArchive::by_index`/`by_name` — the raw, manual
/// entry-access API that puts the caller on the hook for path-traversal
/// validation themselves (contrast `cxf_audit::assert_safe_archive`, which
/// does it for you). Severity is downgraded if the file already references
/// `cxf_audit` somewhere, since that's a (crude, same-file-only) signal the
/// developer is already using the safe wrapper.
pub fn scan(source: &str, file: &str) -> Vec<SourceFinding> {
    let mut parser = Parser::new();
    parser
        .set_language(tree_sitter_rust::language())
        .expect("tree-sitter-rust grammar is statically linked and must load");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let query = Query::new(tree_sitter_rust::language(), QUERY)
        .expect("QUERY is a fixed, tested string — must compile");
    let mut cursor = QueryCursor::new();
    let call_idx = query.capture_index_for_name("call").unwrap();
    let method_idx = query.capture_index_for_name("method").unwrap();

    let looks_guarded = source.contains("cxf_audit");
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
        if !DANGEROUS_METHODS.contains(&method_name) {
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
                "Gọi `{method_name}` trực tiếp trên ZipArchive — API thô, tự bạn phải validate \
                 tên entry chống path traversal trước khi ghi file. Cân nhắc dùng \
                 cxf_audit::assert_safe_archive() thay vì tự viết lại.{}",
                if looks_guarded {
                    " (file này có tham chiếu cxf_audit ở đâu đó — có thể đã guard, hạ severity)"
                } else {
                    ""
                }
            ),
        });
    }
    findings
}
