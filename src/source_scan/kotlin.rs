use tree_sitter::{Node, Parser};

use super::SourceFinding;
use crate::Severity;

/// Flags `File(dir, entry.name)` (or `entry.entryName`) — the textbook Java/
/// Kotlin zip-slip antipattern (see OWASP's zip-slip writeup): constructing
/// a destination path directly from an untrusted zip entry name, with no
/// traversal check. This grammar (tree-sitter-kotlin) doesn't label AST
/// fields, so unlike the Rust rule this walks nodes manually rather than
/// using a declarative query, and falls back to a text-contains check on the
/// call's own span for the `.name`/`.entryName` argument — a heuristic, not
/// full data-flow analysis. False positives are possible on unrelated
/// `File(...)` calls that happen to mention `.name` in another argument.
pub fn scan(source: &str, file: &str) -> Vec<SourceFinding> {
    let mut parser = Parser::new();
    parser
        .set_language(tree_sitter_kotlin::language())
        .expect("tree-sitter-kotlin grammar is statically linked and must load");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    walk(tree.root_node(), source, file, &mut findings);
    findings
}

fn walk(node: Node, source: &str, file: &str, findings: &mut Vec<SourceFinding>) {
    if node.kind() == "call_expression" {
        if let Some(finding) = check_call(node, source, file) {
            findings.push(finding);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, file, findings);
    }
}

fn check_call(node: Node, source: &str, file: &str) -> Option<SourceFinding> {
    let callee = node.named_child(0)?;
    if callee.kind() != "simple_identifier" {
        return None;
    }
    if callee.utf8_text(source.as_bytes()).ok()? != "File" {
        return None;
    }
    let call_text = node.utf8_text(source.as_bytes()).ok()?;
    if !(call_text.contains(".name") || call_text.contains(".entryName")) {
        return None;
    }
    Some(SourceFinding {
        file: file.to_string(),
        line: node.start_position().row + 1,
        severity: Severity::Critical,
        message: "File(dir, entry.name) — zip-slip antipattern kinh điển (OWASP): tên entry \
                   dùng thẳng để tạo đường dẫn file, chưa thấy check path traversal (canonicalPath \
                   + startsWith) nào ở đây. Validate hoặc dùng entry name đã qua sanitize trước."
            .to_string(),
        rule_id: "kotlin-zip-slip-file-constructor",
    })
}
