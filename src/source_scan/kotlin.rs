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
/// Same-file markers that downgrade severity: some `java.io.File`
/// canonicalization property (`canonicalPath: String` or the equivalent
/// `canonicalFile: File`) combined with a `startsWith` containment check is
/// the standard Java/Kotlin zip-slip mitigation (the same one this rule's
/// own message recommends). Requiring *both* forms of canonicalization
/// isn't redundant — confirmed against two real, independent codebases that
/// each pick a different one for the same check:
/// pass-with-high-score/blockads-android's `ZipUtils.kt` uses
/// `canonicalPath`; vayun-mathur/Modern-Apps's `UnzipWorker.kt` uses
/// `canonicalFile` — the first version of this marker only recognized the
/// former and still flagged the (equally safe) latter as Critical.
const CANONICALIZATION_MARKERS: &[&str] = &["canonicalPath", "canonicalFile"];
const CONTAINMENT_CHECK_MARKER: &str = "startsWith";

pub fn scan(source: &str, file: &str) -> Vec<SourceFinding> {
    let mut parser = Parser::new();
    parser
        .set_language(tree_sitter_kotlin::language())
        .expect("tree-sitter-kotlin grammar is statically linked and must load");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let looks_guarded = source.contains(CONTAINMENT_CHECK_MARKER)
        && CANONICALIZATION_MARKERS.iter().any(|m| source.contains(m));
    let mut findings = Vec::new();
    walk(tree.root_node(), source, file, looks_guarded, &mut findings);
    findings
}

fn walk(
    node: Node,
    source: &str,
    file: &str,
    looks_guarded: bool,
    findings: &mut Vec<SourceFinding>,
) {
    if node.kind() == "call_expression" {
        if let Some(finding) = check_call(node, source, file, looks_guarded) {
            findings.push(finding);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, file, looks_guarded, findings);
    }
}

fn check_call(node: Node, source: &str, file: &str, looks_guarded: bool) -> Option<SourceFinding> {
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
        severity: if looks_guarded {
            Severity::Info
        } else {
            Severity::Critical
        },
        message: format!(
            "File(dir, entry.name) — zip-slip antipattern kinh điển (OWASP): tên entry \
             dùng thẳng để tạo đường dẫn file, chưa thấy check path traversal (canonicalPath \
             + startsWith) nào ở đây. Validate hoặc dùng entry name đã qua sanitize trước.{}",
            if looks_guarded {
                " (file này có tham chiếu canonicalPath/canonicalFile và startsWith ở đâu đó \
                   — có thể đã guard, hạ severity)"
            } else {
                ""
            }
        ),
        rule_id: "kotlin-zip-slip-file-constructor",
    })
}
