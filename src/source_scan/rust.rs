use tree_sitter::{Node, Parser, Query, QueryCursor};

use super::SourceFinding;
use crate::Severity;

const DANGEROUS_METHODS: &[&str] = &["by_index", "by_name"];
const BOMB_GUARD_MARKERS: &[&str] = &["check_resource_limits", "assert_within_limits", "ZipLimits"];
const UNAUTHENTICATED_HPKE_MODES: &[&str] = &["Base", "Psk"];
/// Same-file markers that downgrade the zip-slip finding's severity: not
/// just our own `cxf_audit` helpers, but known-legitimate hand-rolled
/// sanitization idioms — `Component::Normal` filtering (the standard
/// std-library-only way to strip `..`/absolute-path components from an
/// untrusted path, confirmed against a real external crate,
/// georust/transitfeed's `sanitize_filename`, which uses exactly this and
/// is NOT vulnerable) and a literal `.contains("..")` check (weaker, but
/// the same idiom this tool's own Kotlin/Swift rules treat as a guard).
const SLIP_GUARD_MARKERS: &[&str] = &["cxf_audit", "Component::Normal", ".contains(\"..\")"];

const CALL_QUERY: &str = r#"
(call_expression
  function: (field_expression
    field: (field_identifier) @method)
) @call
"#;

const HPKE_MODE_QUERY: &str = r#"
(scoped_identifier
  path: (identifier) @path
  name: (identifier) @variant
) @expr
"#;

fn parse(source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(tree_sitter_rust::language())
        .expect("tree-sitter-rust grammar is statically linked and must load");
    parser.parse(source, None)
}

/// Flags calls to `ZipArchive::by_index`/`by_name` (raw entry access, path
/// traversal is on the caller), and — if none of the entries found in the
/// same scan also indicate a zip-bomb guard is present — a companion
/// zip-bomb finding (threat-model.md §2.4's open question on archive
/// limits). Also flags constructing `HpkeMode::Base`/`HpkeMode::Psk` (§2.3):
/// unauthenticated at the KEM layer, security then depends entirely on the
/// separate challenge signature binding to the HPKE public key.
pub fn scan(source: &str, file: &str) -> Vec<SourceFinding> {
    let Some(tree) = parse(source) else {
        return Vec::new();
    };

    let mut findings = scan_zip_calls(&tree, source, file);
    findings.extend(scan_hpke_mode(&tree, source, file));
    findings
}

fn scan_zip_calls(tree: &tree_sitter::Tree, source: &str, file: &str) -> Vec<SourceFinding> {
    let query = Query::new(tree_sitter_rust::language(), CALL_QUERY)
        .expect("CALL_QUERY is a fixed, tested string — must compile");
    let mut cursor = QueryCursor::new();
    let call_idx = query.capture_index_for_name("call").unwrap();
    let method_idx = query.capture_index_for_name("method").unwrap();

    let looks_slip_guarded = SLIP_GUARD_MARKERS.iter().any(|m| source.contains(m));
    let looks_bomb_guarded = BOMB_GUARD_MARKERS.iter().any(|m| source.contains(m));

    let mut findings = Vec::new();
    let mut first_dangerous_call: Option<Node> = None;

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
        if first_dangerous_call.is_none() {
            first_dangerous_call = Some(call_node.node);
        }
        findings.push(SourceFinding {
            file: file.to_string(),
            line: call_node.node.start_position().row + 1,
            severity: if looks_slip_guarded {
                Severity::Info
            } else {
                Severity::Critical
            },
            message: format!(
                "Gọi `{method_name}` trực tiếp trên ZipArchive — API thô, tự bạn phải validate \
                 tên entry chống path traversal trước khi ghi file. Cân nhắc dùng \
                 cxf_audit::assert_safe_archive() thay vì tự viết lại.{}",
                if looks_slip_guarded {
                    " (file này có tham chiếu cxf_audit, lọc Component::Normal, hoặc check \
                       .contains(\"..\") ở đâu đó — có thể đã guard, hạ severity)"
                } else {
                    ""
                }
            ),
            rule_id: "rust-zip-raw-extraction",
        });
    }

    if let Some(call_node) = first_dangerous_call {
        if !looks_bomb_guarded {
            findings.push(SourceFinding {
                file: file.to_string(),
                line: call_node.start_position().row + 1,
                severity: Severity::Info,
                message: "Đọc entry ZipArchive nhưng không thấy check giới hạn số entry/kích \
                           thước giải nén ở đâu trong file (zip-bomb) — cân nhắc gọi \
                           cxf_audit::assert_within_limits() trước khi lặp qua các entry."
                    .to_string(),
                rule_id: "rust-zip-bomb-unchecked",
            });
        }
    }

    findings
}

fn scan_hpke_mode(tree: &tree_sitter::Tree, source: &str, file: &str) -> Vec<SourceFinding> {
    let query = Query::new(tree_sitter_rust::language(), HPKE_MODE_QUERY)
        .expect("HPKE_MODE_QUERY is a fixed, tested string — must compile");
    let mut cursor = QueryCursor::new();
    let expr_idx = query.capture_index_for_name("expr").unwrap();
    let path_idx = query.capture_index_for_name("path").unwrap();
    let variant_idx = query.capture_index_for_name("variant").unwrap();

    let mut findings = Vec::new();
    for m in cursor.matches(&query, tree.root_node(), source.as_bytes()) {
        let expr_node = m.captures.iter().find(|c| c.index == expr_idx);
        let path_node = m.captures.iter().find(|c| c.index == path_idx);
        let variant_node = m.captures.iter().find(|c| c.index == variant_idx);
        let (Some(expr_node), Some(path_node), Some(variant_node)) =
            (expr_node, path_node, variant_node)
        else {
            continue;
        };
        let Ok(path_text) = path_node.node.utf8_text(source.as_bytes()) else {
            continue;
        };
        if path_text != "HpkeMode" {
            continue;
        }
        let Ok(variant_text) = variant_node.node.utf8_text(source.as_bytes()) else {
            continue;
        };
        if !UNAUTHENTICATED_HPKE_MODES.contains(&variant_text) {
            continue;
        }
        findings.push(SourceFinding {
            file: file.to_string(),
            line: expr_node.node.start_position().row + 1,
            severity: Severity::Info,
            message: format!(
                "HpkeMode::{variant_text} không xác thực người gửi ở tầng KEM (RFC 9180) — an \
                 toàn phụ thuộc hoàn toàn vào chữ ký challenge riêng có bind vào public key HPKE \
                 hay không (xem threat-model.md §2.3). Nếu không chắc chữ ký có bind, cân nhắc \
                 HpkeMode::Auth/AuthPsk."
            ),
            rule_id: "rust-hpke-unauthenticated-mode",
        });
    }
    findings
}
