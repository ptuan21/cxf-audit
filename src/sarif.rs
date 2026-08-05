use serde_json::{json, Value};

use crate::{Severity, SourceFinding};

fn rule_description(rule_id: &str) -> &'static str {
    match rule_id {
        "rust-zip-raw-extraction" => {
            "Raw ZipArchive::by_index/by_name access without a path-traversal check"
        }
        "rust-zip-bomb-unchecked" => {
            "ZipArchive entries read without a resource-limit (zip-bomb) check"
        }
        "rust-hpke-unauthenticated-mode" => {
            "HpkeMode::Base/Psk construction — unauthenticated at the KEM layer"
        }
        "kotlin-zip-slip-file-constructor" => {
            "File(dir, entry.name) constructed from an untrusted zip entry name"
        }
        "swift-archive-extract-raw" => "Archive.extract(...) called without a path-traversal check",
        _ => "cxf-audit finding",
    }
}

fn severity_to_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "error",
        Severity::Info => "warning",
    }
}

/// Renders `scan-source` findings as SARIF 2.1.0, for tools like GitHub Code
/// Scanning (`github/codeql-action/upload-sarif`) that expect it. `file`
/// paths in `findings` should be relative to the repo root for GitHub to
/// map results onto the right file in the PR/Security tab UI — that's the
/// caller's responsibility (this function passes them through as-is).
pub fn to_sarif(findings: &[SourceFinding]) -> Value {
    let mut rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
    rule_ids.sort_unstable();
    rule_ids.dedup();

    let rules: Vec<Value> = rule_ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "shortDescription": { "text": rule_description(id) },
                "helpUri": "https://github.com/ptuan21/cxf-audit",
            })
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "level": severity_to_level(f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file },
                        "region": { "startLine": f.line }
                    }
                }]
            })
        })
        .collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cxf-audit",
                    "informationUri": "https://github.com/ptuan21/cxf-audit",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                }
            },
            "results": results,
        }]
    })
}
