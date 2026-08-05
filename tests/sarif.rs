use cxf_audit::{to_sarif, Severity, SourceFinding};

fn finding(rule_id: &'static str, severity: Severity, line: usize) -> SourceFinding {
    SourceFinding {
        file: "src/importer.rs".to_string(),
        line,
        severity,
        message: "test message".to_string(),
        rule_id,
    }
}

#[test]
fn empty_findings_produce_empty_results() {
    let sarif = to_sarif(&[]);
    assert_eq!(sarif["version"], "2.1.0");
    assert!(sarif["runs"][0]["results"].as_array().unwrap().is_empty());
    assert!(sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn critical_maps_to_error_and_info_maps_to_warning() {
    let findings = vec![
        finding("rust-zip-raw-extraction", Severity::Critical, 11),
        finding("rust-zip-bomb-unchecked", Severity::Info, 7),
    ];
    let sarif = to_sarif(&findings);
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["level"], "error");
    assert_eq!(results[1]["level"], "warning");
}

#[test]
fn location_carries_file_and_line() {
    let findings = vec![finding("rust-zip-raw-extraction", Severity::Critical, 42)];
    let sarif = to_sarif(&findings);
    let loc = &sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
    assert_eq!(loc["artifactLocation"]["uri"], "src/importer.rs");
    assert_eq!(loc["region"]["startLine"], 42);
}

#[test]
fn rule_ids_used_are_all_declared_in_driver_rules() {
    let findings = vec![
        finding("rust-zip-raw-extraction", Severity::Critical, 1),
        finding("rust-zip-raw-extraction", Severity::Critical, 2),
        finding("rust-hpke-unauthenticated-mode", Severity::Info, 3),
    ];
    let sarif = to_sarif(&findings);
    let declared: std::collections::HashSet<_> = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect();
    // Two results share a rule id — driver.rules must be deduplicated, not
    // one entry per result.
    assert_eq!(declared.len(), 2);
    for result in sarif["runs"][0]["results"].as_array().unwrap() {
        let rule_id = result["ruleId"].as_str().unwrap();
        assert!(declared.contains(rule_id), "undeclared ruleId: {rule_id}");
    }
}

#[test]
fn unknown_rule_id_still_gets_a_generic_description_not_a_panic() {
    let findings = vec![finding(
        "some-future-rule-not-yet-mapped",
        Severity::Info,
        1,
    )];
    let sarif = to_sarif(&findings);
    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["shortDescription"]["text"], "cxf-audit finding");
}
