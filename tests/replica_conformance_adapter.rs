use sekai_chisei::db::replica_conformance::{
    MAX_CHECKS, Report, SCHEMA_JSON, VERSION, require_version, run,
};

#[test]
fn public_adapter_matches_the_pinned_contract() {
    let report = run();
    assert!(report.passed, "{report:?}");
    assert_eq!(report.version, VERSION);
    assert_eq!(report.runtime_instances, 2);
    assert_eq!(report.checks.len(), MAX_CHECKS);
    let round_trip: Report =
        serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
    assert_eq!(round_trip, report);

    let schema: serde_json::Value = serde_json::from_str(SCHEMA_JSON).unwrap();
    assert_eq!(schema["version"], VERSION);
    assert_eq!(schema["max_checks"].as_u64(), Some(MAX_CHECKS as u64));
}

#[test]
fn an_unknown_contract_version_is_not_accepted() {
    assert!(require_version(VERSION).is_ok());
    assert!(require_version("incompatible/v2").is_err());
}
