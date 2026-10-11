//! Check and discover conformance against a fixed fake source (#1408).

use sekai_source_sdk::{
    ConnectionFailure, DiscoveredColumn, DiscoveredRecordKind, SOURCE_DISCOVERY_VERSION,
    SourceDiscovery, SourceInspector, assert_deterministic_discovery, run_check_conformance,
};

/// Fake source with a read counter. `leaky_check` and `drift` are the
/// deliberately divergent behaviours the kit must reject.
struct FakeSource {
    credentials: Result<(), ConnectionFailure>,
    records_read: u64,
    leaky_check: bool,
    drift: bool,
    discoveries: u32,
}

impl FakeSource {
    fn new() -> Self {
        Self {
            credentials: Ok(()),
            records_read: 0,
            leaky_check: false,
            drift: false,
            discoveries: 0,
        }
    }
}

impl SourceInspector for FakeSource {
    fn check(&mut self) -> Result<(), ConnectionFailure> {
        if self.leaky_check {
            self.records_read += 1;
        }
        self.credentials
    }

    fn discover(&mut self) -> Result<SourceDiscovery, ConnectionFailure> {
        self.credentials?;
        self.discoveries += 1;
        let column = |name: &str, nullable| DiscoveredColumn {
            name: name.into(),
            data_type: "text".into(),
            nullable,
            profile: None,
        };
        let mut account = DiscoveredRecordKind {
            record_kind: "Account".into(),
            schema_revision: "v1".into(),
            columns: vec![column("id", false), column("name", true)],
            key_candidates: vec![vec!["id".into()]],
        };
        if self.drift && self.discoveries > 1 {
            account.columns.push(column("tier", true));
        }
        Ok(SourceDiscovery {
            contract_version: SOURCE_DISCOVERY_VERSION.into(),
            source: "fake.crm".into(),
            record_kinds: vec![account],
        })
    }
}

#[test]
fn check_reports_typed_outcomes_without_reading_records() {
    let mut source = FakeSource::new();
    assert_eq!(
        run_check_conformance(&mut source, |source| source.records_read),
        Ok(Ok(()))
    );
    for failure in [
        ConnectionFailure::Unreachable,
        ConnectionFailure::AuthFailed,
        ConnectionFailure::PermissionMissing,
    ] {
        source.credentials = Err(failure);
        assert_eq!(
            run_check_conformance(&mut source, |source| source.records_read),
            Ok(Err(failure))
        );
    }
}

#[test]
fn kit_rejects_a_check_that_reads_records() {
    let mut source = FakeSource::new();
    source.leaky_check = true;
    assert!(run_check_conformance(&mut source, |source| source.records_read).is_err());
}

#[test]
fn discovery_is_deterministic_and_drafts_descriptors() {
    let discovery = assert_deterministic_discovery(&mut FakeSource::new()).unwrap();
    let drafts = discovery.descriptor_drafts().unwrap();
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].source, "fake.crm");
    assert_eq!(drafts[0].record_kind, "Account");
    assert_eq!(drafts[0].schema_revision, "v1");
}

#[test]
fn kit_rejects_drifting_or_failing_discovery() {
    let mut drifting = FakeSource::new();
    drifting.drift = true;
    assert!(assert_deterministic_discovery(&mut drifting).is_err());

    let mut denied = FakeSource::new();
    denied.credentials = Err(ConnectionFailure::AuthFailed);
    assert!(assert_deterministic_discovery(&mut denied).is_err());
}
