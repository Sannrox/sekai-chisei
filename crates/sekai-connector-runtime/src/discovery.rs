//! Source discovery (#3091): a caller's request to discover a registered
//! Source, run here because the Source's credential lives here. The plane
//! hands the request only to a runtime the Source's placement admits.
//!
//! The runtime claims it, runs the connector's `discover` under a
//! heartbeated lease, attaches reference candidates and value-shape
//! findings from one bounded sample per record kind, and acknowledges with
//! the discovery in the `sekai.source-discovery/v1` shape plus those
//! samples. A cell whose value looks like a secret is dropped before it
//! leaves, and samples stop once [`SAMPLE_BUDGET_BYTES`] is spent. A type
//! that does not declare `discover` fails as `unsupported`; a credential
//! the runtime cannot resolve fails as `unavailable`.

use std::collections::BTreeMap;

use sekai_client::claim::{ClaimAttempt, RuntimeClaimError, WorkFence, WorkKind};
use sekai_client::protocol::sekai::{
    SourceDiscoveryAckOptions, SourceDiscoverySample, SourceDiscoverySampleRow,
    SourceDiscoveryWork, ack_work_request, claim_work_response,
};
use sekai_source_sdk::{
    ConnectionFailure, Connector, ConnectorFailure, DiscoverySample, Operation, SourceDiscovery,
    SourceInspector, attach_references, attach_value_findings, cap_discovery_sample,
    contains_secret_like_text,
};

use crate::runtime::{LIST_LIMIT, Ran, Runtime};
use crate::sync::{SyncFailure, blocking, prepare};

/// Sample bytes (names and values) one discovery sends at most; record
/// kinds past it are sent without a sample. Well under the plane's bound.
pub const SAMPLE_BUDGET_BYTES: usize = 1024 * 1024;

/// A discovery with its samples, ready to acknowledge.
#[derive(Debug, Clone, PartialEq)]
pub struct Discovered {
    pub discovery: SourceDiscovery,
    pub samples: Vec<SourceDiscoverySample>,
}

/// Runs a connector's discovery with references, value findings and
/// samples. Each record kind is sampled once. Blocking.
pub fn discover(connector: &mut dyn Connector) -> Result<Discovered, SyncFailure> {
    let mut discovery = connector.discover().map_err(SyncFailure::from)?;
    discovery.validate().map_err(|_| SyncFailure::Invalid)?;
    let mut inspector = Sampling {
        connector,
        samples: BTreeMap::new(),
        failure: None,
    };
    let attached = attach_references(&mut inspector, &mut discovery)
        .and_then(|_| attach_value_findings(&mut inspector, &mut discovery));
    if let Err(failure) = attached {
        return Err(inspector
            .failure
            .map_or(failure_of(failure), SyncFailure::from));
    }
    let mut budget = SAMPLE_BUDGET_BYTES;
    let mut samples = Vec::new();
    for kind in &discovery.record_kinds {
        let sample = inspector.sample(&kind.record_kind)?;
        let Some(sample) = to_proto(&kind.record_kind, sample, &mut budget) else {
            break;
        };
        samples.push(sample);
    }
    Ok(Discovered { discovery, samples })
}

/// The proto sample, with secret-like cells dropped, or `None` once the
/// budget is spent.
fn to_proto(
    record_kind: &str,
    sample: DiscoverySample,
    budget: &mut usize,
) -> Option<SourceDiscoverySample> {
    let rows = match sample {
        DiscoverySample::Rows { cells } => cells,
        _ => {
            return Some(SourceDiscoverySample {
                record_kind: record_kind.into(),
                unsupported: true,
                rows: Vec::new(),
            });
        }
    };
    let rows: Vec<SourceDiscoverySampleRow> = rows
        .into_iter()
        .map(|row| SourceDiscoverySampleRow {
            cells: row
                .into_iter()
                .filter(|(_, value)| !contains_secret_like_text(value))
                .collect(),
        })
        .collect();
    let bytes: usize = rows
        .iter()
        .flat_map(|row| &row.cells)
        .map(|(name, value)| name.len() + value.len())
        .sum();
    *budget = budget.checked_sub(bytes)?;
    Some(SourceDiscoverySample {
        record_kind: record_kind.into(),
        unsupported: false,
        rows,
    })
}

fn failure_of(failure: ConnectionFailure) -> SyncFailure {
    match failure {
        ConnectionFailure::Unreachable => SyncFailure::Unreachable,
        ConnectionFailure::AuthFailed => SyncFailure::AuthFailed,
        _ => SyncFailure::PermissionMissing,
    }
}

/// A connector seen as a [`SourceInspector`], sampling each record kind at
/// most once. The first connector failure is kept, so it is reported as
/// the connector named it.
struct Sampling<'a> {
    connector: &'a mut dyn Connector,
    samples: BTreeMap<String, DiscoverySample>,
    failure: Option<ConnectorFailure>,
}

impl Sampling<'_> {
    fn sample(&mut self, record_kind: &str) -> Result<DiscoverySample, ConnectorFailure> {
        if let Some(sample) = self.samples.get(record_kind) {
            return Ok(sample.clone());
        }
        let sample = match self.connector.sample_rows(record_kind) {
            Ok(sample) => cap_discovery_sample(sample),
            Err(ConnectorFailure::Unsupported) => DiscoverySample::Unsupported,
            Err(failure) => return Err(failure),
        };
        self.samples.insert(record_kind.into(), sample.clone());
        Ok(sample)
    }
}

impl SourceInspector for Sampling<'_> {
    fn check(&mut self) -> Result<(), ConnectionFailure> {
        Ok(())
    }

    fn discover(&mut self) -> Result<SourceDiscovery, ConnectionFailure> {
        Err(ConnectionFailure::PermissionMissing)
    }

    fn sample_rows(&mut self, record_kind: &str) -> Result<DiscoverySample, ConnectionFailure> {
        self.sample(record_kind).map_err(|failure| {
            self.failure.get_or_insert(failure);
            match failure {
                ConnectorFailure::Unreachable => ConnectionFailure::Unreachable,
                ConnectorFailure::AuthFailed => ConnectionFailure::AuthFailed,
                _ => ConnectionFailure::PermissionMissing,
            }
        })
    }
}

/// The failure classes the plane takes for a discovery.
fn reported(failure: SyncFailure) -> SyncFailure {
    match failure {
        SyncFailure::Conflict | SyncFailure::Refused => SyncFailure::Invalid,
        other => other,
    }
}

impl Runtime {
    /// Claims the next discovery request for a Source of a type that
    /// declares `discover`, in the namespace at `index`. A plane that does
    /// not know the kind has none to hand out.
    pub async fn claim_discovery(
        &self,
        index: usize,
    ) -> Result<Option<SourceDiscoveryWork>, RuntimeClaimError> {
        let claims = self.clients[index].runtime_claim();
        let types = self.connectors.types_for(Operation::Discover);
        if types.is_empty() {
            return Ok(None);
        }
        let listed = match claims
            .list_source_discovery_work(&self.options.runtime_id, LIST_LIMIT, types)
            .await
        {
            Ok(listed) => listed,
            Err(RuntimeClaimError::Invalid(_)) => {
                eprintln!("sekai-connector-runtime: source discovery list refused as invalid");
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if !listed.is_empty() {
            eprintln!(
                "sekai-connector-runtime: listed {} source discoveries",
                listed.len()
            );
        }
        for work in listed {
            let runs = work
                .source
                .as_ref()
                .is_some_and(|source| self.connectors.runs(source, Operation::Discover));
            if !runs {
                continue;
            }
            let attempt = claims
                .claim_work(
                    WorkKind::SourceDiscovery,
                    &self.options.runtime_id,
                    &work.discovery_id,
                    self.options.lease,
                    None,
                )
                .await;
            match attempt {
                Ok(ClaimAttempt::Claimed(claim_work_response::Payload::SourceDiscovery(work))) => {
                    return Ok(Some(work));
                }
                Ok(_) | Err(RuntimeClaimError::Contention) => continue,
                Err(RuntimeClaimError::Unavailable(_) | RuntimeClaimError::FenceLost) => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    /// Runs a claimed discovery, heartbeating while it runs, and
    /// acknowledges its result or failure once.
    pub async fn run_discovery(
        &self,
        index: usize,
        work: SourceDiscoveryWork,
    ) -> Result<Ran, RuntimeClaimError> {
        let claims = self.clients[index].runtime_claim();
        let source = work.source.unwrap_or_default();
        let discovery_id = work.discovery_id.clone();
        let fence = WorkFence {
            kind: WorkKind::SourceDiscovery,
            work_id: discovery_id.clone(),
            runtime_id: work.claim_owner,
            generation: work.claim_generation,
            fencing_token: work.fencing_token,
        };
        let outcome = match prepare(&source, &self.bindings) {
            Err(failure) => Err(failure),
            Ok(prepared) => {
                let connectors = self.connectors.clone();
                let job = blocking(move || connectors.discover(&prepared));
                match self.heartbeated(&claims, &fence, job).await {
                    Some(outcome) => outcome,
                    None => return Ok(Ran::DiscoveryLost { discovery_id }),
                }
            }
        };
        let (status, reason, options) = match &outcome {
            Ok(found) => (
                "completed",
                String::new(),
                Some(ack_work_request::Options::SourceDiscovery(
                    SourceDiscoveryAckOptions {
                        discovery_json: serde_json::to_string(&found.discovery).unwrap_or_default(),
                        samples: found.samples.clone(),
                    },
                )),
            ),
            Err(failure) => ("failed", reported(*failure).wire_name().to_string(), None),
        };
        match claims.ack_work(&fence, status, reason, options).await {
            Ok(_) => Ok(Ran::Discovered {
                discovery_id,
                outcome: outcome.map(|_| ()).map_err(reported),
            }),
            Err(RuntimeClaimError::FenceLost) => Ok(Ran::DiscoveryLost { discovery_id }),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_source_sdk::{DiscoveredColumn, DiscoveredRecordKind, SOURCE_DISCOVERY_VERSION};

    /// Two record kinds; `order.customer_id` points at `customer.id`.
    struct Fixture {
        sampled: Vec<String>,
    }

    fn kind(name: &str, columns: &[&str]) -> DiscoveredRecordKind {
        DiscoveredRecordKind {
            record_kind: name.into(),
            schema_revision: "1".into(),
            columns: columns
                .iter()
                .map(|column| DiscoveredColumn {
                    name: (*column).into(),
                    data_type: "text".into(),
                    nullable: false,
                    profile: None,
                })
                .collect(),
            key_candidates: vec![vec!["id".into()]],
            references: Vec::new(),
            value_findings: Vec::new(),
        }
    }

    impl Connector for Fixture {
        fn discover(&mut self) -> Result<SourceDiscovery, ConnectorFailure> {
            Ok(SourceDiscovery {
                contract_version: SOURCE_DISCOVERY_VERSION.into(),
                source: "fixture".into(),
                record_kinds: vec![
                    kind("customer", &["id", "token"]),
                    kind("order", &["id", "customer_id"]),
                ],
            })
        }

        fn sample_rows(&mut self, record_kind: &str) -> Result<DiscoverySample, ConnectorFailure> {
            self.sampled.push(record_kind.into());
            let rows = (1..=20).map(|n| match record_kind {
                "customer" => BTreeMap::from([
                    ("id".into(), format!("c{n}")),
                    (
                        "token".into(),
                        "ghp_abcdefghijklmnopqrstuvwxyz0123456789".into(),
                    ),
                ]),
                _ => BTreeMap::from([
                    ("id".into(), format!("o{n}")),
                    ("customer_id".into(), format!("c{n}")),
                ]),
            });
            Ok(DiscoverySample::Rows {
                cells: rows.collect(),
            })
        }
    }

    #[test]
    fn a_discovery_carries_findings_and_bounded_secret_free_samples() {
        let mut fixture = Fixture {
            sampled: Vec::new(),
        };
        let found = discover(&mut fixture).unwrap();
        assert_eq!(
            fixture.sampled,
            ["customer", "order"],
            "each kind is sampled once"
        );
        let order = &found.discovery.record_kinds[1];
        assert_eq!(order.references[0].target_record_kind, "customer");
        assert_eq!(found.samples.len(), 2);
        let customer = &found.samples[0];
        assert_eq!(
            customer.rows.len(),
            sekai_source_sdk::MAX_DISCOVERY_SAMPLE_ROWS
        );
        assert!(
            customer
                .rows
                .iter()
                .all(|row| !row.cells.contains_key("token")),
            "a secret-like value never leaves the runtime"
        );
        // The document round-trips as the v1 JSON shape.
        let json = serde_json::to_string(&found.discovery).unwrap();
        let read: SourceDiscovery = serde_json::from_str(&json).unwrap();
        read.validate().unwrap();
        assert_eq!(read, found.discovery);
    }

    #[test]
    fn a_type_without_discover_is_unsupported() {
        struct Bare;
        impl Connector for Bare {}
        assert_eq!(discover(&mut Bare).unwrap_err(), SyncFailure::Unsupported);
    }

    #[test]
    fn samples_stop_at_the_budget() {
        let mut budget = 10;
        let big = DiscoverySample::Rows {
            cells: vec![BTreeMap::from([("id".into(), "x".repeat(20))])],
        };
        assert!(to_proto("k", big, &mut budget).is_none());
    }
}
