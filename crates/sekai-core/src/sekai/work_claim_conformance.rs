//! One claim conformance suite for every work kind on both stores
//! (ADR 0149): claim, heartbeat, expiry, reclaim under a higher generation,
//! a stale token refused on write-back, and failure after the lease-expiry
//! limit. Each kind is driven through its own store entry points.
//! Export delivery has no lease-expiry limit: retention bounds it.

use std::collections::HashMap;

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action_effect::{EFFECT_STATUS_DEAD_LETTERED, plan_effects_for_admit};
use crate::sekai::agent_turn::{self, Cause, Outcome, TurnError, Wake};
use crate::sekai::data_export::export_receipt;
use crate::sekai::dataset::{ColumnDef, Dataset};
use crate::sekai::export_delivery::{self, DeliveryError};
use crate::sekai::governed_transform::{
    CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, STALE_TRANSFORM_CLAIM,
    TRANSFORM_WORK_FAILED, WriteTransformRunCommand,
};
use crate::sekai::site_agent_instance;
use crate::sekai::work_claim::{ClaimError, Fence, WorkKind};

/// The claim a test holds.
struct Held {
    owner: String,
    generation: i64,
    token: String,
}

impl Held {
    fn fence(&self) -> Fence<'_> {
        Fence {
            owner: &self.owner,
            generation: self.generation,
            token: &self.token,
        }
    }
}

/// One piece of work of one kind, driven through that kind's store calls.
struct Subject<'a> {
    db: &'a RuntimeDb,
    kind: WorkKind,
    namespace: String,
    id: String,
}

const TTL_MS: i64 = 1_000;

impl Subject<'_> {
    /// Claims the work; `None` when it is held, closed or just failed.
    fn claim(&self, owner: &str, now_ms: i64) -> Option<Held> {
        match self.kind {
            WorkKind::Transform => self
                .db
                .claim_transform_work_outcome(&self.namespace, owner, &self.id, TTL_MS, now_ms, &[])
                .unwrap()
                .claimed
                .map(|(work, _)| Held {
                    owner: work.claim_owner,
                    generation: work.claim_generation,
                    token: work.fencing_token,
                }),
            WorkKind::Action => self
                .db
                .claim_action_work(
                    &self.id,
                    owner,
                    &format!("{owner}-{now_ms}"),
                    "op",
                    TTL_MS,
                    now_ms,
                )
                .ok()
                .map(|effect| Held {
                    owner: effect.claim_owner,
                    generation: i64::try_from(effect.claim_generation).unwrap(),
                    token: effect.claim_fencing_token,
                }),
            WorkKind::AgentTurn => {
                match agent_turn::claim(self.db, &self.namespace, owner, &self.id, TTL_MS, now_ms) {
                    Ok(turn) => Some(Held {
                        owner: turn.claim_owner,
                        generation: turn.claim_generation,
                        token: turn.fencing_token,
                    }),
                    Err(TurnError::NotClaimable) => None,
                    Err(error) => panic!("agent turn claim failed: {error}"),
                }
            }
            WorkKind::ExportDelivery => {
                match export_delivery::claim(self.db, &self.receipt(), owner, TTL_MS, now_ms) {
                    Ok(artifact) => Some(Held {
                        owner: artifact.claim.owner,
                        generation: artifact.claim.generation,
                        token: artifact.claim.fencing_token,
                    }),
                    Err(DeliveryError::Claim(ClaimError::Held)) => None,
                    Err(error) => panic!("export delivery claim failed: {error}"),
                }
            }
            _ => unreachable!("not a kind under test"),
        }
    }

    fn receipt(&self) -> sekai_domain::receipt::OperationReceipt {
        export_receipt(self.db, &self.id).unwrap().unwrap()
    }

    fn heartbeat(&self, held: &Held, now_ms: i64) -> bool {
        match self.kind {
            WorkKind::Transform => self
                .db
                .heartbeat_transform_work(
                    &self.id,
                    &held.owner,
                    held.generation,
                    &held.token,
                    TTL_MS,
                    now_ms,
                )
                .is_ok(),
            WorkKind::Action => self
                .db
                .heartbeat_action_claim(
                    &self.id,
                    &held.owner,
                    u64::try_from(held.generation).unwrap(),
                    &held.token,
                    TTL_MS,
                    now_ms,
                )
                .is_ok(),
            WorkKind::AgentTurn => agent_turn::heartbeat(
                self.db,
                &self.id,
                &held.owner,
                held.generation,
                &held.token,
                TTL_MS,
                now_ms,
            )
            .is_ok(),
            WorkKind::ExportDelivery => {
                export_delivery::heartbeat(self.db, &self.receipt(), held.fence(), TTL_MS, now_ms)
                    .is_ok()
            }
            _ => unreachable!("not a kind under test"),
        }
    }

    /// Writes the work back under `held`; returns whether it was refused as
    /// stale.
    fn write_back_refused_as_stale(&self, held: &Held, now_ms: i64) -> bool {
        match self.kind {
            WorkKind::Transform => {
                let error = self
                    .db
                    .write_transform_run(
                        WriteTransformRunCommand {
                            run_id: self.id.clone(),
                            runtime_id: held.owner.clone(),
                            claim_generation: held.generation,
                            fencing_token: held.token.clone(),
                            rows: Vec::new(),
                            output_digest: String::new(),
                            quarantined: false,
                            quality_rule: String::new(),
                            replaced_partitions: Vec::new(),
                            partition_key: None,
                            max_bytes: 0,
                        },
                        now_ms,
                    )
                    .unwrap_err();
                error == STALE_TRANSFORM_CLAIM
            }
            WorkKind::Action => self
                .db
                .ack_action_work(
                    &self.id,
                    &held.owner,
                    u64::try_from(held.generation).unwrap(),
                    &held.token,
                    "completed",
                    "",
                    now_ms,
                )
                .unwrap_err()
                .contains("fencing token or generation mismatch"),
            WorkKind::AgentTurn => {
                agent_turn::acknowledge(
                    self.db,
                    &self.id,
                    &held.owner,
                    held.generation,
                    &held.token,
                    Outcome::Completed,
                    "done",
                    now_ms,
                )
                .unwrap_err()
                    == TurnError::StaleClaim
            }
            WorkKind::ExportDelivery => {
                let digest = crate::sekai::data_export::completed_digest(&self.receipt()).unwrap();
                export_delivery::acknowledge_export_delivery(
                    self.db,
                    &self.id,
                    &digest,
                    Some(held.fence()),
                    now_ms,
                )
                .unwrap_err()
                    == DeliveryError::Claim(ClaimError::FenceLost)
            }
            _ => unreachable!("not a kind under test"),
        }
    }

    /// Whether the work ended in the kind's failed state.
    fn failed(&self) -> bool {
        match self.kind {
            WorkKind::Transform => {
                self.db
                    .get_governed_transform_run(&self.id)
                    .unwrap()
                    .unwrap()
                    .dispatch_status
                    == TRANSFORM_WORK_FAILED
            }
            WorkKind::Action => {
                self.db.get_action_effect(&self.id).unwrap().unwrap().status
                    == EFFECT_STATUS_DEAD_LETTERED
            }
            WorkKind::AgentTurn => {
                agent_turn::get(self.db, &self.id).unwrap().unwrap().status == "failed"
            }
            _ => unreachable!("not a kind under test"),
        }
    }
}

/// Admits one piece of `kind` work in a namespace unique to this run.
fn admit<'a>(db: &'a RuntimeDb, kind: WorkKind, prefix: &str) -> Subject<'a> {
    let namespace = format!(
        "{prefix}-{}-{}",
        kind.wire_name(),
        uuid::Uuid::new_v4().simple()
    );
    let id = match kind {
        WorkKind::Transform => admit_transform(db, &namespace),
        WorkKind::Action => {
            let mut effect = plan_effects_for_admit(
                &format!("{namespace}-instance"),
                &namespace,
                &format!("{namespace}-operation"),
                &["runtime_dispatch".into()],
                r#"{"runtime":"worker"}"#,
                10,
                false,
            )
            .unwrap()
            .remove(0);
            effect.effect_id = format!("{namespace}-effect");
            db.put_action_effects(std::slice::from_ref(&effect))
                .unwrap();
            effect.effect_id
        }
        WorkKind::AgentTurn => admit_turn(db, &namespace),
        WorkKind::ExportDelivery => {
            export_delivery::tests::completed_artifact(db, &namespace).operation_id
        }
        _ => unreachable!("not a kind under test"),
    };
    Subject {
        db,
        kind,
        namespace,
        id,
    }
}

fn admit_transform(db: &RuntimeDb, namespace: &str) -> String {
    let dataset = |id: String| Dataset {
        name: id.clone(),
        id,
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    };
    let input = format!("{namespace}-in");
    let output = format!("{namespace}-out");
    db.create_dataset(&dataset(input.clone())).unwrap();
    db.create_dataset(&dataset(output.clone())).unwrap();
    db.append_rows(&input, &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: namespace.into(),
        transform_id: "claim".into(),
        input_dataset_id: input,
        output_dataset_id: output,
        steps: Vec::new(),
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: None,
        isolated_process: Some(IsolatedProcessSpec {
            engine: "python".into(),
            runtime_image: "runner:1".into(),
            inputs: Vec::new(),
            requires: Default::default(),
            code: String::new(),
        }),
        schedule: None,
        trigger: None,
    }
    .prepare()
    .unwrap();
    db.put_governed_transform(&transform, 10).unwrap();
    db.run_governed_transform(namespace, "claim", false, 20)
        .unwrap()
        .run_id
}

fn admit_turn(db: &RuntimeDb, namespace: &str) -> String {
    let instance = format!("{namespace}-agent");
    db.create_object(&crate::domain::Object {
        id: instance.clone(),
        kind: site_agent_instance::KIND.into(),
        name: "agent".into(),
        namespace: namespace.into(),
        external_id: String::new(),
        properties: HashMap::from([
            ("principal_id".to_string(), format!("agent:{instance}")),
            (
                site_agent_instance::FROZEN_PROPERTY.to_string(),
                "false".into(),
            ),
        ]),
        created: 1,
        updated: 1,
    })
    .unwrap();
    agent_turn::admit(
        db,
        Wake {
            namespace: namespace.into(),
            instance_id: instance,
            cause: Cause::Manual,
            cause_ref: "claim".into(),
            due_at_ms: 100,
        },
        "plane",
        1,
    )
    .unwrap()
    .turn_id
}

/// The claim contract for `kind` on `db`.
fn claim_contract(db: &RuntimeDb, kind: WorkKind, prefix: &str) {
    let work = admit(db, kind, prefix);
    let first = work.claim("a", 1_000).expect("open work is claimable");
    assert!(
        work.claim("b", 1_500).is_none(),
        "{kind}: a live claim excludes"
    );
    assert!(
        work.heartbeat(&first, 1_500),
        "{kind}: heartbeat extends the lease"
    );
    assert!(
        work.claim("b", 2_400).is_none(),
        "{kind}: the extended lease holds"
    );
    assert!(
        !work.heartbeat(&first, 2_600),
        "{kind}: an expired lease is fenced"
    );

    let second = work
        .claim("b", 2_600)
        .expect("a lapsed claim is reclaimable");
    assert!(
        second.generation > first.generation,
        "{kind}: reclaim raises the generation"
    );
    assert!(
        work.write_back_refused_as_stale(&first, 2_700),
        "{kind}: the stale token cannot write back"
    );
    assert!(
        work.heartbeat(&second, 2_700),
        "{kind}: the current claim still holds"
    );

    if kind == WorkKind::ExportDelivery {
        // No lease-expiry limit: retention bounds the reclaims.
        let third = work
            .claim("c", 5_000)
            .expect("a second lapse is reclaimable");
        let fourth = work.claim("d", 8_000).expect("and a third");
        assert!(fourth.generation > third.generation);
        return;
    }
    // The second lapse is counted at this claim, the third fails the work.
    work.claim("c", 5_000)
        .expect("a second lapse is reclaimable");
    assert!(
        work.claim("d", 8_000).is_none(),
        "{kind}: the third lapse is not reclaimed"
    );
    assert!(
        work.failed(),
        "{kind}: the lease-expiry limit fails the work"
    );
}

pub(crate) fn postgres() -> RuntimeDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
    let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
            &url,
            4,
            &std::fs::read(path).unwrap(),
        ),
        Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
    };
    RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()))
}

#[test]
fn sqlite_transform_claim_conformance() {
    claim_contract(&RuntimeDb::memory(), WorkKind::Transform, "sqlite");
}

#[test]
fn sqlite_action_claim_conformance() {
    claim_contract(&RuntimeDb::memory(), WorkKind::Action, "sqlite");
}

#[test]
fn sqlite_agent_turn_claim_conformance() {
    claim_contract(&RuntimeDb::memory(), WorkKind::AgentTurn, "sqlite");
}

#[test]
fn sqlite_export_delivery_claim_conformance() {
    claim_contract(&RuntimeDb::memory(), WorkKind::ExportDelivery, "sqlite");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
fn postgres_transform_claim_conformance() {
    claim_contract(
        &postgres(),
        WorkKind::Transform,
        &format!("pg{}", std::process::id()),
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
fn postgres_action_claim_conformance() {
    claim_contract(
        &postgres(),
        WorkKind::Action,
        &format!("pg{}", std::process::id()),
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
fn postgres_agent_turn_claim_conformance() {
    claim_contract(
        &postgres(),
        WorkKind::AgentTurn,
        &format!("pg{}", std::process::id()),
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
fn postgres_export_delivery_claim_conformance() {
    claim_contract(
        &postgres(),
        WorkKind::ExportDelivery,
        &format!("pg{}", std::process::id()),
    );
}
