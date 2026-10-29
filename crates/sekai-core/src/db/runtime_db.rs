//! Dual-backend community store used by the public control plane.
//!
//! Area dispatch lives in `runtime_db_*.rs` as extra `impl RuntimeDb` blocks.
//! This file keeps the type, constructors, and temporary `pub(crate)` re-exports
//! so in-flight lanes that add methods here still compile after rebase.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
pub(crate) use crate::db::postgres::PostgresDb;
pub(crate) use crate::db::sekai::{PrincipalCredential, SekaiDb};
pub(crate) use postgres::GenericClient;
pub(crate) use std::sync::Arc;

#[cfg(any(test, feature = "gateway-test-support"))]
pub mod source_batch_auth_counters {
    use std::cell::Cell;

    thread_local! {
        pub static LOOKUP_QUERIES: Cell<usize> = const { Cell::new(0) };
        pub static POLICY_LOOKUPS: Cell<usize> = const { Cell::new(0) };
    }
}

pub(crate) use crate::db::definition_branch::DefinitionBranchBackend;
pub(crate) use crate::db::object_sync::ObjectSyncBackend;
pub(crate) use crate::domain::{Direction, Link, ListFilter, Object};
pub(crate) use crate::sekai::action_policy::ActionPolicy;
pub(crate) use crate::sekai::attestation::{AttestationVerification, PolicyAttestation};
pub(crate) use crate::sekai::audit::{ChangeAttribution, Decision, DecisionFilter, ObjectChange};
pub(crate) use crate::sekai::coordination::*;
pub(crate) use crate::sekai::dataset::{
    Dataset, DatasetRedaction, RowFilter, RowQuery, VirtualTable,
};
pub(crate) use crate::sekai::dataset_health::{
    DatasetAlert, DatasetHealthCheck, DatasetHealthResult, DatasetHealthState,
};
pub(crate) use crate::sekai::dataset_version::{DatasetRollback, DatasetVersion};
pub(crate) use crate::sekai::deduplication::*;
pub(crate) use crate::sekai::definition_branch::*;
pub(crate) use crate::sekai::definition_proposal::*;
pub(crate) use crate::sekai::evidence::{
    EvidenceClassification, EvidenceEnvelope, EvidenceLifecycleState,
};
pub(crate) use crate::sekai::evidence_projection::EvidenceProjectionOutcome;
pub(crate) use crate::sekai::evidence_store::{
    EvidenceAdmission, EvidenceProducerCapability, EvidenceSchemaDefinition,
    EvidenceSubmissionFilter, EvidenceSubmissionRecord, UsableEvidenceContext,
};
pub(crate) use crate::sekai::execution_evidence::*;
pub(crate) use crate::sekai::external_permit::{HostContext, Permit, Redemption};
pub(crate) use crate::sekai::function::Function;
pub(crate) use crate::sekai::handoff::*;
pub(crate) use crate::sekai::lease::{Lease, LeaseError};
pub(crate) use crate::sekai::ledger::*;
pub(crate) use crate::sekai::object_security::{
    ObjectSecurityActivation, ObjectSecurityPolicy, ObjectSecurityPolicyRevision,
    PrincipalPolicyContext, PropertyGrantAccess,
};
pub(crate) use crate::sekai::object_sync::{SourceBatch, SourceBatchResult, SourceSyncState};
pub(crate) use crate::sekai::observation::{TaskObservation, TaskObservationBaseline, *};
pub(crate) use crate::sekai::ontology::*;
pub(crate) use crate::sekai::retention::*;
pub(crate) use crate::sekai::schema::*;
pub(crate) use crate::sekai::security::*;
pub(crate) use ed25519_dalek::VerifyingKey;
pub(crate) use sekai_domain::receipt::{OperationReceipt, OperationReceiptEvent, ReceiptEventKind};
pub(crate) use sekai_types::evolve;
pub(crate) use sekai_types::principal::PrincipalContext;
pub(crate) use std::collections::{BTreeMap, BTreeSet, HashMap};
pub(crate) use std::path::Path;
pub(crate) use std::time::Instant;

#[derive(Clone)]
pub enum RuntimeDb {
    Sqlite(Arc<SekaiDb>),
    Postgres(Arc<PostgresDb>),
}

impl std::fmt::Debug for RuntimeDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sqlite(_) => "RuntimeDb::Sqlite",
            Self::Postgres(_) => "RuntimeDb::Postgres",
        })
    }
}

#[path = "runtime_db_actions.rs"]
mod actions;
#[path = "runtime_db_autonomy.rs"]
mod autonomy;
#[path = "runtime_db_connector.rs"]
mod connector;
#[path = "runtime_db_coordination.rs"]
mod coordination;
#[path = "runtime_db_datasets.rs"]
mod datasets;
#[path = "runtime_db_definitions.rs"]
mod definitions;
#[path = "runtime_db_documents.rs"]
mod documents;
#[path = "runtime_db_event_stream.rs"]
mod event_stream;
#[path = "runtime_db_evidence.rs"]
mod evidence;
#[path = "runtime_db_ezu_geo_feed.rs"]
mod ezu_geo_feed;
#[path = "runtime_db_federation.rs"]
mod federation;
#[path = "runtime_db_functions.rs"]
mod functions;
#[path = "runtime_db_images.rs"]
mod images;
#[path = "runtime_db_lakehouse.rs"]
mod lakehouse;
#[path = "runtime_db_model_platform.rs"]
mod model_platform;
#[path = "runtime_db_object_security.rs"]
mod object_security;
#[path = "runtime_db_objects.rs"]
mod objects;
#[path = "runtime_db_ontology.rs"]
mod ontology;
#[path = "runtime_db_open_table.rs"]
mod open_table;
#[path = "runtime_db_packages.rs"]
mod packages;
#[path = "runtime_db_receipts.rs"]
mod receipts;
#[path = "runtime_db_retention.rs"]
mod retention;
#[path = "runtime_db_source_sync.rs"]
mod source_sync;
#[path = "runtime_db_transforms.rs"]
mod transforms;
#[path = "runtime_db_warehouse.rs"]
mod warehouse;
#[path = "runtime_db_workflow.rs"]
mod workflow;

impl RuntimeDb {
    /// Connection-pool ceiling used as the gRPC `spawn_blocking` bound.
    pub fn connection_pool_max(&self) -> u32 {
        match self {
            Self::Sqlite(db) => db.as_ref().pool_max_size(),
            Self::Postgres(db) => db.as_ref().max_connections(),
        }
    }

    /// Labels this store's connection-pool signals with the plane it serves.
    pub fn set_pool_plane(&self, plane: crate::obs::labels::PoolPlane) {
        match self {
            RuntimeDb::Sqlite(db) => db.set_pool_plane(plane),
            RuntimeDb::Postgres(db) => db.set_pool_plane(plane),
        }
    }

    /// In-memory SQLite store for tests.
    pub fn memory() -> Self {
        Self::Sqlite(Arc::new(SekaiDb::new(":memory:").expect("memory sqlite")))
    }

    /// In-memory SQLite plus tables for Chisei SQL functions still in this crate.
    #[cfg(test)]
    pub fn memory_for_chisei_sql_functions() -> Self {
        Self::Sqlite(Arc::new(SekaiDb::memory_for_chisei_sql_functions()))
    }

    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Sqlite(_) => "sqlite",
            Self::Postgres(_) => "postgres",
        }
    }

    pub fn db_lock_poisoned_total(&self) -> u64 {
        match self {
            Self::Sqlite(db) => db.db_lock_poisoned_total(),
            Self::Postgres(_) => 0,
        }
    }

    pub fn enterprise_extension(&self) -> Option<&Arc<dyn crate::enterprise::EnterpriseExtension>> {
        match self {
            Self::Sqlite(db) => db.enterprise_extension(),
            Self::Postgres(db) => db.enterprise_extension(),
        }
    }

    pub fn as_sqlite(&self) -> Option<&SekaiDb> {
        match self {
            Self::Sqlite(db) => Some(db.as_ref()),
            Self::Postgres(_) => None,
        }
    }

    pub fn as_sqlite_arc(&self) -> Option<Arc<SekaiDb>> {
        match self {
            Self::Sqlite(db) => Some(db.clone()),
            Self::Postgres(_) => None,
        }
    }

    pub fn require_sqlite_arc(&self) -> Result<Arc<SekaiDb>, String> {
        self.as_sqlite_arc().ok_or_else(|| {
            "this code path still requires the SQLite community store; PostgreSQL dual-wiring is incomplete for this operation"
                .into()
        })
    }

    pub fn ping(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.ping(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.ping()),
        }
    }

    /// SQLite-only raw connection access for legacy internals/tests.
    pub fn with_sqlite_conn<R>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> R,
    ) -> Result<R, String> {
        match self {
            Self::Sqlite(db) => {
                let conn = db.conn();
                Ok(f(&conn))
            }
            Self::Postgres(_) => Err("raw SQLite connection is unavailable on PostgreSQL".into()),
        }
    }

    pub fn migrate_all(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.migrate_all(),
            Self::Postgres(_) => {
                Err("migrate_all is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn migrate_schema_types(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.migrate_schema_types(),
            Self::Postgres(_) => Err(
                "migrate_schema_types is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn conn(&self) -> crate::db::sekai::SqliteConn {
        match self {
            Self::Sqlite(db) => db.conn(),
            Self::Postgres(_) => panic!("conn() is only available for the SQLite community store"),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn migrate_audit(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.migrate_audit(),
            Self::Postgres(_) => {
                Err("migrate_audit is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }
}
