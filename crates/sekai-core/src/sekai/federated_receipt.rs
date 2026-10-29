//! Federated aggregate receipts (ADR 0134 §8, #1996).
//!
//! Every federated query writes one receipt per tenant it touches: the
//! requesting tenant and each participating tenant. A receipt is opened
//! before any partial leaves its tenant and closed afterwards with the
//! groups returned, the groups suppressed and any exclusions. The key is the
//! query id and the tenant, so opening again with the same content is a
//! no-op and a retry records nothing twice.
//!
//! A receipt is closed exactly once. Closing, aborting and the stale sweep
//! each update the row only while it is still open, so when they race on
//! several replicas exactly one of them decides the outcome; the others see
//! the decided receipt. A query whose receipt was closed by someone else
//! (for example aborted by the sweep while it ran) gets [`RECEIPT_CLOSED`]
//! and must not return its result. The stale bound must therefore exceed
//! the longest a query may run.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::federated_aggregate::ExclusionReason;

/// An open receipt with the same key holds different content.
pub const RECEIPT_CONFLICT: &str = "federated_receipt_conflict";
/// The receipt was already closed with another outcome.
pub const RECEIPT_CLOSED: &str = "federated_receipt_closed";
/// How long a receipt may stay open before the sweep aborts it.
pub const DEFAULT_STALE_AFTER_MS: i64 = 15 * 60 * 1000;
/// Receipts one sweep pass aborts at most; the next pass takes the rest.
const SWEEP_BATCH: i64 = 256;
const MAX_FIELD: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptRole {
    /// The tenant that asked.
    Requester,
    /// A tenant whose data the query evaluated, or that it excluded.
    Participant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    Open,
    Completed,
    Aborted,
}

impl ReceiptState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Completed => "completed",
            Self::Aborted => "aborted",
        }
    }
}

/// What a receipt is opened with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenReceipt {
    /// One id per federated query, shared by all of its receipts.
    pub query_id: String,
    pub tenant: String,
    pub role: ReceiptRole,
    /// The requesting tenant or space, as the allowances name it.
    pub requester: String,
    /// The principal that asked.
    pub actor: String,
    pub query_digest: String,
    /// The digest of the allowance the tenant took part under; empty on the
    /// requester's receipt and for a tenant without an allowance.
    #[serde(default)]
    pub allowance_digest: String,
}

/// How a query ended for one tenant. Counts only: no group key leaves into
/// a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptOutcome {
    pub returned_groups: u64,
    pub suppressed_groups: u64,
    /// Excluded tenants and why (§6).
    #[serde(default)]
    pub excluded: BTreeMap<String, ExclusionReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederatedReceipt {
    #[serde(flatten)]
    pub opened: OpenReceipt,
    pub opened_at_ms: i64,
    pub state: ReceiptState,
    /// 0 while open.
    #[serde(default)]
    pub closed_at_ms: i64,
    /// Present once completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ReceiptOutcome>,
    /// Why an aborted receipt was aborted.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub abort_reason: String,
}

fn check(opened: &OpenReceipt) -> Result<(), String> {
    for (name, value) in [
        ("query id", &opened.query_id),
        ("tenant", &opened.tenant),
        ("requester", &opened.requester),
        ("actor", &opened.actor),
        ("query digest", &opened.query_digest),
    ] {
        if value.trim().is_empty() || value.len() > MAX_FIELD {
            return Err(format!("receipt {name} must be 1 to {MAX_FIELD} bytes"));
        }
    }
    if opened.allowance_digest.len() > MAX_FIELD {
        return Err(format!(
            "receipt allowance digest exceeds {MAX_FIELD} bytes"
        ));
    }
    Ok(())
}

/// Open the receipt for `opened`'s query and tenant. Opening it again with
/// the same content returns the stored receipt, in whatever state it is: a
/// caller lets partials leave only while it is [`ReceiptState::Open`].
pub fn open(db: &RuntimeDb, opened: OpenReceipt, now_ms: i64) -> Result<FederatedReceipt, String> {
    check(&opened)?;
    let receipt = FederatedReceipt {
        opened,
        opened_at_ms: now_ms,
        state: ReceiptState::Open,
        closed_at_ms: 0,
        outcome: None,
        abort_reason: String::new(),
    };
    if db.insert_federated_receipt(&receipt)? {
        return Ok(receipt);
    }
    let stored = get(db, &receipt.opened.query_id, &receipt.opened.tenant)?
        .ok_or_else(|| "federated receipt vanished while opening".to_string())?;
    if stored.opened != receipt.opened {
        return Err(RECEIPT_CONFLICT.into());
    }
    Ok(stored)
}

/// Close an open receipt with `outcome`. Closing it again with the same
/// outcome returns it; a receipt closed otherwise (aborted, or completed
/// with another outcome) is [`RECEIPT_CLOSED`].
pub fn close(
    db: &RuntimeDb,
    query_id: &str,
    tenant: &str,
    outcome: ReceiptOutcome,
    now_ms: i64,
) -> Result<FederatedReceipt, String> {
    decide(db, query_id, tenant, now_ms, |receipt| {
        receipt.state = ReceiptState::Completed;
        receipt.outcome = Some(outcome.clone());
    })
    .and_then(|receipt| {
        if receipt.state == ReceiptState::Completed && receipt.outcome.as_ref() == Some(&outcome) {
            Ok(receipt)
        } else {
            Err(RECEIPT_CLOSED.into())
        }
    })
}

/// Abort an open receipt, for a query that failed before it finished.
/// Returns the receipt as decided, which is the earlier outcome when it was
/// already closed.
pub fn abort(
    db: &RuntimeDb,
    query_id: &str,
    tenant: &str,
    reason: &str,
    now_ms: i64,
) -> Result<FederatedReceipt, String> {
    decide(db, query_id, tenant, now_ms, |receipt| {
        receipt.state = ReceiptState::Aborted;
        receipt.abort_reason = reason.chars().take(MAX_FIELD).collect();
    })
}

/// Abort every receipt open since before `now_ms - stale_after_ms`. Returns
/// the receipts this call aborted: a receipt another sweep, a close or an
/// abort decided first is not among them, so concurrent sweeps on several
/// replicas abort each receipt exactly once.
pub fn sweep_stale(
    db: &RuntimeDb,
    now_ms: i64,
    stale_after_ms: i64,
) -> Result<Vec<FederatedReceipt>, String> {
    sweep(db, None, now_ms, stale_after_ms)
}

/// [`sweep_stale`] for one tenant's receipts only.
pub fn sweep_stale_for_tenant(
    db: &RuntimeDb,
    tenant: &str,
    now_ms: i64,
    stale_after_ms: i64,
) -> Result<Vec<FederatedReceipt>, String> {
    sweep(db, Some(tenant), now_ms, stale_after_ms)
}

fn sweep(
    db: &RuntimeDb,
    tenant: Option<&str>,
    now_ms: i64,
    stale_after_ms: i64,
) -> Result<Vec<FederatedReceipt>, String> {
    let cutoff = now_ms.saturating_sub(stale_after_ms.max(0));
    let mut aborted = Vec::new();
    for mut receipt in db.stale_federated_receipts(tenant, cutoff, SWEEP_BATCH)? {
        receipt.state = ReceiptState::Aborted;
        receipt.closed_at_ms = now_ms;
        receipt.abort_reason = "stale".into();
        if db.decide_federated_receipt(&receipt)? {
            aborted.push(receipt);
        }
    }
    Ok(aborted)
}

pub fn get(
    db: &RuntimeDb,
    query_id: &str,
    tenant: &str,
) -> Result<Option<FederatedReceipt>, String> {
    db.federated_receipt(query_id, tenant)
}

/// A tenant's receipts, newest first.
pub fn list_for_tenant(
    db: &RuntimeDb,
    tenant: &str,
    limit: i64,
) -> Result<Vec<FederatedReceipt>, String> {
    db.federated_receipts_for_tenant(tenant, limit.clamp(1, 1000))
}

/// Apply `close` to the open receipt under the open-state condition; when
/// someone else decided it first, return their decision.
fn decide(
    db: &RuntimeDb,
    query_id: &str,
    tenant: &str,
    now_ms: i64,
    close: impl FnOnce(&mut FederatedReceipt),
) -> Result<FederatedReceipt, String> {
    let mut receipt =
        get(db, query_id, tenant)?.ok_or_else(|| "federated receipt not found".to_string())?;
    if receipt.state != ReceiptState::Open {
        return Ok(receipt);
    }
    receipt.closed_at_ms = now_ms;
    close(&mut receipt);
    if db.decide_federated_receipt(&receipt)? {
        return Ok(receipt);
    }
    get(db, query_id, tenant)?.ok_or_else(|| "federated receipt vanished while closing".to_string())
}

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS sekai_federated_receipts (
    query_id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    state TEXT NOT NULL,
    opened_at_ms INTEGER NOT NULL,
    receipt_json TEXT NOT NULL,
    PRIMARY KEY (query_id, tenant)
);
CREATE INDEX IF NOT EXISTS sekai_federated_receipts_open
    ON sekai_federated_receipts (state, opened_at_ms);
CREATE INDEX IF NOT EXISTS sekai_federated_receipts_tenant
    ON sekai_federated_receipts (tenant, opened_at_ms);
";

const INSERT: &str = "INSERT INTO sekai_federated_receipts
    (query_id, tenant, state, opened_at_ms, receipt_json) VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT DO NOTHING";
const DECIDE: &str = "UPDATE sekai_federated_receipts SET state = $1, receipt_json = $2
    WHERE query_id = $3 AND tenant = $4 AND state = 'open'";
const GET: &str =
    "SELECT receipt_json FROM sekai_federated_receipts WHERE query_id = $1 AND tenant = $2";
const STALE: &str = "SELECT receipt_json FROM sekai_federated_receipts
    WHERE state = 'open' AND opened_at_ms <= $1 ORDER BY opened_at_ms, query_id, tenant LIMIT $2";
const STALE_FOR_TENANT: &str = "SELECT receipt_json FROM sekai_federated_receipts
    WHERE state = 'open' AND opened_at_ms <= $1 AND tenant = $3
    ORDER BY opened_at_ms, query_id, tenant LIMIT $2";
const FOR_TENANT: &str = "SELECT receipt_json FROM sekai_federated_receipts
    WHERE tenant = $1 ORDER BY opened_at_ms DESC, query_id LIMIT $2";

fn encode(receipt: &FederatedReceipt) -> Result<String, String> {
    serde_json::to_string(receipt).map_err(|error| error.to_string())
}

fn decode(json: &str) -> Result<FederatedReceipt, String> {
    serde_json::from_str(json).map_err(|error| format!("corrupt federated receipt: {error}"))
}

/// SQLite takes `?N` placeholders; the statements are written once with `$N`.
fn sqlite(sql: &str) -> String {
    sql.replace('$', "?")
}

impl SekaiDb {
    pub(crate) fn migrate_federated_receipts(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
    }

    fn federated_receipt_query(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<FederatedReceipt>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(&sqlite(sql))
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params, |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        rows.map(|row| decode(&row.map_err(|error| error.to_string())?))
            .collect()
    }

    fn federated_receipt_write(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<bool, String> {
        self.conn()
            .execute(&sqlite(sql), params)
            .map(|changed| changed == 1)
            .map_err(|error| error.to_string())
    }
}

impl PostgresDb {
    fn federated_receipt_query(
        &self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<Vec<FederatedReceipt>, String> {
        self.connection()?
            .query(sql, params)
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| decode(row.get(0)))
            .collect()
    }

    fn federated_receipt_write(
        &self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<bool, String> {
        self.connection()?
            .execute(sql, params)
            .map(|changed| changed == 1)
            .map_err(|error| error.to_string())
    }
}

impl RuntimeDb {
    /// Inserts a new receipt; false when one with its key exists.
    pub fn insert_federated_receipt(&self, receipt: &FederatedReceipt) -> Result<bool, String> {
        let json = encode(receipt)?;
        let state = receipt.state.as_str();
        let (query_id, tenant) = (&receipt.opened.query_id, &receipt.opened.tenant);
        match self {
            Self::Sqlite(db) => db.federated_receipt_write(
                INSERT,
                &[query_id, tenant, &state, &receipt.opened_at_ms, &json],
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.federated_receipt_write(
                    INSERT,
                    &[query_id, tenant, &state, &receipt.opened_at_ms, &json],
                )
            }),
        }
    }

    /// Stores `receipt`'s decision if its row is still open; false when
    /// another close, abort or sweep decided it first.
    pub fn decide_federated_receipt(&self, receipt: &FederatedReceipt) -> Result<bool, String> {
        let json = encode(receipt)?;
        let state = receipt.state.as_str();
        let (query_id, tenant) = (&receipt.opened.query_id, &receipt.opened.tenant);
        match self {
            Self::Sqlite(db) => {
                db.federated_receipt_write(DECIDE, &[&state, &json, query_id, tenant])
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.federated_receipt_write(DECIDE, &[&state, &json, query_id, tenant])
            }),
        }
    }

    pub fn federated_receipt(
        &self,
        query_id: &str,
        tenant: &str,
    ) -> Result<Option<FederatedReceipt>, String> {
        let rows = match self {
            Self::Sqlite(db) => db.federated_receipt_query(GET, &[&query_id, &tenant]),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.federated_receipt_query(GET, &[&query_id, &tenant])
            }),
        }?;
        Ok(rows.into_iter().next())
    }

    /// Open receipts opened at or before `cutoff_ms`, oldest first; with
    /// `tenant`, only that tenant's.
    pub fn stale_federated_receipts(
        &self,
        tenant: Option<&str>,
        cutoff_ms: i64,
        limit: i64,
    ) -> Result<Vec<FederatedReceipt>, String> {
        match (self, tenant) {
            (Self::Sqlite(db), None) => db.federated_receipt_query(STALE, &[&cutoff_ms, &limit]),
            (Self::Sqlite(db), Some(tenant)) => {
                db.federated_receipt_query(STALE_FOR_TENANT, &[&cutoff_ms, &limit, &tenant])
            }
            (Self::Postgres(db), None) => crate::db::postgres::off_runtime(|| {
                db.federated_receipt_query(STALE, &[&cutoff_ms, &limit])
            }),
            (Self::Postgres(db), Some(tenant)) => crate::db::postgres::off_runtime(|| {
                db.federated_receipt_query(STALE_FOR_TENANT, &[&cutoff_ms, &limit, &tenant])
            }),
        }
    }

    pub fn federated_receipts_for_tenant(
        &self,
        tenant: &str,
        limit: i64,
    ) -> Result<Vec<FederatedReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.federated_receipt_query(FOR_TENANT, &[&tenant, &limit]),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.federated_receipt_query(FOR_TENANT, &[&tenant, &limit])
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opened(query_id: &str, tenant: &str, role: ReceiptRole) -> OpenReceipt {
        OpenReceipt {
            query_id: query_id.into(),
            tenant: tenant.into(),
            role,
            requester: "buyer".into(),
            actor: "analyst".into(),
            query_digest: "sha256:query".into(),
            allowance_digest: match role {
                ReceiptRole::Requester => String::new(),
                ReceiptRole::Participant => "sha256:allowance".into(),
            },
        }
    }

    /// Open in two tenants, close both: the same query digest, allowance
    /// digest and outcome in each. Open and close are idempotent; a
    /// conflicting open and a second, different close are refused.
    fn receipt_contract(db: &RuntimeDb, prefix: &str) {
        let query = format!("{prefix}-q1");
        let (north, south) = (format!("{prefix}-north"), format!("{prefix}-south"));
        let requester = format!("{prefix}-buyer");
        open(db, opened(&query, &requester, ReceiptRole::Requester), 10).unwrap();
        for tenant in [&north, &south] {
            let receipt = open(db, opened(&query, tenant, ReceiptRole::Participant), 10).unwrap();
            assert_eq!(receipt.state, ReceiptState::Open);
            // A retry returns the stored receipt, opened at the first time.
            let again = open(db, opened(&query, tenant, ReceiptRole::Participant), 11).unwrap();
            assert_eq!(again, receipt);
        }
        let mut other = opened(&query, &north, ReceiptRole::Participant);
        other.query_digest = "sha256:another".into();
        assert_eq!(open(db, other, 12).unwrap_err(), RECEIPT_CONFLICT);

        let outcome = ReceiptOutcome {
            returned_groups: 3,
            suppressed_groups: 1,
            excluded: BTreeMap::from([(format!("{prefix}-west"), ExclusionReason::NoAllowance)]),
        };
        for tenant in [&north, &south, &requester] {
            let closed = close(db, &query, tenant, outcome.clone(), 20).unwrap();
            assert_eq!(closed.state, ReceiptState::Completed);
            assert_eq!(
                close(db, &query, tenant, outcome.clone(), 21).unwrap(),
                closed
            );
            assert_eq!(
                close(db, &query, tenant, ReceiptOutcome::default(), 22).unwrap_err(),
                RECEIPT_CLOSED
            );
            // A late abort leaves the completed receipt as it was.
            assert_eq!(abort(db, &query, tenant, "late", 23).unwrap(), closed);
        }
        let north_receipt = get(db, &query, &north).unwrap().unwrap();
        let south_receipt = get(db, &query, &south).unwrap().unwrap();
        for receipt in [&north_receipt, &south_receipt] {
            assert_eq!(receipt.opened.query_digest, "sha256:query");
            assert_eq!(receipt.opened.allowance_digest, "sha256:allowance");
            assert_eq!(receipt.outcome.as_ref(), Some(&outcome));
            assert_eq!((receipt.opened_at_ms, receipt.closed_at_ms), (10, 20));
        }
        assert_eq!(
            list_for_tenant(db, &north, 10).unwrap(),
            vec![north_receipt]
        );
        assert!(close(db, "missing", &north, outcome, 30).is_err());
    }

    /// A receipt open past the stale bound is aborted exactly once, also by
    /// concurrent sweeps; a fresh one and a closed one are left alone, and
    /// a close after the sweep is refused. The sweeps are scoped to this
    /// run's tenant, so on a shared database they never touch another run's
    /// receipts.
    fn sweep_contract(db: &RuntimeDb, prefix: &str) {
        let stale = format!("{prefix}-stale");
        let fresh = format!("{prefix}-fresh");
        let tenant = format!("{prefix}-north");
        open(db, opened(&stale, &tenant, ReceiptRole::Participant), 1_000).unwrap();
        open(db, opened(&fresh, &tenant, ReceiptRole::Participant), 9_000).unwrap();
        let now = 10_000;
        let sweeps: Vec<_> = (0..4)
            .map(|_| {
                let db = db.clone();
                let tenant = tenant.clone();
                std::thread::spawn(move || {
                    sweep_stale_for_tenant(&db, &tenant, now, 5_000).unwrap()
                })
            })
            .collect();
        let aborted: Vec<FederatedReceipt> = sweeps
            .into_iter()
            .flat_map(|sweep| sweep.join().unwrap())
            .collect();
        assert_eq!(aborted.len(), 1, "{aborted:?}");
        assert_eq!(aborted[0].opened.query_id, stale);
        let stored = get(db, &stale, &tenant).unwrap().unwrap();
        assert_eq!(stored.state, ReceiptState::Aborted);
        assert_eq!(
            (stored.abort_reason.as_str(), stored.closed_at_ms),
            ("stale", now)
        );
        assert!(
            sweep_stale_for_tenant(db, &tenant, now, 5_000)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            close(db, &stale, &tenant, ReceiptOutcome::default(), now).unwrap_err(),
            RECEIPT_CLOSED
        );
        assert_eq!(
            get(db, &fresh, &tenant).unwrap().unwrap().state,
            ReceiptState::Open
        );
    }

    #[test]
    fn sqlite_receipts_follow_the_contract() {
        let db = RuntimeDb::memory();
        receipt_contract(&db, "sqlite");
        sweep_contract(&db, "sqlite");
        // The unscoped sweep, on a database this test owns alone: it takes
        // any tenant's stale receipt, and leaves the others to the scope.
        let other = opened("q-other", "sqlite-south", ReceiptRole::Participant);
        open(&db, other, 1_000).unwrap();
        assert!(
            sweep_stale_for_tenant(&db, "sqlite-north", 10_000, 5_000)
                .unwrap()
                .is_empty()
        );
        let swept = sweep_stale(&db, 10_000, 5_000).unwrap();
        assert_eq!(swept.len(), 1, "{swept:?}");
        assert_eq!(swept[0].opened.tenant, "sqlite-south");
    }

    fn postgres() -> RuntimeDb {
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

    // Synchronous, as the store is: off a runtime, the blocking client runs
    // on the calling thread, and the sweeps run on threads of their own.
    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_receipts_follow_the_contract() {
        let db = postgres();
        // Ids of their own, so concurrent or repeated runs never share a
        // receipt, and the sweep's results are filtered to this run.
        let prefix = format!("receipt-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        receipt_contract(&db, &prefix);
        sweep_contract(&db, &prefix);
    }
}
