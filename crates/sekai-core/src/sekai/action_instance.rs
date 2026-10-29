//! Governed ActionInstance admission (#397 / research #395).
//!
//! Thin durable decision envelope: type + parameters + idempotency →
//! admit/deny with a bound `operation_id`. Effects live in `action_effect`.

use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STATUS_ADMITTED: &str = "admitted";
pub const STATUS_DENIED: &str = "denied";
/// Admitted to wait for an approver: the policy decided `require_approval`.
/// A decision moves it to `admitted` or `denied` exactly once (#1084).
pub const STATUS_PARKED: &str = "parked";
pub const DECISION_GRANT: &str = "grant";
pub const DECISION_DENY: &str = "deny";

/// Policy action name used when resolving ActionPolicy for submits.
pub const SUBMIT_POLICY_ACTION: &str = "submit_action_instance";

/// Budget root for hierarchical action-class metering of submits.
pub const SUBMIT_BUDGET_ROOT: &str = "action:governed";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionInstance {
    pub instance_id: String,
    pub namespace: String,
    pub type_id: String,
    pub version: String,
    pub principal: String,
    #[serde(default)]
    pub delegating_actor: Option<String>,
    /// JSON object. Untrusted user/producer content — never treated as instructions.
    pub parameters_json: String,
    pub request_digest: String,
    pub idempotency_key: String,
    /// Bound operation correlation spine for receipts/harvest (#400).
    pub operation_id: String,
    /// `admitted`, `denied`, or `parked` awaiting an approver decision.
    pub status: String,
    pub deny_reason: String,
    pub evidence_submission_ids: Vec<String>,
    pub policy_decision: String,
    pub budget_decision: String,
    pub created_at_ms: i64,
    pub decided_at_ms: i64,
    /// Bind + parameter-body provenance when the type has a System One bind.
    #[serde(default)]
    pub system_one_fill_json: String,
    /// Digest of the target object when the instance parked; a grant fails
    /// closed if the object changed since. Empty when no object is bound.
    #[serde(default)]
    pub parked_object_digest: String,
    /// Approver who decided a parked instance, and their decision.
    #[serde(default)]
    pub decided_by: String,
    #[serde(default)]
    pub approval_decision: String,
    /// Autonomous envelope the submit was bound to, so a later grant can
    /// require it to still be live.
    #[serde(default)]
    pub autonomous_envelope_id: String,
    /// Review-queue placement when the type routed this park (#1455).
    #[serde(default)]
    pub review: crate::sekai::review_queue::ReviewPlacement,
    /// Admission classified the submitter as an agent Action. Persisted so
    /// parked grant and in-flight ack keep that classification after the
    /// submitting credential is gone.
    #[serde(default)]
    pub agent_action: bool,
    /// Tenant used at admission for freeze matching. Empty when the submit
    /// had no tenant context and no registered owning tenant.
    #[serde(default)]
    pub admission_tenant: String,
    /// Shared-space owner tenant at admission, when it differed from the
    /// acting tenant. Parked grant and ack keep checking it.
    #[serde(default)]
    pub resource_tenant: String,
    /// The marking derived at admission (#1706): the least upper bound of
    /// the bound object's marking and the submitting binding's markings.
    /// Reading the instance, its effects or its receipt needs clearance for
    /// it, and objects it writes inherit it. Empty when unmarked.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub marking: String,
    /// Set when the Action was prepared offline (#1580).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline: Option<crate::sekai::offline_action::OfflineSubmission>,
    /// Set when an offline Action met an object changed past its base; the
    /// instance is then denied with `offline_conflict`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict: Option<crate::sekai::offline_action::ActionConflict>,
    /// Why the instance parked and who may decide it (#1867). Set when it
    /// parks and kept after the decision; `None` for an instance that never
    /// parked or was stored before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalRequirement>,
    /// Who holds the admission reservation, and until when (#1930). The
    /// object write and the receipt are accepted only from this owner and
    /// generation while the lease is live. `None` on instances stored before
    /// leases existed; those stay unfenced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_lease: Option<AdmissionLease>,
    /// The agent turn whose token submitted this Action (ADR 0142): its
    /// admission commits only while that turn is still claimed at this
    /// generation, so a superseded worker's submission cannot outlive a
    /// takeover. Absent for other submissions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_turn: Option<AgentTurnFence>,
    /// The ontology digest the submit was bound to, kept so a takeover
    /// repairs the receipt with the original binding, not a retry's (#1931).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_ontology_digest: Option<String>,
    /// Whether the submit's budget was already reserved upstream, kept so a
    /// takeover charges it the way the original admission would (#1931).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub admission_budget_already_reserved: bool,
}

/// How long an admission may take before its reservation is considered
/// abandoned. Below the plan execution lease, which waits on in-progress
/// admissions.
pub const ADMISSION_LEASE_MS: i64 = 60_000;

/// Refusal when a write arrives from an owner that no longer holds the
/// admission reservation, or after its lease expired.
pub const ADMISSION_FENCE_LOST: &str = "action instance admission lost its reservation";

/// Prefix of the error an admission write returns when an object its plan
/// read changed since (#1941); the object's id follows.
pub const REFERENCE_CHANGED: &str = "admission reference changed: ";

/// An object an admission's plan read, as it read it (#1941): present with
/// its state, or absent. The write commits only while each still holds.
#[derive(Debug, Clone)]
pub enum PlanReference {
    Present(crate::domain::Object),
    Absent(String),
}

impl PlanReference {
    pub fn id(&self) -> &str {
        match self {
            Self::Present(object) => &object.id,
            Self::Absent(id) => id,
        }
    }

    /// Whether `current`, the object stored now, is as planning read it.
    pub fn holds(&self, current: Option<&crate::domain::Object>) -> bool {
        match self {
            Self::Present(read) => {
                current.is_some_and(|current| current.persisted_state_matches(read))
            }
            Self::Absent(_) => current.is_none(),
        }
    }
}

/// The holder of an admission reservation. A takeover (#1931) bumps the
/// generation; an owner's writes are refused once it is not current.
/// What an admission receipt's transaction checks before it commits the
/// Action. A receipt that is the Action's commit checks its site agent and
/// its turn; a parked submission's receipt, which commits it for approval,
/// checks its turn; a denial, or a receipt after the object write already
/// committed under these checks, checks neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitCheck {
    None,
    TurnFence,
    SiteAgent,
}

/// The claim of the agent turn an Action was submitted under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTurnFence {
    pub turn_id: String,
    pub claim_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionLease {
    pub owner: String,
    pub generation: u64,
    pub expires_at_ms: i64,
    /// Set true in the same transaction as the admission's object write, so
    /// a takeover knows the write committed whatever happened to the object
    /// since (#1931). `None` on a lease an older binary wrote: such a
    /// reservation is never taken over, because its writes left no marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_committed: Option<bool>,
    /// Set true in the same transaction as the admission's receipt, so a
    /// takeover never races a receipt that commits after it looked (#1931).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_recorded: Option<bool>,
    /// [`object_state_digest`] of the object as the committed write
    /// persisted it, set with `write_committed`. A takeover treats the
    /// current object as that write only while its state still matches
    /// (#1931).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_object_digest: Option<String>,
    /// Set true once the decision record, budget charge and effects that
    /// follow the receipt are all recorded (#1943). A replay that finds a
    /// receipt with this still false finishes them; each is idempotent.
    /// `None` on a lease an older binary wrote: its follow-ups are not
    /// idempotent, so they are never resumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_ups_recorded: Option<bool>,
    /// The same for an approver's decision on a parked instance (#1948):
    /// `Some(false)` from the decision's write until its decision record,
    /// budget charge, effects and revocation are recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_follow_ups_recorded: Option<bool>,
    /// Whether the decided admission's charge was already reserved before it
    /// parked, so its decision charges nothing (#1948).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_budget_reserved: Option<bool>,
}

/// Wall-clock milliseconds. Leases run on the wall clock, not on the
/// request's `now`, so a writer that stalls past its lease is refused at the
/// write itself.
pub fn lease_clock_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

impl AdmissionLease {
    /// The lease a takeover installs: a new owner, the next generation, and
    /// a fresh expiry (#1931).
    pub fn succeeding(&self) -> Self {
        Self {
            owner: uuid::Uuid::new_v4().to_string(),
            generation: self.generation.saturating_add(1),
            expires_at_ms: lease_clock_ms().saturating_add(ADMISSION_LEASE_MS),
            write_committed: self.write_committed,
            receipt_recorded: self.receipt_recorded,
            written_object_digest: self.written_object_digest.clone(),
            follow_ups_recorded: self.follow_ups_recorded,
            decision_follow_ups_recorded: self.decision_follow_ups_recorded,
            decision_budget_reserved: self.decision_budget_reserved,
        }
    }

    /// Whether this lease has run out on the lease clock.
    pub fn expired(&self) -> bool {
        self.expires_at_ms <= lease_clock_ms()
    }

    /// A fresh first-generation lease for one admit attempt.
    pub fn first() -> Self {
        Self {
            owner: uuid::Uuid::new_v4().to_string(),
            generation: 1,
            expires_at_ms: lease_clock_ms().saturating_add(ADMISSION_LEASE_MS),
            write_committed: Some(false),
            receipt_recorded: Some(false),
            written_object_digest: None,
            follow_ups_recorded: Some(false),
            decision_follow_ups_recorded: None,
            decision_budget_reserved: None,
        }
    }

    /// Whether the stored lease fields name this holder and, when
    /// `now_ms` is given, are still live at that time.
    pub fn holds(
        &self,
        owner: Option<&str>,
        generation: Option<i64>,
        expires_at_ms: Option<i64>,
        now_ms: Option<i64>,
    ) -> bool {
        owner == Some(self.owner.as_str())
            && generation == i64::try_from(self.generation).ok()
            && now_ms.is_none_or(|now| expires_at_ms.is_some_and(|expires| expires > now))
    }
}

/// What required approval for a parked instance, and who is entitled to
/// decide it, as admission saw it at park time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequirement {
    /// Action policy scope whose rule required approval. Empty when agent
    /// autonomy parked a submit the policy allowed.
    pub policy_scope: String,
    /// The deciding clause: `action_override:<action>`,
    /// `risk_override:<class>`, `default_decision`, or
    /// `agent_autonomy:propose_only`.
    pub rule: String,
    /// Principals the Action type names as approvers. The submitter never
    /// decides their own instance, even when listed.
    pub approvers: Vec<String>,
    /// `namespace_admin` when the type names no approvers, else empty.
    pub approver_role: String,
}

/// `approver_role` when an Action type names no approvers.
pub const APPROVER_ROLE_NAMESPACE_ADMIN: &str = "namespace_admin";
/// `rule` when agent autonomy, not the policy, parked the submit.
pub const RULE_AGENT_PROPOSE_ONLY: &str = "agent_autonomy:propose_only";

impl ApprovalRequirement {
    /// The requirement for a park decided by `rule` in `policy_scope`, with
    /// the type's declared `approvers`.
    pub fn new(policy_scope: &str, rule: String, approvers: &[String]) -> Self {
        Self {
            policy_scope: policy_scope.to_string(),
            rule,
            approvers: approvers.to_vec(),
            approver_role: if approvers.is_empty() {
                APPROVER_ROLE_NAMESPACE_ADMIN.into()
            } else {
                String::new()
            },
        }
    }
}

impl ActionInstance {
    pub fn validate_fields(&self) -> Result<(), String> {
        if self.namespace.trim().is_empty() {
            return Err("namespace required".into());
        }
        if self.type_id.trim().is_empty() {
            return Err("type_id required".into());
        }
        if self.version.trim().is_empty() {
            return Err("version required".into());
        }
        if self.idempotency_key.trim().is_empty() {
            return Err("idempotency_key required".into());
        }
        if self.idempotency_key.chars().any(char::is_whitespace) {
            return Err("idempotency_key must not contain whitespace".into());
        }
        validate_parameters_json(&self.parameters_json)?;
        if self.status != STATUS_ADMITTED
            && self.status != STATUS_DENIED
            && self.status != STATUS_PARKED
        {
            return Err(format!("invalid status {:?}", self.status));
        }
        Ok(())
    }
}

/// Canonical digest of the decision-relevant request body.
/// Bound to the idempotency key: same key + different digest is a conflict.
pub fn compute_request_digest(
    namespace: &str,
    type_id: &str,
    version: &str,
    parameters_json: &str,
    evidence_submission_ids: &[String],
) -> Result<String, String> {
    compute_request_digest_with_envelope(
        namespace,
        type_id,
        version,
        parameters_json,
        evidence_submission_ids,
        "",
    )
}

pub fn compute_request_digest_with_envelope(
    namespace: &str,
    type_id: &str,
    version: &str,
    parameters_json: &str,
    evidence_submission_ids: &[String],
    autonomous_envelope_id: &str,
) -> Result<String, String> {
    reject_duplicate_parameter_keys(parameters_json)?;
    let params: serde_json::Value = serde_json::from_str(parameters_json)
        .map_err(|e| format!("parameters_json must be JSON: {e}"))?;
    if !params.is_object() {
        return Err("parameters_json must be a JSON object".into());
    }
    let mut evidence = evidence_submission_ids.to_vec();
    evidence.sort();
    evidence.dedup();
    let mut body = serde_json::json!({
        "namespace": namespace,
        "type_id": type_id,
        "version": version,
        "parameters": params,
        "evidence_submission_ids": evidence,
    });
    let envelope_id = autonomous_envelope_id.trim();
    if !envelope_id.is_empty() {
        body.as_object_mut()
            .expect("request digest body is an object")
            .insert(
                "autonomous_envelope_id".into(),
                serde_json::Value::String(envelope_id.to_string()),
            );
    }
    let canonical = serde_json::to_string(&body).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn validate_parameters_json(parameters_json: &str) -> Result<(), String> {
    reject_duplicate_parameter_keys(parameters_json)?;
    let params: serde_json::Value = serde_json::from_str(parameters_json)
        .map_err(|e| format!("parameters_json must be JSON: {e}"))?;
    if !params.is_object() {
        return Err("parameters_json must be a JSON object".into());
    }
    Ok(())
}

fn reject_duplicate_parameter_keys(parameters_json: &str) -> Result<(), String> {
    let duplicate = crate::sekai::json::contains_duplicate_object_keys(parameters_json)
        .map_err(|error| format!("parameters_json must be JSON: {error}"))?;
    if duplicate {
        return Err("parameters_json must not contain duplicate object keys".into());
    }
    Ok(())
}

/// Hierarchical budget subject for governed ActionInstance submit.
/// Empty `budget_scope` uses the namespace default root; non-empty scopes pin a
/// dedicated leaf under the governed root.
pub fn submit_budget_subject(namespace: &str, actor: &str, budget_scope: &str) -> String {
    let root = if budget_scope.trim().is_empty() {
        SUBMIT_BUDGET_ROOT.to_string()
    } else {
        format!("{SUBMIT_BUDGET_ROOT}:{}", budget_scope.trim())
    };
    if namespace.trim().is_empty() {
        return root;
    }
    if actor.trim().is_empty() {
        return format!("{root}/project:{}", namespace.trim());
    }
    format!("{root}/project:{}/agent:{}", namespace.trim(), actor.trim())
}

/// How releasing an admission reservation undoes its object write. The undo
/// applies only while no later write changed the object.
#[derive(Debug, Clone)]
pub enum AdmissionUndo {
    None,
    /// Remove the created object, if it is still exactly as created.
    AbortCreate {
        object_id: String,
        object_kind: String,
    },
    /// Restore `previous`, if the object still carries the admission's write.
    RestoreUpdate {
        previous: crate::domain::Object,
        applied_updated: i64,
    },
}

/// Result of a fenced admission write.
#[derive(Debug, Clone)]
pub enum FencedAdmissionWrite<T> {
    Applied(T),
    /// The caller no longer holds the reservation, or its lease expired.
    FenceLost,
    /// The submitting site agent's instance refused the write when it
    /// committed (#1970): it froze, or the memory's instance changed
    /// principal. The reservation was marked denied with this reason in the
    /// same transaction, and nothing was written.
    Refused(String),
}

/// The object write a parked grant commits with its transition.
pub enum ParkedGrantWrite {
    Create(crate::domain::Object),
    Update(crate::domain::Object),
}

/// Result of [`SekaiDb::grant_parked_action_instance`].
/// The plan execution claim a grant made for a plan step must still hold
/// (#1679): a run that lost it, or a stopped plan, grants nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionClaim {
    pub plan_id: String,
    pub holder: String,
}

pub enum ParkedGrantOutcome {
    /// The write and the transition committed; `previous` is the prior
    /// object state for an update.
    Granted {
        previous: Option<crate::domain::Object>,
    },
    /// Another decision already moved the instance.
    NotParked,
    /// The submitting site agent's instance refuses the write (#1970).
    Refused(String),
    /// The plan execution claim the grant was made under is gone.
    ClaimLost,
    /// The target object changed since the instance parked.
    Stale,
}

/// Canonical digest of an object's persisted state; `"absent"` when missing.
/// Properties are sorted, so an unchanged object always digests the same.
pub fn object_state_digest(object: Option<&crate::domain::Object>) -> Result<String, String> {
    let Some(object) = object else {
        return Ok("absent".into());
    };
    let properties: std::collections::BTreeMap<&String, &String> =
        object.properties.iter().collect();
    let body = serde_json::to_vec(&(
        &object.id,
        &object.kind,
        &object.name,
        &object.namespace,
        &object.external_id,
        properties,
        object.created,
        object.updated,
    ))
    .map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(body)))
}

impl SekaiDb {
    pub fn migrate_action_instances(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_action_instances (
                instance_id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL,
                type_id TEXT NOT NULL,
                version TEXT NOT NULL,
                principal TEXT NOT NULL,
                parameters_json TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                status TEXT NOT NULL,
                deny_reason TEXT NOT NULL DEFAULT '',
                evidence_submission_ids_json TEXT NOT NULL,
                policy_decision TEXT NOT NULL DEFAULT '',
                budget_decision TEXT NOT NULL DEFAULT '',
                created_at_ms INTEGER NOT NULL,
                decided_at_ms INTEGER NOT NULL,
                body_json TEXT NOT NULL,
                UNIQUE (namespace, idempotency_key)
            );
            CREATE INDEX IF NOT EXISTS idx_action_instances_ns
                ON sekai_action_instances(namespace, created_at_ms DESC);
            CREATE INDEX IF NOT EXISTS idx_action_instances_op
                ON sekai_action_instances(operation_id);
            CREATE INDEX IF NOT EXISTS idx_action_instances_type
                ON sekai_action_instances(namespace, type_id, version);",
        )
        .map_err(|e| e.to_string())
    }

    pub fn get_action_instance_by_idempotency(
        &self,
        namespace: &str,
        idempotency_key: &str,
    ) -> Result<Option<ActionInstance>, String> {
        self.migrate_action_instances()?;
        let conn = self.conn();
        conn.query_row(
            "SELECT body_json FROM sekai_action_instances
             WHERE namespace = ?1 AND idempotency_key = ?2",
            params![namespace, idempotency_key],
            |row| {
                let body: String = row.get(0)?;
                Ok(body)
            },
        )
        .optional()
        .map_err(|e| e.to_string())?
        .map(|body| {
            serde_json::from_str(&body).map_err(|e| format!("corrupt action instance body: {e}"))
        })
        .transpose()
    }

    pub fn get_action_instance_by_operation_id(
        &self,
        operation_id: &str,
    ) -> Result<Option<ActionInstance>, String> {
        self.migrate_action_instances()?;
        if operation_id.trim().is_empty() {
            return Ok(None);
        }
        let conn = self.conn();
        conn.query_row(
            "SELECT body_json FROM sekai_action_instances WHERE operation_id = ?1",
            params![operation_id],
            |row| {
                let body: String = row.get(0)?;
                Ok(body)
            },
        )
        .optional()
        .map_err(|e| e.to_string())?
        .map(|body| {
            serde_json::from_str(&body).map_err(|e| format!("corrupt action instance body: {e}"))
        })
        .transpose()
    }

    pub fn get_action_instance(&self, instance_id: &str) -> Result<Option<ActionInstance>, String> {
        self.migrate_action_instances()?;
        let conn = self.conn();
        conn.query_row(
            "SELECT body_json FROM sekai_action_instances WHERE instance_id = ?1",
            params![instance_id],
            |row| {
                let body: String = row.get(0)?;
                Ok(body)
            },
        )
        .optional()
        .map_err(|e| e.to_string())?
        .map(|body| {
            serde_json::from_str(&body).map_err(|e| format!("corrupt action instance body: {e}"))
        })
        .transpose()
    }

    pub fn list_action_instances(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ActionInstance>, String> {
        self.list_action_instances_page(namespace, type_id, status, limit, 0)
    }

    pub fn list_action_instances_page(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        status: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ActionInstance>, String> {
        self.migrate_action_instances()?;
        let limit = limit.clamp(1, 500);
        let offset = i64::try_from(offset).map_err(|_| "action instance offset overflow")?;
        let type_filter = type_id.filter(|t| !t.trim().is_empty());
        let status_filter = status.filter(|s| !s.trim().is_empty());
        let conn = self.conn();
        let mut bodies: Vec<String> = Vec::new();
        match (type_filter, status_filter) {
            (Some(type_id), Some(status)) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT body_json FROM sekai_action_instances
                         WHERE namespace = ?1 AND type_id = ?2 AND status = ?3
                         ORDER BY created_at_ms DESC, instance_id DESC LIMIT ?4 OFFSET ?5",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(
                        params![namespace, type_id, status, limit as i64, offset],
                        |row| row.get(0),
                    )
                    .map_err(|e| e.to_string())?;
                for row in rows {
                    bodies.push(row.map_err(|e| e.to_string())?);
                }
            }
            (Some(type_id), None) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT body_json FROM sekai_action_instances
                         WHERE namespace = ?1 AND type_id = ?2
                         ORDER BY created_at_ms DESC, instance_id DESC LIMIT ?3 OFFSET ?4",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(params![namespace, type_id, limit as i64, offset], |row| {
                        row.get(0)
                    })
                    .map_err(|e| e.to_string())?;
                for row in rows {
                    bodies.push(row.map_err(|e| e.to_string())?);
                }
            }
            (None, Some(status)) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT body_json FROM sekai_action_instances
                         WHERE namespace = ?1 AND status = ?2
                         ORDER BY created_at_ms DESC, instance_id DESC LIMIT ?3 OFFSET ?4",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(params![namespace, status, limit as i64, offset], |row| {
                        row.get(0)
                    })
                    .map_err(|e| e.to_string())?;
                for row in rows {
                    bodies.push(row.map_err(|e| e.to_string())?);
                }
            }
            (None, None) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT body_json FROM sekai_action_instances
                         WHERE namespace = ?1
                         ORDER BY created_at_ms DESC, instance_id DESC LIMIT ?2 OFFSET ?3",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(params![namespace, limit as i64, offset], |row| row.get(0))
                    .map_err(|e| e.to_string())?;
                for row in rows {
                    bodies.push(row.map_err(|e| e.to_string())?);
                }
            }
        }
        bodies
            .into_iter()
            .map(|body| {
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action instance body: {e}"))
            })
            .collect()
    }

    /// Insert a newly decided instance. Caller must already have checked
    /// idempotency. Returns conflict if the unique key races.
    pub fn put_action_instance(&self, instance: &ActionInstance) -> Result<ActionInstance, String> {
        self.migrate_action_instances()?;
        instance.validate_fields()?;
        // Avoid holding conn across a re-get on race.
        if let Some(existing) =
            self.get_action_instance_by_idempotency(&instance.namespace, &instance.idempotency_key)?
        {
            if existing.request_digest == instance.request_digest {
                return Ok(existing);
            }
            return Err("idempotency key conflict: same key with different request digest".into());
        }
        let mut stored = instance.clone();
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        sqlite_redact_if_forgotten_writer(&tx, &mut stored)?;
        let body_json = serde_json::to_string(&stored).map_err(|e| e.to_string())?;
        let evidence_json =
            serde_json::to_string(&stored.evidence_submission_ids).map_err(|e| e.to_string())?;
        match tx.execute(
            "INSERT INTO sekai_action_instances
             (instance_id, namespace, type_id, version, principal, parameters_json,
              request_digest, idempotency_key, operation_id, status, deny_reason,
              evidence_submission_ids_json, policy_decision, budget_decision,
              created_at_ms, decided_at_ms, body_json)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                stored.instance_id,
                stored.namespace,
                stored.type_id,
                stored.version,
                stored.principal,
                stored.parameters_json,
                stored.request_digest,
                stored.idempotency_key,
                stored.operation_id,
                stored.status,
                stored.deny_reason,
                evidence_json,
                stored.policy_decision,
                stored.budget_decision,
                stored.created_at_ms,
                stored.decided_at_ms,
                body_json,
            ],
        ) {
            Ok(_) => {
                tx.commit().map_err(|e| e.to_string())?;
                Ok(stored)
            }
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                // Race: re-read and apply digest rules.
                drop(tx);
                drop(conn);
                if let Some(existing) = self.get_action_instance_by_idempotency(
                    &instance.namespace,
                    &instance.idempotency_key,
                )? {
                    if existing.request_digest == instance.request_digest {
                        return Ok(existing);
                    }
                    return Err(
                        "idempotency key conflict: same key with different request digest".into(),
                    );
                }
                Err("idempotency key conflict".into())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Grants a parked instance and applies its object write in one
    /// transaction (#1139). The target object is re-digested under the write
    /// lock, so a grant either commits both the write and the transition or
    /// neither: no orphan write, and no concurrent grant can apply twice.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_parked_action_instance(
        &self,
        granted: &ActionInstance,
        target_object_id: &str,
        parked_object_digest: &str,
        write: Option<&ParkedGrantWrite>,
        references: &[PlanReference],
        actor: &str,
        claim: Option<&ExecutionClaim>,
    ) -> Result<ParkedGrantOutcome, String> {
        self.migrate_action_instances()?;
        granted.validate_fields()?;
        let mut stored = granted.clone();
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let row: Option<(String, String)> = tx
            .query_row(
                "SELECT status, parameters_json FROM sekai_action_instances WHERE instance_id = ?1",
                params![granted.instance_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((status, existing_params)) = row else {
            return Ok(ParkedGrantOutcome::NotParked);
        };
        if status != STATUS_PARKED {
            return Ok(ParkedGrantOutcome::NotParked);
        }
        let written = write.map(|write| match write {
            ParkedGrantWrite::Create(object) | ParkedGrantWrite::Update(object) => object,
        });
        if let Some(reason) =
            sqlite_site_agent_refusal(&tx, &granted.namespace, &granted.principal, written)?
        {
            return Ok(ParkedGrantOutcome::Refused(reason));
        }
        if let Some(claim) = claim {
            let holder: Option<Option<String>> = tx
                .query_row(
                    "SELECT json_extract(body_json, '$.claim_holder') FROM sekai_plan_executions
                     WHERE namespace = ?1 AND plan_id = ?2",
                    params![granted.namespace, claim.plan_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            if holder.flatten().as_deref() != Some(claim.holder.as_str()) {
                return Ok(ParkedGrantOutcome::ClaimLost);
            }
        }
        if !target_object_id.is_empty() {
            let current = tx
                .query_row(
                    "SELECT id, kind, name, namespace, external_id, properties, created, updated
                     FROM sekai_objects WHERE id = ?1",
                    params![target_object_id],
                    crate::db::sekai::row_to_object,
                )
                .optional()
                .map_err(|error| error.to_string())?;
            if object_state_digest(current.as_ref())? != parked_object_digest {
                return Ok(ParkedGrantOutcome::Stale);
            }
        }
        if sqlite_changed_reference(&tx, references)?.is_some() {
            return Ok(ParkedGrantOutcome::Stale);
        }
        let previous = match write {
            Some(ParkedGrantWrite::Create(object)) => {
                crate::sekai::audit::insert_created_object_in(
                    &tx,
                    object,
                    actor,
                    None,
                    &crate::sekai::audit::ChangeAttribution::action(
                        &granted.instance_id,
                        &granted.operation_id,
                    ),
                )?;
                None
            }
            Some(ParkedGrantWrite::Update(object)) => Some(
                crate::sekai::audit::update_object_in(
                    &tx,
                    object,
                    None,
                    actor,
                    None,
                    &crate::sekai::audit::ChangeAttribution::action(
                        &granted.instance_id,
                        &granted.operation_id,
                    ),
                )?
                .ok_or_else(|| format!("object {} not found", object.id))?,
            ),
            None => None,
        };
        sqlite_redact_if_forgotten_writer(&tx, &mut stored)?;
        if sqlite_stored_writer_already_redacted(Some(&existing_params), &stored) {
            crate::sekai::site_agent_memory::redact_writer_instance(&mut stored);
        }
        let body_json = serde_json::to_string(&stored).map_err(|e| e.to_string())?;
        let updated = tx
            .execute(
                "UPDATE sekai_action_instances
             SET status = ?2, deny_reason = ?3, policy_decision = ?4, budget_decision = ?5,
                 decided_at_ms = ?6, body_json = ?7, parameters_json = ?10
             WHERE instance_id = ?1 AND status = ?8
               AND coalesce(json_extract(body_json, '$.review.assignee'), '') = ?9",
                params![
                    stored.instance_id,
                    stored.status,
                    stored.deny_reason,
                    stored.policy_decision,
                    stored.budget_decision,
                    stored.decided_at_ms,
                    body_json,
                    STATUS_PARKED,
                    stored.review.assignee,
                    stored.parameters_json,
                ],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Ok(ParkedGrantOutcome::NotParked);
        }
        sqlite_redact_forgotten_memory_actions(&tx, written)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(ParkedGrantOutcome::Granted { previous })
    }

    /// Moves a parked instance to its decided state. Returns false when the
    /// instance is no longer parked, so the first decision wins.
    pub fn decide_parked_action_instance(&self, decided: &ActionInstance) -> Result<bool, String> {
        self.transition_action_instance(STATUS_PARKED, decided, &decided.review.assignee)
    }

    /// Replaces an instance only while it still has `expected_status`.
    pub fn transition_action_instance(
        &self,
        expected_status: &str,
        decided: &ActionInstance,
        expected_assignee: &str,
    ) -> Result<bool, String> {
        self.migrate_action_instances()?;
        decided.validate_fields()?;
        let mut stored = decided.clone();
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let existing_params: Option<String> = tx
            .query_row(
                "SELECT parameters_json FROM sekai_action_instances WHERE instance_id = ?1",
                params![decided.instance_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        sqlite_redact_if_forgotten_writer(&tx, &mut stored)?;
        if sqlite_stored_writer_already_redacted(existing_params.as_deref(), &stored) {
            crate::sekai::site_agent_memory::redact_writer_instance(&mut stored);
        }
        let body_json = serde_json::to_string(&stored).map_err(|e| e.to_string())?;
        let updated = tx
            .execute(
                "UPDATE sekai_action_instances
             SET status = ?2, deny_reason = ?3, policy_decision = ?4, budget_decision = ?5,
                 decided_at_ms = ?6, body_json = ?7, parameters_json = ?10
             WHERE instance_id = ?1 AND status = ?8
               AND coalesce(json_extract(body_json, '$.review.assignee'), '') = ?9",
                params![
                    stored.instance_id,
                    stored.status,
                    stored.deny_reason,
                    stored.policy_decision,
                    stored.budget_decision,
                    stored.decided_at_ms,
                    body_json,
                    expected_status,
                    expected_assignee,
                    stored.parameters_json,
                ],
            )
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(updated == 1)
    }

    pub fn delete_action_instance(&self, instance_id: &str) -> Result<(), String> {
        self.migrate_action_instances()?;
        let conn = self.conn();
        conn.execute(
            "DELETE FROM sekai_action_instances WHERE instance_id = ?1",
            params![instance_id],
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    }

    /// Applies an admission's object write only while `lease` still names the
    /// reservation's owner and generation and has not expired (#1930). A
    /// takeover bumps the generation, so a stale owner's write is refused.
    /// Each of `references` must still be stored as planning read it
    /// (#1941); a changed one fails with [`REFERENCE_CHANGED`] and its id.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_admission_object_write(
        &self,
        instance_id: &str,
        lease: &AdmissionLease,
        write: &ParkedGrantWrite,
        expected: Option<&crate::domain::Object>,
        references: &[PlanReference],
        actor: &str,
        attribution: &crate::sekai::audit::ChangeAttribution,
    ) -> Result<FencedAdmissionWrite<Option<crate::domain::Object>>, String> {
        self.migrate_action_instances()?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if !sqlite_admission_fence_holds(&tx, instance_id, lease, true)? {
            return Ok(FencedAdmissionWrite::FenceLost);
        }
        let written = match write {
            ParkedGrantWrite::Create(object) | ParkedGrantWrite::Update(object) => object,
        };
        if let Some(reason) = sqlite_reservation_refusal(&tx, instance_id, Some(written))? {
            sqlite_deny_reservation(&tx, instance_id, &reason)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(FencedAdmissionWrite::Refused(reason));
        }
        if let Some(changed) = sqlite_changed_reference(&tx, references)? {
            return Err(format!("{REFERENCE_CHANGED}{changed}"));
        }
        let previous = match write {
            ParkedGrantWrite::Create(object) => {
                crate::sekai::audit::insert_created_object_in(
                    &tx,
                    object,
                    actor,
                    None,
                    attribution,
                )?;
                None
            }
            ParkedGrantWrite::Update(object) => Some(
                crate::sekai::audit::update_object_in(
                    &tx,
                    object,
                    expected,
                    actor,
                    None,
                    attribution,
                )?
                .ok_or_else(|| format!("object {} not found", object.id))?,
            ),
        };
        // The state as persisted, read back in this transaction.
        let object_id = match write {
            ParkedGrantWrite::Create(object) | ParkedGrantWrite::Update(object) => &object.id,
        };
        let persisted = tx
            .query_row(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated
                 FROM sekai_objects WHERE id = ?1",
                params![object_id],
                crate::db::sekai::row_to_object,
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let written = object_state_digest(persisted.as_ref())?;
        // The turn's lease runs on while the write is made; check it again
        // before the marker that would exempt this write from it.
        if sqlite_turn_fence_refusal(&tx, instance_id)?.is_some() {
            return Ok(FencedAdmissionWrite::FenceLost);
        }
        tx.execute(
            "UPDATE sekai_action_instances
             SET body_json = json_set(body_json,
                 '$.admission_lease.write_committed', json('true'),
                 '$.admission_lease.written_object_digest', ?2)
             WHERE instance_id = ?1",
            params![instance_id, written],
        )
        .map_err(|error| error.to_string())?;
        sqlite_redact_forgotten_memory_actions(
            &tx,
            Some(match write {
                ParkedGrantWrite::Create(object) | ParkedGrantWrite::Update(object) => object,
            }),
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(FencedAdmissionWrite::Applied(previous))
    }

    /// Releases a failed admission in one transaction: while `lease` still
    /// names the reservation's owner and generation, undoes its object write
    /// and deletes the reservation (#1930). A crash leaves either both or
    /// neither. Expiry is not checked: an owner may always clean up. Returns
    /// whether this owner released it.
    pub fn release_admission(
        &self,
        instance_id: &str,
        lease: &AdmissionLease,
        undo: &AdmissionUndo,
        actor: &str,
    ) -> Result<bool, String> {
        self.migrate_action_instances()?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if !sqlite_admission_fence_holds(&tx, instance_id, lease, false)? {
            return Ok(false);
        }
        let current = |id: &str| {
            tx.query_row(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated
                 FROM sekai_objects WHERE id = ?1",
                params![id],
                crate::db::sekai::row_to_object,
            )
            .optional()
            .map_err(|error| error.to_string())
        };
        match undo {
            AdmissionUndo::None => {}
            AdmissionUndo::AbortCreate {
                object_id,
                object_kind,
            } => {
                if current(object_id)?.is_some_and(|object| {
                    object.kind == *object_kind && object.created == object.updated
                }) {
                    tx.execute(
                        "DELETE FROM sekai_objects WHERE id = ?1",
                        params![object_id],
                    )
                    .map_err(|error| error.to_string())?;
                    tx.execute(
                        "DELETE FROM sekai_object_changes WHERE object_id = ?1",
                        params![object_id],
                    )
                    .map_err(|error| error.to_string())?;
                }
            }
            AdmissionUndo::RestoreUpdate {
                previous,
                applied_updated,
            } => {
                if let Some(object) = current(&previous.id)?
                    && object.updated == *applied_updated
                {
                    let mut restored = previous.clone();
                    restored.updated = object.updated.saturating_add(1);
                    crate::sekai::audit::update_object_in(
                        &tx,
                        &restored,
                        None,
                        actor,
                        None,
                        &crate::sekai::audit::ChangeAttribution::default(),
                    )?;
                }
            }
        }
        tx.execute(
            "DELETE FROM sekai_action_instances WHERE instance_id = ?1",
            params![instance_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    /// Takes over an abandoned reservation (#1931): replaces `expired` with
    /// `next` only while `expired` still names the owner and generation, its
    /// lease has run out on the lease clock, and its commit marker is still
    /// the one read. One conditional update, so a live admission is never
    /// taken, two takers cannot both win, and a write that committed after
    /// the read is never overwritten as uncommitted. The status must also be
    /// the one read, so a refusal committed since (#1970) is never discarded.
    pub fn take_over_admission(
        &self,
        instance: &ActionInstance,
        expired: &AdmissionLease,
        next: &AdmissionLease,
    ) -> Result<bool, String> {
        self.migrate_action_instances()?;
        let lease_json = serde_json::to_string(next).map_err(|error| error.to_string())?;
        let conn = self.conn();
        let updated = conn
            .execute(
                "UPDATE sekai_action_instances
                 SET body_json = json_set(body_json, '$.admission_lease', json(?2))
                 WHERE instance_id = ?1
                   AND json_extract(body_json, '$.admission_lease.owner') = ?3
                   AND json_extract(body_json, '$.admission_lease.generation') = ?4
                   AND json_extract(body_json, '$.admission_lease.expires_at_ms') <= ?5
                   AND json_extract(body_json, '$.admission_lease.write_committed') = ?6
                   AND json_extract(body_json, '$.admission_lease.receipt_recorded') = 0
                   AND status = ?7",
                params![
                    instance.instance_id,
                    lease_json,
                    expired.owner,
                    i64::try_from(expired.generation).unwrap_or(i64::MAX),
                    lease_clock_ms(),
                    expired.write_committed.unwrap_or(false),
                    instance.status,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(updated == 1)
    }

    /// Marks an approver decision's follow-ups recorded (#1948); see
    /// [`Self::mark_admission_follow_ups_recorded`].
    pub fn mark_decision_follow_ups_recorded(&self, instance_id: &str) -> Result<(), String> {
        self.migrate_action_instances()?;
        self.conn()
            .execute(
                "UPDATE sekai_action_instances
                 SET body_json = json_set(body_json, '$.admission_lease.decision_follow_ups_recorded', json('true'))
                 WHERE instance_id = ?1
                   AND json_extract(body_json, '$.admission_lease.decision_follow_ups_recorded') = 0",
                params![instance_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Marks the admission's follow-ups recorded (#1943). Idempotent, and
    /// unfenced: whoever finished them may say so.
    pub fn mark_admission_follow_ups_recorded(&self, instance_id: &str) -> Result<(), String> {
        self.migrate_action_instances()?;
        self.conn()
            .execute(
                "UPDATE sekai_action_instances
                 SET body_json = json_set(body_json, '$.admission_lease.follow_ups_recorded', json('true'))
                 WHERE instance_id = ?1
                   AND json_extract(body_json, '$.admission_lease.follow_ups_recorded') = 0",
                params![instance_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Deletes the reservation only while `lease` still names its owner and
    /// generation, so a stale owner's compensation cannot remove a newer
    /// owner's row. Expiry is not checked: an owner may always clean up.
    pub fn delete_action_instance_fenced(
        &self,
        instance_id: &str,
        lease: &AdmissionLease,
    ) -> Result<bool, String> {
        self.migrate_action_instances()?;
        let conn = self.conn();
        let deleted = conn
            .execute(
                "DELETE FROM sekai_action_instances
                 WHERE instance_id = ?1
                   AND json_extract(body_json, '$.admission_lease.owner') = ?2
                   AND json_extract(body_json, '$.admission_lease.generation') = ?3",
                params![
                    instance_id,
                    lease.owner,
                    i64::try_from(lease.generation).unwrap_or(i64::MAX)
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(deleted == 1)
    }
}

/// A sample instance in `status`, for other modules' tests.
#[cfg(test)]
pub(crate) fn sample_for_test(status: &str) -> ActionInstance {
    tests::sample(status)
}

/// Stores a leased reservation, as admission does before its object write,
/// and returns its instance id and lease.
#[cfg(test)]
pub(crate) fn reserve_for_test(
    db: &crate::db::runtime_db::RuntimeDb,
    instance_id: &str,
    now_ms: i64,
) -> (String, AdmissionLease) {
    let _ = now_ms;
    let lease = AdmissionLease::first();
    let mut instance = tests::sample(STATUS_ADMITTED);
    instance.instance_id = instance_id.into();
    instance.idempotency_key = format!("key-{instance_id}");
    instance.operation_id = format!("op-{instance_id}");
    instance.admission_lease = Some(lease.clone());
    db.put_action_instance(&instance).unwrap();
    (instance.instance_id, lease)
}

/// The id of the first of `references` no longer as planning read it
/// (#1941), inside `tx`.
fn sqlite_changed_reference(
    tx: &rusqlite::Transaction<'_>,
    references: &[PlanReference],
) -> Result<Option<String>, String> {
    for reference in references {
        let current = tx
            .query_row(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated
                 FROM sekai_objects WHERE id = ?1",
                params![reference.id()],
                crate::db::sekai::row_to_object,
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if !reference.holds(current.as_ref()) {
            return Ok(Some(reference.id().to_string()));
        }
    }
    Ok(None)
}

/// Whether `lease` holds the instance's admission reservation inside `tx`,
/// and, with `check_expiry`, is still live on the lease clock.
/// Why the reservation's site agent refuses its write now, read in `tx`.
pub(crate) fn sqlite_reservation_refusal(
    tx: &rusqlite::Transaction<'_>,
    instance_id: &str,
    written: Option<&crate::domain::Object>,
) -> Result<Option<String>, String> {
    if let Some(reason) = sqlite_turn_fence_refusal(tx, instance_id)? {
        return Ok(Some(reason));
    }
    let (namespace, principal): (String, String) = tx
        .query_row(
            "SELECT namespace, principal FROM sekai_action_instances WHERE instance_id = ?1",
            params![instance_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| error.to_string())?;
    sqlite_site_agent_refusal(tx, &namespace, &principal, written)
}

/// Why an Action submitted under an agent turn's token is refused as it
/// commits (ADR 0142): its turn is no longer claimed at the submission's
/// generation, or its lease lapsed on the lease clock. Every admission
/// commits through it, a parked one included, so a superseded worker's
/// submission never becomes approvable.
pub(crate) fn sqlite_turn_fence_refusal(
    tx: &rusqlite::Transaction<'_>,
    instance_id: &str,
) -> Result<Option<String>, String> {
    let (turn_id, turn_generation, write_committed): (Option<String>, Option<i64>, Option<bool>) =
        tx.query_row(
            "SELECT json_extract(body_json, '$.agent_turn.turn_id'),
                    json_extract(body_json, '$.agent_turn.claim_generation'),
                    json_extract(body_json, '$.admission_lease.write_committed')
             FROM sekai_action_instances WHERE instance_id = ?1",
            params![instance_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| error.to_string())?;
    // A write that committed under the fence stays authorized (#1931).
    let Some(turn_id) = turn_id.filter(|_| write_committed != Some(true)) else {
        return Ok(None);
    };
    let live: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM sekai_agent_turn
             WHERE turn_id = ?1 AND status = 'claimed' AND claim_generation = ?2
               AND claim_expires_at_ms > ?3",
            params![turn_id, turn_generation.unwrap_or(-1), lease_clock_ms()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    Ok(live
        .is_none()
        .then(|| format!("agent turn {turn_id} is no longer claimed by this submission")))
}

fn sqlite_redact_if_forgotten_writer(
    tx: &rusqlite::Transaction<'_>,
    instance: &mut ActionInstance,
) -> Result<(), String> {
    if sqlite_writer_target_forgotten(tx, instance)? {
        crate::sekai::site_agent_memory::redact_writer_instance(instance);
    }
    Ok(())
}

fn sqlite_writer_target_forgotten(
    tx: &rusqlite::Transaction<'_>,
    instance: &ActionInstance,
) -> Result<bool, String> {
    if !crate::sekai::site_agent_memory::is_writer_action(&instance.type_id) {
        return Ok(false);
    }
    let Some(object_id) =
        crate::sekai::site_agent_memory::writer_object_id(&instance.parameters_json)
    else {
        return Ok(false);
    };
    let forgotten: Option<String> = tx
        .query_row(
            "SELECT json_extract(properties, '$.forgotten') FROM sekai_objects
             WHERE id = ?1 AND kind = ?2 AND namespace = ?3",
            params![
                object_id,
                crate::sekai::site_agent_memory::KIND,
                instance.namespace
            ],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .flatten();
    Ok(forgotten.as_deref() == Some("true"))
}

fn sqlite_stored_writer_already_redacted(
    stored_parameters: Option<&str>,
    incoming: &ActionInstance,
) -> bool {
    crate::sekai::site_agent_memory::stored_writer_already_redacted(stored_parameters, incoming)
}

/// Empty forgotten memory `content` in writer Action parameters, in this
/// transaction (#1969). Leaves each stored request digest as it was.
pub(crate) fn sqlite_redact_forgotten_memory_actions(
    tx: &rusqlite::Transaction<'_>,
    written: Option<&crate::domain::Object>,
) -> Result<(), String> {
    use crate::sekai::site_agent_memory::{
        ACTION_CREATE, ACTION_FORGET, ACTION_UPDATE, is_forgotten, redact_writer_instance,
    };
    let Some(object) = written.filter(|object| is_forgotten(object)) else {
        return Ok(());
    };
    let mut stmt = tx
        .prepare(
            "SELECT instance_id, parameters_json, body_json FROM sekai_action_instances
             WHERE namespace = ?1
               AND type_id IN (?2, ?3, ?4)
               AND json_extract(parameters_json, '$.object_id') = ?5",
        )
        .map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map(
            params![
                object.namespace,
                ACTION_CREATE,
                ACTION_UPDATE,
                ACTION_FORGET,
                object.id
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(|error| error.to_string())?;
    let mut updates = Vec::new();
    for row in rows {
        let (instance_id, parameters_json, body_json) = row.map_err(|error| error.to_string())?;
        let mut instance: ActionInstance = serde_json::from_str(&body_json)
            .map_err(|error| format!("corrupt action instance body: {error}"))?;
        instance.parameters_json = parameters_json;
        if !redact_writer_instance(&mut instance) {
            continue;
        }
        let parameters_json = instance.parameters_json.clone();
        let body_json = serde_json::to_string(&instance).map_err(|error| error.to_string())?;
        updates.push((instance_id, parameters_json, body_json));
    }
    drop(stmt);
    for (instance_id, parameters_json, body_json) in updates {
        tx.execute(
            "UPDATE sekai_action_instances
             SET parameters_json = ?2, body_json = ?3
             WHERE instance_id = ?1",
            params![instance_id, parameters_json, body_json],
        )
        .map_err(|error| error.to_string())?;
    }
    sqlite_redact_forgotten_memory_decisions(tx, object)
}

fn sqlite_redact_forgotten_memory_decisions(
    tx: &rusqlite::Transaction<'_>,
    object: &crate::domain::Object,
) -> Result<(), String> {
    use crate::sekai::decision_memory::DecisionMemory;
    use crate::sekai::site_agent_memory::{ACTION_CREATE, ACTION_FORGET, ACTION_UPDATE};
    let present: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'sekai_action_decision_memory'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if present == 0 {
        return Ok(());
    }
    let mut stmt = tx
        .prepare(
            "SELECT memory_id, body_json FROM sekai_action_decision_memory
             WHERE namespace = ?1 AND type_id IN (?2, ?3, ?4)",
        )
        .map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map(
            params![
                object.namespace,
                ACTION_CREATE,
                ACTION_UPDATE,
                ACTION_FORGET
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(|error| error.to_string())?;
    let mut updates = Vec::new();
    for row in rows {
        let (memory_id, body_json) = row.map_err(|error| error.to_string())?;
        let mut memory: DecisionMemory = serde_json::from_str(&body_json)
            .map_err(|error| format!("corrupt decision memory: {error}"))?;
        let object_id = crate::sekai::site_agent_memory::writer_object_id(&memory.parameters_json)
            .or_else(|| crate::sekai::site_agent_memory::writer_object_id(&memory.facts_json));
        if object_id.as_deref() != Some(object.id.as_str()) {
            continue;
        }
        if !crate::sekai::site_agent_memory::redact_decision_memory(&mut memory) {
            continue;
        }
        let body_json = serde_json::to_string(&memory).map_err(|error| error.to_string())?;
        updates.push((memory_id, body_json));
    }
    drop(stmt);
    for (memory_id, body_json) in updates {
        tx.execute(
            "UPDATE sekai_action_decision_memory SET body_json = ?2 WHERE memory_id = ?1",
            params![memory_id, body_json],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Why a site agent write by `principal` in `namespace` is refused as it
/// commits (#1970): the principal's instance is frozen, or `written` is a
/// working memory item whose instance is gone, frozen, or acts as another
/// principal. Read in `tx`, so a freeze committing first is seen and one
/// committing after waits.
pub(crate) fn sqlite_site_agent_refusal(
    tx: &rusqlite::Transaction<'_>,
    namespace: &str,
    principal: &str,
    written: Option<&crate::domain::Object>,
) -> Result<Option<String>, String> {
    use crate::sekai::{site_agent_instance as instance, site_agent_memory as memory};
    let frozen: Option<String> = tx
        .query_row(
            "SELECT id FROM sekai_objects
             WHERE kind = ?1 AND namespace = ?2
               AND json_extract(properties, '$.principal_id') = ?3
               AND json_extract(properties, '$.frozen') = 'true'
             ORDER BY id LIMIT 1",
            params![instance::KIND, namespace, principal],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if let Some(id) = frozen {
        return Ok(Some(format!("site agent instance {id} is frozen")));
    }
    let Some(owner) = written
        .filter(|object| object.kind == memory::KIND)
        .and_then(|object| object.properties.get(memory::INSTANCE_PROPERTY))
    else {
        return Ok(None);
    };
    let current: Option<(Option<String>, Option<String>)> = tx
        .query_row(
            "SELECT json_extract(properties, '$.principal_id'),
                    json_extract(properties, '$.frozen')
             FROM sekai_objects WHERE id = ?1 AND kind = ?2 AND namespace = ?3",
            params![owner, instance::KIND, namespace],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    Ok(memory_refusal(owner, principal, current))
}

/// Why a memory write by `principal` into instance `owner` is refused, given
/// that instance's stored `(principal_id, frozen)`.
pub(crate) fn memory_refusal(
    owner: &str,
    principal: &str,
    current: Option<(Option<String>, Option<String>)>,
) -> Option<String> {
    match current {
        None => Some(format!(
            "site agent instance {owner} not found in this namespace"
        )),
        Some((_, Some(frozen))) if frozen == "true" => {
            Some(format!("site agent instance {owner} is frozen"))
        }
        Some((owner_principal, _)) if owner_principal.as_deref() != Some(principal) => Some(
            format!("only the principal of site agent instance {owner} writes its memory"),
        ),
        Some(_) => None,
    }
}

/// Marks the reservation denied with `reason`, in `tx`.
pub(crate) fn sqlite_deny_reservation(
    tx: &rusqlite::Transaction<'_>,
    instance_id: &str,
    reason: &str,
) -> Result<(), String> {
    tx.execute(
        "UPDATE sekai_action_instances
         SET status = ?2, deny_reason = ?3,
             body_json = json_set(body_json, '$.status', ?2, '$.deny_reason', ?3)
         WHERE instance_id = ?1",
        params![instance_id, STATUS_DENIED, reason],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

pub(crate) fn sqlite_admission_fence_holds(
    tx: &rusqlite::Transaction<'_>,
    instance_id: &str,
    lease: &AdmissionLease,
    check_expiry: bool,
) -> Result<bool, String> {
    let stored = tx
        .query_row(
            "SELECT json_extract(body_json, '$.admission_lease.owner'),
                    json_extract(body_json, '$.admission_lease.generation'),
                    json_extract(body_json, '$.admission_lease.expires_at_ms')
             FROM sekai_action_instances WHERE instance_id = ?1",
            params![instance_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    // Read the clock after the row read, so time spent waiting for the
    // transaction lock counts against the lease.
    let now_ms = check_expiry.then(lease_clock_ms);
    Ok(stored.is_some_and(|(owner, generation, expires)| {
        lease.holds(owner.as_deref(), generation, expires, now_ms)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn sample(status: &str) -> ActionInstance {
        ActionInstance {
            agent_turn: None,
            autonomous_envelope_id: String::new(),
            parked_object_digest: String::new(),
            decided_by: String::new(),
            approval_decision: String::new(),
            review: Default::default(),
            agent_action: false,
            admission_tenant: String::new(),
            resource_tenant: String::new(),
            instance_id: "ai-1".into(),
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
            principal: "tester".into(),
            delegating_actor: None,
            parameters_json: r#"{"summary":"hello"}"#.into(),
            request_digest: compute_request_digest(
                "acme",
                "review.intake",
                "1.0.0",
                r#"{"summary":"hello"}"#,
                &[],
            )
            .unwrap(),
            idempotency_key: "key-1".into(),
            operation_id: "op-1".into(),
            status: status.into(),
            deny_reason: String::new(),
            evidence_submission_ids: vec![],
            policy_decision: "allow".into(),
            budget_decision: "allow".into(),
            created_at_ms: 10,
            decided_at_ms: 10,
            system_one_fill_json: String::new(),
            marking: String::new(),
            conflict: None,
            approval: None,
            offline: None,
            admission_lease: None,
            admission_ontology_digest: None,
            admission_budget_already_reserved: false,
        }
    }

    #[test]
    fn digest_is_stable_and_order_insensitive_for_evidence() {
        let a = compute_request_digest(
            "acme",
            "t",
            "1",
            r#"{"a":1,"b":2}"#,
            &["e2".into(), "e1".into()],
        )
        .unwrap();
        let b = compute_request_digest(
            "acme",
            "t",
            "1",
            r#"{"a":1,"b":2}"#,
            &["e1".into(), "e2".into()],
        )
        .unwrap();
        assert_eq!(a, b);
        let c = compute_request_digest("acme", "t", "1", r#"{"a":1,"b":3}"#, &[]).unwrap();
        assert_ne!(a, c);
        let duplicate = compute_request_digest("acme", "t", "1", r#"{"a":1,"a":2}"#, &[]);
        assert!(duplicate.unwrap_err().contains("duplicate object keys"));
    }

    #[test]
    fn put_get_list_and_idempotent_replay() {
        let db = SekaiDb::new(":memory:").unwrap();
        let put = db.put_action_instance(&sample(STATUS_ADMITTED)).unwrap();
        assert_eq!(put.instance_id, "ai-1");
        let got = db.get_action_instance("ai-1").unwrap().unwrap();
        assert_eq!(got.status, STATUS_ADMITTED);

        let replay = db.put_action_instance(&sample(STATUS_ADMITTED)).unwrap();
        assert_eq!(replay.instance_id, "ai-1");

        let mut conflict = sample(STATUS_ADMITTED);
        conflict.instance_id = "ai-2".into();
        conflict.parameters_json = r#"{"summary":"other"}"#.into();
        conflict.request_digest = compute_request_digest(
            "acme",
            "review.intake",
            "1.0.0",
            r#"{"summary":"other"}"#,
            &[],
        )
        .unwrap();
        let err = db.put_action_instance(&conflict).unwrap_err();
        assert!(err.contains("conflict"), "{err}");

        let listed = db
            .list_action_instances("acme", Some("review.intake"), None, 10)
            .unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn budget_subject_hierarchy() {
        assert_eq!(
            submit_budget_subject("acme", "tester", ""),
            "action:governed/project:acme/agent:tester"
        );
        assert_eq!(
            submit_budget_subject("acme", "tester", "reviews"),
            "action:governed:reviews/project:acme/agent:tester"
        );
    }

    /// After a takeover the first owner is stale: its object write, receipt,
    /// and compensation delete are refused, while the current owner's go
    /// through (#1930).
    fn stale_admission_owner_is_fenced(db: &crate::db::runtime_db::RuntimeDb) {
        let (instance_id, stale) = reserve_for_test(db, "ai-fence", 100);
        // Simulate the follow-up takeover: same reservation, next generation.
        let mut current_instance = db.get_action_instance(&instance_id).unwrap().unwrap();
        let current = AdmissionLease {
            owner: "recovering-owner".into(),
            generation: stale.generation + 1,
            expires_at_ms: lease_clock_ms() + ADMISSION_LEASE_MS,
            write_committed: Some(false),
            receipt_recorded: Some(false),
            written_object_digest: None,
            follow_ups_recorded: Some(false),
            decision_follow_ups_recorded: None,
            decision_budget_reserved: None,
        };
        current_instance.admission_lease = Some(current.clone());
        db.delete_action_instance(&instance_id).unwrap();
        db.put_action_instance(&current_instance).unwrap();

        let object = |id: &str| crate::domain::Object {
            id: id.into(),
            kind: "customer_record".into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 300,
            updated: 300,
        };
        let attribution = crate::sekai::audit::ChangeAttribution::action(
            &instance_id,
            &current_instance.operation_id,
        );
        let write = ParkedGrantWrite::Create(object("rec-stale"));
        assert!(matches!(
            db.apply_admission_object_write(
                &instance_id,
                &stale,
                &write,
                None,
                &[],
                "a",
                &attribution
            )
            .unwrap(),
            FencedAdmissionWrite::FenceLost
        ));
        assert!(db.get_object("rec-stale").unwrap().is_none());

        let receipt = sekai_domain::receipt::OperationReceipt {
            version: sekai_domain::receipt::OPERATION_RECEIPT_VERSION.into(),
            operation_id: current_instance.operation_id.clone(),
            parent_operation_id: None,
            namespace: "acme".into(),
            operation_class: "action_instance".into(),
            initiating_actor: "a".into(),
            schema_version: "v1".into(),
            policy_version: "v1".into(),
            started_at_ms: 300,
            completed_at_ms: None,
            events: vec![],
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
            ontology_digest: None,
            artifact: None,
        };
        assert!(
            !db.put_admission_receipt(&instance_id, &stale, &receipt)
                .unwrap()
        );
        assert!(
            db.get_operation_receipt(&current_instance.operation_id)
                .unwrap()
                .is_none()
        );
        assert!(
            !db.delete_action_instance_fenced(&instance_id, &stale)
                .unwrap()
        );
        assert!(db.get_action_instance(&instance_id).unwrap().is_some());

        let write = ParkedGrantWrite::Create(object("rec-current"));
        assert!(matches!(
            db.apply_admission_object_write(
                &instance_id,
                &current,
                &write,
                None,
                &[],
                "a",
                &attribution
            )
            .unwrap(),
            FencedAdmissionWrite::Applied(None)
        ));
        assert!(db.get_object("rec-current").unwrap().is_some());
        assert!(
            db.put_admission_receipt(&instance_id, &current, &receipt)
                .unwrap()
        );
        // Release undoes the write and drops the reservation together, and
        // only for the current owner.
        let undo = AdmissionUndo::AbortCreate {
            object_id: "rec-current".into(),
            object_kind: "customer_record".into(),
        };
        assert!(
            !db.release_admission(&instance_id, &stale, &undo, "a")
                .unwrap()
        );
        assert!(db.get_object("rec-current").unwrap().is_some());
        assert!(db.get_action_instance(&instance_id).unwrap().is_some());
        assert!(
            db.release_admission(&instance_id, &current, &undo, "a")
                .unwrap()
        );
        assert!(db.get_object("rec-current").unwrap().is_none());
        assert!(db.get_action_instance(&instance_id).unwrap().is_none());

        // An expired lease is refused at the write and the receipt, though
        // its owner can still release the reservation.
        let (expired_id, mut expired) = reserve_for_test(db, "ai-expired", 100);
        expired.expires_at_ms = lease_clock_ms() - 1;
        let mut stored = db.get_action_instance(&expired_id).unwrap().unwrap();
        stored.admission_lease = Some(expired.clone());
        db.delete_action_instance(&expired_id).unwrap();
        db.put_action_instance(&stored).unwrap();
        let write = ParkedGrantWrite::Create(object("rec-expired"));
        assert!(matches!(
            db.apply_admission_object_write(
                &expired_id,
                &expired,
                &write,
                None,
                &[],
                "a",
                &attribution
            )
            .unwrap(),
            FencedAdmissionWrite::FenceLost
        ));
        assert!(db.get_object("rec-expired").unwrap().is_none());
        let mut late = receipt.clone();
        late.operation_id = stored.operation_id.clone();
        assert!(
            !db.put_admission_receipt(&expired_id, &expired, &late)
                .unwrap()
        );
        assert!(
            db.delete_action_instance_fenced(&expired_id, &expired)
                .unwrap()
        );

        // A takeover built from a snapshot whose commit marker went stale
        // matches nothing: the write that committed since is never lost
        // (#1931).
        let (raced_id, mut snapshot) = reserve_for_test(db, "ai-raced", 100);
        snapshot.expires_at_ms = lease_clock_ms() - 1;
        let mut stored = db.get_action_instance(&raced_id).unwrap().unwrap();
        let mut committed = snapshot.clone();
        committed.write_committed = Some(true);
        stored.admission_lease = Some(committed.clone());
        db.delete_action_instance(&raced_id).unwrap();
        db.put_action_instance(&stored).unwrap();
        let mut stale = stored.clone();
        stale.admission_lease = Some(snapshot.clone());
        assert!(
            !db.take_over_admission(&stale, &snapshot, &snapshot.succeeding())
                .unwrap()
        );
        let next = committed.succeeding();
        assert!(db.take_over_admission(&stored, &committed, &next).unwrap());
        let taken = db.get_action_instance(&raced_id).unwrap().unwrap();
        assert_eq!(taken.admission_lease.unwrap().write_committed, Some(true));
    }

    /// An admission write commits only while each reference is stored as
    /// planning read it (#1941).
    fn references_fence_the_admission_write(db: &crate::db::runtime_db::RuntimeDb, tag: &str) {
        let record = |id: &str, updated| crate::domain::Object {
            id: id.into(),
            kind: "customer_record".into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 500,
            updated,
        };
        let reference_id = format!("ref-{tag}");
        db.create_object_with_audit(&record(&reference_id, 500), "a")
            .unwrap();
        let planned = db.get_object(&reference_id).unwrap().unwrap();
        let mut changed = planned.clone();
        changed.updated = 501;
        changed.properties.insert("tier".into(), "gold".into());
        db.update_object(&changed).unwrap();
        let attribution = crate::sekai::audit::ChangeAttribution::default();
        let write = ParkedGrantWrite::Create(record(&format!("new-{tag}"), 600));
        let (stale_id, stale_lease) = reserve_for_test(db, &format!("ai-ref-stale-{tag}"), 100);
        let error = db
            .apply_admission_object_write(
                &stale_id,
                &stale_lease,
                &write,
                None,
                &[PlanReference::Present(planned.clone())],
                "a",
                &attribution,
            )
            .unwrap_err();
        assert_eq!(error, format!("{REFERENCE_CHANGED}{reference_id}"));
        assert!(db.get_object(&format!("new-{tag}")).unwrap().is_none());

        let current = db.get_object(&reference_id).unwrap().unwrap();
        let (fresh_id, fresh_lease) = reserve_for_test(db, &format!("ai-ref-fresh-{tag}"), 100);
        assert!(matches!(
            db.apply_admission_object_write(
                &fresh_id,
                &fresh_lease,
                &write,
                None,
                &[PlanReference::Present(current.clone())],
                "a",
                &attribution,
            )
            .unwrap(),
            FencedAdmissionWrite::Applied(None)
        ));

        // A reference read as absent refuses once it exists.
        let ghost = format!("ghost-{tag}");
        db.create_object_with_audit(&record(&ghost, 700), "a")
            .unwrap();
        let (absent_id, absent_lease) = reserve_for_test(db, &format!("ai-ref-absent-{tag}"), 100);
        let error = db
            .apply_admission_object_write(
                &absent_id,
                &absent_lease,
                &ParkedGrantWrite::Create(record(&format!("other-{tag}"), 800)),
                None,
                &[PlanReference::Absent(ghost.clone())],
                "a",
                &attribution,
            )
            .unwrap_err();
        assert_eq!(error, format!("{REFERENCE_CHANGED}{ghost}"));
    }

    #[test]
    fn sqlite_references_fence_the_admission_write() {
        references_fence_the_admission_write(&crate::db::runtime_db::RuntimeDb::memory(), "s");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_references_fence_the_admission_write() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = crate::db::runtime_db::RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect()));
        references_fence_the_admission_write(&db, "p");
    }

    /// A frozen site agent instance of the reservation's principal refuses
    /// the write and the admission without an object write, and marks the
    /// reservation denied in the same transaction (#1970).
    fn a_frozen_site_agent_refuses_the_commit(db: &crate::db::runtime_db::RuntimeDb, tag: &str) {
        let sample = tests::sample(STATUS_ADMITTED);
        db.create_object_with_audit(
            &crate::domain::Object {
                id: format!("line-{tag}"),
                kind: crate::sekai::site_agent_instance::KIND.into(),
                name: format!("line-{tag}"),
                namespace: sample.namespace.clone(),
                external_id: String::new(),
                properties: std::collections::HashMap::from([
                    ("principal_id".into(), sample.principal.clone()),
                    ("frozen".into(), "true".into()),
                ]),
                created: 500,
                updated: 500,
            },
            "a",
        )
        .unwrap();
        let reason = format!("site agent instance line-{tag} is frozen");
        let write = ParkedGrantWrite::Create(crate::domain::Object {
            id: format!("rec-{tag}"),
            kind: "customer_record".into(),
            name: format!("rec-{tag}"),
            namespace: sample.namespace.clone(),
            external_id: String::new(),
            properties: Default::default(),
            created: 600,
            updated: 600,
        });
        let (written_id, written_lease) = reserve_for_test(db, &format!("ai-frozen-{tag}"), 100);
        let refused = db
            .apply_admission_object_write(
                &written_id,
                &written_lease,
                &write,
                None,
                &[],
                "a",
                &crate::sekai::audit::ChangeAttribution::default(),
            )
            .unwrap();
        assert!(matches!(&refused, FencedAdmissionWrite::Refused(why) if *why == reason));
        assert!(db.get_object(&format!("rec-{tag}")).unwrap().is_none());
        let denied = db.get_action_instance(&written_id).unwrap().unwrap();
        assert_eq!(
            (denied.status.as_str(), denied.deny_reason.as_str()),
            (STATUS_DENIED, reason.as_str())
        );

        // An Action writing no object commits at its receipt: the receipt
        // is refused and the reservation denied in that transaction.
        let (plain_id, plain_lease) = reserve_for_test(db, &format!("ai-plain-{tag}"), 100);
        let plain = db.get_action_instance(&plain_id).unwrap().unwrap();
        let receipt = sekai_domain::receipt::OperationReceipt {
            version: sekai_domain::receipt::OPERATION_RECEIPT_VERSION.into(),
            operation_id: plain.operation_id.clone(),
            parent_operation_id: None,
            namespace: plain.namespace.clone(),
            operation_class: "action_instance".into(),
            initiating_actor: "a".into(),
            schema_version: "v1".into(),
            policy_version: "v1".into(),
            started_at_ms: 300,
            completed_at_ms: None,
            events: vec![],
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
            ontology_digest: None,
            artifact: None,
        };
        assert!(matches!(
            db.put_admission_receipt_checked(&plain_id, &plain_lease, &receipt, CommitCheck::SiteAgent)
                .unwrap(),
            FencedAdmissionWrite::Refused(why) if why == reason
        ));
        assert!(
            db.get_operation_receipt(&plain.operation_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            db.get_action_instance(&plain_id).unwrap().unwrap().status,
            STATUS_DENIED
        );
    }

    /// An Action submitted under an agent turn's token commits only while
    /// that turn is still claimed at the token's generation: once another
    /// worker reclaims the turn, the superseded submission is refused and
    /// its reservation denied (ADR 0142).
    fn a_superseded_turn_refuses_the_commit(db: &crate::db::runtime_db::RuntimeDb, tag: &str) {
        use crate::sekai::agent_turn;
        let sample = tests::sample(STATUS_ADMITTED);
        db.create_object_with_audit(
            &crate::domain::Object {
                id: format!("line-{tag}"),
                kind: crate::sekai::site_agent_instance::KIND.into(),
                name: format!("line-{tag}"),
                namespace: sample.namespace.clone(),
                external_id: String::new(),
                properties: std::collections::HashMap::from([
                    ("principal_id".into(), sample.principal.clone()),
                    ("frozen".into(), "false".into()),
                ]),
                created: 500,
                updated: 500,
            },
            "a",
        )
        .unwrap();
        let turn = agent_turn::admit(
            db,
            agent_turn::Wake {
                namespace: sample.namespace.clone(),
                instance_id: format!("line-{tag}"),
                cause: agent_turn::Cause::Manual,
                cause_ref: format!("wake-{tag}"),
                due_at_ms: 1,
            },
            "root",
            1,
        )
        .unwrap();
        // Claims run on the lease clock the commit reads.
        let now = lease_clock_ms();
        let held = agent_turn::claim(
            db,
            &sample.namespace,
            "runner-a",
            &turn.turn_id,
            60_000,
            now,
        )
        .unwrap();
        let submitted = |instance_id: &str, generation: i64| {
            let lease = AdmissionLease::first();
            let mut instance = tests::sample(STATUS_ADMITTED);
            instance.instance_id = instance_id.into();
            instance.idempotency_key = format!("key-{instance_id}");
            instance.operation_id = format!("op-{instance_id}");
            instance.admission_lease = Some(lease.clone());
            instance.agent_turn = Some(AgentTurnFence {
                turn_id: turn.turn_id.clone(),
                claim_generation: u64::try_from(generation).unwrap(),
            });
            db.put_action_instance(&instance).unwrap();
            lease
        };
        let write = |id: &str| {
            ParkedGrantWrite::Create(crate::domain::Object {
                id: id.into(),
                kind: "customer_record".into(),
                name: id.into(),
                namespace: sample.namespace.clone(),
                external_id: String::new(),
                properties: Default::default(),
                created: 600,
                updated: 600,
            })
        };
        let apply = |instance_id: &str, lease: &AdmissionLease, object_id: &str| {
            db.apply_admission_object_write(
                instance_id,
                lease,
                &write(object_id),
                None,
                &[],
                "a",
                &crate::sekai::audit::ChangeAttribution::default(),
            )
            .unwrap()
        };

        // Under the live claim, the submission commits.
        let live = format!("ai-live-{tag}");
        let lease = submitted(&live, held.claim_generation);
        assert!(!matches!(
            apply(&live, &lease, &format!("rec-live-{tag}")),
            FencedAdmissionWrite::Refused(_) | FencedAdmissionWrite::FenceLost
        ));

        // After the lease lapses and another worker reclaims the turn, a
        // submission fenced on the old generation is refused.
        let reclaimed = agent_turn::claim(
            db,
            &sample.namespace,
            "runner-b",
            &turn.turn_id,
            60_000,
            now + 61_000,
        )
        .unwrap();
        assert!(reclaimed.claim_generation > held.claim_generation);
        let stale = format!("ai-stale-{tag}");
        let lease = submitted(&stale, held.claim_generation);
        let refused = apply(&stale, &lease, &format!("rec-stale-{tag}"));
        assert!(
            matches!(&refused, FencedAdmissionWrite::Refused(why) if why.contains("no longer claimed")),
            "{refused:?}"
        );
        assert!(
            db.get_object(&format!("rec-stale-{tag}"))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            db.get_action_instance(&stale).unwrap().unwrap().status,
            STATUS_DENIED
        );

        // A submission that parks commits only its receipt, without the site
        // agent check; the turn's fence still refuses it, so a superseded
        // worker never leaves an approvable Action behind.
        let parked = format!("ai-parked-{tag}");
        let lease = submitted(&parked, held.claim_generation);
        let instance = db.get_action_instance(&parked).unwrap().unwrap();
        let receipt = sekai_domain::receipt::OperationReceipt {
            version: sekai_domain::receipt::OPERATION_RECEIPT_VERSION.into(),
            operation_id: instance.operation_id.clone(),
            parent_operation_id: None,
            namespace: instance.namespace.clone(),
            operation_class: "action_instance".into(),
            initiating_actor: "a".into(),
            schema_version: "v1".into(),
            policy_version: "v1".into(),
            started_at_ms: 300,
            completed_at_ms: None,
            events: vec![],
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
            ontology_digest: None,
            artifact: None,
        };
        assert!(matches!(
            db.put_admission_receipt_checked(&parked, &lease, &receipt, CommitCheck::TurnFence)
                .unwrap(),
            FencedAdmissionWrite::Refused(why) if why.contains("no longer claimed")
        ));
        assert_eq!(
            db.get_action_instance(&parked).unwrap().unwrap().status,
            STATUS_DENIED
        );
        // The denial's own receipt records without a live turn.
        let denial = sekai_domain::receipt::OperationReceipt {
            operation_id: format!("op-{stale}"),
            ..receipt.clone()
        };
        let stale_lease = db
            .get_action_instance(&stale)
            .unwrap()
            .unwrap()
            .admission_lease
            .unwrap();
        assert!(matches!(
            db.put_admission_receipt_checked(&stale, &stale_lease, &denial, CommitCheck::None)
                .unwrap(),
            FencedAdmissionWrite::Applied(())
        ));

        // A write that committed under a live claim stays authorized when
        // its receipt follows the claim's end.
        let committed = format!("ai-committed-{tag}");
        let lease = AdmissionLease {
            write_committed: Some(true),
            ..AdmissionLease::first()
        };
        let mut instance = tests::sample(STATUS_ADMITTED);
        instance.instance_id = committed.clone();
        instance.idempotency_key = format!("key-{committed}");
        instance.operation_id = format!("op-{committed}");
        instance.admission_lease = Some(lease.clone());
        instance.agent_turn = Some(AgentTurnFence {
            turn_id: turn.turn_id.clone(),
            claim_generation: u64::try_from(held.claim_generation).unwrap(),
        });
        db.put_action_instance(&instance).unwrap();
        let after_write = sekai_domain::receipt::OperationReceipt {
            operation_id: instance.operation_id.clone(),
            ..receipt.clone()
        };
        let recorded = db
            .put_admission_receipt_checked(&committed, &lease, &after_write, CommitCheck::TurnFence)
            .unwrap();
        assert!(
            matches!(recorded, FencedAdmissionWrite::Applied(())),
            "{recorded:?}"
        );
    }

    #[test]
    fn sqlite_a_superseded_turn_refuses_the_commit() {
        a_superseded_turn_refuses_the_commit(&crate::db::runtime_db::RuntimeDb::memory(), "s");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_a_superseded_turn_refuses_the_commit() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = crate::db::runtime_db::RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect()));
        a_superseded_turn_refuses_the_commit(&db, "p");
    }

    #[test]
    fn sqlite_a_frozen_site_agent_refuses_the_commit() {
        a_frozen_site_agent_refuses_the_commit(&crate::db::runtime_db::RuntimeDb::memory(), "s");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_a_frozen_site_agent_refuses_the_commit() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = crate::db::runtime_db::RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect()));
        a_frozen_site_agent_refuses_the_commit(&db, "p");
    }

    #[test]
    fn sqlite_stale_admission_owner_is_fenced() {
        stale_admission_owner_is_fenced(&crate::db::runtime_db::RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_stale_admission_owner_is_fenced() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = crate::db::runtime_db::RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect()));
        stale_admission_owner_is_fenced(&db);

        // PostgreSQL keeps its monotonic revision token on a fenced update:
        // one that does not advance `updated` is a revision conflict.
        let (instance_id, lease) = reserve_for_test(&db, "ai-revision", 100);
        let object = crate::domain::Object {
            id: "rec-revision".into(),
            kind: "customer_record".into(),
            name: "rec-revision".into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: Default::default(),
            created: 500,
            updated: 500,
        };
        db.create_object_with_audit(&object, "a").unwrap();
        let attribution = crate::sekai::audit::ChangeAttribution::default();
        let same = ParkedGrantWrite::Update(object.clone());
        let error = db
            .apply_admission_object_write(&instance_id, &lease, &same, None, &[], "a", &attribution)
            .unwrap_err();
        assert_eq!(error, "object revision conflict");
        let advanced = ParkedGrantWrite::Update(crate::domain::Object {
            updated: 501,
            ..object
        });
        assert!(matches!(
            db.apply_admission_object_write(
                &instance_id,
                &lease,
                &advanced,
                None,
                &[],
                "a",
                &attribution
            )
            .unwrap(),
            FencedAdmissionWrite::Applied(Some(_))
        ));
    }

    #[test]
    fn a_lease_holds_only_for_its_owner_generation_and_live_window() {
        let lease = AdmissionLease {
            owner: "a".into(),
            generation: 2,
            expires_at_ms: 1_000,
            write_committed: Some(false),
            receipt_recorded: Some(false),
            written_object_digest: None,
            follow_ups_recorded: Some(false),
            decision_follow_ups_recorded: None,
            decision_budget_reserved: None,
        };
        assert!(lease.holds(Some("a"), Some(2), Some(1_000), None));
        assert!(!lease.holds(Some("b"), Some(2), Some(1_000), None));
        assert!(!lease.holds(Some("a"), Some(3), Some(1_000), None));
        assert!(!lease.holds(None, None, None, None));
        assert!(lease.holds(Some("a"), Some(2), Some(1_000), Some(999)));
        assert!(!lease.holds(Some("a"), Some(2), Some(1_000), Some(1_000)));
    }
}
