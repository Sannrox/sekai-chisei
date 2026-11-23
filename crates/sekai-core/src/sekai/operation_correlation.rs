//! Caller-supplied operation identity across spans, receipts, and object changes.
//!
//! The identity is an opaque key chosen by the caller. It is never derived
//! from request content, so equal identities do not prove equal inputs.

use std::collections::{BTreeSet, HashMap};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::audit::DecisionFilter;

pub const OPERATION_METADATA: &str = "x-sekai-operation-id";
pub const SPAN_FIELD: &str = "sekai.operation_id";
pub const RECEIPT_FIELD: &str = "operation_id";
pub const EVENT_FIELD: &str = "operation_id";
pub const TRACEPARENT: &str = "traceparent";
pub const MAX_IDENTITY_CHARS: usize = 200;
pub const ACTION_SUBMIT: &str = "submit_action_instance";

/// Bind the header and `SubmitActionInstanceRequest.request_id` to one identity.
///
/// Empty on both sides leaves minting to admission (`op-gai-*`).
pub fn bind_submit_identity(header: Option<&str>, request_id: &str) -> Result<String, String> {
    let header = normalize_identity(header.unwrap_or(""))?;
    let request_id = normalize_identity(request_id)?;
    match (header.is_empty(), request_id.is_empty()) {
        (true, true) => Ok(String::new()),
        (false, true) => Ok(header),
        (true, false) => Ok(request_id),
        (false, false) if header == request_id => Ok(request_id),
        (false, false) => Err(format!(
            "{OPERATION_METADATA} must match request_id when both are set"
        )),
    }
}

pub fn normalize_identity(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.chars().any(char::is_whitespace) {
        return Err("operation identity must not contain whitespace".into());
    }
    if value.chars().count() > MAX_IDENTITY_CHARS {
        return Err(format!(
            "operation identity must be at most {MAX_IDENTITY_CHARS} characters"
        ));
    }
    Ok(value.to_string())
}

/// The identity of a write call (#3087): the caller's header when it carries
/// one, otherwise `<prefix>-<uuid>` minted by the plane, as receipts do.
pub fn call_identity(header: Option<&str>, prefix: &str) -> Result<String, String> {
    let header = normalize_identity(header.unwrap_or(""))?;
    if header.is_empty() {
        return Ok(format!("{prefix}-{}", uuid::Uuid::new_v4().simple()));
    }
    Ok(header)
}

/// Submit decisions read per page while correlating objects to operations.
const SUBMIT_PAGE: i32 = 512;

/// Plane-stamped operation identities for objects mutated by governed actions.
///
/// Pages through submit decisions newest first and stops once every requested
/// object has an identity or the ledger runs out. A decision inserted while
/// paging shifts older rows to a later page, which can only repeat a row,
/// never skip one.
pub fn operation_ids_for_objects(
    db: &RuntimeDb,
    object_ids: &BTreeSet<String>,
) -> Result<HashMap<String, String>, String> {
    let mut found = HashMap::new();
    let mut offset = 0;
    while found.len() < object_ids.len() {
        let decisions = db.list_decisions(&DecisionFilter {
            action: Some(ACTION_SUBMIT.into()),
            limit: SUBMIT_PAGE,
            offset,
            ..DecisionFilter::default()
        })?;
        let page_len = decisions.len();
        for decision in decisions {
            let Some(object_id) = decision.evidence.get("object_id") else {
                continue;
            };
            if !object_ids.contains(object_id) || found.contains_key(object_id) {
                continue;
            }
            let Some(operation_id) = decision.evidence.get("operation_id") else {
                continue;
            };
            if operation_id.trim().is_empty() {
                continue;
            }
            found.insert(object_id.clone(), operation_id.clone());
        }
        if page_len < SUBMIT_PAGE as usize {
            break;
        }
        offset = offset.saturating_add(SUBMIT_PAGE);
    }
    Ok(found)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationCarriers {
    pub span: String,
    pub receipt: String,
    pub object_change_event: String,
}

impl OperationCarriers {
    pub fn require_same_identity(&self, expected: &str) -> Result<(), String> {
        let expected = normalize_identity(expected)?;
        if expected.is_empty() {
            return Err("expected operation identity required".into());
        }
        for (name, value) in [
            (SPAN_FIELD, self.span.as_str()),
            (RECEIPT_FIELD, self.receipt.as_str()),
            (EVENT_FIELD, self.object_change_event.as_str()),
        ] {
            if value != expected {
                return Err(format!("{name} omitted or renamed the operation identity"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_submit(db: &RuntimeDb, seq: usize, object_id: &str, operation_id: &str) {
        db.record_decision(&crate::sekai::audit::Decision {
            id: format!("decision-{seq}"),
            timestamp: 1_000 + seq as i64,
            actor: "agent".into(),
            action: ACTION_SUBMIT.into(),
            reason: String::new(),
            evidence: HashMap::from([
                ("object_id".to_string(), object_id.to_string()),
                ("operation_id".to_string(), operation_id.to_string()),
            ]),
            target_id: String::new(),
            outcome: "allowed".into(),
        })
        .unwrap();
    }

    #[test]
    fn operation_ids_reach_submits_older_than_one_page() {
        let db = RuntimeDb::memory();
        record_submit(&db, 0, "old-object", "op-old");
        for seq in 1..=(SUBMIT_PAGE as usize + 10) {
            record_submit(&db, seq, &format!("noise-{seq}"), &format!("op-{seq}"));
        }
        let wanted = BTreeSet::from(["old-object".to_string(), "never-submitted".to_string()]);

        let found = operation_ids_for_objects(&db, &wanted).unwrap();

        assert_eq!(
            found,
            HashMap::from([("old-object".to_string(), "op-old".to_string())])
        );
    }

    #[test]
    fn header_fills_empty_request_id() {
        assert_eq!(
            bind_submit_identity(Some("op-cross-plane-1"), "").unwrap(),
            "op-cross-plane-1"
        );
    }

    #[test]
    fn mismatched_header_and_request_id_fail_closed() {
        let error = bind_submit_identity(Some("op-a"), "op-b").unwrap_err();
        assert!(error.contains("must match request_id"), "{error}");
    }

    #[test]
    fn whitespace_identity_is_rejected() {
        assert!(normalize_identity("op with space").is_err());
    }

    #[test]
    fn omitted_carrier_fails_the_identity_check() {
        let carriers = OperationCarriers {
            span: "op-1".into(),
            receipt: "op-1".into(),
            object_change_event: String::new(),
        };
        let error = carriers.require_same_identity("op-1").unwrap_err();
        assert!(
            error.contains(EVENT_FIELD),
            "missing object-change identity must fail: {error}"
        );
    }

    #[test]
    fn matching_carriers_pass() {
        let carriers = OperationCarriers {
            span: "op-1".into(),
            receipt: "op-1".into(),
            object_change_event: "op-1".into(),
        };
        carriers.require_same_identity("op-1").unwrap();
    }
}
