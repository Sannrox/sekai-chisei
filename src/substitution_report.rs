//! Namespace-authorized reporting for realized lookup-first and model paths.

use crate::chisei::lookup_first::{self, ANSWER_PATH_LOOKUP_HIT, ANSWER_PATH_MODEL};
use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent, ReceiptEventKind};
use crate::db::runtime_db::RuntimeDb;
use crate::obs::console::{is_safe_namespace, principal_can_access_namespace};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const SUBSTITUTION_REPORT_VERSION: &str = "chisei.lookup-first-substitution/v1";
pub const MAX_SUBSTITUTION_WINDOW_MS: i64 = 366 * 24 * 60 * 60 * 1000;
pub const MAX_SUBSTITUTION_RECEIPTS: usize = 4_096;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SubstitutionCounts {
    pub lookup_hit: u64,
    pub model_path: u64,
    pub lookup_refusal: u64,
    pub unclassified: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProviderUsage {
    pub calls: u64,
    pub priced_calls: u64,
    pub unpriced_calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cost_usd_micros: u64,
}

impl ProviderUsage {
    fn add_event(&mut self, event: &OperationReceiptEvent) {
        self.calls = self.calls.saturating_add(1);
        let input_tokens = nonnegative_u64(event, "input_tokens");
        let output_tokens = nonnegative_u64(event, "output_tokens");
        self.input_tokens = self.input_tokens.saturating_add(input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(output_tokens);
        self.total_tokens = self
            .total_tokens
            .saturating_add(input_tokens.saturating_add(output_tokens));
        match event
            .attributes
            .get("cost_usd_micros")
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(cost) => {
                self.priced_calls = self.priced_calls.saturating_add(1);
                self.cost_usd_micros = self.cost_usd_micros.saturating_add(cost);
            }
            None => self.unpriced_calls = self.unpriced_calls.saturating_add(1),
        }
    }

    fn merge(&mut self, other: &Self) {
        self.calls = self.calls.saturating_add(other.calls);
        self.priced_calls = self.priced_calls.saturating_add(other.priced_calls);
        self.unpriced_calls = self.unpriced_calls.saturating_add(other.unpriced_calls);
        self.input_tokens = self.input_tokens.saturating_add(other.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(other.output_tokens);
        self.total_tokens = self.total_tokens.saturating_add(other.total_tokens);
        self.cost_usd_micros = self.cost_usd_micros.saturating_add(other.cost_usd_micros);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ModelUsage {
    pub calls: u64,
    pub priced_calls: u64,
    pub unpriced_calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cost_usd_micros: u64,
    pub providers: BTreeMap<String, ProviderUsage>,
}

impl ModelUsage {
    fn add_event(&mut self, event: &OperationReceiptEvent) {
        let provider = event
            .attributes
            .get("provider")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown")
            .to_string();
        let mut usage = ProviderUsage::default();
        usage.add_event(event);
        self.calls = self.calls.saturating_add(usage.calls);
        self.priced_calls = self.priced_calls.saturating_add(usage.priced_calls);
        self.unpriced_calls = self.unpriced_calls.saturating_add(usage.unpriced_calls);
        self.input_tokens = self.input_tokens.saturating_add(usage.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(usage.output_tokens);
        self.total_tokens = self.total_tokens.saturating_add(usage.total_tokens);
        self.cost_usd_micros = self.cost_usd_micros.saturating_add(usage.cost_usd_micros);
        self.providers.entry(provider).or_default().merge(&usage);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TaskTypeSummary {
    pub receipts: u64,
    pub lookup_hit: u64,
    pub model_path: u64,
    pub lookup_refusal: u64,
    pub non_eligible_model_path: u64,
    pub lookup_refusal_reasons: BTreeMap<String, u64>,
    pub model_usage: ModelUsage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SubstitutionReport {
    pub version: String,
    pub namespace: String,
    pub since_ms: i64,
    pub until_ms: i64,
    pub receipts_considered: u64,
    pub counts: SubstitutionCounts,
    pub non_eligible_model_paths: u64,
    pub lookup_refusal_reasons: BTreeMap<String, u64>,
    pub model_usage: ModelUsage,
    pub by_task_type: BTreeMap<String, TaskTypeSummary>,
}

#[derive(Debug, Default)]
struct ReceiptSummary {
    task_type: String,
    lookup_hit: bool,
    model_path: bool,
    refusal_reasons: BTreeSet<String>,
    model_events: Vec<usize>,
}

pub fn query_substitution_report(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
    since_ms: i64,
    until_ms: i64,
) -> Result<SubstitutionReport, String> {
    let namespace = namespace.trim();
    if !is_safe_namespace(namespace) {
        return Err("invalid namespace".into());
    }
    if !principal_can_access_namespace(db, principal.trim(), namespace).unwrap_or(false) {
        return Err("namespace access denied".into());
    }
    if until_ms <= since_ms {
        return Err("until_ms must be greater than since_ms".into());
    }
    if until_ms.saturating_sub(since_ms) > MAX_SUBSTITUTION_WINDOW_MS {
        return Err("substitution report window exceeds one year".into());
    }

    let receipts = db.list_operation_receipts_in_window(
        namespace,
        since_ms,
        until_ms,
        MAX_SUBSTITUTION_RECEIPTS.saturating_add(1),
    )?;
    if receipts.len() > MAX_SUBSTITUTION_RECEIPTS {
        return Err(format!(
            "substitution report receipt limit exceeded ({MAX_SUBSTITUTION_RECEIPTS})"
        ));
    }

    let mut report = SubstitutionReport {
        version: SUBSTITUTION_REPORT_VERSION.into(),
        namespace: namespace.into(),
        since_ms,
        until_ms,
        receipts_considered: receipts.len() as u64,
        counts: SubstitutionCounts::default(),
        non_eligible_model_paths: 0,
        lookup_refusal_reasons: BTreeMap::new(),
        model_usage: ModelUsage::default(),
        by_task_type: BTreeMap::new(),
    };

    for receipt in &receipts {
        let summary = summarize_receipt(receipt, since_ms, until_ms);
        let task_type = if summary.task_type.is_empty() {
            "unknown".to_string()
        } else {
            summary.task_type.clone()
        };
        let task = report.by_task_type.entry(task_type).or_default();
        task.receipts = task.receipts.saturating_add(1);

        if summary.lookup_hit {
            report.counts.lookup_hit = report.counts.lookup_hit.saturating_add(1);
            task.lookup_hit = task.lookup_hit.saturating_add(1);
        }
        if summary.model_path {
            report.counts.model_path = report.counts.model_path.saturating_add(1);
            task.model_path = task.model_path.saturating_add(1);
            if !lookup_first::is_lookup_first_capability(&summary.task_type) {
                report.non_eligible_model_paths = report.non_eligible_model_paths.saturating_add(1);
                task.non_eligible_model_path = task.non_eligible_model_path.saturating_add(1);
            }
            for index in &summary.model_events {
                report.model_usage.add_event(&receipt.events[*index]);
                task.model_usage.add_event(&receipt.events[*index]);
            }
        }
        if !summary.lookup_hit && !summary.model_path {
            report.counts.unclassified = report.counts.unclassified.saturating_add(1);
        }

        if !summary.refusal_reasons.is_empty() {
            report.counts.lookup_refusal = report.counts.lookup_refusal.saturating_add(1);
            task.lookup_refusal = task.lookup_refusal.saturating_add(1);
            for reason in summary.refusal_reasons {
                increment(&mut report.lookup_refusal_reasons, &reason);
                increment(&mut task.lookup_refusal_reasons, &reason);
            }
        }
    }

    Ok(report)
}

fn summarize_receipt(receipt: &OperationReceipt, since_ms: i64, until_ms: i64) -> ReceiptSummary {
    let task_type = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .and_then(|event| event.attributes.get("task_type"))
        .map(String::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    let mut refusal_reasons = BTreeSet::new();
    let mut lookup_hit = false;
    let mut model_path = false;
    let mut model_events = Vec::new();
    for (index, event) in receipt.events.iter().enumerate() {
        if event.timestamp_ms < since_ms || event.timestamp_ms >= until_ms {
            continue;
        }
        if event.kind == ReceiptEventKind::ModelCalled {
            model_events.push(index);
            model_path = true;
        }
        match event.attributes.get("answer_path").map(String::as_str) {
            Some(ANSWER_PATH_LOOKUP_HIT) => lookup_hit = true,
            Some(ANSWER_PATH_MODEL) => model_path = true,
            _ => {}
        }
        if let Some(reason) = event
            .attributes
            .get("lookup_refusal")
            .map(String::as_str)
            .map(str::trim)
            .filter(|reason| !reason.is_empty())
        {
            refusal_reasons.insert(reason.to_string());
        }
    }
    ReceiptSummary {
        task_type,
        lookup_hit,
        model_path,
        refusal_reasons,
        model_events,
    }
}

fn increment(map: &mut BTreeMap<String, u64>, key: &str) {
    let value = map.entry(key.to_string()).or_default();
    *value = value.saturating_add(1);
}

fn nonnegative_u64(event: &OperationReceiptEvent, key: &str) -> u64 {
    event
        .attributes
        .get(key)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::OPERATION_RECEIPT_VERSION;
    use crate::domain::Object;
    use crate::sekai::security::{Grant, Role};
    use std::collections::HashMap;

    fn event(
        operation_id: &str,
        id: &str,
        timestamp_ms: i64,
        kind: ReceiptEventKind,
        attributes: &[(&str, &str)],
    ) -> OperationReceiptEvent {
        OperationReceiptEvent {
            event_id: format!("{operation_id}:{id}"),
            operation_id: operation_id.into(),
            parent_event_id: None,
            timestamp_ms,
            kind,
            surface: kind.surface(),
            actor: "test".into(),
            references: vec![],
            attributes: attributes
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
        }
    }

    fn receipt(
        operation_id: &str,
        namespace: &str,
        started_at_ms: i64,
        task_type: &str,
        events: Vec<OperationReceiptEvent>,
    ) -> OperationReceipt {
        let mut events = events;
        events.insert(
            0,
            event(
                operation_id,
                "intent",
                started_at_ms,
                ReceiptEventKind::IntentRecorded,
                &[("task_type", task_type)],
            ),
        );
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: operation_id.into(),
            parent_operation_id: None,
            namespace: namespace.into(),
            operation_class: "native_execution".into(),
            initiating_actor: "alice".into(),
            schema_version: "test/v1".into(),
            policy_version: "test/v1".into(),
            started_at_ms,
            completed_at_ms: Some(started_at_ms + 1),
            events,
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
        }
    }

    #[test]
    fn aggregates_hits_refusals_and_non_eligible_model_paths() {
        let db = RuntimeDb::memory();
        db.insert_operation_receipt(&receipt(
            "hit",
            "alpha",
            10,
            "sekai.semantic.resolve_ref",
            vec![event(
                "hit",
                "outcome",
                20,
                ReceiptEventKind::OutcomeRecorded,
                &[("answer_path", ANSWER_PATH_LOOKUP_HIT)],
            )],
        ))
        .unwrap();
        db.insert_operation_receipt(&receipt(
            "mixed",
            "alpha",
            15,
            "sekai.semantic.resolve_ref",
            vec![event(
                "mixed",
                "model",
                25,
                ReceiptEventKind::ModelCalled,
                &[
                    ("answer_path", ANSWER_PATH_LOOKUP_HIT),
                    ("provider", "mixed-provider"),
                    ("input_tokens", "1"),
                    ("output_tokens", "1"),
                ],
            )],
        ))
        .unwrap();
        db.insert_operation_receipt(&receipt(
            "refusal",
            "alpha",
            30,
            "sekai.semantic.expand_relations",
            vec![event(
                "refusal",
                "model",
                40,
                ReceiptEventKind::ModelCalled,
                &[
                    ("answer_path", ANSWER_PATH_MODEL),
                    ("lookup_refusal", "truncated"),
                    ("provider", "openai"),
                    ("input_tokens", "10"),
                    ("output_tokens", "4"),
                    ("cost_usd_micros", "12"),
                ],
            )],
        ))
        .unwrap();
        db.insert_operation_receipt(&receipt(
            "non-eligible",
            "alpha",
            50,
            "freeform.chat",
            vec![event(
                "non-eligible",
                "model",
                60,
                ReceiptEventKind::ModelCalled,
                &[
                    ("provider", "ollama"),
                    ("input_tokens", "2"),
                    ("output_tokens", "3"),
                ],
            )],
        ))
        .unwrap();

        let report = query_substitution_report(&db, "local", "alpha", 0, 100).unwrap();
        assert_eq!(report.receipts_considered, 4);
        assert_eq!(report.counts.lookup_hit, 2);
        assert_eq!(report.counts.model_path, 3);
        assert_eq!(report.counts.lookup_refusal, 1);
        assert_eq!(report.non_eligible_model_paths, 1);
        assert_eq!(report.lookup_refusal_reasons["truncated"], 1);
        assert_eq!(report.model_usage.calls, 3);
        assert_eq!(report.model_usage.input_tokens, 13);
        assert_eq!(report.model_usage.output_tokens, 8);
        assert_eq!(report.model_usage.cost_usd_micros, 12);
        assert_eq!(report.model_usage.providers["openai"].priced_calls, 1);
        assert_eq!(report.model_usage.providers["ollama"].unpriced_calls, 1);
        assert_eq!(report.model_usage.providers["mixed-provider"].calls, 1);
        assert_eq!(
            report.by_task_type["sekai.semantic.expand_relations"].lookup_refusal,
            1
        );
    }

    #[test]
    fn namespace_access_is_required_before_receipts_are_read() {
        let db = RuntimeDb::memory();
        db.create_object(&Object {
            id: "namespace-alpha".into(),
            kind: "namespace".into(),
            name: "alpha".into(),
            namespace: String::new(),
            external_id: "namespace:alpha".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_grant(&Grant {
            id: "grant-alpha-alice".into(),
            object_id: "namespace-alpha".into(),
            principal: "alice".into(),
            role: Role::Viewer,
            created: 1,
        })
        .unwrap();
        db.insert_operation_receipt(&receipt(
            "receipt",
            "alpha",
            10,
            "sekai.semantic.resolve_ref",
            vec![],
        ))
        .unwrap();

        assert_eq!(
            query_substitution_report(&db, "mallory", "alpha", 0, 100).unwrap_err(),
            "namespace access denied"
        );
        assert_eq!(
            query_substitution_report(&db, "alice", "alpha", 0, 100)
                .unwrap()
                .receipts_considered,
            1
        );
    }

    #[test]
    fn event_paths_outside_the_window_are_not_counted() {
        let db = RuntimeDb::memory();
        db.insert_operation_receipt(&receipt(
            "outside",
            "alpha",
            10,
            "sekai.semantic.resolve_ref",
            vec![event(
                "outside",
                "outcome",
                200,
                ReceiptEventKind::OutcomeRecorded,
                &[("answer_path", ANSWER_PATH_LOOKUP_HIT)],
            )],
        ))
        .unwrap();
        let report = query_substitution_report(&db, "local", "alpha", 0, 100).unwrap();
        assert_eq!(report.receipts_considered, 1);
        assert_eq!(report.counts.unclassified, 1);
        assert_eq!(report.counts.lookup_hit, 0);
    }
}
