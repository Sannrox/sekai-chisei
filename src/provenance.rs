use std::collections::{BTreeSet, HashMap};

use crate::db::sekai::SekaiDb;
use crate::sekai::audit::Decision;
use crate::sekai::dataset::{RowFilter, RowQuery};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCall {
    pub request_id: String,
    pub timestamp_ms: i64,
    pub provider: String,
    pub requested_model: String,
    pub resolved_model: String,
    pub status: String,
    pub refusal_reason: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cost_usd_micros: i64,
}

#[derive(Debug, Clone)]
pub struct ProvenanceReport {
    pub work_unit_id: String,
    pub calls: Vec<ModelCall>,
    pub decisions: Vec<Decision>,
}

impl ProvenanceReport {
    pub fn total_cost_usd_micros(&self) -> i64 {
        self.calls.iter().map(|call| call.cost_usd_micros).sum()
    }
}

pub fn assemble_report(db: &SekaiDb, work_unit_id: &str) -> Result<ProvenanceReport, String> {
    if work_unit_id.trim().is_empty() {
        return Err("work unit id must not be empty".into());
    }
    let rows = db.query_rows(
        "llm_calls",
        &RowQuery {
            filters: vec![RowFilter {
                column: "work_unit_id".into(),
                op: "eq".into(),
                value: work_unit_id.into(),
            }],
            ..Default::default()
        },
    )?;
    let request_ids = rows
        .iter()
        .filter_map(|row| row.get("request_id"))
        .cloned()
        .collect::<BTreeSet<_>>();
    let decisions = db.list_work_unit_decisions(work_unit_id, &request_ids)?;

    let mut calls = rows.into_iter().map(model_call).collect::<Vec<_>>();
    calls.sort_by_key(|call| call.timestamp_ms);
    Ok(ProvenanceReport {
        work_unit_id: work_unit_id.into(),
        calls,
        decisions,
    })
}

fn model_call(row: HashMap<String, String>) -> ModelCall {
    let value = |key: &str| row.get(key).cloned().unwrap_or_default();
    let number = |key: &str| value(key).parse().unwrap_or(0);
    ModelCall {
        request_id: value("request_id"),
        timestamp_ms: number("timestamp_ms"),
        provider: value("provider"),
        requested_model: value("model"),
        resolved_model: value("resolved_model"),
        status: value("status"),
        refusal_reason: value("refusal_reason"),
        input_tokens: number("input_tokens"),
        output_tokens: number("output_tokens"),
        cost_usd_micros: number("cost_usd_micros"),
    }
}

pub fn render_text(report: &ProvenanceReport) -> String {
    let mut output = format!(
        "Provenance for {}\n\nSummary\n  model calls: {}\n  audit decisions: {}\n  cost: ${:.6}\n\nModel calls\n",
        report.work_unit_id,
        report.calls.len(),
        report.decisions.len(),
        report.total_cost_usd_micros() as f64 / 1_000_000.0,
    );
    for call in &report.calls {
        let model = if call.resolved_model.is_empty() {
            &call.requested_model
        } else {
            &call.resolved_model
        };
        output.push_str(&format!(
            "  {}  provider={} model={} status={} tokens={}/{} cost=${:.6}",
            call.request_id,
            call.provider,
            model,
            call.status,
            call.input_tokens,
            call.output_tokens,
            call.cost_usd_micros as f64 / 1_000_000.0
        ));
        if !call.refusal_reason.is_empty() {
            output.push_str(&format!(" refusal={}", call.refusal_reason));
        }
        output.push('\n');
    }
    output.push_str("\nAudit trail\n");
    for decision in &report.decisions {
        output.push_str(&format!(
            "  {}  actor={} action={} outcome={} reason={}\n",
            decision.id, decision.actor, decision.action, decision.outcome, decision.reason
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::dataset::{ColumnDef, Dataset};

    #[test]
    fn assembles_calls_and_request_linked_decisions() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: "llm_calls".into(),
            name: "LLM calls".into(),
            columns: vec![ColumnDef {
                name: "work_unit_id".into(),
                col_type: "string".into(),
            }],
            object_id: String::new(),
            created: 1,
        })
        .unwrap();
        db.append_rows(
            "llm_calls",
            &[HashMap::from([
                ("request_id".into(), "req-1".into()),
                ("work_unit_id".into(), "task-1".into()),
                ("provider".into(), "anthropic".into()),
                ("resolved_model".into(), "claude".into()),
                ("status".into(), "200".into()),
                ("input_tokens".into(), "10".into()),
                ("output_tokens".into(), "5".into()),
                ("cost_usd_micros".into(), "42".into()),
            ])],
        )
        .unwrap();
        db.record_decision(&Decision {
            id: "dec-1".into(),
            timestamp: 2,
            actor: "gateway".into(),
            action: "gateway.policy".into(),
            reason: "matched".into(),
            evidence: HashMap::from([("request_id".into(), "req-1".into())]),
            target_id: "llm_calls".into(),
            outcome: "allowed".into(),
        })
        .unwrap();

        let report = assemble_report(&db, "task-1").unwrap();
        assert_eq!(report.calls.len(), 1);
        assert_eq!(report.decisions.len(), 1);
        assert_eq!(report.total_cost_usd_micros(), 42);
        assert!(render_text(&report).contains("provider=anthropic model=claude"));
    }

    #[test]
    fn includes_work_unit_budget_warnings() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: "llm_calls".into(),
            name: "LLM calls".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
        })
        .unwrap();
        db.append_rows(
            "llm_calls",
            &[HashMap::from([
                ("request_id".into(), "req-1".into()),
                ("work_unit_id".into(), "task-1".into()),
                ("timestamp_ms".into(), "10".into()),
            ])],
        )
        .unwrap();
        db.record_decision(&Decision {
            id: "warning".into(),
            timestamp: 11,
            actor: "gateway".into(),
            action: "gateway.budget_warning".into(),
            reason: "threshold".into(),
            evidence: HashMap::from([
                ("scope_kind".into(), "work_unit".into()),
                (
                    "budget_subject".into(),
                    "project:p/agent:a/work_unit:task-1".into(),
                ),
            ]),
            target_id: "llm_calls".into(),
            outcome: "warned".into(),
        })
        .unwrap();

        assert_eq!(assemble_report(&db, "task-1").unwrap().decisions.len(), 1);
    }

    #[test]
    fn evidence_matching_is_exact_for_free_form_work_unit_ids() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: "llm_calls".into(),
            name: "LLM calls".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
        })
        .unwrap();
        db.append_rows(
            "llm_calls",
            &[HashMap::from([
                ("request_id".into(), "req".into()),
                ("work_unit_id".into(), "task_%".into()),
            ])],
        )
        .unwrap();
        for (id, key, value) in [
            ("work", "work_unit", "task_%"),
            ("work-id", "work_unit_id", "task_%"),
            ("case-variant", "work_unit", "TASK_%"),
        ] {
            db.record_decision(&Decision {
                id: id.into(),
                timestamp: 1,
                actor: "agent".into(),
                action: "action".into(),
                reason: String::new(),
                evidence: HashMap::from([(key.into(), value.into())]),
                target_id: "object".into(),
                outcome: "allowed".into(),
            })
            .unwrap();
        }

        let report = assemble_report(&db, "task_%").unwrap();
        assert_eq!(
            report
                .decisions
                .iter()
                .map(|d| d.id.as_str())
                .collect::<Vec<_>>(),
            vec!["work", "work-id"]
        );
    }
}
