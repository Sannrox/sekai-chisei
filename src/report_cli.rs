use crate::chisei::receipt::OperationReceipt;
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::GetOperationReceiptRequest;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::operation_report::{ClaimState, OperationReport, OperationSummary};
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl report <operation-id> [--attempt <number>] [--output <file>] [--json]\n  sekaictl report substitution --namespace <name> --since-ms <time> --until-ms <time> [--principal <name>] [--output <file>] [--json]\n  sekaictl report summary <report.json>... --since-ms <time> --until-ms <time> [--namespace <name>] [--output <file>]\n  sekaictl report bundle <operation-id> --output <bundle> [attest export options]\n  sekaictl report verify <bundle> [attest verify options]"
}

pub async fn run_report_command(args: Vec<String>) -> Result<(), BoxErr> {
    if args.first().is_some_and(|arg| arg == "substitution") {
        return substitution_report(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "summary") {
        return summarize(&args[1..]);
    }
    if matches!(args.first().map(String::as_str), Some("bundle" | "verify")) {
        return crate::attest_cli::run_attest_command(attest_args(args).expect("matched command"))
            .await;
    }
    let operation_id = args
        .first()
        .filter(|arg| !arg.starts_with('-'))
        .ok_or_else(|| std::io::Error::other(usage()))?
        .clone();
    let attempt = flag(&args, "--attempt")
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or_default();
    let target = std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".into());
    let receipt_json = ChiseiServiceClient::new(connect_sekai(&target).await?)
        .get_operation_receipt(GetOperationReceiptRequest {
            operation_id,
            request_id: String::new(),
            caller_scope: String::new(),
            attempt,
        })
        .await?
        .into_inner()
        .receipt_json;
    let report = OperationReport::from_authorized_receipt(
        &serde_json::from_str::<OperationReceipt>(&receipt_json)?,
    );
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(output) = flag(&args, "--output").map(PathBuf::from) {
        std::fs::write(&output, format!("{json}\n"))?;
        println!("created {}", output.display());
    } else if args.iter().any(|arg| arg == "--json") {
        println!("{json}");
    } else {
        print!("{}", render_report(&report));
    }
    Ok(())
}

fn substitution_report(args: &[String]) -> Result<(), BoxErr> {
    let namespace = flag(args, "--namespace")
        .ok_or_else(|| std::io::Error::other("--namespace is required"))?;
    let since_ms = flag(args, "--since-ms")
        .ok_or_else(|| std::io::Error::other("--since-ms is required"))?
        .parse::<i64>()?;
    let until_ms = flag(args, "--until-ms")
        .ok_or_else(|| std::io::Error::other("--until-ms is required"))?
        .parse::<i64>()?;
    let config = crate::config::Config::from_env();
    let backend_config = crate::runtime_backend::RuntimeBackendConfig::from_env(&config.db_path)
        .map_err(std::io::Error::other)?;
    let backend = crate::runtime_backend::RuntimeBackend::initialize(backend_config)
        .map_err(std::io::Error::other)?;
    let database = backend.database();
    let principal = report_principal(args, database.as_ref())?;
    let report = crate::substitution_report::query_substitution_report(
        database.as_ref(),
        &principal,
        &namespace,
        since_ms,
        until_ms,
    )
    .map_err(std::io::Error::other)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(output) = flag(args, "--output") {
        std::fs::write(&output, format!("{json}\n"))?;
        println!("created {output}");
    } else if args.iter().any(|arg| arg == "--json") {
        println!("{json}");
    } else {
        print!("{}", render_substitution_report(&report));
    }
    Ok(())
}

fn report_principal(
    args: &[String],
    db: &crate::db::runtime_db::RuntimeDb,
) -> Result<String, BoxErr> {
    let requested = flag(args, "--principal")
        .or_else(|| std::env::var("SEKAI_PRINCIPAL").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let credential_token = std::env::var("SEKAI_CREDENTIAL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let Some(token) = credential_token else {
        if let Some(principal) = requested.as_deref()
            && principal != "local"
        {
            return Err(std::io::Error::other(
                "--principal requires a valid SEKAI_CREDENTIAL; local is the only unauthenticated CLI principal",
            )
            .into());
        }
        return Ok("local".into());
    };

    let store = crate::sekai::credentials::PrincipalCredentialStore::new();
    if !store.maybe_reload(db) {
        return Err(std::io::Error::other("SEKAI_CREDENTIAL could not be authenticated").into());
    }
    let authenticated = store
        .resolve(&token)
        .ok_or_else(|| std::io::Error::other("SEKAI_CREDENTIAL could not be authenticated"))?;
    if let Some(requested) = requested
        && requested != authenticated.principal
    {
        return Err(std::io::Error::other(
            "--principal does not match the authenticated SEKAI_CREDENTIAL principal",
        )
        .into());
    }
    Ok(authenticated.principal)
}

fn render_substitution_report(report: &crate::substitution_report::SubstitutionReport) -> String {
    let mut out = format!(
        "namespace: {}\nwindow: [{}..{})\nreceipts_considered: {}\nlookup_hit: {}\nmodel_path: {}\nlookup_refusal: {}\nunclassified: {}\nnon_eligible_model_paths: {}\n",
        text_value(&report.namespace),
        report.since_ms,
        report.until_ms,
        report.receipts_considered,
        report.counts.lookup_hit,
        report.counts.model_path,
        report.counts.lookup_refusal,
        report.counts.unclassified,
        report.non_eligible_model_paths,
    );
    for (reason, count) in &report.lookup_refusal_reasons {
        out.push_str(&format!(
            "lookup_refusal_reason: {}={count}\n",
            text_value(reason)
        ));
    }
    out.push_str(&format!(
        "model_calls: {}\ninput_tokens: {}\noutput_tokens: {}\ntotal_tokens: {}\ncost_usd_micros: {}\n",
        report.model_usage.calls,
        report.model_usage.input_tokens,
        report.model_usage.output_tokens,
        report.model_usage.total_tokens,
        report.model_usage.cost_usd_micros,
    ));
    for (provider, usage) in &report.model_usage.providers {
        out.push_str(&format!(
            "provider: {} calls={} input_tokens={} output_tokens={} cost_usd_micros={}\n",
            text_value(provider),
            usage.calls,
            usage.input_tokens,
            usage.output_tokens,
            usage.cost_usd_micros
        ));
    }
    for (task_type, summary) in &report.by_task_type {
        out.push_str(&format!(
            "task_type: {} receipts={} lookup_hit={} model_path={} lookup_refusal={} non_eligible_model_path={}\n",
            text_value(task_type),
            summary.receipts,
            summary.lookup_hit,
            summary.model_path,
            summary.lookup_refusal,
            summary.non_eligible_model_path,
        ));
        for (reason, count) in &summary.lookup_refusal_reasons {
            out.push_str(&format!(
                "  task_type_lookup_refusal_reason: {}={count}\n",
                text_value(reason)
            ));
        }
    }
    out
}

fn summarize(args: &[String]) -> Result<(), BoxErr> {
    let since_ms = flag(args, "--since-ms")
        .ok_or_else(|| std::io::Error::other("--since-ms is required"))?
        .parse()?;
    let until_ms = flag(args, "--until-ms")
        .ok_or_else(|| std::io::Error::other("--until-ms is required"))?
        .parse()?;
    let paths = positional_values(args);
    if paths.is_empty() {
        return Err(std::io::Error::other("at least one report artifact is required").into());
    }
    let reports = paths
        .iter()
        .map(|path| -> Result<OperationReport, BoxErr> {
            Ok(serde_json::from_slice(&std::fs::read(path)?)?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let namespace = flag(args, "--namespace");
    let json = serde_json::to_string_pretty(&OperationSummary::from_reports(
        &reports,
        namespace.as_deref(),
        since_ms,
        until_ms,
    ))?;
    if let Some(output) = flag(args, "--output") {
        std::fs::write(&output, format!("{json}\n"))?;
        println!("created {output}");
    } else {
        println!("{json}");
    }
    Ok(())
}

fn positional_values(args: &[String]) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index].starts_with('-') {
            index += 2;
        } else {
            values.push(args[index].clone());
            index += 1;
        }
    }
    values
}

pub fn render_report(report: &OperationReport) -> String {
    let mut out = format!(
        "operation: {}\nnamespace: {}\nclass: {}\nactor: {}\nstarted_at_ms: {}\n",
        report.operation_id,
        report.namespace,
        report.operation_class,
        report.initiating_actor,
        report.started_at_ms
    );
    if let Some(value) = report.completed_at_ms {
        out.push_str(&format!("completed_at_ms: {value}\n"));
    }
    if let Some(value) = report.duration_ms {
        out.push_str(&format!("latency_ms: {value}\n"));
    }
    out.push_str(&format!(
        "evidence_complete: {}\nintegrity: {}\npolicy_compliance: {}\n",
        report.claims.evidence_complete,
        claim(&report.claims.integrity),
        claim(&report.claims.policy_compliance)
    ));
    for evidence in &report.external_evidence_versions {
        out.push_str(&format!(
            "external_evidence: {}@{} digest={} event={}\n",
            text_value(&evidence.submission_id),
            text_value(&evidence.source_version),
            text_value(&evidence.content_digest),
            text_value(&evidence.receipt_event_id)
        ));
    }
    for surface in &report.missing_surfaces {
        out.push_str(&format!("missing_surface: {}\n", surface.as_str()));
    }
    for gap in &report.uncovered_surfaces {
        out.push_str(&format!(
            "coverage_gap: {} ({})\n",
            gap.surface.as_str(),
            gap.reason
        ));
    }
    for error in &report.structural_errors {
        out.push_str(&format!("structural_error: {error}\n"));
    }
    out.push_str("causal_operation:\n");
    for (stage, value) in causal_operation_view(report) {
        out.push_str(&format!("  {stage}: {}\n", text_value(&value)));
    }
    out.push_str("evidence:\n");
    for (surface, events) in &report.sections {
        out.push_str(&format!("  {surface}:\n"));
        for event in events {
            out.push_str(&format!(
                "    - {} [{}] actor={} at={}\n",
                event.event_id, event.kind, event.actor, event.timestamp_ms
            ));
            for (key, value) in &event.attributes {
                out.push_str(&format!("      {key}: {value}\n"));
            }
            for reference in &event.references {
                out.push_str(&format!(
                    "      reference: {} {}{}\n",
                    reference.kind,
                    reference.reference,
                    if reference.omitted { " (omitted)" } else { "" }
                ));
            }
        }
    }
    out
}

/// Project the agent-facing causal path without claiming that an absent event
/// occurred. Values come only from the authorized receipt projection.
pub fn causal_operation_view(report: &OperationReport) -> Vec<(&'static str, String)> {
    let attribute = |surface: &str, key: &str| {
        report
            .sections
            .get(surface)
            .and_then(|events| events.iter().find_map(|event| event.attributes.get(key)))
            .cloned()
    };
    let has_surface = |surface: &str| report.sections.get(surface).is_some_and(|v| !v.is_empty());
    let outcome = attribute("outcome", "outcome").unwrap_or_else(|| "not_reported".into());
    let approval = attribute("approval", "decision")
        .or_else(|| {
            (outcome == "approval_required").then(|| {
                let id = attribute("outcome", "approval_id").unwrap_or_else(|| "unknown".into());
                format!("required:{id}")
            })
        })
        .unwrap_or_else(|| "not_required_or_not_reported".into());
    vec![
        (
            "discovered_catalog",
            attribute("intent", "reported_catalog_version")
                .unwrap_or_else(|| "not_reported".into()),
        ),
        (
            "selected_capability",
            attribute("intent", "capability").unwrap_or_else(|| "not_reported".into()),
        ),
        ("requested_operation", report.operation_id.clone()),
        (
            "policy_decision",
            attribute("policy", "decision").unwrap_or_else(|| "not_reached".into()),
        ),
        ("approval_or_permit", approval),
        (
            "invocation",
            if has_surface("attempt") || has_surface("action") {
                "executed".into()
            } else if outcome == "succeeded" {
                "completed_by_native_rpc".into()
            } else {
                "not_executed".into()
            },
        ),
        (
            "action_or_evidence",
            if has_surface("action") || has_surface("artifact") {
                "recorded".into()
            } else {
                "not_reported".into()
            },
        ),
        (
            "verification",
            if has_surface("verification") {
                "recorded".into()
            } else {
                "not_reported".into()
            },
        ),
        ("outcome", outcome),
    ]
}

fn claim(state: &ClaimState) -> &'static str {
    match state {
        ClaimState::NotVerified => "not_verified",
        ClaimState::Verified => "verified",
        ClaimState::Failed => "failed",
    }
}

fn text_value(value: &str) -> String {
    serde_json::to_string(value).expect("strings are always JSON serializable")
}
fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn attest_args(args: Vec<String>) -> Option<Vec<String>> {
    let command = match args.first()?.as_str() {
        "bundle" => "export",
        "verify" => "verify",
        _ => return None,
    };
    Some(
        std::iter::once(command.to_string())
            .chain(args.into_iter().skip(1))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation_report::{AssuranceClaims, OPERATION_REPORT_VERSION};
    use std::collections::BTreeMap;
    #[test]
    fn text_report_keeps_assurance_claims_distinct() {
        let report = OperationReport {
            version: OPERATION_REPORT_VERSION.into(),
            source_receipt_version: "operation.receipt/v1".into(),
            operation_id: "op-1".into(),
            parent_operation_id: None,
            namespace: "team".into(),
            operation_class: "analysis".into(),
            initiating_actor: "alice".into(),
            schema_version: "v1".into(),
            policy_version: "v1".into(),
            started_at_ms: 1,
            completed_at_ms: Some(3),
            duration_ms: Some(2),
            governance: crate::operation_report::GovernanceProjection {
                authorization_enforced_at_source: true,
                receipt_disclosures_only: true,
                retention_redactions: 0,
                tombstone_redactions: 0,
            },
            claims: AssuranceClaims {
                evidence_complete: false,
                integrity: ClaimState::NotVerified,
                policy_compliance: ClaimState::Failed,
            },
            external_evidence_versions: vec![],
            sections: BTreeMap::new(),
            missing_surfaces: vec![],
            uncovered_surfaces: vec![],
            structural_errors: vec![],
        };
        let rendered = render_report(&report);
        assert!(rendered.contains("evidence_complete: false"));
        assert!(rendered.contains("integrity: not_verified"));
        assert!(rendered.contains("policy_compliance: failed"));
        assert!(rendered.contains("causal_operation:"));
        assert!(rendered.contains("outcome: \"not_reported\""));
    }

    #[test]
    fn causal_view_distinguishes_success_from_denial() {
        use crate::operation_report::ReportEvent;
        let event = |kind: &str, attributes: &[(&str, &str)]| ReportEvent {
            event_id: kind.into(),
            parent_event_id: None,
            timestamp_ms: 1,
            kind: kind.into(),
            actor: "host:test".into(),
            attributes: attributes
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
            references: vec![],
        };
        let mut report = OperationReport {
            version: OPERATION_REPORT_VERSION.into(),
            source_receipt_version: "operation.receipt/v1".into(),
            operation_id: "op-success".into(),
            parent_operation_id: None,
            namespace: "team".into(),
            operation_class: "catalog_invocation".into(),
            initiating_actor: "host:test".into(),
            schema_version: "1.0".into(),
            policy_version: "live_invocation_check".into(),
            started_at_ms: 1,
            completed_at_ms: Some(2),
            duration_ms: Some(1),
            governance: Default::default(),
            claims: AssuranceClaims {
                evidence_complete: true,
                integrity: ClaimState::NotVerified,
                policy_compliance: ClaimState::NotVerified,
            },
            external_evidence_versions: vec![],
            sections: BTreeMap::from([
                (
                    "intent".into(),
                    vec![event(
                        "intent_recorded",
                        &[
                            ("reported_catalog_version", "sha256:catalog"),
                            ("capability", "sekai.actions.set_property"),
                        ],
                    )],
                ),
                (
                    "policy".into(),
                    vec![event("policy_decided", &[("decision", "allow")])],
                ),
                (
                    "outcome".into(),
                    vec![event("outcome_recorded", &[("outcome", "succeeded")])],
                ),
            ]),
            missing_surfaces: vec![],
            uncovered_surfaces: vec![],
            structural_errors: vec![],
        };
        let success = causal_operation_view(&report);
        assert!(success.contains(&("discovered_catalog", "sha256:catalog".into())));
        assert!(success.contains(&("invocation", "completed_by_native_rpc".into())));
        report.operation_id = "op-denied".into();
        report.sections.get_mut("policy").unwrap()[0]
            .attributes
            .insert("decision".into(), "deny".into());
        report.sections.get_mut("outcome").unwrap()[0]
            .attributes
            .insert("outcome".into(), "denied".into());
        let denied = causal_operation_view(&report);
        assert!(denied.contains(&("policy_decision", "deny".into())));
        assert!(denied.contains(&("invocation", "not_executed".into())));
    }

    #[test]
    fn report_bundle_and_verify_reuse_attestation_commands() {
        assert_eq!(
            attest_args(vec!["bundle".into(), "op-1".into()]).unwrap(),
            vec!["export", "op-1"]
        );
        assert_eq!(
            attest_args(vec!["verify".into(), "bundle.json".into()]).unwrap(),
            vec!["verify", "bundle.json"]
        );
    }

    #[test]
    fn text_report_escapes_untrusted_evidence_identifiers() {
        let mut report = OperationReport {
            version: OPERATION_REPORT_VERSION.into(),
            source_receipt_version: "operation.receipt/v1".into(),
            operation_id: "op-1".into(),
            parent_operation_id: None,
            namespace: "team".into(),
            operation_class: "analysis".into(),
            initiating_actor: "alice".into(),
            schema_version: "v1".into(),
            policy_version: "v1".into(),
            started_at_ms: 1,
            completed_at_ms: Some(3),
            duration_ms: Some(2),
            governance: Default::default(),
            claims: AssuranceClaims {
                evidence_complete: true,
                integrity: ClaimState::NotVerified,
                policy_compliance: ClaimState::NotVerified,
            },
            external_evidence_versions: vec![],
            sections: BTreeMap::new(),
            missing_surfaces: vec![],
            uncovered_surfaces: vec![],
            structural_errors: vec![],
        };
        report
            .external_evidence_versions
            .push(crate::operation_report::ExternalEvidenceVersion {
                submission_id: "submission-1".into(),
                source_version: "attempt-1\npolicy_compliance: verified".into(),
                content_digest: "abc".into(),
                disclosed_fields: vec![],
                receipt_event_id: "context".into(),
            });
        let rendered = render_report(&report);
        assert!(rendered.contains(r#""attempt-1\npolicy_compliance: verified""#));
        assert_eq!(
            rendered
                .lines()
                .filter(|line| line.starts_with("external_evidence:"))
                .count(),
            1
        );
    }
}
