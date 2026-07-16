use crate::chisei::receipt::OperationReceipt;
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::GetOperationReceiptRequest;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::operation_report::{ClaimState, OperationReport};
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl report <operation-id> [--attempt <number>] [--output <file>] [--json]"
}

pub async fn run_report_command(args: Vec<String>) -> Result<(), BoxErr> {
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
    let report =
        OperationReport::from_receipt(&serde_json::from_str::<OperationReceipt>(&receipt_json)?);
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

fn claim(state: &ClaimState) -> &'static str {
    match state {
        ClaimState::NotVerified => "not_verified",
        ClaimState::Verified => "verified",
        ClaimState::Failed => "failed",
    }
}
fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
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
            claims: AssuranceClaims {
                evidence_complete: false,
                integrity: ClaimState::NotVerified,
                policy_compliance: ClaimState::Failed,
            },
            sections: BTreeMap::new(),
            missing_surfaces: vec![],
            uncovered_surfaces: vec![],
            structural_errors: vec![],
        };
        let rendered = render_report(&report);
        assert!(rendered.contains("evidence_complete: false"));
        assert!(rendered.contains("integrity: not_verified"));
        assert!(rendered.contains("policy_compliance: failed"));
    }
}
