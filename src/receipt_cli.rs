use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent};
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::GetOperationReceiptRequest;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use std::collections::HashMap;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl receipt <id> [--request-id] [--scope <caller-scope>] [--attempt <number>] [--json]"
}

fn target() -> String {
    std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".to_string())
}

pub async fn run_receipt_command(args: Vec<String>) -> Result<(), BoxErr> {
    let id = args
        .first()
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| std::io::Error::other(usage()))?;
    let mut client = ChiseiServiceClient::new(connect_sekai(&target()).await?);
    let by_request_id = args.iter().any(|arg| arg == "--request-id");
    let caller_scope = args
        .windows(2)
        .find(|pair| pair[0] == "--scope")
        .map(|pair| pair[1].clone())
        .unwrap_or_default();
    let attempt = args
        .windows(2)
        .find(|pair| pair[0] == "--attempt")
        .map(|pair| pair[1].parse::<u32>())
        .transpose()?
        .unwrap_or_default();
    let response = client
        .get_operation_receipt(GetOperationReceiptRequest {
            operation_id: if by_request_id {
                String::new()
            } else {
                id.clone()
            },
            request_id: if by_request_id {
                id.clone()
            } else {
                String::new()
            },
            caller_scope,
            attempt,
        })
        .await?
        .into_inner();
    let receipt: OperationReceipt = serde_json::from_str(&response.receipt_json)?;
    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&receipt)?);
    } else {
        print!("{}", render_receipt(&receipt));
    }
    Ok(())
}

pub fn render_receipt(receipt: &OperationReceipt) -> String {
    let completeness = receipt.completeness();
    let mut out = String::new();
    out.push_str(&format!("operation: {}\n", receipt.operation_id));
    out.push_str(&format!("version: {}\n", receipt.version));
    out.push_str(&format!("namespace: {}\n", receipt.namespace));
    out.push_str(&format!("class: {}\n", receipt.operation_class));
    out.push_str(&format!("actor: {}\n", receipt.initiating_actor));
    out.push_str(&format!("complete: {}\n", completeness.complete));
    if !completeness.missing_surfaces.is_empty() {
        out.push_str(&format!(
            "missing: {}\n",
            completeness
                .missing_surfaces
                .iter()
                .map(|surface| surface.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for uncovered in &receipt.uncovered_surfaces {
        out.push_str(&format!(
            "uncovered: {} ({})\n",
            uncovered.surface.as_str(),
            uncovered.reason
        ));
    }
    out.push_str("events:\n");
    let by_id = receipt
        .events
        .iter()
        .map(|event| (event.event_id.as_str(), event))
        .collect::<HashMap<_, _>>();
    let mut events = receipt.events.iter().collect::<Vec<_>>();
    events.sort_by_key(|event| {
        (
            causal_depth(event, &by_id),
            event.timestamp_ms,
            event.event_id.as_str(),
        )
    });
    for event in events {
        out.push_str(&format!(
            "  - {} [{}] actor={} at={}\n",
            event.event_id,
            event.kind.as_str(),
            event.actor,
            event.timestamp_ms
        ));
        if let Some(parent) = &event.parent_event_id {
            out.push_str(&format!("    parent: {parent}\n"));
        }
        for (key, value) in &event.attributes {
            out.push_str(&format!("    {key}: {value}\n"));
        }
        for reference in &event.references {
            out.push_str(&format!(
                "    reference: {} {}{}\n",
                reference.kind,
                reference.reference,
                if reference.omitted {
                    " (content omitted)"
                } else {
                    ""
                }
            ));
        }
    }
    out
}

fn causal_depth(
    event: &OperationReceiptEvent,
    events: &HashMap<&str, &OperationReceiptEvent>,
) -> usize {
    let mut depth = 0;
    let mut parent = event.parent_event_id.as_deref();
    let mut remaining = events.len();
    while let Some(parent_id) = parent {
        if remaining == 0 {
            break;
        }
        remaining -= 1;
        depth += 1;
        parent = events
            .get(parent_id)
            .and_then(|event| event.parent_event_id.as_deref());
    }
    depth
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{OPERATION_RECEIPT_VERSION, ReceiptEventKind, ReceiptSurface};
    use std::collections::BTreeMap;

    #[test]
    fn renderer_orders_events_by_causality() {
        let event =
            |id: &str, parent: Option<&str>, kind: ReceiptEventKind| OperationReceiptEvent {
                event_id: id.into(),
                operation_id: "op-1".into(),
                parent_event_id: parent.map(str::to_string),
                timestamp_ms: 1,
                kind,
                surface: kind.surface(),
                actor: "local".into(),
                references: vec![],
                attributes: BTreeMap::new(),
            };
        let receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: "op-1".into(),
            parent_operation_id: None,
            namespace: "default".into(),
            operation_class: "test".into(),
            initiating_actor: "local".into(),
            schema_version: "v1".into(),
            policy_version: "v1".into(),
            started_at_ms: 1,
            completed_at_ms: Some(1),
            events: vec![
                event("outcome", Some("intent"), ReceiptEventKind::OutcomeRecorded),
                event("intent", None, ReceiptEventKind::IntentRecorded),
            ],
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
            ontology_digest: None,
        };
        let rendered = render_receipt(&receipt);
        assert!(rendered.find("intent [").unwrap() < rendered.find("outcome [").unwrap());
        assert!(rendered.contains(ReceiptSurface::Outcome.as_str()));
    }
}
