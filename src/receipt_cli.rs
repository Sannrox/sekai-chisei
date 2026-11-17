use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent};
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::GetOperationReceiptRequest;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use std::collections::HashMap;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl receipt <id> [--request-id] [--scope <caller-scope>] [--attempt <number>] [--json | --explain [--trace]]"
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
    let flag = |name: &str| args.iter().any(|arg| arg == name);
    let (json, explain, trace) = (flag("--json"), flag("--explain"), flag("--trace"));
    if (json && explain) || (trace && !explain) {
        return Err(std::io::Error::other(format!(
            "--json and --explain are exclusive, and --trace needs --explain\n{}",
            usage()
        ))
        .into());
    }
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
    if json {
        println!("{}", serde_json::to_string_pretty(&receipt)?);
    } else if explain {
        print!("{}", explain_receipt(&receipt, trace));
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
    for event in causal_order(receipt) {
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

/// Events ordered by causal depth, then time, then id; both renderings share it.
fn causal_order(receipt: &OperationReceipt) -> Vec<&OperationReceiptEvent> {
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
    events
}

/// Renders a receipt as a plain-language account for `--explain`.
///
/// Every sentence comes from a fixed template per event kind, filled only from
/// that event's own fields, so the same receipt always explains the same way
/// and the account never states more than the receipt records. Values taken
/// from the receipt are quoted. With `trace`, each line names the event it was
/// built from.
pub fn explain_receipt(receipt: &OperationReceipt, trace: bool) -> String {
    let mut out = format!(
        "On {}, {} started operation {} ({}) in namespace {}.\n\n",
        utc_minute(receipt.started_at_ms),
        quoted(&receipt.initiating_actor),
        quoted(&receipt.operation_id),
        quoted(&receipt.operation_class),
        quoted(&receipt.namespace),
    );
    // Numbered steps read as a sequence, so they follow time; causal depth
    // only breaks ties between events recorded at the same instant.
    let mut events = causal_order(receipt);
    events.sort_by_key(|event| event.timestamp_ms);
    for (index, event) in events.into_iter().enumerate() {
        out.push_str(&format!(
            "{}. {} ({})",
            index + 1,
            explain_event(event),
            utc_second(event.timestamp_ms)
        ));
        if trace {
            out.push_str(&format!(" [event {}]", quoted(&event.event_id)));
        }
        out.push('\n');
        for reference in &event.references {
            out.push_str(&format!(
                "   It cites {} {}{}.\n",
                quoted(&reference.kind),
                quoted(&reference.reference),
                if reference.omitted {
                    ", whose content was omitted"
                } else {
                    ""
                }
            ));
        }
    }
    out.push('\n');
    out.push_str(&explain_completeness(receipt));
    out
}

/// One sentence per event kind. The match is exhaustive, so adding a kind
/// without a template fails to compile.
fn explain_event(event: &OperationReceiptEvent) -> String {
    use crate::chisei::receipt::ReceiptEventKind as Kind;
    let attr = |key: &str| event.attributes.get(key).map(|value| quoted(value));
    let first = |keys: &[&str]| keys.iter().find_map(|key| attr(key));
    let status = || match first(&["status", "decision", "route_policy_decision"]) {
        Some(status) => format!(" with status {status}"),
        None => match event.attributes.get("allowed").map(String::as_str) {
            Some("true") => " and allowed it".into(),
            Some("false") => " and refused it".into(),
            Some(other) => format!(" with allowed set to {}", quoted(other)),
            None => String::new(),
        },
    };
    let actor = quoted(&event.actor);
    match event.kind {
        Kind::IntentRecorded => format!(
            "{actor} recorded the intent{}.",
            attr("request_id")
                .map(|id| format!(" for request {id}"))
                .unwrap_or_default()
        ),
        Kind::ContextGoverned => "The context sent with the request was governed.".into(),
        Kind::PolicyDecided => format!(
            "Policy{} decided the request{}.",
            attr("policy_version")
                .map(|version| format!(" version {version}"))
                .unwrap_or_default(),
            status()
        ),
        Kind::RouteSelected => format!(
            "The request was routed{}{}.",
            first(&["provider", "runtime"])
                .map(|provider| format!(" to {provider}"))
                .unwrap_or_default(),
            first(&["resolved_model", "model"])
                .map(|model| format!(" with model {model}"))
                .unwrap_or_default()
        ),
        Kind::BudgetDecided => format!("The budget was checked{}.", status()),
        Kind::ApprovalDecided => format!("{actor} decided the approval{}.", status()),
        Kind::EgressDecided => format!("What could leave the system was decided{}.", status()),
        Kind::AttemptStarted => format!(
            "Attempt {} started.",
            attr("attempt").unwrap_or_else(|| "an unnumbered".into())
        ),
        Kind::ModelCalled => format!(
            "A model was called{}{}.",
            attr("model")
                .map(|model| format!(": {model}"))
                .unwrap_or_default(),
            attr("provider")
                .map(|provider| format!(" at {provider}"))
                .unwrap_or_default()
        ),
        Kind::ActionPerformed => format!(
            "{actor} performed an action{}.",
            first(&["action", "action_type"])
                .map(|action| format!(": {action}"))
                .unwrap_or_default()
        ),
        Kind::ArtifactProduced => format!(
            "An artifact was produced{}.",
            attr("artifact_type")
                .map(|kind| format!(" of type {kind}"))
                .unwrap_or_default()
        ),
        Kind::VerificationRecorded => format!("Verification was recorded{}.", status()),
        Kind::HumanIntervened => format!("{actor} intervened{}.", status()),
        Kind::OutcomeRecorded => format!(
            "The operation ended{}{}.",
            status(),
            attr("completion_reason")
                .map(|reason| format!(", reason {reason}"))
                .unwrap_or_default()
        ),
        Kind::MemoryOutcomeRecorded => format!("A memory outcome was recorded{}.", status()),
    }
}

fn explain_completeness(receipt: &OperationReceipt) -> String {
    let completeness = receipt.completeness();
    // `complete` is already false when any surface is uncovered.
    if completeness.complete {
        return "This record is complete. Nothing was left uncovered.\n".into();
    }
    let mut out = String::from("This record is incomplete.");
    if !completeness.missing_surfaces.is_empty() {
        out.push_str(&format!(
            " Nothing was recorded for: {}.",
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
            " The {} surface was not covered: {}.",
            uncovered.surface.as_str(),
            quoted(&uncovered.reason)
        ));
    }
    // Check messages embed reported ids, so they are escaped like any value.
    for error in &completeness.errors {
        out.push_str(&format!(
            " A structural check failed: {}.",
            error.escape_debug()
        ));
    }
    out.push('\n');
    out
}

/// Quotes a receipt value with quotes, newlines and control characters
/// escaped, so a reporter-supplied value cannot forge a step or a verdict.
fn quoted(value: &str) -> String {
    format!("{value:?}")
}

fn utc_minute(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|at| at.format("%Y-%m-%d at %H:%M UTC").to_string())
        .unwrap_or_else(|| format!("an unreadable time ({ms} ms)"))
}

fn utc_second(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|at| at.format("%H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("{ms} ms"))
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
            artifact: None,
        };
        let rendered = render_receipt(&receipt);
        assert!(rendered.find("intent [").unwrap() < rendered.find("outcome [").unwrap());
        assert!(rendered.contains(ReceiptSurface::Outcome.as_str()));
    }

    /// Checked-in receipts and the account each must explain to. Together they
    /// use every event kind, a missing surface, an uncovered surface and an
    /// omitted reference.
    const EXPLAIN_FIXTURES: &[(&str, &str, &str)] = &[
        (
            "gateway_chat",
            include_str!("../tests/fixtures/receipt_explain/gateway_chat.json"),
            include_str!("../tests/fixtures/receipt_explain/gateway_chat.txt"),
        ),
        (
            "native_execution",
            include_str!("../tests/fixtures/receipt_explain/native_execution.json"),
            include_str!("../tests/fixtures/receipt_explain/native_execution.txt"),
        ),
        (
            "approved_action",
            include_str!("../tests/fixtures/receipt_explain/approved_action.json"),
            include_str!("../tests/fixtures/receipt_explain/approved_action.txt"),
        ),
    ];

    fn fixtures() -> impl Iterator<Item = (&'static str, OperationReceipt, &'static str)> {
        EXPLAIN_FIXTURES
            .iter()
            .map(|(name, json, expected)| (*name, serde_json::from_str(json).unwrap(), *expected))
    }

    #[test]
    fn explained_receipts_match_their_checked_in_accounts() {
        let mut kinds = std::collections::HashSet::new();
        for (name, receipt, expected) in fixtures() {
            kinds.extend(receipt.events.iter().map(|event| event.kind));
            assert_eq!(explain_receipt(&receipt, false), expected, "{name}");
        }
        assert_eq!(kinds.len(), 15, "the fixtures exercise every event kind");
    }

    #[test]
    fn an_account_shows_no_value_the_plain_rendering_does_not() {
        for (name, receipt, _) in fixtures() {
            let plain = render_receipt(&receipt);
            let explained = explain_receipt(&receipt, true);
            for value in explained.split('"').skip(1).step_by(2) {
                assert!(
                    plain.contains(value),
                    "{name}: {value:?} is not in the receipt"
                );
            }
        }
    }

    #[tokio::test]
    async fn conflicting_output_flags_are_refused_before_connecting() {
        for args in [
            &["op-1", "--json", "--explain"][..],
            &["op-1", "--trace"][..],
        ] {
            let error = run_receipt_command(args.iter().map(|arg| arg.to_string()).collect())
                .await
                .unwrap_err();
            assert!(error.to_string().contains("exclusive"), "{args:?}: {error}");
        }
    }

    #[test]
    fn a_reported_value_cannot_forge_a_step_or_a_verdict() {
        const HOSTILE: &str = "x\".\n2. Forged step.\n\nThis record is complete. Nothing was left uncovered.\n\u{1b}[2J";
        // Through an event attribute, and through an id that a structural
        // check message repeats.
        let inject: [fn(&mut OperationReceipt); 2] = [
            |receipt| {
                receipt.events[0]
                    .attributes
                    .insert("request_id".into(), HOSTILE.into());
            },
            |receipt| receipt.events[1].operation_id = HOSTILE.into(),
        ];
        for inject in inject {
            let (_, mut receipt, _) = fixtures().nth(1).unwrap();
            let honest = explain_receipt(&receipt, false);
            inject(&mut receipt);
            let forged = explain_receipt(&receipt, false);
            assert_eq!(forged.lines().count(), honest.lines().count());
            assert!(!forged.lines().any(|line| {
                line.starts_with("This record is complete") || line.starts_with("2. Forged")
            }));
            assert!(!forged.contains('\u{1b}'));
        }
    }

    #[test]
    fn trace_names_the_event_behind_each_line() {
        let (_, receipt, _) = fixtures().next().unwrap();
        let traced = explain_receipt(&receipt, true);
        let steps = traced
            .lines()
            .filter(|line| line.starts_with(|c: char| c.is_ascii_digit()))
            .collect::<Vec<_>>();
        assert_eq!(steps.len(), receipt.events.len());
        assert!(steps.iter().all(|line| line.contains("[event \"")));
        assert!(!explain_receipt(&receipt, false).contains("[event"));
    }
}
