use crate::sdk::{ConformanceProfile, EvidenceDraft};
use sekai_chisei::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
    ReceiptSurface, UncoveredSurface,
};
use sekai_chisei::grpc::pb::sekai::EvidenceCausality;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const HARNESS_PROFILE: &str = "chisei.responses-harness/v1";
pub const MAX_SSE_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_STREAM_BYTES: usize = 16 * MAX_SSE_FRAME_BYTES;
pub const EVIDENCE_TYPE: &str = "verification.result";
pub const CONFORMANCE_PROFILE: ConformanceProfile = ConformanceProfile {
    source_type: "native_harness",
    evidence_type: EVIDENCE_TYPE,
    signal: "verification",
    schema_id: "adapter.batch_harness.outcome",
    schema_version: "1.0.0",
    delivery: "batch",
    requires_expiry: false,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchHarnessResult {
    pub terminal: String,
    pub text: String,
    pub tool_calls: BTreeMap<u64, BatchToolCall>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub unknown_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchToolCall {
    pub item_id: String,
    pub call_id: String,
    pub name: String,
    pub output_index: u64,
    pub arguments: String,
}

#[derive(Debug, Clone, Copy)]
pub struct BatchReceiptContext<'a> {
    pub operation_id: &'a str,
    pub namespace: &'a str,
    pub operation_class: &'a str,
    pub actor: &'a str,
    pub policy_version: &'a str,
    pub verification_passed: Option<bool>,
    pub started_at_ms: i64,
    pub completed_at_ms: i64,
}

#[derive(Debug, Clone)]
struct WireEvent {
    event: String,
    data: Value,
}

struct OutputAssembly<'a> {
    text_by_position: &'a mut BTreeMap<(u64, u64), String>,
    content_kinds: &'a mut BTreeMap<(u64, u64), &'static str>,
    completed_content: &'a mut BTreeSet<(u64, u64)>,
    tool_calls: &'a mut BTreeMap<u64, BatchToolCall>,
    item_indexes: &'a mut BTreeMap<String, u64>,
    item_kinds: &'a mut BTreeMap<String, String>,
    item_statuses: &'a mut BTreeMap<String, String>,
    completed_items: &'a mut BTreeSet<String>,
    pending_arguments: &'a mut BTreeMap<String, String>,
    call_ids: &'a mut BTreeSet<String>,
}

pub fn run_fixture(bytes: &[u8]) -> Result<BatchHarnessResult, String> {
    if bytes.len() > MAX_STREAM_BYTES {
        return Err("batch harness stream exceeds the size limit".into());
    }
    let events = decode_sse(bytes)?;
    let mut terminal = None;
    let mut text_by_position = BTreeMap::<(u64, u64), String>::new();
    let mut content_kinds = BTreeMap::<(u64, u64), &'static str>::new();
    let mut completed_content = BTreeSet::<(u64, u64)>::new();
    let mut tool_calls = BTreeMap::new();
    let mut item_indexes = BTreeMap::<String, u64>::new();
    let mut item_kinds = BTreeMap::<String, String>::new();
    let mut item_statuses = BTreeMap::<String, String>::new();
    let mut completed_items = BTreeSet::<String>::new();
    let mut pending_arguments = BTreeMap::<String, String>::new();
    let mut call_ids = BTreeSet::<String>::new();
    let mut usage = (None, None);
    let mut unknown_events = 0;
    let mut response_id = None::<String>;
    let mut saw_non_created_event = false;
    for event in events {
        if terminal.is_some() {
            return Err("batch harness received an event after its terminal event".into());
        }
        if event
            .data
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|data_type| data_type != event.event)
        {
            return Err("batch harness SSE event and payload type disagree".into());
        }
        if event.event == "response.created" && saw_non_created_event {
            return Err("batch harness received response.created after response output".into());
        }
        if event.event != "response.created" {
            saw_non_created_event = true;
            validate_response_identity(&event, response_id.as_deref())?;
        }
        match event.event.as_str() {
            "response.created" => {
                let id = event
                    .data
                    .get("response")
                    .ok_or_else(|| "batch harness response.created requires response".to_string())
                    .and_then(|response| required_str(response, "id"))?;
                if response_id.replace(id.into()).is_some() {
                    return Err("batch harness received duplicate response.created".into());
                }
            }
            "response.output_item.added" => {
                let item = event
                    .data
                    .get("item")
                    .ok_or_else(|| "batch harness added output requires item".to_string())?;
                reserve_item(
                    &mut item_indexes,
                    &mut item_kinds,
                    required_str(item, "id")?,
                    required_u64(&event.data, "output_index")?,
                    required_str(item, "type")?,
                )?;
            }
            "response.output_text.delta" | "response.refusal.delta" => {
                let item_id = required_str(&event.data, "item_id")?;
                let index = required_u64(&event.data, "output_index")?;
                reserve_item(
                    &mut item_indexes,
                    &mut item_kinds,
                    item_id,
                    index,
                    "message",
                )?;
                if completed_items.contains(item_id) {
                    return Err("batch harness received text after item completion".into());
                }
                let content_index = optional_u64(&event.data, "content_index")?.unwrap_or(0);
                let kind = if event.event == "response.output_text.delta" {
                    "output_text"
                } else {
                    "refusal"
                };
                append_content(
                    &mut text_by_position,
                    &mut content_kinds,
                    &completed_content,
                    (index, content_index),
                    kind,
                    string_field(&event.data, "delta")?,
                )?;
            }
            "response.output_text.done" | "response.refusal.done" => {
                let item_id = required_str(&event.data, "item_id")?;
                let index = required_u64(&event.data, "output_index")?;
                reserve_item(
                    &mut item_indexes,
                    &mut item_kinds,
                    item_id,
                    index,
                    "message",
                )?;
                if completed_items.contains(item_id) {
                    return Err("batch harness received text after item completion".into());
                }
                let content_index = optional_u64(&event.data, "content_index")?.unwrap_or(0);
                let (kind, field) = if event.event == "response.output_text.done" {
                    ("output_text", "text")
                } else {
                    ("refusal", "refusal")
                };
                finalize_content(
                    &mut text_by_position,
                    &mut content_kinds,
                    &mut completed_content,
                    (index, content_index),
                    kind,
                    string_field(&event.data, field)?,
                )?;
            }
            "response.function_call_arguments.delta" => {
                let item_id = required_str(&event.data, "item_id")?;
                let index = required_u64(&event.data, "output_index")?;
                reserve_item(
                    &mut item_indexes,
                    &mut item_kinds,
                    item_id,
                    index,
                    "function_call",
                )?;
                if completed_items.contains(item_id) {
                    return Err("batch harness received arguments after item completion".into());
                }
                pending_arguments
                    .entry(item_id.into())
                    .or_default()
                    .push_str(required_str(&event.data, "delta")?);
            }
            "response.output_item.done" => {
                let item = event
                    .data
                    .get("item")
                    .ok_or_else(|| "batch harness item completion requires item".to_string())?;
                let item_id = required_str(item, "id")?;
                let index = required_u64(&event.data, "output_index")?;
                let item_kind = required_str(item, "type")?;
                reserve_item(
                    &mut item_indexes,
                    &mut item_kinds,
                    item_id,
                    index,
                    item_kind,
                )?;
                if let Some(status) = item.get("status").and_then(Value::as_str) {
                    if item_kind == "message" && !matches!(status, "completed" | "incomplete") {
                        return Err("batch harness completed output item has invalid status".into());
                    }
                    item_statuses.insert(item_id.into(), status.into());
                }
                if !completed_items.insert(item_id.into()) {
                    return Err("batch harness received duplicate item completion".into());
                }
                if item_kind == "message" {
                    finalize_message_content(
                        item,
                        index,
                        &mut text_by_position,
                        &mut content_kinds,
                        &mut completed_content,
                    )?;
                } else if item_kind == "function_call" {
                    if required_str(item, "status")? != "completed" {
                        return Err("batch harness tool call was not completed".into());
                    }
                    let call_id = required_str(item, "call_id")?;
                    let name = required_str(item, "name")?;
                    if !call_ids.insert(call_id.into()) {
                        return Err("batch harness received a duplicate function call id".into());
                    }
                    let arguments = required_str(item, "arguments")?;
                    let parsed_arguments = serde_json::from_str::<Value>(arguments)
                        .map_err(|error| format!("batch harness tool arguments: {error}"))?;
                    if !parsed_arguments.is_object() {
                        return Err("batch harness tool arguments must be a JSON object".into());
                    }
                    if pending_arguments
                        .remove(item_id)
                        .is_some_and(|pending| pending != arguments)
                    {
                        return Err(
                            "batch harness tool arguments differ from streamed deltas".into()
                        );
                    }
                    if tool_calls
                        .insert(
                            index,
                            BatchToolCall {
                                item_id: item_id.into(),
                                call_id: call_id.into(),
                                name: name.into(),
                                output_index: index,
                                arguments: arguments.into(),
                            },
                        )
                        .is_some()
                    {
                        return Err("batch harness tool calls reused an output index".into());
                    }
                }
            }
            "response.completed"
            | "response.incomplete"
            | "response.failed"
            | "response.cancelled"
            | "chisei.response.interrupted" => {
                validate_terminal(&event)?;
                if event.event == "response.completed" {
                    reconcile_terminal_output(
                        &event,
                        &mut OutputAssembly {
                            text_by_position: &mut text_by_position,
                            content_kinds: &mut content_kinds,
                            completed_content: &mut completed_content,
                            tool_calls: &mut tool_calls,
                            item_indexes: &mut item_indexes,
                            item_kinds: &mut item_kinds,
                            item_statuses: &mut item_statuses,
                            completed_items: &mut completed_items,
                            pending_arguments: &mut pending_arguments,
                            call_ids: &mut call_ids,
                        },
                    )?;
                }
                if event.event == "response.completed"
                    && item_statuses.values().any(|status| status != "completed")
                {
                    return Err("batch harness completed response contains partial output".into());
                }
                if event.event == "response.completed"
                    && (!pending_arguments.is_empty()
                        || item_indexes
                            .keys()
                            .any(|item| !completed_items.contains(item)))
                {
                    return Err("batch harness completed with unfinished output".into());
                }
                usage = terminal_usage(&event)?;
                terminal = Some(event.event);
            }
            _ => unknown_events += 1,
        }
    }
    Ok(BatchHarnessResult {
        terminal: terminal
            .ok_or_else(|| "batch harness fixture has no terminal event".to_string())?,
        text: text_by_position.into_values().collect(),
        tool_calls,
        input_tokens: usage.0,
        output_tokens: usage.1,
        unknown_events,
    })
}

pub fn operation_receipt(
    result: &BatchHarnessResult,
    context: BatchReceiptContext<'_>,
) -> Result<OperationReceipt, String> {
    let BatchReceiptContext {
        operation_id,
        namespace,
        operation_class,
        actor,
        policy_version,
        verification_passed,
        started_at_ms,
        completed_at_ms,
    } = context;
    for (name, value) in [
        ("operation_id", operation_id),
        ("namespace", namespace),
        ("operation_class", operation_class),
        ("actor", actor),
        ("policy_version", policy_version),
    ] {
        if value.trim().is_empty() {
            return Err(format!("batch harness {name} is required"));
        }
    }
    if started_at_ms < 0 || completed_at_ms < started_at_ms {
        return Err("batch harness receipt timestamps are invalid".into());
    }
    if verification_passed.is_some() && result.terminal != "response.completed" {
        return Err("batch harness cannot evaluate a non-completed response".into());
    }
    let mut kinds = vec![ReceiptEventKind::IntentRecorded];
    if verification_passed.is_some() {
        kinds.push(ReceiptEventKind::VerificationRecorded);
    }
    kinds.push(ReceiptEventKind::OutcomeRecorded);
    let mut events = kinds
        .into_iter()
        .enumerate()
        .map(|(index, kind)| OperationReceiptEvent {
            event_id: format!("{operation_id}:batch:{index}"),
            operation_id: operation_id.into(),
            parent_event_id: (index > 0).then(|| format!("{operation_id}:batch:{}", index - 1)),
            timestamp_ms: if matches!(
                kind,
                ReceiptEventKind::VerificationRecorded | ReceiptEventKind::OutcomeRecorded
            ) {
                completed_at_ms
            } else {
                started_at_ms
            },
            kind,
            surface: kind.surface(),
            actor: actor.into(),
            references: Vec::new(),
            attributes: BTreeMap::new(),
        })
        .collect::<Vec<_>>();
    if let Some(passed) = verification_passed {
        let verification = events
            .iter_mut()
            .find(|event| event.kind == ReceiptEventKind::VerificationRecorded)
            .expect("requested verification event is present");
        verification.attributes.insert(
            "status".into(),
            if passed { "passed" } else { "failed" }.into(),
        );
        verification
            .attributes
            .insert("passed".into(), passed.to_string());
    }
    let outcome = events.last_mut().expect("receipt contains an outcome");
    outcome.attributes.insert(
        "status".into(),
        result
            .terminal
            .strip_prefix("response.")
            .or_else(|| result.terminal.strip_prefix("chisei.response."))
            .unwrap_or(&result.terminal)
            .into(),
    );
    if let Some(passed) = verification_passed {
        outcome
            .attributes
            .insert("passed".into(), passed.to_string());
        outcome
            .attributes
            .insert("outcome_metric".into(), "verification_pass_rate".into());
        outcome.attributes.insert(
            "outcome_value".into(),
            if passed { "1" } else { "0" }.into(),
        );
    }
    outcome
        .attributes
        .insert("harness_profile".into(), HARNESS_PROFILE.into());
    if let Some(input) = result.input_tokens {
        outcome
            .attributes
            .insert("input_tokens".into(), input.to_string());
    }
    if let Some(output) = result.output_tokens {
        outcome
            .attributes
            .insert("output_tokens".into(), output.to_string());
    }
    let receipt = OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: operation_id.into(),
        parent_operation_id: None,
        namespace: namespace.into(),
        operation_class: operation_class.into(),
        initiating_actor: actor.into(),
        schema_version: HARNESS_PROFILE.into(),
        policy_version: policy_version.into(),
        started_at_ms,
        completed_at_ms: Some(completed_at_ms),
        events,
        uncovered_surfaces: [
            ReceiptSurface::Policy,
            ReceiptSurface::Routing,
            ReceiptSurface::Budget,
            ReceiptSurface::Attempt,
        ]
        .into_iter()
        .map(|surface| UncoveredSurface {
            surface,
            reason: "not observed by the batch response harness".into(),
        })
        .collect(),
        reporter_grants: Vec::new(),
    };
    let completeness = receipt.completeness();
    if !completeness.errors.is_empty() {
        Err(format!(
            "batch harness receipt is structurally invalid: {completeness:?}"
        ))
    } else {
        Ok(receipt)
    }
}

pub fn evidence(
    result: &BatchHarnessResult,
    operation_id: &str,
    verification_passed: bool,
    observed_at_ms: i64,
) -> Result<EvidenceDraft, String> {
    if operation_id.trim().is_empty() || observed_at_ms < 0 {
        return Err("batch harness evidence identity and time are required".into());
    }
    if result.terminal != "response.completed" {
        return Err(
            "batch harness cannot emit verification evidence for a non-completed response".into(),
        );
    }
    Ok(EvidenceDraft {
        source_type: "native_harness".into(),
        source_record_id: operation_id.into(),
        source_version: format!("{HARNESS_PROFILE}:{observed_at_ms}"),
        source_sequence: observed_at_ms,
        evidence_type: EVIDENCE_TYPE.into(),
        signal: "verification".into(),
        schema_id: "adapter.batch_harness.outcome".into(),
        schema_version: "1.0.0".into(),
        observed_at_ms,
        expires_at_ms: None,
        content: serde_json::json!({
            "outcome": if verification_passed { "passed" } else { "failed" },
            "terminal": result.terminal,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
        }),
        relationships: Vec::new(),
        confidence_bps: 10_000,
        provenance: HashMap::from([
            ("delivery".into(), "batch".into()),
            ("harness_profile".into(), HARNESS_PROFILE.into()),
        ]),
        causality: Some(EvidenceCausality {
            operation_id: operation_id.into(),
            parent_operation_id: String::new(),
            attempt_id: String::new(),
            model_call_id: String::new(),
            subject_references: Vec::new(),
            trace_context: HashMap::new(),
        }),
    })
}

fn decode_sse(bytes: &[u8]) -> Result<Vec<WireEvent>, String> {
    let mut consumed = 0;
    while let Some((_, separator_end)) = find_frame_boundary(&bytes[consumed..]) {
        consumed += separator_end;
    }
    if bytes[consumed..]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        return Err("batch harness stream ended within an SSE frame".into());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "batch harness stream is not valid UTF-8")?
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut events = Vec::new();
    for frame in text.split("\n\n").filter(|frame| !frame.trim().is_empty()) {
        if frame.len() > MAX_SSE_FRAME_BYTES {
            return Err("batch harness SSE frame exceeds the size limit".into());
        }
        let mut event = None;
        let mut data = Vec::new();
        for line in frame.lines() {
            if line.starts_with(':') || line.is_empty() {
                continue;
            }
            if let Some(value) = line.strip_prefix("event:") {
                event = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("data:") {
                data.push(value.trim_start());
            }
        }
        if data.is_empty() {
            continue;
        }
        let data: Value = serde_json::from_str(&data.join("\n"))
            .map_err(|error| format!("batch harness SSE data: {error}"))?;
        let event = event
            .or_else(|| data.get("type").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| "unknown".into());
        events.push(WireEvent { event, data });
    }
    Ok(events)
}

fn reserve_item(
    items: &mut BTreeMap<String, u64>,
    kinds: &mut BTreeMap<String, String>,
    item_id: &str,
    index: u64,
    kind: &str,
) -> Result<(), String> {
    if items
        .get(item_id)
        .is_some_and(|existing| *existing != index)
        || items
            .iter()
            .any(|(existing, value)| *value == index && existing != item_id)
    {
        return Err("batch harness output identity changed".into());
    }
    if kinds.get(item_id).is_some_and(|existing| existing != kind) {
        return Err("batch harness output item kind changed".into());
    }
    items.insert(item_id.into(), index);
    kinds.insert(item_id.into(), kind.into());
    Ok(())
}

fn reconcile_terminal_output(
    event: &WireEvent,
    assembly: &mut OutputAssembly<'_>,
) -> Result<(), String> {
    let Some(output) = event
        .data
        .get("response")
        .and_then(|response| response.get("output"))
    else {
        return Ok(());
    };
    let output = output
        .as_array()
        .ok_or_else(|| "batch harness terminal response output must be an array".to_string())?;
    let mut expected_items = BTreeSet::new();
    for (output_index, item) in output.iter().enumerate() {
        let output_index = output_index as u64;
        let item_id = required_str(item, "id")?;
        let item_kind = required_str(item, "type")?;
        reserve_item(
            assembly.item_indexes,
            assembly.item_kinds,
            item_id,
            output_index,
            item_kind,
        )?;
        expected_items.insert(item_id.to_string());
        if let Some(status) = item.get("status").and_then(Value::as_str)
            && assembly
                .item_statuses
                .insert(item_id.into(), status.into())
                .is_some_and(|stored| stored != status)
        {
            return Err("batch harness terminal output status changed".into());
        }
        assembly.completed_items.insert(item_id.into());
        match item_kind {
            "message" => finalize_message_content(
                item,
                output_index,
                assembly.text_by_position,
                assembly.content_kinds,
                assembly.completed_content,
            )?,
            "function_call" => {
                if required_str(item, "status")? != "completed" {
                    return Err("batch harness tool call was not completed".into());
                }
                let arguments = required_str(item, "arguments")?;
                let parsed_arguments = serde_json::from_str::<Value>(arguments)
                    .map_err(|error| format!("batch harness tool arguments: {error}"))?;
                if !parsed_arguments.is_object() {
                    return Err("batch harness tool arguments must be a JSON object".into());
                }
                if assembly
                    .pending_arguments
                    .remove(item_id)
                    .is_some_and(|pending| pending != arguments)
                {
                    return Err("batch harness tool arguments differ from streamed deltas".into());
                }
                let candidate = BatchToolCall {
                    item_id: item_id.into(),
                    call_id: required_str(item, "call_id")?.into(),
                    name: required_str(item, "name")?.into(),
                    output_index,
                    arguments: arguments.into(),
                };
                match assembly.tool_calls.get(&output_index) {
                    Some(stored) if stored != &candidate => {
                        return Err(
                            "batch harness terminal tool call differs from streamed output".into(),
                        );
                    }
                    Some(_) => {}
                    None => {
                        if !assembly.call_ids.insert(candidate.call_id.clone()) {
                            return Err(
                                "batch harness received a duplicate function call id".into()
                            );
                        }
                        assembly.tool_calls.insert(output_index, candidate);
                    }
                }
            }
            _ => {}
        }
    }
    if assembly
        .item_indexes
        .keys()
        .any(|item_id| !expected_items.contains(item_id))
    {
        return Err("batch harness terminal response omitted streamed output".into());
    }
    Ok(())
}

fn validate_terminal(event: &WireEvent) -> Result<(), String> {
    let expected = event
        .event
        .strip_prefix("response.")
        .unwrap_or("interrupted");
    let status = event
        .data
        .get("response")
        .and_then(|response| response.get("status"))
        .or_else(|| event.data.get("status"))
        .and_then(Value::as_str);
    let data_type = event.data.get("type").and_then(Value::as_str);
    if status.is_none() && data_type.is_none() {
        return Err("batch harness terminal metadata is required".into());
    }
    if status.is_none_or(|value| value == expected)
        && data_type.is_none_or(|value| value == event.event)
    {
        Ok(())
    } else {
        Err("batch harness terminal metadata is inconsistent".into())
    }
}

fn validate_response_identity(event: &WireEvent, created_id: Option<&str>) -> Result<(), String> {
    let terminal_id = event
        .data
        .get("response")
        .and_then(|response| response.get("id"))
        .and_then(Value::as_str);
    let terminal_event = matches!(
        event.event.as_str(),
        "response.completed"
            | "response.incomplete"
            | "response.failed"
            | "response.cancelled"
            | "chisei.response.interrupted"
    );
    if created_id.is_some() && terminal_event && terminal_id.is_none() {
        return Err("batch harness terminal response identity is required".into());
    }
    if let (Some(created_id), Some(terminal_id)) = (created_id, terminal_id)
        && created_id != terminal_id
    {
        return Err("batch harness terminal response identity changed".into());
    }
    Ok(())
}

fn find_frame_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut index = 0;
    while index < bytes.len() {
        let Some(first_end) = line_ending_len(bytes, index) else {
            index += 1;
            continue;
        };
        let next = index + first_end;
        if let Some(second_end) = line_ending_len(bytes, next) {
            return Some((index, next + second_end));
        }
        index = next;
    }
    None
}

fn line_ending_len(bytes: &[u8], index: usize) -> Option<usize> {
    match bytes.get(index) {
        Some(b'\r') if bytes.get(index + 1) == Some(&b'\n') => Some(2),
        Some(b'\r' | b'\n') => Some(1),
        _ => None,
    }
}

fn terminal_usage(event: &WireEvent) -> Result<(Option<u64>, Option<u64>), String> {
    let usage = event
        .data
        .get("response")
        .and_then(|response| response.get("usage"))
        .or_else(|| event.data.get("usage"));
    let Some(usage) = usage.filter(|usage| !usage.is_null()) else {
        return Ok((None, None));
    };
    Ok((
        Some(
            usage
                .get("input_tokens")
                .and_then(Value::as_u64)
                .ok_or_else(|| "batch harness usage requires input_tokens".to_string())?,
        ),
        Some(
            usage
                .get("output_tokens")
                .and_then(Value::as_u64)
                .ok_or_else(|| "batch harness usage requires output_tokens".to_string())?,
        ),
    ))
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("batch harness event requires {field}"))
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("batch harness event requires string {field}"))
}

fn append_content(
    content: &mut BTreeMap<(u64, u64), String>,
    kinds: &mut BTreeMap<(u64, u64), &'static str>,
    completed: &BTreeSet<(u64, u64)>,
    position: (u64, u64),
    kind: &'static str,
    delta: &str,
) -> Result<(), String> {
    if completed.contains(&position) {
        return Err("batch harness received content after content completion".into());
    }
    if kinds
        .insert(position, kind)
        .is_some_and(|stored| stored != kind)
    {
        return Err("batch harness content position changed type".into());
    }
    content.entry(position).or_default().push_str(delta);
    Ok(())
}

fn finalize_content(
    content: &mut BTreeMap<(u64, u64), String>,
    kinds: &mut BTreeMap<(u64, u64), &'static str>,
    completed: &mut BTreeSet<(u64, u64)>,
    position: (u64, u64),
    kind: &'static str,
    authoritative: &str,
) -> Result<(), String> {
    if kinds
        .insert(position, kind)
        .is_some_and(|stored| stored != kind)
    {
        return Err("batch harness content position changed type".into());
    }
    match content.get(&position) {
        Some(assembled) if assembled != authoritative => {
            return Err("batch harness text differs from finalized output".into());
        }
        Some(_) => {}
        None => {
            content.insert(position, authoritative.into());
        }
    }
    completed.insert(position);
    Ok(())
}

fn finalize_message_content(
    item: &Value,
    output_index: u64,
    content: &mut BTreeMap<(u64, u64), String>,
    kinds: &mut BTreeMap<(u64, u64), &'static str>,
    completed: &mut BTreeSet<(u64, u64)>,
) -> Result<(), String> {
    let finalized = item
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| "batch harness completed message requires content".to_string())?;
    let mut expected = BTreeSet::new();
    for (content_index, part) in finalized.iter().enumerate() {
        let (kind, field) = match required_str(part, "type")? {
            "output_text" => ("output_text", "text"),
            "refusal" => ("refusal", "refusal"),
            other => {
                return Err(format!(
                    "batch harness unsupported message content {other:?}"
                ));
            }
        };
        let position = (output_index, content_index as u64);
        expected.insert(position);
        finalize_content(
            content,
            kinds,
            completed,
            position,
            kind,
            string_field(part, field)?,
        )?;
    }
    if content
        .keys()
        .any(|position| position.0 == output_index && !expected.contains(position))
    {
        return Err("batch harness finalized message omitted streamed content".into());
    }
    Ok(())
}

fn required_u64(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("batch harness event requires {field}"))
}

fn optional_u64(value: &Value, field: &str) -> Result<Option<u64>, String> {
    match value.get(field) {
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("batch harness event {field} must be an unsigned integer")),
        None => Ok(None),
    }
}
