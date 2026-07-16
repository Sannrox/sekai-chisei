//! Provider-neutral Responses stream conformance primitives for native harnesses.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const RESPONSES_HARNESS_PROFILE_VERSION: &str = "chisei.responses-harness/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessEvent {
    pub event: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDisposition {
    RetryWithNewAttempt,
    DoNotRetry,
    OutcomeAmbiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetrySafety {
    Safe,
    Ambiguous,
    NotRetryable,
}

pub fn retry_disposition(code: &str, safety: RetrySafety) -> RetryDisposition {
    match (code, safety) {
        (_, RetrySafety::Ambiguous) => RetryDisposition::OutcomeAmbiguous,
        ("rate_limited" | "upstream_unavailable" | "upstream_timeout", RetrySafety::Safe) => {
            RetryDisposition::RetryWithNewAttempt
        }
        _ => RetryDisposition::DoNotRetry,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCallAssembly {
    pub item_id: String,
    pub call_id: String,
    pub name: String,
    pub output_index: u64,
    pub arguments: String,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedOutputItem {
    pub output_index: u64,
    pub item: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingToolArguments {
    output_index: u64,
    arguments: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: Option<u64>,
    pub partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamAssembly {
    pub text: String,
    pub output_items: Vec<CompletedOutputItem>,
    pub tool_calls: Vec<ToolCallAssembly>,
    pub terminal: Option<String>,
    pub usage: Option<NormalizedUsage>,
    pending_tool_arguments: BTreeMap<String, PendingToolArguments>,
    completed_item_ids: BTreeSet<String>,
    output_identities: BTreeMap<String, u64>,
    output_indexes: BTreeMap<u64, String>,
    output_kinds: BTreeMap<String, String>,
}

impl StreamAssembly {
    pub fn from_events(events: &[HarnessEvent]) -> Result<Self, String> {
        let mut assembly = Self {
            text: String::new(),
            output_items: Vec::new(),
            tool_calls: Vec::new(),
            terminal: None,
            usage: None,
            pending_tool_arguments: BTreeMap::new(),
            completed_item_ids: BTreeSet::new(),
            output_identities: BTreeMap::new(),
            output_indexes: BTreeMap::new(),
            output_kinds: BTreeMap::new(),
        };
        for event in events {
            assembly.apply(event)?;
        }
        Ok(assembly)
    }

    fn apply(&mut self, event: &HarnessEvent) -> Result<(), String> {
        if self.terminal.is_some() {
            return Err(format!("event {} followed a terminal event", event.event));
        }
        match event.event.as_str() {
            "response.output_text.delta" => {
                let item_id = required_str(&event.data, "item_id")?;
                let output_index = required_u64(&event.data, "output_index")?;
                if self.completed_item_ids.contains(item_id) {
                    return Err(format!("text delta followed completed item {item_id}"));
                }
                self.reserve_output_identity(item_id, output_index, "message")?;
                self.text.push_str(required_str(&event.data, "delta")?);
            }
            "response.function_call_arguments.delta" => {
                let item_id = event
                    .data
                    .get("item_id")
                    .and_then(|value| value.as_str())
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "tool argument delta requires item_id".to_string())?;
                if self.completed_item_ids.contains(item_id) {
                    return Err(format!(
                        "tool argument delta followed completed item {item_id}"
                    ));
                }
                let delta = required_str(&event.data, "delta")?;
                let output_index = required_u64(&event.data, "output_index")?;
                self.reserve_output_identity(item_id, output_index, "function_call")?;
                if self
                    .tool_calls
                    .iter()
                    .any(|call| call.output_index == output_index && call.item_id != item_id)
                    || self
                        .pending_tool_arguments
                        .iter()
                        .any(|(pending_id, pending)| {
                            pending.output_index == output_index && pending_id != item_id
                        })
                {
                    return Err(format!(
                        "output_index {output_index} already belongs to another item"
                    ));
                }
                let pending = self
                    .pending_tool_arguments
                    .entry(item_id.to_owned())
                    .or_insert_with(|| PendingToolArguments {
                        output_index,
                        arguments: String::new(),
                    });
                if pending.output_index != output_index {
                    return Err(format!("tool item {item_id} changed output_index"));
                }
                pending.arguments.push_str(delta);
            }
            "response.output_item.added" => {
                let item = event
                    .data
                    .get("item")
                    .ok_or_else(|| "response.output_item.added requires item".to_string())?;
                let item_id = required_str(item, "id")?;
                let item_kind = required_str(item, "type")?;
                let output_index = required_u64(&event.data, "output_index")?;
                self.reserve_output_identity(item_id, output_index, item_kind)?;
            }
            "response.output_item.done" => {
                let item = event
                    .data
                    .get("item")
                    .ok_or_else(|| "response.output_item.done requires item".to_string())?;
                let item_id = required_str(item, "id")?;
                let output_index = required_u64(&event.data, "output_index")?;
                let item_kind = required_str(item, "type")?;
                self.reserve_output_identity(item_id, output_index, item_kind)?;
                if self.completed_item_ids.contains(item_id) {
                    return Err(format!("duplicate completion for output item {item_id}"));
                }
                self.output_items.push(CompletedOutputItem {
                    output_index,
                    item: item.clone(),
                });
                self.output_items.sort_by_key(|item| item.output_index);
                if item.get("type").and_then(|value| value.as_str()) == Some("function_call") {
                    let call_id = required_str(item, "call_id")?;
                    let name = required_str(item, "name")?;
                    if required_str(item, "status")? != "completed" {
                        return Err(format!("tool item {item_id} is not completed"));
                    }
                    let arguments = required_str(item, "arguments")?;
                    serde_json::from_str::<serde_json::Value>(arguments).map_err(|error| {
                        format!("tool call {call_id} has invalid arguments: {error}")
                    })?;
                    let streamed = self.pending_tool_arguments.remove(item_id);
                    if streamed
                        .as_ref()
                        .is_some_and(|pending| pending.output_index != output_index)
                    {
                        return Err(format!("tool item {item_id} changed output_index"));
                    }
                    let streamed_arguments = streamed.map(|pending| pending.arguments);
                    if streamed_arguments
                        .as_deref()
                        .is_some_and(|streamed| streamed != arguments)
                    {
                        return Err(format!(
                            "tool call {call_id} arguments do not match its deltas"
                        ));
                    }
                    if self.tool_calls.iter().any(|call| call.call_id == call_id) {
                        return Err(format!("duplicate function call id {call_id}"));
                    }
                    if self
                        .tool_calls
                        .iter()
                        .any(|call| call.output_index == output_index)
                        || self
                            .pending_tool_arguments
                            .iter()
                            .any(|(pending_id, pending)| {
                                pending.output_index == output_index && pending_id != item_id
                            })
                    {
                        return Err(format!("duplicate output_index {output_index}"));
                    }
                    self.tool_calls.push(ToolCallAssembly {
                        item_id: item_id.to_owned(),
                        call_id: call_id.to_owned(),
                        name: name.to_owned(),
                        output_index,
                        arguments: arguments.to_owned(),
                        complete: true,
                    });
                    self.tool_calls.sort_by_key(|call| call.output_index);
                }
                self.completed_item_ids.insert(item_id.to_owned());
            }
            "response.completed"
            | "response.incomplete"
            | "response.failed"
            | "response.cancelled"
            | "chisei.response.interrupted" => {
                validate_terminal_metadata(event)?;
                if event.event == "response.completed" {
                    let unfinished_output = self
                        .output_kinds
                        .keys()
                        .any(|item_id| !self.completed_item_ids.contains(item_id));
                    if !self.pending_tool_arguments.is_empty() || unfinished_output {
                        return Err("terminal event arrived with an incomplete output item".into());
                    }
                }
                self.terminal = Some(event.event.clone());
                self.usage = normalized_terminal_usage(event)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn reserve_output_identity(
        &mut self,
        item_id: &str,
        output_index: u64,
        item_kind: &str,
    ) -> Result<(), String> {
        if self
            .output_identities
            .get(item_id)
            .is_some_and(|existing| *existing != output_index)
        {
            return Err(format!("output item {item_id} changed output_index"));
        }
        if self
            .output_indexes
            .get(&output_index)
            .is_some_and(|existing| existing != item_id)
        {
            return Err(format!(
                "output_index {output_index} already belongs to another item"
            ));
        }
        if self
            .output_kinds
            .get(item_id)
            .is_some_and(|existing| existing != item_kind)
        {
            return Err(format!("output item {item_id} changed kind"));
        }
        self.output_identities
            .insert(item_id.to_owned(), output_index);
        self.output_indexes.insert(output_index, item_id.to_owned());
        self.output_kinds
            .insert(item_id.to_owned(), item_kind.to_owned());
        Ok(())
    }
}

fn validate_terminal_metadata(event: &HarnessEvent) -> Result<(), String> {
    let expected_status = match event.event.as_str() {
        "response.completed" => "completed",
        "response.incomplete" => "incomplete",
        "response.failed" => "failed",
        "response.cancelled" => "cancelled",
        "chisei.response.interrupted" => "interrupted",
        _ => return Ok(()),
    };
    let data_event = event.data.get("type").and_then(|value| value.as_str());
    let response_status = event
        .data
        .get("response")
        .and_then(|response| response.get("status"))
        .or_else(|| event.data.get("status"))
        .and_then(|value| value.as_str());
    if data_event.is_some_and(|data_event| data_event != event.event)
        || response_status.is_some_and(|status| status != expected_status)
        || (data_event.is_none() && response_status.is_none())
    {
        return Err("terminal event has inconsistent response metadata".into());
    }
    Ok(())
}

fn required_str<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("event requires non-empty {field}"))
}

fn required_u64(value: &serde_json::Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(|value| value.as_u64())
        .ok_or_else(|| format!("event requires non-negative {field}"))
}

fn normalized_terminal_usage(event: &HarnessEvent) -> Result<Option<NormalizedUsage>, String> {
    let usage = event
        .data
        .get("response")
        .and_then(|response| response.get("usage"))
        .or_else(|| event.data.get("usage"));
    let Some(usage) = usage.filter(|usage| !usage.is_null()) else {
        return Ok(None);
    };
    let input_tokens = usage
        .get("input_tokens")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| "terminal usage requires input_tokens".to_string())?;
    let output_tokens = usage
        .get("output_tokens")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| "terminal usage requires output_tokens".to_string())?;
    Ok(Some(NormalizedUsage {
        input_tokens,
        output_tokens,
        total_tokens: usage.get("total_tokens").and_then(|value| value.as_u64()),
        partial: event.event != "response.completed",
    }))
}

#[derive(Debug, Clone, Default)]
pub struct SseDecoder {
    buffer: Vec<u8>,
}

impl SseDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<HarnessEvent>, String> {
        self.buffer.extend_from_slice(bytes);
        let mut events = Vec::new();
        while let Some((frame_end, separator_end)) = find_frame_boundary(&self.buffer) {
            let frame = std::str::from_utf8(&self.buffer[..frame_end])
                .map_err(|_| "responses stream is not valid UTF-8")?
                .to_owned();
            self.buffer.drain(..separator_end);
            if let Some(event) = parse_frame(&frame)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    pub fn finish(self) -> Result<Vec<HarnessEvent>, String> {
        if self.buffer.iter().all(u8::is_ascii_whitespace) {
            return Ok(Vec::new());
        }
        Err("responses stream ended within an SSE frame".into())
    }
}

pub(crate) fn find_frame_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
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

fn parse_frame(frame: &str) -> Result<Option<HarnessEvent>, String> {
    let mut event = None;
    let mut data = Vec::new();
    let normalized = frame.replace("\r\n", "\n").replace('\r', "\n");
    for line in normalized.lines() {
        if line.starts_with(':') || line.is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("event:") {
            event = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("data:") {
            data.push(value.trim_start());
        }
    }
    if data.is_empty() {
        return Ok(None);
    }
    let data = data.join("\n");
    let value: serde_json::Value =
        serde_json::from_str(&data).map_err(|error| format!("invalid SSE data: {error}"))?;
    let event = event
        .or_else(|| {
            value
                .get("type")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".to_owned());
    Ok(Some(HarnessEvent { event, data: value }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_fragmented_frames_and_preserves_unknown_events() {
        let fixture = include_bytes!("../tests/fixtures/responses/fragmented-and-unknown.sse");
        let mut decoder = SseDecoder::default();
        let mut events = Vec::new();
        for chunk in fixture.chunks(7) {
            events.extend(decoder.push(chunk).unwrap());
        }
        events.extend(decoder.push(b"\n").unwrap());
        events.extend(decoder.finish().unwrap());
        assert_eq!(events.len(), 4);
        assert_eq!(events[1].event, "response.future.delta");
        assert_eq!(events.last().unwrap().event, "response.completed");
    }

    #[test]
    fn rejects_unterminated_frame_at_eof() {
        let mut decoder = SseDecoder::default();
        assert!(
            decoder
                .push(b"data: {\"type\":\"response.completed\"}")
                .unwrap()
                .is_empty()
        );
        assert!(decoder.finish().is_err());
    }

    #[test]
    fn fixtures_have_exactly_one_terminal_event() {
        for fixture in [
            include_bytes!("../tests/fixtures/responses/multiple-tools.sse").as_slice(),
            include_bytes!("../tests/fixtures/responses/failed-partial.sse").as_slice(),
            include_bytes!("../tests/fixtures/responses/cancelled.sse").as_slice(),
            include_bytes!("../tests/fixtures/responses/interrupted.sse").as_slice(),
            include_bytes!("../tests/fixtures/responses/incomplete.sse").as_slice(),
        ] {
            let mut decoder = SseDecoder::default();
            let mut events = decoder.push(fixture).unwrap();
            events.extend(decoder.push(b"\n").unwrap());
            events.extend(decoder.finish().unwrap());
            let terminals = events
                .iter()
                .filter(|event| {
                    matches!(
                        event.event.as_str(),
                        "response.completed"
                            | "response.incomplete"
                            | "response.failed"
                            | "response.cancelled"
                            | "chisei.response.interrupted"
                    )
                })
                .count();
            assert_eq!(terminals, 1);
            StreamAssembly::from_events(&events).unwrap();
        }
    }

    #[test]
    fn assembles_interleaved_tools_for_portable_continuation() {
        let fixture = include_bytes!("../tests/fixtures/responses/multiple-tools.sse");
        let mut decoder = SseDecoder::default();
        let mut events = decoder.push(fixture).unwrap();
        events.extend(decoder.push(b"\n").unwrap());
        events.extend(decoder.finish().unwrap());
        let assembly = StreamAssembly::from_events(&events).unwrap();
        assert_eq!(assembly.terminal.as_deref(), Some("response.completed"));
        assert_eq!(assembly.tool_calls.len(), 2);
        assert_eq!(assembly.output_items.len(), 2);
        assert!(
            assembly
                .output_items
                .windows(2)
                .all(|items| items[0].output_index < items[1].output_index)
        );
        assert!(
            assembly
                .output_items
                .iter()
                .all(|item| item.item["type"] == "function_call")
        );
        assert!(assembly.tool_calls.iter().all(|call| call.complete));
        assert_eq!(assembly.tool_calls[0].name, "lookup_weather");
        assert_eq!(assembly.tool_calls[1].name, "search_docs");
        assert!(!assembly.usage.unwrap().partial);
    }

    #[test]
    fn preserves_non_function_output_items_for_portable_continuation() {
        let events = [
            HarnessEvent {
                event: "response.output_item.done".into(),
                data: serde_json::json!({
                    "output_index": 0,
                    "item": {"id":"reasoning-1","type":"reasoning","summary":[]}
                }),
            },
            HarnessEvent {
                event: "response.completed".into(),
                data: serde_json::json!({
                    "type":"response.completed",
                    "response":{"status":"completed"}
                }),
            },
        ];
        let assembly = StreamAssembly::from_events(&events).unwrap();
        assert_eq!(assembly.output_items.len(), 1);
        assert_eq!(assembly.output_items[0].output_index, 0);
        assert_eq!(assembly.output_items[0].item["type"], "reasoning");
    }

    #[test]
    fn failed_and_cancelled_usage_remains_partial() {
        for fixture in [
            include_bytes!("../tests/fixtures/responses/failed-partial.sse").as_slice(),
            include_bytes!("../tests/fixtures/responses/cancelled.sse").as_slice(),
        ] {
            let events = SseDecoder::default().push(fixture).unwrap();
            let usage = StreamAssembly::from_events(&events).unwrap().usage.unwrap();
            assert!(usage.partial);
        }
    }

    #[test]
    fn malformed_or_incomplete_tool_calls_fail_closed() {
        let malformed = HarnessEvent {
            event: "response.output_item.done".into(),
            data: serde_json::json!({
                "output_index": 0,
                "item": {"type":"function_call", "id":"item_1", "call_id":"call_1", "name":"read", "status":"completed", "arguments":"{"}
            }),
        };
        assert!(StreamAssembly::from_events(&[malformed]).is_err());

        let incomplete = [
            HarnessEvent {
                event: "response.function_call_arguments.delta".into(),
                data: serde_json::json!({"item_id":"item_1", "output_index":0, "delta":"{"}),
            },
            HarnessEvent {
                event: "response.completed".into(),
                data: serde_json::json!({
                    "type":"response.completed",
                    "response":{"status":"completed","usage":{"input_tokens":1,"output_tokens":1}}
                }),
            },
        ];
        assert!(StreamAssembly::from_events(&incomplete).is_err());

        let added_without_done = [
            HarnessEvent {
                event: "response.output_item.added".into(),
                data: serde_json::json!({
                    "output_index": 0,
                    "item": {"type":"function_call", "id":"item_1", "call_id":"call_1", "name":"read"}
                }),
            },
            HarnessEvent {
                event: "response.completed".into(),
                data: serde_json::json!({"response":{"usage":{"input_tokens":1,"output_tokens":1}}}),
            },
        ];
        assert!(StreamAssembly::from_events(&added_without_done).is_err());

        let unfinished_message = [
            HarnessEvent {
                event: "response.output_item.added".into(),
                data: serde_json::json!({
                    "output_index": 0,
                    "item": {"type":"message", "id":"message_1", "content":[]}
                }),
            },
            HarnessEvent {
                event: "response.output_text.delta".into(),
                data: serde_json::json!({
                    "item_id":"message_1", "output_index":0, "delta":"partial"
                }),
            },
            HarnessEvent {
                event: "response.completed".into(),
                data: serde_json::json!({
                    "type":"response.completed", "response":{"status":"completed"}
                }),
            },
        ];
        assert!(StreamAssembly::from_events(&unfinished_message).is_err());

        let truncated = HarnessEvent {
            event: "response.output_item.done".into(),
            data: serde_json::json!({
                "output_index": 0,
                "item": {"type":"function_call", "id":"item_1", "call_id":"call_1", "name":"read", "status":"incomplete", "arguments":"{}"}
            }),
        };
        assert!(StreamAssembly::from_events(&[truncated]).is_err());
    }

    #[test]
    fn duplicate_or_post_terminal_events_are_rejected() {
        let terminal = HarnessEvent {
            event: "response.completed".into(),
            data: serde_json::json!({"response":{"usage":{"input_tokens":1,"output_tokens":1}}}),
        };
        assert!(StreamAssembly::from_events(&[terminal.clone(), terminal]).is_err());
    }

    #[test]
    fn retry_rules_preserve_ambiguous_outcomes() {
        assert_eq!(
            retry_disposition("rate_limited", RetrySafety::Safe),
            RetryDisposition::RetryWithNewAttempt
        );
        assert_eq!(
            retry_disposition("upstream_stream_error", RetrySafety::Ambiguous),
            RetryDisposition::OutcomeAmbiguous
        );
        assert_eq!(
            retry_disposition("upstream_timeout", RetrySafety::Ambiguous),
            RetryDisposition::OutcomeAmbiguous
        );
        assert_eq!(
            retry_disposition("upstream_unavailable", RetrySafety::Ambiguous),
            RetryDisposition::OutcomeAmbiguous
        );
        assert_eq!(
            retry_disposition("invalid_request", RetrySafety::NotRetryable),
            RetryDisposition::DoNotRetry
        );
    }

    #[test]
    fn item_identity_is_distinct_from_function_call_identity() {
        let events = [
            HarnessEvent {
                event: "response.function_call_arguments.delta".into(),
                data: serde_json::json!({"item_id":"item_1", "output_index":3, "delta":"{}"}),
            },
            HarnessEvent {
                event: "response.output_item.done".into(),
                data: serde_json::json!({
                    "output_index":3,
                    "item": {"type":"function_call", "id":"item_1", "call_id":"call_1", "name":"read", "status":"completed", "arguments":"{}"}
                }),
            },
            HarnessEvent {
                event: "response.completed".into(),
                data: serde_json::json!({
                    "type":"response.completed",
                    "response":{"status":"completed","usage":{"input_tokens":1,"output_tokens":1}}
                }),
            },
        ];
        let assembly = StreamAssembly::from_events(&events).unwrap();
        assert_eq!(assembly.tool_calls[0].call_id, "call_1");
        assert_eq!(assembly.tool_calls[0].item_id, "item_1");
        assert_eq!(assembly.tool_calls[0].name, "read");
        assert_eq!(assembly.tool_calls[0].output_index, 3);

        let contradictory_terminal = HarnessEvent {
            event: "response.completed".into(),
            data: serde_json::json!({
                "type":"response.failed",
                "response":{"status":"failed"}
            }),
        };
        assert!(StreamAssembly::from_events(&[contradictory_terminal]).is_err());

        let mut late = events.to_vec();
        late.insert(
            2,
            HarnessEvent {
                event: "response.function_call_arguments.delta".into(),
                data: serde_json::json!({"item_id":"item_1", "output_index":3, "delta":"{}"}),
            },
        );
        assert!(StreamAssembly::from_events(&late).is_err());
    }

    #[test]
    fn output_indexes_have_one_owner_across_pending_and_complete_calls() {
        let conflicting = [
            HarnessEvent {
                event: "response.function_call_arguments.delta".into(),
                data: serde_json::json!({"item_id":"item_a", "output_index":0, "delta":"{}"}),
            },
            HarnessEvent {
                event: "response.function_call_arguments.delta".into(),
                data: serde_json::json!({"item_id":"item_b", "output_index":0, "delta":"{}"}),
            },
        ];
        assert!(StreamAssembly::from_events(&conflicting).is_err());

        let cross_type_conflict = [
            HarnessEvent {
                event: "response.output_text.delta".into(),
                data: serde_json::json!({"item_id":"message_a", "output_index":0, "delta":"text"}),
            },
            HarnessEvent {
                event: "response.output_item.done".into(),
                data: serde_json::json!({
                    "output_index":0,
                    "item":{"type":"function_call", "id":"tool_b", "call_id":"call_b", "name":"read", "status":"completed", "arguments":"{}"}
                }),
            },
        ];
        assert!(StreamAssembly::from_events(&cross_type_conflict).is_err());

        let kind_change = [
            HarnessEvent {
                event: "response.output_text.delta".into(),
                data: serde_json::json!({"item_id":"item_1", "output_index":0, "delta":"text"}),
            },
            HarnessEvent {
                event: "response.output_item.done".into(),
                data: serde_json::json!({
                    "output_index":0,
                    "item":{"type":"function_call", "id":"item_1", "call_id":"call_1", "name":"read", "status":"completed", "arguments":"{}"}
                }),
            },
        ];
        assert!(StreamAssembly::from_events(&kind_change).is_err());

        let text_after_done = [
            HarnessEvent {
                event: "response.output_item.done".into(),
                data: serde_json::json!({
                    "output_index":0,
                    "item":{"type":"message", "id":"message_1", "status":"completed"}
                }),
            },
            HarnessEvent {
                event: "response.output_text.delta".into(),
                data: serde_json::json!({"item_id":"message_1", "output_index":0, "delta":"late"}),
            },
        ];
        assert!(StreamAssembly::from_events(&text_after_done).is_err());

        let added_kind_change = [
            HarnessEvent {
                event: "response.output_item.added".into(),
                data: serde_json::json!({
                    "output_index":0,
                    "item":{"type":"message", "id":"item_1"}
                }),
            },
            HarnessEvent {
                event: "response.output_item.done".into(),
                data: serde_json::json!({
                    "output_index":0,
                    "item":{"type":"function_call", "id":"item_1", "call_id":"call_1", "name":"read", "status":"completed", "arguments":"{}"}
                }),
            },
        ];
        assert!(StreamAssembly::from_events(&added_kind_change).is_err());
    }

    #[test]
    fn accepts_utf8_code_points_split_across_chunks() {
        let frame = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"世\"}\n\n";
        let split = frame.find('世').unwrap() + 1;
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(&frame.as_bytes()[..split]).unwrap().is_empty());
        let events = decoder.push(&frame.as_bytes()[split..]).unwrap();
        assert_eq!(events[0].data["delta"], "世");
    }

    #[test]
    fn emits_crlf_delimited_frames_incrementally() {
        let mut decoder = SseDecoder::default();
        let events = decoder
            .push(b"event: response.completed\r\ndata: {\"type\":\"response.completed\"}\r\n\r\n")
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "response.completed");
    }

    #[test]
    fn emits_bare_cr_delimited_frames() {
        let mut decoder = SseDecoder::default();
        let events = decoder
            .push(b"event: response.completed\rdata: {\"type\":\"response.completed\"}\r\r")
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "response.completed");
    }
}
