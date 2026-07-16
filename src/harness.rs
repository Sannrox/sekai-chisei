//! Provider-neutral Responses stream conformance primitives for native harnesses.

use serde::{Deserialize, Serialize};

pub const RESPONSES_HARNESS_PROFILE_VERSION: &str = "chisei.responses-harness/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessEvent {
    pub event: String,
    pub data: serde_json::Value,
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

    pub fn finish(mut self) -> Result<Vec<HarnessEvent>, String> {
        if self.buffer.iter().all(u8::is_ascii_whitespace) {
            return Ok(Vec::new());
        }
        let frame = std::mem::take(&mut self.buffer);
        let frame =
            std::str::from_utf8(&frame).map_err(|_| "responses stream is not valid UTF-8")?;
        Ok(parse_frame(frame)?.into_iter().collect())
    }
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
        events.extend(decoder.finish().unwrap());
        assert_eq!(events.len(), 4);
        assert_eq!(events[1].event, "response.future.delta");
        assert_eq!(events.last().unwrap().event, "response.completed");
    }

    #[test]
    fn fixtures_have_exactly_one_terminal_event() {
        for fixture in [
            include_bytes!("../tests/fixtures/responses/multiple-tools.sse").as_slice(),
            include_bytes!("../tests/fixtures/responses/failed-partial.sse").as_slice(),
            include_bytes!("../tests/fixtures/responses/cancelled.sse").as_slice(),
            include_bytes!("../tests/fixtures/responses/interrupted.sse").as_slice(),
        ] {
            let mut decoder = SseDecoder::default();
            let events = decoder.push(fixture).unwrap();
            let terminals = events
                .iter()
                .filter(|event| {
                    matches!(
                        event.event.as_str(),
                        "response.completed"
                            | "response.failed"
                            | "response.cancelled"
                            | "chisei.response.interrupted"
                    )
                })
                .count();
            assert_eq!(terminals, 1);
        }
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
