//! OpenTelemetry GenAI client spans for outbound model calls.
//!
//! Every provider call Chisei makes, native or through the gateway, opens one
//! `client` span named `chat {model}` with the GenAI semantic-convention
//! attributes. The span is a child of whatever span is current, so it sits
//! under the inbound trace.
//!
//! Only identifiers, counts, and bounded outcome tokens are recorded. Prompts,
//! completions, tool arguments, evidence, and provider error messages never
//! enter a field: outcome strings that do not look like a short token are
//! replaced with `other`.

use std::future::Future;

use tracing::Span;
use tracing::field::Empty;

tokio::task_local! {
    static OPERATION_ID: String;
}

/// Run `future` with the caller's operation identity available to every
/// GenAI span opened inside it on the same task.
pub async fn with_operation_id<F: Future>(operation_id: String, future: F) -> F::Output {
    OPERATION_ID.scope(operation_id, future).await
}

fn current_operation_id() -> String {
    OPERATION_ID.try_with(String::clone).unwrap_or_default()
}

/// Open the client span for one model call. `provider` is the route's
/// provider id; `operation_id` overrides the task-scoped identity when the
/// caller already holds one (the gateway does).
pub fn client_span(provider: &str, request_model: &str, operation_id: Option<&str>) -> Span {
    let operation_id = match operation_id {
        Some(id) => id.to_string(),
        None => current_operation_id(),
    };
    tracing::info_span!(
        "gen_ai.client",
        otel.name = format!("chat {request_model}"),
        otel.kind = "client",
        otel.status_code = Empty,
        gen_ai.operation.name = "chat",
        gen_ai.provider.name = provider_name(provider),
        gen_ai.request.model = request_model,
        gen_ai.usage.input_tokens = Empty,
        gen_ai.usage.output_tokens = Empty,
        gen_ai.response.finish_reasons = Empty,
        "error.type" = Empty,
        sekai.operation_id = operation_id.as_str(),
    )
}

/// Record provider-reported token counts. Negative counts mean "not reported"
/// and are left unset.
pub fn record_usage(span: &Span, input_tokens: i64, output_tokens: i64) {
    if input_tokens >= 0 {
        span.record("gen_ai.usage.input_tokens", input_tokens);
    }
    if output_tokens >= 0 {
        span.record("gen_ai.usage.output_tokens", output_tokens);
    }
}

pub fn record_finish_reason(span: &Span, reason: &str) {
    if !reason.is_empty() {
        span.record("gen_ai.response.finish_reasons", bounded_token(reason));
    }
}

/// Mark the call failed with a bounded error class, never a message.
pub fn record_error(span: &Span, error_type: &str) {
    span.record("error.type", bounded_token(error_type));
    span.record("otel.status_code", "ERROR");
}

/// Error class for an encoded provider error string.
pub fn provider_error_type(error: &str) -> &'static str {
    match crate::llm::decode_provider_error(error.to_string()) {
        crate::llm::ProviderError::Precondition(_) => "precondition",
        crate::llm::ProviderError::Unavailable(_) => "unavailable",
        crate::llm::ProviderError::Upstream(_) => "upstream_error",
    }
}

/// Semantic-convention provider names where they differ from route ids.
fn provider_name(provider: &str) -> &str {
    match provider {
        "xai" => "x_ai",
        other => other,
    }
}

/// A short lowercase token passes through; anything else could carry
/// provider- or caller-controlled text and becomes `other`.
fn bounded_token(value: &str) -> &str {
    let token = value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    if token { value } else { "other" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_text_never_passes_as_an_outcome_token() {
        assert_eq!(bounded_token("end_turn"), "end_turn");
        assert_eq!(bounded_token("upstream_http_error"), "upstream_http_error");
        assert_eq!(bounded_token("the secret prompt"), "other");
        assert_eq!(bounded_token(&"a".repeat(65)), "other");
    }

    #[test]
    fn provider_errors_map_to_classes_not_messages() {
        let encoded = crate::llm::encode_provider_error(crate::llm::ProviderError::Unavailable(
            "registry at /secret/path".into(),
        ));
        assert_eq!(provider_error_type(&encoded), "unavailable");
        assert_eq!(
            provider_error_type("HTTP 500: prompt echo"),
            "upstream_error"
        );
    }
}
