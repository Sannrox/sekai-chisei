use super::*;

const DEFAULT_CONTEXT_ADMISSION_POLICY_JSON: &str = r#"{"contract_version":"chisei.context-admission/v1","default_action":"include","unknown_action":"hold_out","rules":[]}"#;

#[test]
fn only_registered_gateway_identities_can_delegate_principals() {
    let registered = GatewayIdentity {
        agent: "alice".into(),
        project: "acme".into(),
        user_id: "alice".into(),
        key_id: "alice-key".into(),
        tier: DEFAULT_GATEWAY_TIER.into(),
    };
    assert!(registered.can_delegate_principal());
    assert_eq!(registered.delegated_principal(), "alice");

    let passthrough = GatewayIdentity {
        key_id: String::new(),
        ..registered.clone()
    };
    assert!(!passthrough.can_delegate_principal());

    let derived = GatewayIdentity {
        tier: "untrusted".into(),
        ..registered
    };
    assert!(!derived.can_delegate_principal());
}

#[test]
fn correlation_round_trips_harness_metadata() {
    let mut headers = HeaderMap::new();
    headers.insert(&X_CHISEI_OPERATION_ID, "operation-1".parse().unwrap());
    headers.insert(&X_CHISEI_REQUEST_ID, "request-1".parse().unwrap());
    headers.insert(
        &X_CHISEI_PARENT_OPERATION_ID,
        "operation-parent".parse().unwrap(),
    );
    headers.insert(&X_CHISEI_TURN_ID, "turn-2".parse().unwrap());
    headers.insert(&X_CHISEI_ATTEMPT, "3".parse().unwrap());
    headers.insert(&X_CHISEI_CYCLE_ID, "cycle-4".parse().unwrap());
    headers.insert(
        &TRACEPARENT,
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
            .parse()
            .unwrap(),
    );

    let correlation = GatewayCorrelation::from_headers(&headers, "caller-a").unwrap();
    assert_eq!(correlation.operation_id, "chisei:caller-a:operation-1");
    assert_eq!(
        correlation.request_id,
        scoped_request_id("request-1", "caller-a")
    );
    assert_ne!(
        scoped_request_id("request-1", "caller-a"),
        scoped_request_id("chisei:caller-a:request-1", "caller-a")
    );
    assert_eq!(correlation.lookup_request_id.as_deref(), Some("request-1"));
    assert_eq!(
        correlation.parent_operation_id.as_deref(),
        Some("chisei:caller-a:operation-parent")
    );
    assert_eq!(correlation.turn_id.as_deref(), Some("turn-2"));
    assert_eq!(correlation.attempt, 3);
    assert_eq!(correlation.cycle_id.as_deref(), Some("cycle-4"));

    let mut response = Response::new(Body::empty());
    correlation.apply_response_headers(&mut response);
    assert_eq!(
        response.headers()[&X_CHISEI_OPERATION_ID],
        "chisei:caller-a:operation-1"
    );
    assert_eq!(response.headers()[&X_CHISEI_REQUEST_ID], "request-1");
    assert_eq!(response.headers()[&X_CHISEI_ATTEMPT], "3");
}

#[test]
fn route_override_header_accepts_only_canonical_model_ids() {
    let mut headers = HeaderMap::new();
    headers.insert(&X_CHISEI_ROUTE_OVERRIDE, "openai/gpt-5.5".parse().unwrap());
    assert_eq!(
        route_override_header(&headers).unwrap().as_deref(),
        Some("openai/gpt-5.5")
    );
    headers.insert(&X_CHISEI_ROUTE_OVERRIDE, "gpt-5.5".parse().unwrap());
    assert!(route_override_header(&headers).is_err());
    headers.insert(
        &X_CHISEI_ROUTE_OVERRIDE,
        "openai/gpt/escape".parse().unwrap(),
    );
    assert!(route_override_header(&headers).is_err());
}

#[test]
fn request_alias_derives_stable_operation_identity_when_unspecified() {
    let mut headers = HeaderMap::new();
    headers.insert(&X_CHISEI_REQUEST_ID, "retryable-alias".parse().unwrap());

    let first = GatewayCorrelation::from_headers(&headers, "caller-a").unwrap();
    let second = GatewayCorrelation::from_headers(&headers, "caller-a").unwrap();
    assert_eq!(first.request_id, second.request_id);
    assert_eq!(first.operation_id, first.request_id);
    assert_eq!(second.operation_id, second.request_id);
}

#[test]
fn correlation_rejects_ambiguous_or_forged_metadata() {
    let mut headers = HeaderMap::new();
    headers.insert(&X_CHISEI_OPERATION_ID, "operation/escape".parse().unwrap());
    assert!(GatewayCorrelation::from_headers(&headers, "caller-a").is_err());

    headers.clear();
    headers.insert(
        &TRACEPARENT,
        "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
            .parse()
            .unwrap(),
    );
    assert!(GatewayCorrelation::from_headers(&headers, "caller-a").is_err());

    headers.clear();
    headers.insert(
        &X_CHISEI_OPERATION_ID,
        "chisei:caller-b:operation-1".parse().unwrap(),
    );
    assert!(GatewayCorrelation::from_headers(&headers, "caller-a").is_err());

    headers.clear();
    headers.insert(&X_CHISEI_REQUEST_ID, "request/escape".parse().unwrap());
    assert!(GatewayCorrelation::from_headers(&headers, "caller-a").is_err());

    headers.clear();
    headers.insert(
        &X_CHISEI_REQUEST_ID,
        "chisei:caller-a:request-1".parse().unwrap(),
    );
    assert!(GatewayCorrelation::from_headers(&headers, "caller-a").is_err());
}

#[test]
fn generated_correlation_preserves_request_receipt_identity() {
    let correlation = GatewayCorrelation::generated("caller-a");
    assert_eq!(correlation.operation_id, correlation.request_id);
    assert_eq!(
        scoped_operation_id(&correlation.operation_id, "caller-a").unwrap(),
        correlation.operation_id
    );
    assert_ne!(
        gateway_provider_receipt_id("operation-1", "request-1", 1, 1),
        gateway_provider_receipt_id("operation-1", "request-2", 1, 1)
    );
}

#[tokio::test]
async fn gateway_errors_include_stable_codes() {
    let response = json_error(
        StatusCode::BAD_REQUEST,
        "capability_unsupported",
        "unsupported",
    );
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["type"], "capability_unsupported");
    assert_eq!(body["error"]["code"], "capability_unsupported");
    assert_eq!(
        stable_gateway_error_code("rate_limit_exceeded"),
        "rate_limited"
    );
    assert_eq!(
        stable_gateway_error_code("invalid_request_error"),
        "invalid_request"
    );
    for (legacy, stable) in [
        ("context_denied", "policy_denied"),
        ("context_not_found", "invalid_request"),
        ("governance_unavailable", "upstream_unavailable"),
        ("governance_audit_unavailable", "upstream_unavailable"),
        ("usage_recovery_required", "request_conflict"),
        ("governance_precondition", "request_conflict"),
        ("unsupported_cross_provider_route", "capability_unsupported"),
    ] {
        assert_eq!(stable_gateway_error_code(legacy), stable);
    }
}

#[test]
fn canonical_operation_ids_always_round_trip() {
    let raw = "a".repeat(104);
    let canonical = scoped_operation_id(&raw, "0123456789abcdef").unwrap();
    assert_eq!(canonical.len(), 128);
    assert_eq!(
        scoped_operation_id(&canonical, "0123456789abcdef").unwrap(),
        canonical
    );
    assert!(scoped_operation_id(&"a".repeat(105), "0123456789abcdef").is_err());
    assert!(scoped_operation_id("chisei:0123456789abcdef:", "0123456789abcdef").is_err());
}

#[test]
fn profile_rejects_unenforced_idempotency_keys() {
    let mut headers = HeaderMap::new();
    headers.insert(&IDEMPOTENCY_KEY, "retry-1".parse().unwrap());
    assert!(validate_harness_request_headers(true, &headers).is_err());
    assert!(validate_harness_request_headers(false, &headers).is_ok());
    for path in ["/v1/responses", "/responses"] {
        let uri: Uri = path.parse().unwrap();
        let (_, normalized) = upstream_path(&uri).unwrap();
        assert!(
            validate_harness_request_headers(normalized.starts_with("/responses"), &headers)
                .is_err()
        );
    }
    let uri: Uri = "/v1/responses/resp_1/cancel".parse().unwrap();
    assert!(upstream_path(&uri).is_none());
}

#[test]
fn capability_preflight_rejects_unsupported_paths() {
    assert!(is_responses_create(&Method::POST, "/responses"));
    assert!(is_responses_create(&Method::POST, "/responses/"));
    assert!(!is_responses_create(&Method::GET, "/responses/resp_1"));
    assert!(!is_responses_create(
        &Method::POST,
        "/responses/resp_1/cancel"
    ));
    let parallel_tools = br#"{
        "model":"ollama/model",
        "tools":[{"type":"function","name":"read"}],
        "parallel_tool_calls":true
    }"#;
    let rejection = enforce_provider_capabilities(
        ProviderKind::OpenAi(OpenAiRuntime::Ollama),
        None,
        CapabilityRequestSurface::Responses,
        parallel_tools,
    )
    .unwrap_err();
    assert_eq!(rejection.error_type, "capability_unsupported");
    assert!(rejection.reason.contains("parallel_tools"));

    let built_in = br#"{"model":"gpt-5.5","tools":[{"type":"web_search"}]}"#;
    let rejection = enforce_provider_capabilities(
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        None,
        CapabilityRequestSurface::Responses,
        built_in,
    )
    .unwrap_err();
    assert!(rejection.reason.contains("built_in_tool:web_search"));

    let continuation = br#"{
        "model":"gpt-5.5",
        "previous_response_id":"resp_other_caller",
        "input":[{"type":"message","role":"user","content":"continue"}]
    }"#;
    let rejection = enforce_provider_capabilities(
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        None,
        CapabilityRequestSurface::Responses,
        continuation,
    )
    .unwrap_err();
    assert_eq!(rejection.error_type, "capability_unsupported");
    assert!(rejection.reason.contains("ownership"));

    let chat_tools = br#"{
        "model":"native/mistral",
        "tools":[{"type":"function","function":{"name":"read"}}]
    }"#;
    let rejection = enforce_provider_capabilities(
        ProviderKind::OpenAi(OpenAiRuntime::Native),
        None,
        CapabilityRequestSurface::OpenAiChat,
        chat_tools,
    )
    .unwrap_err();
    assert!(rejection.reason.contains("tools"));

    let anthropic_built_in = br#"{
        "model":"claude-sonnet-4",
        "max_tokens":1024,
        "tools":[{"type":"web_search_20250305","name":"web_search"}]
    }"#;
    let rejection = enforce_provider_capabilities(
        ProviderKind::Anthropic,
        None,
        CapabilityRequestSurface::AnthropicMessages,
        anthropic_built_in,
    )
    .unwrap_err();
    assert!(
        rejection
            .reason
            .contains("built_in_tool:web_search_20250305")
    );
}

#[test]
fn capability_preflight_only_targets_provider_create_requests() {
    assert!(matches!(
        capability_request_surface(&Method::POST, "/responses"),
        Some(CapabilityRequestSurface::Responses)
    ));
    assert!(matches!(
        capability_request_surface(&Method::POST, "/chat/completions"),
        Some(CapabilityRequestSurface::OpenAiChat)
    ));
    assert!(matches!(
        capability_request_surface(&Method::POST, "/messages"),
        Some(CapabilityRequestSurface::AnthropicMessages)
    ));
    assert!(matches!(
        capability_request_surface(&Method::POST, "/messages/"),
        Some(CapabilityRequestSurface::AnthropicMessages)
    ));
    assert!(matches!(
        capability_request_surface(&Method::POST, "/chat/completions/"),
        Some(CapabilityRequestSurface::OpenAiChat)
    ));
    assert!(capability_request_surface(&Method::POST, "/messages/count_tokens").is_none());
    assert!(capability_request_surface(&Method::GET, "/responses/resp_1").is_none());
}

#[test]
fn cross_provider_adapter_rejects_lossy_anthropic_requests() {
    for body in [
        br#"{"tools":[{"name":"read","input_schema":{"type":"object"}}]}"#.as_slice(),
        br#"{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","data":"x"}}]}]}"#.as_slice(),
        br#"{"output_config":{"format":{"type":"json_schema"}}}"#.as_slice(),
        br#"{"output_config":{"effort":"high"}}"#.as_slice(),
        br#"{"messages":[{"role":"user","content":"hello"}],"stop_sequences":["END"]}"#.as_slice(),
        br#"{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","data":"x"}}]}]}"#.as_slice(),
        br#"{"messages":[{"role":"user","content":[{"type":"text","text":"hello","cache_control":{"type":"ephemeral"}}]}]}"#.as_slice(),
        br#"{"messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}]}"#.as_slice(),
        br#"{"system":"prompt"}"#.as_slice(),
        br#"{"messages":"hello"}"#.as_slice(),
    ] {
        let rejection = enforce_adapter_capabilities(
            ProviderKind::Anthropic,
            ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
            CapabilityRequestSurface::AnthropicMessages,
            body,
        )
        .unwrap_err();
        assert_eq!(rejection.error_type, "capability_unsupported");
    }

    assert!(
        enforce_adapter_capabilities(
            ProviderKind::Anthropic,
            ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
            CapabilityRequestSurface::AnthropicMessages,
            br#"{"messages":[{"role":"user","content":"hello"}],"stream":true}"#,
        )
        .is_ok()
    );
}

#[test]
fn capability_discovery_is_versioned_and_provider_specific() {
    let matrix = CapabilityMatrix::built_in();
    assert_eq!(
        matrix.version,
        crate::provider_profile::CAPABILITY_MATRIX_VERSION
    );
    assert!(!matrix.grant_semantics);
    assert!(matrix.capabilities("openai").unwrap().parallel_tools);
    assert!(!matrix.capabilities("openai").unwrap().provider_continuation);
    assert!(!matrix.capabilities("ollama").unwrap().parallel_tools);
    assert!(!matrix.capabilities("anthropic").unwrap().responses);
}

#[test]
fn upstream_cannot_supply_gateway_correlation_headers() {
    assert!(!should_forward_response_header(&X_CHISEI_OPERATION_ID));
    assert!(!should_forward_response_header(
        &X_CHISEI_PARENT_OPERATION_ID
    ));
    assert!(!should_forward_response_header(&TRACEPARENT));
    assert!(!should_forward_response_header(&TRACESTATE));
    assert!(should_forward_response_header(&CONTENT_TYPE));
}

#[test]
fn interrupted_responses_event_is_terminal_and_preserves_partial_usage() {
    let bytes = interrupted_responses_event(
        "openai upstream stream failed",
        Some(&ResponseUsage {
            input_tokens: 7,
            output_tokens: 2,
            total_tokens: 9,
            cache_read_input_tokens: 0,
            cache_creation_input_tokens: 0,
            ..Default::default()
        }),
    );
    let mut decoder = crate::harness::SseDecoder::default();
    let events = decoder.push(&bytes).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "chisei.response.interrupted");
    assert_eq!(events[0].data["response"]["usage"]["total_tokens"], 9);
    assert_eq!(events[0].data["error"]["code"], "upstream_unavailable");
    assert_eq!(events[0].data["error"]["retry_safety"], "ambiguous");

    let bytes = interrupted_responses_event("interrupted", None);
    let events = decoder.push(&bytes).unwrap();
    assert!(events[0].data["response"].get("usage").is_none());

    let mut tap = SseUsageTap::new();
    tap.push(b"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n");
    assert_eq!(tap.terminal(), Some(ResponsesTerminal::Completed));
    let mut tap = SseUsageTap::new();
    tap.push(b"\xef\xbb\xbfdata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":2,\"total_tokens\":3}}}\n\n");
    assert_eq!(tap.terminal(), Some(ResponsesTerminal::Completed));
    assert_eq!(tap.usage.unwrap().total_tokens, 3);
    let mut tap = SseUsageTap::new();
    tap.push(b"event: response.incomplete\ndata: {\"type\":\"response.incomplete\"}\n\n");
    assert_eq!(
        tap.terminal(),
        Some(ResponsesTerminal::Incomplete("response_incomplete".into()))
    );
    let mut tap = SseUsageTap::new();
    tap.push(b"\xef\xbb\xbfevent: response.completed\n\n");
    assert_eq!(tap.terminal(), None);
    let mut tap = SseUsageTap::new();
    tap.push(b"event: response.incomplete\ndata: {\"response\":{\"status\":\"incomplete\",\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}}\n\n");
    assert_eq!(
        tap.terminal(),
        Some(ResponsesTerminal::Incomplete("max_output_tokens".into()))
    );
    let mut tap = SseUsageTap::new();
    tap.push(b"event: response.output_text.delta\nevent: response.completed\ndata: {\"response\":{\"status\":\"completed\"}}\n\n");
    assert_eq!(tap.terminal(), Some(ResponsesTerminal::Completed));
    let mut tap = SseUsageTap::new();
    tap.push(b"event: response.completed\ndata: {}\n\n");
    assert_eq!(tap.terminal(), Some(ResponsesTerminal::Invalid));
    let mut tap = SseUsageTap::new();
    tap.push(b"event: response.completed\ndata: {\"type\":\"response.failed\",\"response\":{\"status\":\"failed\"}}\n\n");
    assert_eq!(tap.terminal(), Some(ResponsesTerminal::Invalid));
    let mut tap = SseUsageTap::new();
    tap.push(b"event: response.completed\nevent: response.output_text.delta\ndata: {\"type\":\"response.completed\"}\n\n");
    assert_eq!(tap.terminal(), None);
    let mut tap = SseUsageTap::new();
    tap.push(b"event: response.completed\nevent:\ndata: {\"type\":\"response.completed\"}\n\n");
    assert_eq!(tap.terminal(), None);
    let mut tap = SseUsageTap::new();
    tap.push(b"\xef\xbb\xbfevent: response.output_text.delta\ndata: {\"type\":\"response.completed\"}\n\n");
    assert_eq!(tap.terminal(), None);
    let mut tap = SseUsageTap::new();
    tap.push(b"event\ndata: {\"type\":\"response.incomplete\"}\n\n");
    assert_eq!(tap.terminal(), None);
    let mut tap = SseUsageTap::new();
    tap.push(b"event: response.output_text.delta\ndata: {\"type\":\"response.incomplete\"}\n\n");
    assert_eq!(tap.terminal(), None);
    let mut tap = SseUsageTap::new();
    tap.push(b"event: response.incomplete\ndata: {\"type\":\"response.output_text.delta\",\"response\":{\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}}\n\n");
    assert_eq!(tap.terminal(), Some(ResponsesTerminal::Invalid));
    let mut tap = SseUsageTap::new();
    tap.push(b"id\rdata: {\"type\":\"response.completed\"}\r\r");
    assert_eq!(tap.terminal(), Some(ResponsesTerminal::Completed));
    for separator in [b"\n\r".as_slice(), b"\n\r\n", b"\r\n\r"] {
        let mut stream =
            b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"x\"}".to_vec();
        stream.extend_from_slice(separator);
        stream.extend_from_slice(b"data: {\"type\":\"response.completed\"}");
        stream.extend_from_slice(separator);
        let mut tap = SseUsageTap::new();
        tap.push(&stream);
        assert_eq!(tap.terminal(), Some(ResponsesTerminal::Completed));
    }
    let mut tap = SseUsageTap::new();
    tap.push(
        b"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\"}\n\n",
    );
    assert_eq!(tap.terminal(), Some(ResponsesTerminal::Invalid));
    let mut tap = SseUsageTap::new();
    tap.push(b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"x\"}\n\n");
    assert_eq!(tap.terminal(), None);

    let mut tap = SseUsageTap::new();
    tap.push(b"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":2,\"total_tokens\":3}}}");
    assert_eq!(tap.terminal(), None);
    let (usage, _, terminal, mode) = tap.finish_with_terminal();
    assert_eq!(terminal, Some(ResponsesTerminal::Completed));
    assert_eq!(mode, SseTapMode::Sse);
    assert_eq!(usage.unwrap().total_tokens, 3);

    let mut tap = SseUsageTap::new();
    tap.push(
        br#"{"type":"response","usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}"#,
    );
    let (usage, _, terminal, mode) = tap.finish_with_terminal();
    assert_eq!(mode, SseTapMode::Raw);
    assert_eq!(terminal, None);
    assert_eq!(usage.unwrap().total_tokens, 3);

    for (status, expected) in [
        (
            "incomplete",
            ResponsesTerminal::Incomplete("response_incomplete".into()),
        ),
        ("failed", ResponsesTerminal::Failed),
        ("cancelled", ResponsesTerminal::Cancelled),
    ] {
        let mut tap = SseUsageTap::new();
        tap.push(format!(r#"{{"status":"{status}"}}"#).as_bytes());
        let (_, _, terminal, mode) = tap.finish_with_terminal();
        assert_eq!(mode, SseTapMode::Raw);
        assert_eq!(terminal, Some(expected));
    }

    let mut tap = SseUsageTap::new();
    tap.push(b"   ");
    let (_, _, terminal, mode) = tap.finish_with_terminal();
    assert_eq!(mode, SseTapMode::Undetected);
    assert_eq!(terminal, None);
}

#[test]
fn stream_overload_errors_preserve_client_wire_format() {
    let anthropic = interrupted_stream_event(false, true, "frame too large", None);
    let anthropic = String::from_utf8(anthropic.to_vec()).unwrap();
    assert!(anthropic.starts_with("event: error\ndata: "));
    assert!(anthropic.contains("\"type\":\"api_error\""));
    assert!(anthropic.contains("\"retry_safety\":\"ambiguous\""));

    let openai = interrupted_stream_event(false, false, "frame too large", None);
    let openai = String::from_utf8(openai.to_vec()).unwrap();
    assert!(openai.starts_with("data: "));
    assert!(openai.contains("\"code\":\"upstream_unavailable\""));
}

#[test]
fn responses_stream_validation_waits_for_complete_frames() {
    let terminal = b"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n";
    let split = terminal.len() - 5;
    let mut validator = ResponsesStreamValidator::default();
    assert!(validator.push(&terminal[..split]).unwrap().is_empty());
    assert!(validator.push(&terminal[split..]).unwrap().is_empty());
    assert!(validator.terminal_seen);
    assert!(
        validator
            .push(b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"late\"}\n\n")
            .is_err()
    );

    let mut validator = ResponsesStreamValidator::default();
    assert!(validator.push(b"data: {not-json}\n\n").is_err());
    let mut validator = ResponsesStreamValidator::default();
    let invalid_terminal = b"event: response.completed\ndata: {}\n\n";
    let mut mixed = invalid_terminal.to_vec();
    mixed.extend_from_slice(
        b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"late\"}\n\n",
    );
    let error = validator.push(&mixed).unwrap_err();
    assert!(error.validated.is_empty());
    assert!(error.reason.contains("inconsistent terminal"));
    assert!(!validator.terminal_seen);
    let mut validator = ResponsesStreamValidator::default();
    let valid = b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"kept\"}\n\n";
    let mut mixed = valid.to_vec();
    mixed.extend_from_slice(b"data: {not-json}\n\n");
    let error = validator.push(&mixed).unwrap_err();
    assert_eq!(error.validated, valid);
    assert!(error.reason.contains("invalid JSON"));

    let mut validator = ResponsesStreamValidator::default();
    let mut mixed = valid.to_vec();
    mixed.extend_from_slice(terminal);
    mixed.extend_from_slice(
        b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"late\"}\n\n",
    );
    let error = validator.push(&mixed).unwrap_err();
    assert_eq!(error.validated, valid);
    assert!(error.reason.contains("data after a terminal"));

    let mut validator = ResponsesStreamValidator::default();
    let raw = br#"{"id":"resp_1","status":"completed"}"#;
    assert!(validator.push(raw).unwrap().is_empty());
    assert_eq!(validator.finish().unwrap(), raw);

    let mut validator = ResponsesStreamValidator::default();
    assert!(
        validator
            .push(br#"{"id":"resp_1","status":"processing"}"#)
            .unwrap()
            .is_empty()
    );
    assert!(validator.finish().is_err());

    let mut validator = ResponsesStreamValidator::default();
    let bare_cr = b"data: {\"type\":\"response.completed\"}\r\r";
    assert!(validator.push(bare_cr).unwrap().is_empty());
    assert_eq!(validator.finish().unwrap(), bare_cr);

    let mut validator = ResponsesStreamValidator::default();
    assert!(validator.push(b"\xef").unwrap().is_empty());
    assert!(validator.push(b"\xbb").unwrap().is_empty());
    let bom_frame = b"\xbfdata: {\"type\":\"response.completed\"}\n\n";
    assert!(validator.push(bom_frame).unwrap().is_empty());
    assert_eq!(
        validator.finish().unwrap(),
        b"\xef\xbb\xbfdata: {\"type\":\"response.completed\"}\n\n"
    );
    assert!(validator.terminal_seen);

    let mut validator = ResponsesStreamValidator::default();
    assert_eq!(
        validator.push(b"event: response.completed\n\n").unwrap(),
        b"event: response.completed\n\n"
    );
    assert!(!validator.terminal_seen);
    assert!(validator.finish().is_ok());

    let mut validator = ResponsesStreamValidator::default();
    let many_frames = b"data: {}\n\n".repeat(100_000);
    assert_eq!(
        validator.push(&many_frames).unwrap().len(),
        many_frames.len()
    );

    let mut validator = ResponsesStreamValidator::default();
    let mut oversized = b"data: \"".to_vec();
    oversized.resize(MAX_SSE_FRAME_BYTES + 1, b'x');
    oversized.extend_from_slice(b"\n\n");
    assert!(validator.push(&oversized).is_err());
}

#[test]
fn streaming_parsers_bound_incomplete_frames() {
    let complete_frames = b"data: {\"delta\":\"x\"}\n\n".repeat(100_000);
    let mut tap = SseUsageTap::sse();
    tap.push(&complete_frames);
    assert_eq!(tap.overflow_reason(), None);
    assert!(tap.pending.is_empty());

    let mut oversized = b"data: \"".to_vec();
    oversized.resize(MAX_SSE_FRAME_BYTES + 1, b'x');

    let mut tap = SseUsageTap::sse();
    tap.push(&oversized);
    assert_eq!(
        tap.overflow_reason(),
        Some("upstream SSE frame exceeds the gateway limit")
    );
    assert!(tap.pending.is_empty());
    assert_eq!(tap.terminal(), Some(ResponsesTerminal::Invalid));

    let mut translator = AnthropicMessageStreamTranslator::new("model".into());
    let mut rejected = false;
    for window in oversized.chunks(SSE_VALIDATION_WINDOW_BYTES) {
        if translator.push_window(window).is_err() {
            rejected = true;
            break;
        }
    }
    assert!(rejected);
    assert!(translator.pending.len() <= MAX_SSE_FRAME_BYTES);

    let mut translator = AnthropicMessageStreamTranslator::new("model".into());
    for window in complete_frames.chunks(SSE_VALIDATION_WINDOW_BYTES) {
        let translated = translator.push_window(window).unwrap();
        assert!(translated.len() <= MAX_SSE_FRAME_BYTES);
    }
    assert!(
        translator
            .push_window(&vec![b'x'; SSE_VALIDATION_WINDOW_BYTES + 1])
            .is_err()
    );
}

#[tokio::test]
async fn retry_safety_is_observable_on_gateway_errors() {
    let response = json_error_with_retry_safety(
        StatusCode::BAD_GATEWAY,
        "upstream_error",
        "upstream failed",
        "ambiguous",
    );
    assert_eq!(response.headers()[&X_CHISEI_RETRY_SAFETY], "ambiguous");
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "upstream_unavailable");
    assert_eq!(body["error"]["retry_safety"], "ambiguous");

    let response = json_error(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limit_exceeded",
        "local rate exceeded",
    );
    assert_eq!(response.headers()[&X_CHISEI_RETRY_SAFETY], "safe");
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["retry_safety"], "safe");

    let response = json_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "provider_registry_unavailable",
        "registry refresh failed",
    );
    assert_eq!(response.headers()[&X_CHISEI_RETRY_SAFETY], "safe");
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "upstream_unavailable");
}

#[test]
fn buffered_responses_preserve_incomplete_reason() {
    assert_eq!(
        buffered_responses_incomplete_reason(
            br#"{"id":"resp_1","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}"#,
        )
        .as_deref(),
        Some("max_output_tokens")
    );
    assert!(
        buffered_responses_incomplete_reason(br#"{"id":"resp_1","status":"completed"}"#,).is_none()
    );
    assert_eq!(
        buffered_responses_terminal(br#"{"id":"resp_1","status":"failed"}"#),
        Some(ResponsesTerminal::Failed)
    );
    assert_eq!(
        buffered_responses_terminal(br#"{"id":"resp_1","status":"cancelled"}"#),
        Some(ResponsesTerminal::Cancelled)
    );
}

#[test]
fn buffered_responses_fail_closed_on_http_and_terminal_errors() {
    assert!(matches!(
        buffered_gateway_usage_outcome(
            StatusCode::BAD_GATEWAY,
            true,
            Some(ResponsesTerminal::Completed)
        ),
        GatewayUsageOutcome::TerminalFailure(_, reason) if reason == "upstream_http_error"
    ));
    assert!(matches!(
        buffered_gateway_usage_outcome(StatusCode::OK, true, None),
        GatewayUsageOutcome::TerminalFailure(_, reason) if reason == "missing_terminal_status"
    ));
    assert!(matches!(
        buffered_gateway_usage_outcome(StatusCode::OK, false, None),
        GatewayUsageOutcome::Success(_)
    ));
    assert!(matches!(
        buffered_gateway_usage_outcome(
            StatusCode::OK,
            true,
            Some(ResponsesTerminal::Failed)
        ),
        GatewayUsageOutcome::TerminalFailure(_, reason) if reason == "response_failed"
    ));
}

#[test]
fn completed_stream_outcome_survives_a_later_transport_error() {
    assert!(matches!(
        streaming_gateway_usage_outcome(
            StatusCode::OK,
            true,
            Some(ResponsesTerminal::Completed),
            true,
            true,
            false,
            Some("connection reset after terminal event".into()),
        ),
        GatewayUsageOutcome::Success(_)
    ));
    assert!(matches!(
        streaming_gateway_usage_outcome(
            StatusCode::OK,
            true,
            None,
            true,
            false,
            true,
            Some("connection reset before terminal event".into()),
        ),
        GatewayUsageOutcome::Interrupted(_, reason)
            if reason == "connection reset before terminal event"
    ));
    assert!(matches!(
        streaming_gateway_usage_outcome(
            StatusCode::OK,
            true,
            Some(ResponsesTerminal::Completed),
            true,
            false,
            false,
            Some("connection reset within terminal frame".into()),
        ),
        GatewayUsageOutcome::Interrupted(_, reason)
            if reason == "connection reset within terminal frame"
    ));
}

#[test]
fn correlation_scope_uses_resolved_identity_only() {
    let identity = GatewayIdentity {
        agent: "codex-app".into(),
        project: "project-a".into(),
        user_id: "user-a".into(),
        key_id: "key-a".into(),
        tier: DEFAULT_GATEWAY_TIER.into(),
    };
    assert_eq!(
        gateway_correlation_scope(&identity),
        gateway_correlation_scope(&identity.clone())
    );
    let mut other = identity;
    other.key_id = "key-b".into();
    assert_ne!(
        gateway_correlation_scope(&other),
        gateway_correlation_scope(&GatewayIdentity {
            key_id: "key-a".into(),
            ..other.clone()
        })
    );
}

#[test]
fn rejects_weak_admin_tokens() {
    let bind = "127.0.0.1:8788".parse().unwrap();
    let keys = HashMap::new();
    assert!(validate_gateway_security(bind, &keys, false, Some("change-me")).is_err());
    assert!(validate_gateway_security(bind, &keys, false, Some("too-short")).is_err());
    assert!(
        validate_gateway_security(bind, &keys, false, Some("0123456789abcdef0123456789abcdef"),)
            .is_ok()
    );
}

#[test]
fn gateway_requires_an_explicit_control_plane_target() {
    assert!(required_control_plane_target(None, None).is_err());
    assert!(required_control_plane_target(Some("  ".into()), None).is_err());
    assert_eq!(
        required_control_plane_target(None, Some("/tmp/sekai.sock".into())).unwrap(),
        "/tmp/sekai.sock"
    );
    assert_eq!(
        required_control_plane_target(Some("  ".into()), Some("/tmp/sekai-fallback.sock".into()))
            .unwrap(),
        "/tmp/sekai-fallback.sock"
    );
    assert_eq!(
        required_control_plane_target(
            Some("http://127.0.0.1:50051".into()),
            Some("/tmp/sekai.sock".into())
        )
        .unwrap(),
        "http://127.0.0.1:50051"
    );
}

#[test]
fn recovery_paths_use_canonical_configuration() {
    assert_eq!(
        resolve_usage_recovery_path(None),
        PathBuf::from(DEFAULT_USAGE_RECOVERY_PATH)
    );
    assert_eq!(
        resolve_usage_recovery_path(Some("/var/lib/sekai/usage.json".into())),
        PathBuf::from("/var/lib/sekai/usage.json")
    );
    assert_eq!(
        resolve_recovery_spool_path(None),
        PathBuf::from(DEFAULT_RECOVERY_SPOOL_PATH)
    );
    assert_eq!(
        resolve_recovery_spool_path(Some("/new/recovery.jsonl".into())),
        PathBuf::from("/new/recovery.jsonl")
    );
}

#[test]
fn exposed_gateway_requires_keys_and_no_auth_passthrough() {
    let bind = "0.0.0.0:8788".parse().unwrap();
    let mut keys = HashMap::new();
    assert!(validate_gateway_security(bind, &keys, false, None).is_err());
    keys.insert(
        "hash".to_string(),
        GatewayIdentity {
            agent: "agent".to_string(),
            project: "project".to_string(),
            user_id: "user".to_string(),
            key_id: "key".to_string(),
            tier: DEFAULT_GATEWAY_TIER.to_string(),
        },
    );
    assert!(validate_gateway_security(bind, &keys, true, None).is_err());
    assert!(validate_gateway_security(bind, &keys, false, None).is_ok());
}

#[test]
fn audit_evidence_drops_credential_fields() {
    let sanitized = sanitize_audit_evidence(HashMap::from([
        ("authorization".to_string(), "Bearer private".to_string()),
        ("upstream-api-key".to_string(), "private".to_string()),
        ("oauth_token".to_string(), "private".to_string()),
        ("session_cookie".to_string(), "private".to_string()),
        ("refresh_token".to_string(), "private".to_string()),
        ("database_password".to_string(), "private".to_string()),
        ("signing_private_key".to_string(), "private".to_string()),
        ("key_id".to_string(), "gateway-key-1".to_string()),
        ("request_id".to_string(), "request-1".to_string()),
        ("input_tokens".to_string(), "42".to_string()),
    ]));
    assert_eq!(sanitized.len(), 3);
    assert_eq!(sanitized["key_id"], "gateway-key-1");
    assert_eq!(sanitized["request_id"], "request-1");
    assert_eq!(sanitized["input_tokens"], "42");
}

#[test]
fn gateway_success_receipt_uses_canonical_complete_shape() {
    let identity = GatewayIdentity {
        agent: "agent:gateway-test".into(),
        project: "project-a".into(),
        user_id: "user-a".into(),
        key_id: "key-a".into(),
        tier: DEFAULT_GATEWAY_TIER.into(),
    };
    let context = UsageContext {
        request_id: "gateway-op-1".into(),
        lookup_request_id: Some("client-request-1".into()),
        caller_scope: "scope-a".into(),
        operation_id: "gateway-op-1".into(),
        parent_operation_id: Some("parent-op".into()),
        turn_id: Some("turn-1".into()),
        attempt: 2,
        provider_ordinal: 1,
        cycle_id: Some("cycle-1".into()),
        traceparent: Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".into()),
        responses_profile: true,
        responses_terminal_required: true,
        provider: ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        requested_model: Some("gpt-5.5".into()),
        resolved_model: Some("openai/gpt-5.5".into()),
        route_override: Some("openai/gpt-5.5".into()),
        requested_alias: Some("gpt-5.5".into()),
        profile_version: Some("openai.builtin/v3".into()),
        capability_snapshot_version: Some(CAPABILITY_MATRIX_VERSION.into()),
        pricing_snapshot_version: Some("openai.unpriced/v1".into()),
        governance_metadata_status: Some("unknown".into()),
        work_unit_id: Some("work-1".into()),
        pipeline_observation: None,
        request_bytes: 42,
        started_ms: 100,
        route_bias: None,
        policy_scope: Some("project-a".into()),
        policy_version: Some("policy-v1".into()),
        context_admission_policy_version: None,
        context_admission_descriptor_version: None,
        context_admission_decision: None,
        context_admission_reasons: Vec::new(),
        task_class: "primary".into(),
        data_class: "sensitive".into(),
        request_hash: "request-hash".into(),
        budget_subject: Some("project:project-a".into()),
        budget_status: "allowed".into(),
        egress_applied: true,
        cache_requested: true,
    };
    let observation = ResponseObservation {
        output_content: "private model output".into(),
        stop_reason: "end_turn".into(),
    };
    let receipt = build_gateway_operation_receipt(
        &identity,
        &context,
        StatusCode::OK,
        Some(&ResponseUsage {
            input_tokens: 10,
            output_tokens: 5,
            total_tokens: 15,
            cache_read_input_tokens: 100,
            cache_creation_input_tokens: 30,
            cache_creation_5m_input_tokens: 20,
            cache_creation_1h_input_tokens: 10,
            cache_read_reported: true,
            cache_creation_reported: true,
            cache_creation_5m_reported: true,
            cache_creation_1h_reported: true,
            provider_total_tokens: Some(145),
            ..Default::default()
        }),
        Some(&observation),
        None,
        None,
        Some(45),
        Some(27),
    );

    assert_eq!(receipt.version, OPERATION_RECEIPT_VERSION);
    assert_eq!(
        receipt.operation_id,
        gateway_provider_receipt_id("gateway-op-1", "gateway-op-1", 2, 1)
    );
    assert_eq!(receipt.parent_operation_id.as_deref(), Some("gateway-op-1"));
    let intent = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .unwrap();
    assert_eq!(intent.attributes["logical_operation_id"], "gateway-op-1");
    assert_eq!(intent.attributes["attempt_id"], "2");
    let route = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::RouteSelected)
        .unwrap();
    assert_eq!(route.attributes["route_override"], "openai/gpt-5.5");
    assert_eq!(route.attributes["bias_bypassed"], "true");
    let priced_call = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::ModelCalled)
        .unwrap();
    assert_eq!(priced_call.attributes["cost_usd_micros"], "45");
    assert_eq!(priced_call.attributes["cache_read_input_tokens"], "100");
    assert_eq!(
        priced_call.attributes["cache_creation_5m_input_tokens"],
        "20"
    );
    assert_eq!(
        priced_call.attributes["cache_creation_1h_input_tokens"],
        "10"
    );
    assert_eq!(priced_call.attributes["provider_total_tokens"], "145");
    assert_eq!(priced_call.attributes["resolved_model"], "openai/gpt-5.5");
    assert_eq!(
        priced_call.attributes["profile_version"],
        "openai.builtin/v3"
    );
    assert_eq!(
        priced_call.attributes["pricing_snapshot_version"],
        "openai.unpriced/v1"
    );
    assert_eq!(priced_call.attributes["cache_savings_usd_micros"], "27");
    let incomplete_receipt = build_gateway_operation_receipt(
        &identity,
        &context,
        StatusCode::OK,
        None,
        Some(&observation),
        None,
        Some(ReceiptTerminalOutcome::Incomplete("max_output_tokens")),
        None,
        None,
    );
    let outcome = incomplete_receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        .unwrap();
    assert_eq!(outcome.attributes["status"], "incomplete");
    assert_eq!(outcome.attributes["completion_reason"], "max_output_tokens");
    let model_call = incomplete_receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::ModelCalled)
        .unwrap();
    assert_eq!(model_call.attributes["usage_status"], "unknown");
    assert!(!model_call.attributes.contains_key("input_tokens"));
    assert!(!model_call.attributes.contains_key("output_tokens"));
    let circuit_rejection = GatewayRejection {
        status: StatusCode::SERVICE_UNAVAILABLE,
        error_type: "upstream_unavailable".into(),
        reason: "provider circuit is open".into(),
        retry_safety: Some("safe"),
    };
    let circuit_receipt = build_gateway_operation_receipt(
        &identity,
        &context,
        StatusCode::SERVICE_UNAVAILABLE,
        None,
        None,
        Some(ReceiptRejection {
            rejection: &circuit_rejection,
            model_attempted: false,
        }),
        None,
        None,
        None,
    );
    assert!(circuit_receipt.events.iter().all(|event| !matches!(
        event.kind,
        ReceiptEventKind::AttemptStarted
            | ReceiptEventKind::ModelCalled
            | ReceiptEventKind::ArtifactProduced
            | ReceiptEventKind::VerificationRecorded
    )));
    assert_eq!(receipt.initiating_actor, identity.agent);
    assert!(receipt.completeness().complete);
    let receipt_db = SekaiDb::new(":memory:").unwrap();
    receipt_db.put_operation_receipt(&receipt).unwrap();
    assert_eq!(
        receipt_db
            .find_gateway_receipt_by_logical_operation_id("gateway-op-1", Some(2))
            .unwrap()
            .unwrap()
            .operation_id,
        receipt.operation_id
    );
    assert_eq!(
        receipt_db
            .find_operation_receipt_by_request_id(&context.request_id)
            .unwrap()
            .unwrap()
            .operation_id,
        receipt.operation_id
    );
    assert_eq!(
        receipt_db
            .find_operation_receipt_by_lookup_request_id(
                "client-request-1",
                Some("scope-a"),
                Some(&identity.agent),
            )
            .unwrap()
            .unwrap()
            .operation_id,
        receipt.operation_id
    );
    assert!(
        receipt_db
            .find_operation_receipt_by_lookup_request_id(
                "client-request-1",
                Some("scope-a"),
                Some("agent:other"),
            )
            .unwrap()
            .is_none()
    );
    let mut legacy_replay = receipt.clone();
    for event in &mut legacy_replay.events {
        if event.kind == ReceiptEventKind::IntentRecorded {
            event.attributes.remove("caller_scope");
        }
    }
    receipt_db.put_operation_receipt(&legacy_replay).unwrap();
    assert!(
        receipt_db
            .find_operation_receipt_by_lookup_request_id(
                "client-request-1",
                Some("scope-a"),
                Some(&identity.agent),
            )
            .unwrap()
            .is_some()
    );
    let mut duplicate_request = receipt.clone();
    duplicate_request.operation_id = "duplicate-operation".into();
    assert!(
        receipt_db
            .put_operation_receipt(&duplicate_request)
            .is_err()
    );

    let mut other_scope = receipt.clone();
    other_scope.operation_id = "other-scope-operation".into();
    for event in &mut other_scope.events {
        event.operation_id = other_scope.operation_id.clone();
        event.event_id = event
            .event_id
            .replace(&receipt.operation_id, &other_scope.operation_id);
        event.parent_event_id = event
            .parent_event_id
            .as_ref()
            .map(|parent| parent.replace(&receipt.operation_id, &other_scope.operation_id));
        if event.kind == ReceiptEventKind::IntentRecorded {
            event
                .attributes
                .insert("request_id".into(), "other-internal-request".into());
            event
                .attributes
                .insert("caller_scope".into(), "scope-b".into());
        }
    }
    receipt_db.put_operation_receipt(&other_scope).unwrap();
    assert_eq!(
        receipt_db
            .find_operation_receipt_by_lookup_request_id(
                "client-request-1",
                Some("scope-b"),
                Some(&identity.agent),
            )
            .unwrap()
            .unwrap()
            .operation_id,
        other_scope.operation_id
    );
    assert!(
        receipt_db
            .find_operation_receipt_by_lookup_request_id("client-request-1", None, None,)
            .unwrap_err()
            .contains("multiple")
    );

    receipt_db
        .gateway_test_execute_batch(
            "DROP INDEX idx_chisei_operation_receipts_lookup;
             UPDATE chisei_operation_receipts
             SET caller_scope=NULL, request_id='chisei:scope-a:legacy', updated_at=999
             WHERE operation_id='other-scope-operation';",
        )
        .unwrap();
    receipt_db.gateway_test_migrate_chisei().unwrap();
    assert_eq!(
        receipt_db
            .find_operation_receipt_by_lookup_request_id(
                "client-request-1",
                Some("scope-a"),
                Some(&identity.agent),
            )
            .unwrap()
            .unwrap()
            .operation_id,
        receipt.operation_id
    );
    receipt_db.put_operation_receipt(&other_scope).unwrap();
    assert!(
        receipt_db
            .find_operation_receipt_by_lookup_request_id(
                "client-request-1",
                Some("scope-b"),
                Some(&identity.agent),
            )
            .unwrap()
            .is_none()
    );

    let mut spoofed_request = receipt.clone();
    spoofed_request.operation_id = "spoofed-operation".into();
    for event in &mut spoofed_request.events {
        if event.kind == ReceiptEventKind::IntentRecorded {
            event.attributes.remove("request_id");
            event.attributes.remove("lookup_request_id");
        } else if event.kind == ReceiptEventKind::VerificationRecorded {
            event
                .attributes
                .insert("request_id".into(), "spoofed-request".into());
        }
    }
    receipt_db.put_operation_receipt(&spoofed_request).unwrap();
    assert!(
        receipt_db
            .find_operation_receipt_by_request_id("spoofed-request")
            .unwrap()
            .is_none()
    );
    let serialized = serde_json::to_string(&receipt).unwrap();
    assert!(serialized.contains("openai.builtin/v3"));
    assert!(serialized.contains(CAPABILITY_MATRIX_VERSION));
    assert!(serialized.contains("openai.unpriced/v1"));
    assert!(!serialized.contains("private task body"));
    assert!(!serialized.contains("private model output"));
}

#[test]
fn gateway_refusal_receipt_is_terminal_and_complete() {
    let identity = GatewayIdentity {
        agent: "agent:gateway-test".into(),
        project: "project-a".into(),
        user_id: "user-a".into(),
        key_id: "key-a".into(),
        tier: DEFAULT_GATEWAY_TIER.into(),
    };
    let context = UsageContext {
        request_id: "gateway-op-denied".into(),
        lookup_request_id: None,
        caller_scope: "scope-a".into(),
        operation_id: "gateway-op-denied".into(),
        parent_operation_id: None,
        turn_id: None,
        attempt: 1,
        provider_ordinal: 1,
        cycle_id: None,
        traceparent: None,
        responses_profile: true,
        responses_terminal_required: true,
        provider: ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        requested_model: Some("gpt-5.5".into()),
        resolved_model: None,
        route_override: None,
        requested_alias: Some("gpt-5.5".into()),
        profile_version: Some("openai.builtin/v3".into()),
        capability_snapshot_version: Some(CAPABILITY_MATRIX_VERSION.into()),
        pricing_snapshot_version: Some("openai.unpriced/v1".into()),
        governance_metadata_status: Some("unknown".into()),
        work_unit_id: Some("legacy-work-unit".into()),
        pipeline_observation: None,
        request_bytes: 42,
        started_ms: 100,
        route_bias: None,
        policy_scope: None,
        policy_version: None,
        context_admission_policy_version: None,
        context_admission_descriptor_version: None,
        context_admission_decision: None,
        context_admission_reasons: Vec::new(),
        task_class: "primary".into(),
        data_class: "unclassified".into(),
        request_hash: "request-hash".into(),
        budget_subject: None,
        budget_status: "not_evaluated".into(),
        egress_applied: false,
        cache_requested: false,
    };
    let rejection =
        GatewayRejection::json(StatusCode::FORBIDDEN, "policy_denied", "request denied");
    let receipt = build_gateway_operation_receipt(
        &identity,
        &context,
        rejection.status,
        None,
        None,
        Some(ReceiptRejection {
            rejection: &rejection,
            model_attempted: false,
        }),
        None,
        None,
        None,
    );
    assert_eq!(
        receipt.parent_operation_id.as_deref(),
        Some("legacy-work-unit")
    );

    assert!(receipt.completeness().complete);
    assert!(receipt.events.iter().any(|event| {
        event.kind == ReceiptEventKind::OutcomeRecorded
            && event.attributes.get("status").map(String::as_str) == Some("denied")
    }));
    assert!(receipt.events.iter().any(|event| {
        event.kind == ReceiptEventKind::PolicyDecided
            && event.attributes.get("status").map(String::as_str) == Some("denied")
    }));

    let budget_rejection = GatewayRejection::json(
        StatusCode::TOO_MANY_REQUESTS,
        "budget_exceeded",
        "budget denied",
    );
    let budget_receipt = build_gateway_operation_receipt(
        &identity,
        &context,
        budget_rejection.status,
        None,
        None,
        Some(ReceiptRejection {
            rejection: &budget_rejection,
            model_attempted: false,
        }),
        None,
        None,
        None,
    );
    assert!(budget_receipt.events.iter().any(|event| {
        event.kind == ReceiptEventKind::PolicyDecided
            && event.attributes.get("status").map(String::as_str) == Some("not_evaluated")
    }));
    assert!(budget_receipt.events.iter().any(|event| {
        event.kind == ReceiptEventKind::BudgetDecided
            && event.attributes.get("status").map(String::as_str) == Some("denied")
    }));
}

#[tokio::test]
async fn rate_limit_is_enforced_for_key_and_agent() {
    let mut runtime = GatewayRuntime::new(Duration::from_secs(30), None);
    runtime.rate_limit_requests = 2;
    runtime.global_rate_limit_requests = 100;
    runtime.rate_limit_window = Duration::from_secs(60);
    let identity = GatewayIdentity {
        agent: "agent".to_string(),
        project: "project".to_string(),
        user_id: "user".to_string(),
        key_id: "key".to_string(),
        tier: DEFAULT_GATEWAY_TIER.to_string(),
    };
    assert_eq!(rate_limit_rejection(&runtime, &identity).await, None);
    assert_eq!(rate_limit_rejection(&runtime, &identity).await, None);
    assert_eq!(
        rate_limit_rejection(&runtime, &identity).await.as_deref(),
        Some("agent:agent")
    );

    let other_key = GatewayIdentity {
        key_id: "other-key".to_string(),
        ..identity
    };
    assert_eq!(
        rate_limit_rejection(&runtime, &other_key).await.as_deref(),
        Some("agent:agent")
    );
}

#[tokio::test]
async fn global_rate_limit_blocks_identity_rotation() {
    let mut runtime = GatewayRuntime::new(Duration::from_secs(30), None);
    runtime.rate_limit_requests = 100;
    runtime.global_rate_limit_requests = 2;
    let identity = |agent: &str| GatewayIdentity {
        agent: agent.to_string(),
        project: "project".to_string(),
        user_id: format!("agent:{agent}"),
        key_id: String::new(),
        tier: DEFAULT_GATEWAY_TIER.to_string(),
    };
    assert_eq!(rate_limit_rejection(&runtime, &identity("one")).await, None);
    assert_eq!(rate_limit_rejection(&runtime, &identity("two")).await, None);
    assert_eq!(
        rate_limit_rejection(&runtime, &identity("three"))
            .await
            .as_deref(),
        Some("gateway:global")
    );
}

#[tokio::test]
async fn oversized_gateway_request_is_rejected() {
    let mut runtime = GatewayRuntime::new(Duration::from_secs(30), None);
    runtime.max_request_bytes = 16;
    let gateway_base = spawn_gateway_with_runtime(routing_config(), runtime).await;
    let response = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("client-oauth-token")
        .header(X_CHISEI_AGENT, "codex-app")
        .body(r#"{"model":"gpt-5.5","input":"too large"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

fn routing_config() -> GatewayConfig {
    GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "https://openai.example/v1".to_string(),
        openai_api_key: None,
        anthropic_base_url: "https://anthropic.example".to_string(),
        anthropic_api_key: None,
        ollama_base_url: "http://localhost:11434/v1".to_string(),
        native_base_url: Some("http://localhost:9999/v1".to_string()),
        chisei_grpc_target: None,
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: true,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    }
}

#[tokio::test]
async fn pending_usage_recovery_is_deduplicated_and_bounded() {
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None);
    let usage = |work_unit: String, tokens_used| RecordUsageRequest {
        user_id: "agent:safe-agent".into(),
        tokens_used,
        subject: String::new(),
        project: "default".into(),
        agent: "safe-agent".into(),
        key_id: "safe-agent".into(),
        work_unit: work_unit.clone(),
        metric: String::new(),
        idempotency_key: format!("test-usage-{work_unit}"),
        operation_receipt_json: String::new(),
        sample_observation: None,
    };
    assert!(
        queue_pending_usage_records(&runtime, [usage("same".into(), 2), usage("same".into(), 3)],)
            .await
    );
    {
        let cache = runtime.usage_recovery.read().await;
        assert_eq!(cache.pending_usage_records.len(), 1);
        assert_eq!(
            cache
                .pending_usage_records
                .values()
                .next()
                .unwrap()
                .tokens_used,
            2
        );
    }
    for index in 1..MAX_PENDING_USAGE_RECOVERIES {
        assert!(queue_pending_usage_records(&runtime, [usage(format!("work-{index}"), 1)],).await);
    }
    assert!(!queue_pending_usage_records(&runtime, [usage("overflow".into(), 1)]).await);
    let cache = runtime.usage_recovery.read().await;
    assert_eq!(
        cache.pending_usage_records.len(),
        MAX_PENDING_USAGE_RECOVERIES
    );
    assert!(cache.usage_recovery_saturated);
}

#[tokio::test]
async fn invalid_usage_recovery_journal_fails_closed() {
    let path = std::env::temp_dir().join(format!(
        "chisei-invalid-usage-recovery-{}.json",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&path, b"not-json").unwrap();

    let runtime = GatewayRuntime::new(Duration::from_secs(30), None)
        .with_usage_recovery_path(Some(path.clone()));
    let cache = runtime.usage_recovery.read().await;
    assert!(cache.pending_usage_records.is_empty());
    assert!(cache.usage_recovery_saturated);

    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn missing_usage_recovery_journal_is_initialized() {
    let path = std::env::temp_dir().join(format!(
        "chisei-new-usage-recovery-{}.json",
        uuid::Uuid::new_v4()
    ));

    let runtime = GatewayRuntime::new(Duration::from_secs(30), None)
        .with_usage_recovery_path(Some(path.clone()));
    let cache = runtime.usage_recovery.read().await;
    assert!(!cache.usage_recovery_saturated);
    assert_eq!(std::fs::read(&path).unwrap(), b"[]");

    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn unavailable_usage_recovery_journal_fails_closed() {
    let parent = std::env::temp_dir().join(format!(
        "chisei-blocked-usage-recovery-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&parent, b"not-a-directory").unwrap();
    let path = parent.join("journal.json");

    let runtime =
        GatewayRuntime::new(Duration::from_secs(30), None).with_usage_recovery_path(Some(path));
    let cache = runtime.usage_recovery.read().await;
    assert!(cache.usage_recovery_saturated);

    std::fs::remove_file(parent).unwrap();
}

#[tokio::test]
async fn gateway_recovery_spool_replays_llm_rows() {
    let directory = std::env::temp_dir().join(format!("chisei-recovery-{}", uuid::Uuid::new_v4()));
    let recovery_path = directory.join("recovery.jsonl");
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None)
        .with_recovery_spool_path(Some(recovery_path.clone()));
    tokio::fs::create_dir_all(&directory).await.unwrap();
    tokio::fs::write(&recovery_path, br#"{"kind":"llm_row""#)
        .await
        .unwrap();
    let values = HashMap::from([
        ("request_id".into(), "recovered-request".into()),
        ("timestamp_ms".into(), "1".into()),
        ("status".into(), "200".into()),
        (
            "resolved_model".into(),
            "anthropic/claude-sonnet-4-6".into(),
        ),
        ("profile_version".into(), "anthropic.builtin/v3".into()),
        (
            "pricing_snapshot_version".into(),
            "anthropic.cache/v1".into(),
        ),
        ("cache_creation_5m_input_tokens".into(), "20".into()),
        ("cache_creation_1h_input_tokens".into(), "10".into()),
        ("cache_savings_usd_micros".into(), "270".into()),
    ]);
    assert!(
        append_gateway_recovery(
            &runtime,
            GatewayRecoveryRecord::LlmRow {
                values: values.clone(),
            },
        )
        .await
    );
    assert!(
        append_gateway_recovery(
            &runtime,
            GatewayRecoveryRecord::LlmRow {
                values: values.clone(),
            },
        )
        .await
    );
    let (target, db) = spawn_control_plane().await;
    let mut config = routing_config();
    config.chisei_grpc_target = Some(target);
    replay_gateway_recovery(&config, &runtime).await;
    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(
        rows.iter()
            .filter(|row| row.get("request_id") == Some(&"recovered-request".into()))
            .count(),
        1
    );
    let recovered = rows
        .iter()
        .find(|row| row.get("request_id") == Some(&"recovered-request".into()))
        .unwrap();
    assert_eq!(
        recovered
            .get("pricing_snapshot_version")
            .map(String::as_str),
        Some("anthropic.cache/v1")
    );
    assert_eq!(
        recovered
            .get("cache_creation_5m_input_tokens")
            .map(String::as_str),
        Some("20")
    );
    assert_eq!(
        recovered
            .get("cache_creation_1h_input_tokens")
            .map(String::as_str),
        Some("10")
    );
    assert_eq!(
        recovered
            .get("cache_savings_usd_micros")
            .map(String::as_str),
        Some("270")
    );
    assert!(!recovery_path.exists());
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn circuit_breaker_opens_at_threshold_and_resets_on_success() {
    let resilience = ResilienceConfig {
        circuit_failure_threshold: 2,
        circuit_cooldown: Duration::from_secs(60),
        ..ResilienceConfig::default()
    };
    let mut circuit = CircuitBreakerState::default();
    circuit.record_failure("first".into(), &resilience);
    assert!(!circuit.is_open());
    circuit.record_failure("second".into(), &resilience);
    assert!(circuit.is_open());
    circuit.record_success();
    assert!(!circuit.is_open());
    assert_eq!(circuit.consecutive_failures, 0);
}

#[test]
fn provider_health_normalizes_quota_rate_limit_and_overload() {
    assert_eq!(
        provider_health_from_status(reqwest::StatusCode::PAYMENT_REQUIRED),
        ProviderHealth::QuotaExhausted
    );
    assert_eq!(
        provider_health_from_status(reqwest::StatusCode::TOO_MANY_REQUESTS),
        ProviderHealth::RateLimited
    );
    assert_eq!(
        provider_health_from_status(reqwest::StatusCode::SERVICE_UNAVAILABLE),
        ProviderHealth::Overloaded
    );
    assert_eq!(
        provider_health_from_status(reqwest::StatusCode::BAD_REQUEST),
        ProviderHealth::Healthy
    );
}

#[test]
fn quota_and_rate_limit_signals_immediately_reduce_eligibility() {
    let resilience = ResilienceConfig {
        circuit_failure_threshold: 10,
        circuit_cooldown: Duration::from_secs(60),
        ..ResilienceConfig::default()
    };
    for health in [ProviderHealth::RateLimited, ProviderHealth::QuotaExhausted] {
        let mut circuit = CircuitBreakerState::default();
        circuit.record_http_signal(health, Some(Duration::from_secs(30)), &resilience);
        assert!(circuit.is_open());
        assert_eq!(circuit.health, health);
    }
}

#[test]
fn retry_after_is_clamped_to_a_safe_circuit_duration() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::RETRY_AFTER,
        reqwest::header::HeaderValue::from_static("18446744073709551615"),
    );
    assert_eq!(
        retry_after_duration(&headers),
        Some(Duration::from_secs(MAX_PROVIDER_RETRY_AFTER_SECS))
    );

    let future = std::time::SystemTime::now() + Duration::from_secs(120);
    headers.insert(
        reqwest::header::RETRY_AFTER,
        reqwest::header::HeaderValue::from_str(&httpdate::fmt_http_date(future)).unwrap(),
    );
    let parsed = retry_after_duration(&headers).unwrap();
    assert!((119..=120).contains(&parsed.as_secs()));
}

#[test]
fn canary_admission_requires_trusted_identity_and_bounded_class() {
    let mut headers = HeaderMap::new();
    headers.insert(&X_CHISEI_TASK_CLASS, HeaderValue::from_static("background"));
    let identity = GatewayIdentity {
        agent: "test".into(),
        project: "default".into(),
        user_id: "agent:test".into(),
        key_id: "test".into(),
        tier: "untrusted".into(),
    };
    let mut context = IdentityContext::machine(identity, UpstreamAuthMode::GatewayKey);
    assert!(!canary_admission_allowed(&context, &headers));
    context.identity.tier = "low-risk".into();
    assert!(canary_admission_allowed(&context, &headers));
    context.upstream_auth = UpstreamAuthMode::Passthrough;
    assert!(!canary_admission_allowed(&context, &headers));
    context.upstream_auth = UpstreamAuthMode::GatewayKey;
    headers.insert(
        &X_CHISEI_TASK_CLASS,
        HeaderValue::from_static("interactive"),
    );
    assert!(!canary_admission_allowed(&context, &headers));
}

#[test]
fn provider_circuit_opens_after_threshold_and_recovers_on_success() {
    let resilience = ResilienceConfig {
        circuit_failure_threshold: 2,
        circuit_cooldown: Duration::from_secs(60),
        ..ResilienceConfig::default()
    };
    let mut circuit = CircuitBreakerState::default();
    circuit.record_failure("upstream-1".into(), &resilience);
    assert!(!circuit.is_open());
    circuit.record_failure("upstream-2".into(), &resilience);
    assert!(circuit.is_open());
    circuit.publish_metrics("openai");
    circuit.record_success();
    assert!(!circuit.is_open());
    circuit.publish_metrics("openai");
}

#[tokio::test]
async fn after_threshold_failures_routing_selects_authorized_fallback() {
    let runtime =
        GatewayRuntime::new(Duration::from_secs(30), None).with_resilience(ResilienceConfig {
            circuit_failure_threshold: 2,
            circuit_cooldown: Duration::from_secs(60),
            ..ResilienceConfig::default()
        });
    {
        let mut circuits = runtime.upstream_circuits.write().await;
        let circuit = circuits.entry("openai".into()).or_default();
        circuit.record_failure("fail-1".into(), &runtime.resilience);
        circuit.record_failure("fail-2".into(), &runtime.resilience);
        circuit.publish_metrics("openai");
        assert!(circuit.is_open());
    }
    let decision = PolicyPreflight {
        body: br#"{"model":"openai/gpt-5.5","input":"hello"}"#.to_vec(),
        resolved_model: Some("openai/gpt-5.5".into()),
        resolved_provider: ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        route_bias: None,
        policy_scope: Some("project:default".into()),
        policy_version: Some("v1".into()),
        fallback_models: vec!["ollama/llama3.2".into()],
        data_class: None,
        context_admission_policy_version: None,
        context_admission_descriptor_version: None,
        context_admission_decision: None,
        context_admission_reasons: Vec::new(),
    };
    let selected = select_healthy_policy_fallback(
        &runtime,
        &ProviderRegistry::built_in(),
        decision,
        Some(CapabilityRequestSurface::Responses),
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(selected.resolved_model.as_deref(), Some("ollama/llama3.2"));
    assert_eq!(selected.route_bias.as_deref(), Some("health_fallback"));
}

#[tokio::test]
async fn unhealthy_routes_use_only_policy_authorized_equivalent_fallbacks() {
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None);
    runtime.upstream_circuits.write().await.insert(
        "openai".into(),
        CircuitBreakerState {
            consecutive_failures: 1,
            open_until: Some(Instant::now() + Duration::from_secs(60)),
            last_failure: Some("rate limited".into()),
            health: ProviderHealth::RateLimited,
        },
    );
    let decision = PolicyPreflight {
        body: br#"{"model":"openai/gpt-5.5","input":"hello"}"#.to_vec(),
        resolved_model: Some("openai/gpt-5.5".into()),
        resolved_provider: ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        route_bias: None,
        policy_scope: Some("project:default".into()),
        policy_version: Some("v1".into()),
        fallback_models: vec!["ollama/llama3.2".into()],
        data_class: None,
        context_admission_policy_version: None,
        context_admission_descriptor_version: None,
        context_admission_decision: None,
        context_admission_reasons: Vec::new(),
    };
    let selected = select_healthy_policy_fallback(
        &runtime,
        &ProviderRegistry::built_in(),
        decision,
        Some(CapabilityRequestSurface::Responses),
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(selected.resolved_model.as_deref(), Some("ollama/llama3.2"));
    assert_eq!(selected.route_bias.as_deref(), Some("health_fallback"));
}

#[tokio::test]
async fn health_fallback_fails_when_capabilities_are_not_equivalent() {
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None);
    runtime.upstream_circuits.write().await.insert(
        "openai".into(),
        CircuitBreakerState {
            consecutive_failures: 1,
            open_until: Some(Instant::now() + Duration::from_secs(60)),
            last_failure: Some("unavailable".into()),
            health: ProviderHealth::Unavailable,
        },
    );
    let decision = PolicyPreflight {
        body: br#"{"model":"openai/gpt-5.5","input":"hello","tools":[{"type":"function","name":"read"}]}"#.to_vec(),
        resolved_model: Some("openai/gpt-5.5".into()),
        resolved_provider: ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        route_bias: None,
        policy_scope: Some("project:default".into()),
        policy_version: Some("v1".into()),
        fallback_models: vec!["native/native-default".into()],
        data_class: None,
        context_admission_policy_version: None,
        context_admission_descriptor_version: None,
        context_admission_decision: None,
        context_admission_reasons: Vec::new(),
    };
    let rejection = select_healthy_policy_fallback(
        &runtime,
        &ProviderRegistry::built_in(),
        decision,
        Some(CapabilityRequestSurface::Responses),
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        false,
        false,
    )
    .await
    .unwrap_err();
    let response = rejection.response();
    assert_eq!(response.headers()[&X_CHISEI_RETRY_SAFETY], "safe");
}

#[tokio::test]
async fn local_free_health_fallback_never_selects_a_paid_provider() {
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None);
    runtime.upstream_circuits.write().await.insert(
        "ollama".into(),
        CircuitBreakerState {
            consecutive_failures: 1,
            open_until: Some(Instant::now() + Duration::from_secs(60)),
            last_failure: Some("unavailable".into()),
            health: ProviderHealth::Unavailable,
        },
    );
    let decision = PolicyPreflight {
        body: br#"{"model":"ollama/llama3.2","input":"hello"}"#.to_vec(),
        resolved_model: Some("ollama/llama3.2".into()),
        resolved_provider: ProviderKind::OpenAi(OpenAiRuntime::Ollama),
        route_bias: Some("local_free".into()),
        policy_scope: Some("project:default".into()),
        policy_version: Some("v1".into()),
        fallback_models: vec!["openai/gpt-5.5".into()],
        data_class: None,
        context_admission_policy_version: None,
        context_admission_descriptor_version: None,
        context_admission_decision: None,
        context_admission_reasons: Vec::new(),
    };
    assert!(
        select_healthy_policy_fallback(
            &runtime,
            &ProviderRegistry::built_in(),
            decision,
            Some(CapabilityRequestSurface::Responses),
            ProviderKind::OpenAi(OpenAiRuntime::Ollama),
            false,
            true,
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn mid_request_failover_selects_next_candidate_after_live_failure() {
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None);
    // Primary is still closed-circuit-healthy; mid-request failover must not
    // require the breaker to already be open.
    let decision = PolicyPreflight {
        body: br#"{"model":"openai/gpt-5.5","input":"hello"}"#.to_vec(),
        resolved_model: Some("openai/gpt-5.5".into()),
        resolved_provider: ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        route_bias: None,
        policy_scope: Some("project:default".into()),
        policy_version: Some("v1".into()),
        fallback_models: vec!["ollama/llama3.2".into()],
        data_class: None,
        context_admission_policy_version: None,
        context_admission_descriptor_version: None,
        context_admission_decision: None,
        context_admission_reasons: Vec::new(),
    };
    let next = select_next_failover_candidate(
        &runtime,
        &ProviderRegistry::built_in(),
        &decision,
        Some(CapabilityRequestSurface::Responses),
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        false,
        false,
        &["openai"],
    )
    .await
    .unwrap()
    .expect("fallback candidate");
    assert_eq!(next.resolved_model.as_deref(), Some("ollama/llama3.2"));
    assert_eq!(next.route_bias.as_deref(), Some("health_fallback"));
    // Mid-request provider receipts are distinct via provider ordinal without
    // consuming the client-controlled attempt namespace.
    assert_ne!(
        gateway_provider_receipt_id("op-1", "req-1", 1, 1),
        gateway_provider_receipt_id("op-1", "req-1", 1, 2)
    );
    assert_eq!(
        gateway_provider_receipt_id("op-1", "req-1", 1, 1),
        gateway_provider_receipt_id("op-1", "req-1", 1, 1)
    );
}

#[tokio::test]
async fn mid_request_failover_skips_already_tried_and_fails_closed_on_unsafe() {
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None);
    runtime.upstream_circuits.write().await.insert(
        "ollama".into(),
        CircuitBreakerState {
            consecutive_failures: 1,
            open_until: Some(Instant::now() + Duration::from_secs(60)),
            last_failure: Some("unavailable".into()),
            health: ProviderHealth::Unavailable,
        },
    );
    let decision = PolicyPreflight {
        body: br#"{"model":"openai/gpt-5.5","input":"hello"}"#.to_vec(),
        resolved_model: Some("openai/gpt-5.5".into()),
        resolved_provider: ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        route_bias: None,
        policy_scope: Some("project:default".into()),
        policy_version: Some("v1".into()),
        fallback_models: vec!["ollama/llama3.2".into()],
        data_class: None,
        context_admission_policy_version: None,
        context_admission_descriptor_version: None,
        context_admission_decision: None,
        context_admission_reasons: Vec::new(),
    };
    // Exclude openai (failed live) and ollama is circuit-open → no candidate.
    assert!(
        select_next_failover_candidate(
            &runtime,
            &ProviderRegistry::built_in(),
            &decision,
            Some(CapabilityRequestSurface::Responses),
            ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
            false,
            false,
            &["openai"],
        )
        .await
        .unwrap()
        .is_none()
    );
}

#[test]
fn client_dispatch_adapter_allows_anthropic_to_openai_only() {
    assert!(client_can_dispatch_to_provider(
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        ProviderKind::OpenAi(OpenAiRuntime::Ollama),
    ));
    assert!(client_can_dispatch_to_provider(
        ProviderKind::Anthropic,
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
    ));
    assert!(!client_can_dispatch_to_provider(
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        ProviderKind::Anthropic,
    ));
}

#[tokio::test]
async fn control_plane_circuit_rejects_after_repeated_connection_failure() {
    let runtime =
        GatewayRuntime::new(Duration::from_secs(30), None).with_resilience(ResilienceConfig {
            control_plane_retries: 0,
            circuit_failure_threshold: 1,
            circuit_cooldown: Duration::from_secs(60),
            ..ResilienceConfig::default()
        });
    let target = "/tmp/sekai-chisei-missing-circuit-test.sock";
    assert!(connect_governance(&runtime, target).await.is_err());
    let error = connect_governance(&runtime, target).await.unwrap_err();
    assert!(error.to_string().contains("circuit is open"));
}

#[test]
fn capability_routing_failure_preserves_gateway_error_type() {
    let rejection = governance_status_rejection(&tonic::Status::failed_precondition(
        "capability_unsupported: no available candidate can preserve required capabilities",
    ));

    assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejection.error_type, "capability_unsupported");
    assert!(
        rejection
            .reason
            .contains("no available candidate can preserve required capabilities")
    );
}

#[tokio::test]
async fn stalled_control_plane_rpc_is_bounded_and_opens_circuit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let runtime =
        GatewayRuntime::new(Duration::from_secs(30), None).with_resilience(ResilienceConfig {
            control_plane_retries: 0,
            control_plane_timeout: Duration::from_millis(25),
            circuit_failure_threshold: 1,
            ..ResilienceConfig::default()
        });

    let started = Instant::now();
    let channel = connect_governance(&runtime, &target).await.unwrap();
    let error = SekaiServiceClient::new(channel)
        .list_schema_types(gateway_request(ListSchemaTypesRequest {}))
        .await
        .unwrap_err();
    assert!(is_transient_governance_status(&error));
    record_control_plane_failure(&runtime, &error).await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(runtime.control_plane_circuit.read().await.is_open());
}

#[tokio::test]
async fn successful_key_store_lookup_resets_control_plane_failures() {
    let (target, db) = spawn_control_plane().await;
    let key = "sk-chisei-resilient-worker";
    db.create_object(&crate::domain::Object {
        id: "gateway-key-resilient-worker".into(),
        kind: "gateway_key".into(),
        name: "resilient-worker".into(),
        namespace: "default".into(),
        external_id: "gateway_key:resilient-worker:default".into(),
        properties: HashMap::from([
            ("agent".into(), "resilient-worker".into()),
            ("project".into(), "default".into()),
            ("status".into(), "active".into()),
            ("key_hash".into(), hash_gateway_key(key)),
        ]),
        created: 0,
        updated: 0,
    })
    .unwrap();
    let runtime =
        GatewayRuntime::new(Duration::from_secs(30), None).with_resilience(ResilienceConfig {
            circuit_failure_threshold: 2,
            ..ResilienceConfig::default()
        });
    runtime
        .control_plane_circuit
        .write()
        .await
        .record_failure("transient".into(), &runtime.resilience);
    let mut config = routing_config();
    config.chisei_grpc_target = Some(target);
    let state = GatewayState {
        client: runtime.http_timeouts.client(),
        config: Arc::new(config),
        runtime: runtime.clone(),
    };

    assert!(
        resolve_identity_from_key_store(&state, key)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        runtime
            .control_plane_circuit
            .read()
            .await
            .consecutive_failures,
        0
    );
}

#[tokio::test]
async fn gateway_health_and_readiness_reflect_governance_availability() {
    let (upstream_base, _) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let mut unavailable_config = routing_config();
    unavailable_config.openai_base_url = upstream_base.clone();
    unavailable_config.chisei_grpc_target = None;
    let gateway_base = spawn_gateway_with_config(unavailable_config).await;
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("{gateway_base}/healthz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .get(format!("{gateway_base}/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    let (target, _) = spawn_control_plane().await;
    let mut config = routing_config();
    config.openai_base_url = upstream_base;
    config.chisei_grpc_target = Some(target);
    let ready_gateway = spawn_gateway_with_config(config).await;
    assert_eq!(
        client
            .get(format!("{ready_gateway}/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn readiness_probe_failures_do_not_mutate_the_traffic_circuit() {
    let runtime =
        GatewayRuntime::new(Duration::from_secs(30), None).with_resilience(ResilienceConfig {
            circuit_failure_threshold: 1,
            ..ResilienceConfig::default()
        });
    let mut config = routing_config();
    config.chisei_grpc_target =
        Some("/tmp/sekai-chisei-missing-readiness-isolation-test.sock".to_string());
    let gateway_base = spawn_gateway_with_runtime(config, runtime.clone()).await;
    for _ in 0..3 {
        assert_eq!(
            reqwest::Client::new()
                .get(format!("{gateway_base}/readyz"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let circuit = runtime.control_plane_circuit.read().await;
    assert_eq!(circuit.consecutive_failures, 0);
    assert!(!circuit.is_open());
}

#[tokio::test]
async fn readiness_fails_when_provider_registry_disappears() {
    let directory = std::env::temp_dir().join(format!(
        "chisei-readiness-provider-registry-{}",
        uuid::Uuid::new_v4()
    ));
    let registry_path = directory.join("registry.json");
    let audit_path = directory.join("audit.jsonl");
    crate::provider_profile::refresh_provider_registry_async(&registry_path)
        .await
        .unwrap();
    std::fs::remove_file(&registry_path).unwrap();
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None)
        .with_provider_registry_state_path(Some(registry_path))
        .with_recovery_spool_path(Some(audit_path));
    let config = routing_config();
    let state = GatewayState {
        client: runtime.http_timeouts.client(),
        config: Arc::new(config),
        runtime,
    };

    let response = gateway_readiness(State(state)).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn capability_snapshot_identifies_registry_state() {
    let mut registry = ProviderRegistry::built_in();
    registry.state_version = 7;

    assert_eq!(
        capability_snapshot_identifier(&registry),
        format!("{CAPABILITY_MATRIX_VERSION}:registry-state-7")
    );
}

#[test]
fn request_rewrite_uses_promoted_registry_models() {
    let mut registry = ProviderRegistry::built_in();
    registry
        .lifecycle_overrides
        .push(crate::provider_profile::RegistryLifecycleOverride {
            target_kind: "provider".into(),
            target: "meta".into(),
            state: "enabled".into(),
            version: 1,
            actor: "operator".into(),
            reason: "verified promotion".into(),
            changed_at: "2026-07-16T00:00:00Z".into(),
        });
    registry.state_version = 1;
    let resolved = registry.resolve_model("meta/muse-spark-1.1").unwrap();
    let prepared = rewrite_resolved_request_model(
        br#"{"model":"meta/muse-spark-1.1","input":"hello"}"#,
        &resolved,
    )
    .unwrap();

    let body: serde_json::Value = serde_json::from_slice(&prepared).unwrap();
    assert_eq!(body["model"], "muse-spark-1.1");
}

#[tokio::test]
async fn request_preparation_rejects_unconfigured_native_endpoint() {
    let registry = ProviderRegistry::built_in();
    let resolved = registry.resolve_model("native/mistral").unwrap();
    let identity = GatewayIdentity {
        agent: "agent:test".into(),
        project: "test".into(),
        user_id: "user:test".into(),
        key_id: "key:test".into(),
        tier: "low-risk".into(),
    };
    let mut config = routing_config();
    config.native_base_url = None;
    let response = match prepare_upstream_request(
        &config,
        &identity,
        &"/v1/responses".parse().unwrap(),
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        ProviderKind::OpenAi(OpenAiRuntime::Native),
        br#"{"model":"native/mistral","input":"hello"}"#.to_vec(),
        Some(&resolved),
    )
    .await
    {
        Ok(_) => panic!("native route unexpectedly used another provider endpoint"),
        Err(response) => response,
    };

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn provider_contact_guard_refreshes_durable_registry_state() {
    let directory = std::env::temp_dir().join(format!(
        "chisei-provider-contact-registry-{}",
        uuid::Uuid::new_v4()
    ));
    let registry_path = directory.join("registry.json");
    crate::provider_profile::refresh_provider_registry_async(&registry_path)
        .await
        .unwrap();
    std::fs::remove_file(&registry_path).unwrap();
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None)
        .with_provider_registry_state_path(Some(registry_path));
    let guard = ProviderContactGuard {
        provider: ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        resolved_model: Some("openai/gpt-5.5".into()),
        requirements: None,
    };

    let (rejection, snapshot_version) = guard.enforce(&runtime).await.unwrap_err();

    assert_eq!(rejection.error_type, "provider_registry_unavailable");
    assert!(snapshot_version.contains("registry-state-"));
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn provider_contact_guard_refreshes_each_attempt() {
    let directory = std::env::temp_dir().join(format!(
        "chisei-provider-contact-cache-{}",
        uuid::Uuid::new_v4()
    ));
    let registry_path = directory.join("registry.json");
    crate::provider_profile::refresh_provider_registry_async(&registry_path)
        .await
        .unwrap();
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None)
        .with_provider_registry_state_path(Some(registry_path.clone()));
    let guard = ProviderContactGuard {
        provider: ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        resolved_model: Some("openai/gpt-5.5".into()),
        requirements: None,
    };

    guard.enforce(&runtime).await.unwrap();
    assert_eq!(
        runtime
            .provider_registry_refresh_generation
            .load(Ordering::Acquire),
        1
    );
    guard.enforce(&runtime).await.unwrap();
    assert_eq!(
        runtime
            .provider_registry_refresh_generation
            .load(Ordering::Acquire),
        2
    );
    std::fs::remove_file(&registry_path).unwrap();
    assert!(guard.enforce(&runtime).await.is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn concurrent_forced_registry_refreshes_share_one_generation() {
    let directory = std::env::temp_dir().join(format!(
        "chisei-provider-refresh-single-flight-{}",
        uuid::Uuid::new_v4()
    ));
    let registry_path = directory.join("registry.json");
    crate::provider_profile::refresh_provider_registry_async(&registry_path)
        .await
        .unwrap();
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None)
        .with_provider_registry_state_path(Some(registry_path));
    let observed_generation = runtime
        .provider_registry_refresh_generation
        .load(Ordering::Acquire);
    let tasks = (0..8)
        .map(|_| {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                runtime
                    .refresh_registry_snapshot_after_generation(true, observed_generation)
                    .await
            })
        })
        .collect::<Vec<_>>();

    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(
        runtime
            .provider_registry_refresh_generation
            .load(Ordering::Acquire),
        1
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn lifecycle_mutation_invalidation_reloads_the_runtime_snapshot() {
    let directory = std::env::temp_dir().join(format!(
        "chisei-provider-refresh-invalidation-{}",
        uuid::Uuid::new_v4()
    ));
    let registry_path = directory.join("registry.json");
    crate::provider_profile::refresh_provider_registry_async(&registry_path)
        .await
        .unwrap();
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None)
        .with_provider_registry_state_path(Some(registry_path.clone()));
    let before = runtime.refresh_registry_snapshot(false).await.unwrap();
    std::fs::write(
        &registry_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "registry_version": before.version.clone(),
            "state_version": 1,
            "lifecycle_overrides": [{
                "target_kind": "provider",
                "target": "openai",
                "state": "disabled",
                "version": 1,
                "actor": "operator",
                "reason": "test invalidation",
                "changed_at": "2026-07-14T00:00:00Z"
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    runtime.invalidate_registry_snapshot().await;
    let after = runtime.refresh_registry_snapshot(false).await.unwrap();

    assert_eq!(before.state_version, 0);
    assert_eq!(after.state_version, 1);
    assert!(after.resolve_model("openai/gpt-5.5").is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn gateway_status_surfaces_sticky_usage_recovery_saturation() {
    let runtime = GatewayRuntime::new(Duration::from_secs(30), None);
    runtime
        .usage_recovery
        .write()
        .await
        .usage_recovery_saturated = true;
    let state = GatewayState {
        client: runtime.http_timeouts.client(),
        config: Arc::new(routing_config()),
        runtime,
    };

    let response = gateway_status(State(state)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["usage_recovery_saturated"], true);
}

#[test]
fn provider_kind_from_model_maps_backends() {
    assert_eq!(
        ProviderKind::from_model("gpt-5.5"),
        Ok(ProviderKind::OpenAi(OpenAiRuntime::OpenAi))
    );
    assert_eq!(
        ProviderKind::from_model("ollama/llama3.2:latest"),
        Ok(ProviderKind::OpenAi(OpenAiRuntime::Ollama))
    );
    assert_eq!(
        ProviderKind::from_model("claude-sonnet-4"),
        Ok(ProviderKind::Anthropic)
    );
    assert!(ProviderKind::from_model("unknown/model").is_err());
}

#[test]
fn strips_accept_encoding_on_upstream_requests() {
    // Accept-Encoding must be stripped in both auth modes so upstreams
    // return identity-encoded bodies the usage parser can read.
    for mode in [UpstreamAuthMode::GatewayKey, UpstreamAuthMode::Passthrough] {
        assert!(
            !should_forward_request_header(&ACCEPT_ENCODING, mode),
            "Accept-Encoding should be stripped in {mode:?} mode"
        );
        // A normal content header still forwards.
        assert!(
            should_forward_request_header(&CONTENT_TYPE, mode),
            "Content-Type should forward in {mode:?} mode"
        );
    }
}

#[test]
fn strips_trace_context_on_upstream_requests() {
    for mode in [UpstreamAuthMode::GatewayKey, UpstreamAuthMode::Passthrough] {
        assert!(!should_forward_request_header(&TRACEPARENT, mode));
        assert!(!should_forward_request_header(&TRACESTATE, mode));
    }
}

#[test]
fn isolated_provider_routes_strip_client_credentials() {
    for header in [&AUTHORIZATION, &X_API_KEY, &COOKIE] {
        assert!(should_strip_isolated_client_credential(header, true));
        assert!(!should_strip_isolated_client_credential(header, false));
    }
    assert!(!should_strip_isolated_client_credential(
        &CONTENT_TYPE,
        true
    ));
}

#[test]
fn anthropic_base_url_normalizes_to_v1() {
    // A base without /v1 gains it; one that already has /v1 is unchanged;
    // trailing slashes and blank input are handled.
    assert_eq!(
        normalize_anthropic_base_url("https://api.anthropic.com"),
        "https://api.anthropic.com/v1"
    );
    assert_eq!(
        normalize_anthropic_base_url("https://api.anthropic.com/"),
        "https://api.anthropic.com/v1"
    );
    assert_eq!(
        normalize_anthropic_base_url("https://api.anthropic.com/v1"),
        "https://api.anthropic.com/v1"
    );
    assert_eq!(
        normalize_anthropic_base_url("https://api.anthropic.com/v1/"),
        "https://api.anthropic.com/v1"
    );
    assert_eq!(
        normalize_anthropic_base_url("  "),
        DEFAULT_ANTHROPIC_BASE_URL
    );
}

#[test]
fn anthropic_messages_route_targets_v1_after_normalization() {
    // The client path /v1/messages strips to /messages and re-appends the
    // base, so a normalized base must yield …/v1/messages.
    let mut config = routing_config();
    config.anthropic_base_url = normalize_anthropic_base_url("https://api.anthropic.com");
    let uri: Uri = "/v1/messages".parse().unwrap();
    assert_eq!(
        upstream_url_for_provider(&config, &uri, ProviderKind::Anthropic).as_deref(),
        Some("https://api.anthropic.com/v1/messages")
    );
}

#[test]
fn per_model_routing_picks_backend_base_url() {
    let config = routing_config();
    let uri: Uri = "/v1/responses".parse().unwrap();
    // The same Responses wire path routes to different backends by provider.
    assert_eq!(
        upstream_url_for_provider(&config, &uri, ProviderKind::OpenAi(OpenAiRuntime::OpenAi))
            .as_deref(),
        Some("https://openai.example/v1/responses")
    );
    assert_eq!(
        upstream_url_for_provider(&config, &uri, ProviderKind::OpenAi(OpenAiRuntime::Ollama))
            .as_deref(),
        Some("http://localhost:11434/v1/responses")
    );
    assert_eq!(
        upstream_url_for_provider(&config, &uri, ProviderKind::OpenAi(OpenAiRuntime::Native))
            .as_deref(),
        Some("http://localhost:9999/v1/responses")
    );
    let mut unconfigured = config.clone();
    unconfigured.native_base_url = None;
    assert_eq!(
        upstream_url_for_provider(
            &unconfigured,
            &uri,
            ProviderKind::OpenAi(OpenAiRuntime::Native)
        ),
        None
    );
    assert_eq!(
        ProviderKind::from_model("xai/grok-4.5"),
        Ok(ProviderKind::OpenAi(OpenAiRuntime::Xai))
    );
    assert_eq!(
        ProviderKind::from_model("meta/muse-spark-1.1"),
        Ok(ProviderKind::OpenAi(OpenAiRuntime::Meta))
    );
}

#[test]
fn strip_ollama_prefix_rewrites_model() {
    let body = br#"{"model":"ollama/llama3.2:latest","input":"hi"}"#;
    let out = strip_ollama_model_prefix(body);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["model"], "llama3.2:latest");
    assert_eq!(v["input"], "hi");
    // Non-ollama models are left untouched.
    let gpt = br#"{"model":"gpt-5.5"}"#;
    let out = strip_ollama_model_prefix(gpt);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["model"], "gpt-5.5");
}

#[test]
fn ollama_and_native_need_no_upstream_auth() {
    let config = routing_config();
    let client = reqwest::Client::new();
    // No OPENAI_API_KEY set, but Ollama/native must still be allowed.
    for provider in [
        ProviderKind::OpenAi(OpenAiRuntime::Ollama),
        ProviderKind::OpenAi(OpenAiRuntime::Native),
    ] {
        let req = client.post("http://localhost/x");
        assert!(apply_provider_auth(req, &config, provider).is_ok());
    }
    // OpenAI still requires a key.
    let req = client.post("http://localhost/x");
    assert!(
        apply_provider_auth(req, &config, ProviderKind::OpenAi(OpenAiRuntime::OpenAi)).is_err()
    );
}

use crate::config::Config;
use crate::test_support::chisei_service::ChiseiServiceImpl;
use crate::test_support::dataset::RowQuery;
use crate::test_support::runtime_db::RuntimeDb;
use crate::test_support::sekai_db::SekaiDb;
use crate::test_support::sekai_service::SekaiServiceImpl;
use axum::body::to_bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::any;
use sekai_chisei::chisei::eval::{
    Case as InternalEvalCase, CaseResult as InternalCaseResult, EvalStore, Run as InternalEvalRun,
    Suite as InternalEvalSuite,
};
use sekai_proto::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_proto::chisei::chisei_service_server::ChiseiServiceServer;
use sekai_proto::chisei::{SetBudgetLimitRequest, SetNamespacePolicyRequest};
use sekai_proto::sekai::sekai_service_server::SekaiServiceServer;
use std::collections::HashSet;
use std::sync::Mutex;
use tonic::transport::Server;

#[derive(Debug, Clone)]
struct RecordedRequest {
    path: String,
    query: Option<String>,
    authorization: Option<String>,
    x_api_key: Option<String>,
    chisei_agent: Option<String>,
    accept_encoding: Option<String>,
    body: String,
}

#[test]
fn parses_gateway_pricing_table() {
    let pricing = parse_pricing_table("gpt-5.5=1.25:10,claude-sonnet-4-6=3:15.000001").unwrap();

    assert_eq!(
        pricing.get("gpt-5.5"),
        Some(&ModelPricing {
            input_usd_micros_per_million: 1_250_000,
            output_usd_micros_per_million: 10_000_000,
            // 2-field entry defaults the cached rate to the input rate.
            cached_input_usd_micros_per_million: 1_250_000,
            ..Default::default()
        })
    );
    assert_eq!(
        pricing.get("claude-sonnet-4-6"),
        Some(&ModelPricing {
            input_usd_micros_per_million: 3_000_000,
            output_usd_micros_per_million: 15_000_001,
            cached_input_usd_micros_per_million: 3_000_000,
            ..Default::default()
        })
    );
    assert!(parse_pricing_table("gpt-5.5=1").is_err());
}

#[test]
fn parses_gateway_pricing_table_with_cached_rate() {
    let pricing = parse_pricing_table("claude-sonnet-4-6=3:15:0.3").unwrap();
    assert_eq!(
        pricing.get("claude-sonnet-4-6"),
        Some(&ModelPricing {
            input_usd_micros_per_million: 3_000_000,
            output_usd_micros_per_million: 15_000_000,
            cached_input_usd_micros_per_million: 300_000,
            ..Default::default()
        })
    );
    // Too many rate fields is rejected.
    assert!(parse_pricing_table("gpt-5.5=1:2:3:4:5:6").is_err());
}

#[test]
fn parses_gateway_pricing_table_with_cache_write_classes() {
    let pricing = parse_pricing_table("claude-sonnet-4-6=3:15:0.3:3.75:6").unwrap();
    let pricing = pricing.get("claude-sonnet-4-6").unwrap();
    assert_eq!(
        pricing.cache_write_5m_usd_micros_per_million,
        Some(3_750_000)
    );
    assert_eq!(
        pricing.cache_write_1h_usd_micros_per_million,
        Some(6_000_000)
    );
}

#[test]
fn configured_pricing_uses_a_deterministic_effective_snapshot() {
    let mut config = routing_config();
    config.pricing = parse_pricing_table("gpt-5.5=1.25:10,claude-sonnet-4-6=3:15").unwrap();
    let registry = ProviderRegistry::built_in();
    let profile = registry.profile("openai").unwrap();

    let version = effective_pricing_snapshot_version(
        &config,
        Some(profile),
        Some("openai/gpt-5.5"),
        Some("gpt-5.5"),
    )
    .unwrap();

    assert!(version.starts_with("chisei.gateway-pricing/v2:"));
    assert_ne!(version, profile.pricing.version);
    assert_eq!(
        effective_pricing_snapshot_version(&config, Some(profile), Some("openai/unpriced"), None,),
        Some(profile.pricing.version.clone())
    );
}

#[test]
fn canonical_models_use_legacy_pricing_entries() {
    let pricing = parse_pricing_table("gpt-5.5=1.25:10,hf.co/org/model=2:4").unwrap();
    let (model, rates) = lookup_pricing_entry(&pricing, "openai/gpt-5.5").unwrap();

    assert_eq!(model, "gpt-5.5");
    assert_eq!(rates.input_usd_micros_per_million, 1_250_000);
    assert!(lookup_pricing_entry(&pricing, "native/gpt-5.5").is_none());
    assert_eq!(
        lookup_pricing_entry(&pricing, "ollama/hf.co/org/model").map(|(model, _)| model),
        Some("hf.co/org/model")
    );
    assert!(lookup_pricing_entry(&pricing, "openai/hf.co/org/model").is_none());
}

#[test]
fn estimate_cost_bills_cache_reads_at_discounted_rate() {
    // 10x cheaper cache reads: input 3 usd/1M, cached 0.3 usd/1M.
    let pricing = parse_pricing_table("claude-sonnet-4-6=3:15:0.3").unwrap();
    let pricing = pricing.get("claude-sonnet-4-6").unwrap();

    // Anthropic: input_tokens is the uncached count; cache tokens separate.
    let fresh = ResponseUsage {
        input_tokens: 1_000_000,
        output_tokens: 0,
        total_tokens: 1_000_000,
        ..Default::default()
    };
    let cached = ResponseUsage {
        input_tokens: 0,
        output_tokens: 0,
        total_tokens: 0,
        cache_read_input_tokens: 1_000_000,
        cache_creation_input_tokens: 0,
        ..Default::default()
    };
    let fresh_cost = cost_for_model("claude-sonnet-4-6", pricing, &fresh).unwrap();
    let cached_cost = cost_for_model("claude-sonnet-4-6", pricing, &cached).unwrap();
    assert_eq!(fresh_cost, 3_000_000);
    assert_eq!(cached_cost, 300_000);
    assert!(cached_cost < fresh_cost);
}

#[test]
fn estimate_cost_excludes_openai_cached_tokens_from_input() {
    // OpenAI reports cached tokens as a subset of prompt_tokens, so the
    // uncached portion must exclude them.
    let pricing = parse_pricing_table("gpt-5.5=1:10:0.1").unwrap();
    let pricing = pricing.get("gpt-5.5").unwrap();
    let usage = ResponseUsage {
        input_tokens: 1_000_000,
        output_tokens: 0,
        total_tokens: 1_000_000,
        cache_read_input_tokens: 800_000,
        cache_creation_input_tokens: 0,
        cache_read_reported: true,
        cache_read_included_in_input: true,
        ..Default::default()
    };
    // 200k uncached * 1 + 800k cached * 0.1 = 200000 + 80000 micros.
    let cost = cost_for_model("gpt-5.5", pricing, &usage).unwrap();
    assert_eq!(cost, 280_000);
}

#[test]
fn estimate_cost_matches_legacy_when_no_cache_tokens() {
    // Back-compat: with zero cache tokens the cost equals input*in + out*out.
    let pricing = parse_pricing_table("gpt-5.5=1.25:10").unwrap();
    let pricing = pricing.get("gpt-5.5").unwrap();
    let usage = ResponseUsage {
        input_tokens: 1_000_000,
        output_tokens: 500_000,
        total_tokens: 1_500_000,
        ..Default::default()
    };
    let cost = cost_for_model("gpt-5.5", pricing, &usage).unwrap();
    assert_eq!(cost, 1_250_000 + 5_000_000);
}

#[test]
fn cache_write_classes_include_premiums_and_break_even() {
    let pricing = parse_pricing_table("claude-sonnet-4-6=3:15:0.3:3.75:6").unwrap();
    let pricing = pricing.get("claude-sonnet-4-6").unwrap();
    let five_minute_write = ResponseUsage {
        cache_creation_input_tokens: 1_000_000,
        cache_creation_5m_input_tokens: 1_000_000,
        cache_creation_reported: true,
        cache_creation_5m_reported: true,
        ..Default::default()
    };
    let one_hour_write = ResponseUsage {
        cache_creation_input_tokens: 1_000_000,
        cache_creation_1h_input_tokens: 1_000_000,
        cache_creation_reported: true,
        cache_creation_1h_reported: true,
        ..Default::default()
    };
    let hit = ResponseUsage {
        cache_read_input_tokens: 1_000_000,
        cache_read_reported: true,
        ..Default::default()
    };
    let five_minute_cost = cost_for_model("claude-sonnet-4-6", pricing, &five_minute_write);
    let one_hour_cost = cost_for_model("claude-sonnet-4-6", pricing, &one_hour_write);
    let hit_cost = cost_for_model("claude-sonnet-4-6", pricing, &hit);
    assert_eq!(five_minute_cost, Some(3_750_000));
    assert_eq!(one_hour_cost, Some(6_000_000));
    assert_eq!(hit_cost, Some(300_000));
    // 5m breaks even after one hit; 1h requires two hits.
    let ordinary = pricing.input_usd_micros_per_million;
    let hit = hit_cost.unwrap();
    assert!(five_minute_cost.unwrap() + hit < 2 * ordinary);
    assert!(one_hour_cost.unwrap() + hit > 2 * ordinary);
    assert!(one_hour_cost.unwrap() + 2 * hit < 3 * ordinary);
    // An aggregate-only write cannot be assigned a premium price class.
    let aggregate_only = ResponseUsage {
        cache_creation_input_tokens: 1_000_000,
        cache_creation_reported: true,
        ..Default::default()
    };
    assert_eq!(
        cost_for_model("claude-sonnet-4-6", pricing, &aggregate_only),
        None
    );
}

#[test]
fn prompt_cache_baseline_covers_required_scenarios() {
    let baseline: serde_json::Value = serde_json::from_str(include_str!(
        "../../../benchmarks/prompt-cache-baseline-v1.json"
    ))
    .unwrap();
    assert_eq!(baseline["version"], "prompt-cache-baseline/v1");
    let names = baseline["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|scenario| scenario["name"].as_str())
        .collect::<HashSet<_>>();
    for required in [
        "uncached",
        "cold_5m",
        "warm_5m",
        "expired_5m",
        "invalidated",
        "cold_1h",
    ] {
        assert!(names.contains(required), "missing {required} baseline");
    }
    assert_eq!(baseline["break_even_hits"]["5m"], 1);
    assert_eq!(baseline["break_even_hits"]["1h"], 2);
}

#[test]
fn buffered_upstream_response_limit_rejects_oversized_chunks() {
    assert!(!buffered_response_exceeds_limit(
        DEFAULT_MAX_RESPONSE_BYTES - 1,
        1
    ));
    assert!(buffered_response_exceeds_limit(
        DEFAULT_MAX_RESPONSE_BYTES,
        1
    ));
    assert!(buffered_response_exceeds_limit(usize::MAX, 1));
}

#[derive(Clone)]
struct FakeUpstreamState {
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    response_body: &'static str,
    content_type: &'static str,
    status: StatusCode,
    delay: Option<Duration>,
}

async fn fake_upstream(
    State(state): State<FakeUpstreamState>,
    uri: Uri,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response<Body> {
    let body = to_bytes(request.into_body(), DEFAULT_MAX_REQUEST_BYTES)
        .await
        .unwrap();
    state.requests.lock().unwrap().push(RecordedRequest {
        path: uri.path().to_string(),
        query: uri.query().map(str::to_string),
        authorization: headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        x_api_key: headers
            .get(X_API_KEY)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        chisei_agent: headers
            .get(X_CHISEI_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        accept_encoding: headers
            .get(ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        body: String::from_utf8(body.to_vec()).unwrap(),
    });
    if let Some(delay) = state.delay {
        tokio::time::sleep(delay).await;
    }

    let mut builder = Response::builder().status(state.status);
    if !state.content_type.is_empty() {
        builder = builder.header(axum::http::header::CONTENT_TYPE, state.content_type);
    }
    builder.body(Body::from(state.response_body)).unwrap()
}

async fn spawn_fake_upstream(
    response_body: &'static str,
    content_type: &'static str,
) -> (String, Arc<Mutex<Vec<RecordedRequest>>>) {
    spawn_fake_upstream_with_delay(response_body, content_type, None).await
}

/// Serves an Ollama `/api/tags` listing so the control-plane resolver can
/// validate an `ollama/<model>` without a live Ollama server (otherwise
/// resolution is environment-dependent: it passes only where Ollama runs).
async fn spawn_fake_ollama_tags(model: &str) -> String {
    let body = format!(r#"{{"models":[{{"name":"{model}"}}]}}"#);
    let app = Router::new().route(
        "/api/tags",
        any(move || {
            let body = body.clone();
            async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn spawn_fake_upstream_with_delay(
    response_body: &'static str,
    content_type: &'static str,
    delay: Option<Duration>,
) -> (String, Arc<Mutex<Vec<RecordedRequest>>>) {
    spawn_fake_upstream_with_status(response_body, content_type, StatusCode::OK, delay).await
}

async fn spawn_fake_upstream_with_status(
    response_body: &'static str,
    content_type: &'static str,
    status: StatusCode,
    delay: Option<Duration>,
) -> (String, Arc<Mutex<Vec<RecordedRequest>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = FakeUpstreamState {
        requests: requests.clone(),
        response_body,
        content_type,
        status,
        delay,
    };
    let app = Router::new()
        .route("/{*path}", any(fake_upstream))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/v1"), requests)
}

/// Streams `chunks` as separate body frames with `delay` between them and
/// no Content-Type header, like the ChatGPT Codex backend.
async fn spawn_fake_chunked_upstream(chunks: &'static [&'static str], delay: Duration) -> String {
    let handler = move || async move {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, std::convert::Infallible>>(1);
        tokio::spawn(async move {
            for (index, chunk) in chunks.iter().enumerate() {
                if index > 0 {
                    tokio::time::sleep(delay).await;
                }
                if tx.send(Ok(chunk.to_string())).await.is_err() {
                    return;
                }
            }
        });
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from_stream(ReceiverStream::new(rx)))
            .unwrap()
    };
    let app = Router::new().route("/{*path}", any(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/v1")
}

async fn spawn_fake_terminal_then_error_upstream() -> String {
    let handler = || async {
        let terminal = Bytes::from_static(
            b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n",
        );
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            tx.send(Ok::<_, std::io::Error>(terminal)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx
                .send(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "reset after terminal",
                )))
                .await;
        });
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(ReceiverStream::new(rx)))
            .unwrap()
    };
    let app = Router::new().route("/{*path}", any(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/v1")
}

/// Usage recording for streamed responses happens in a background task
/// after the last chunk is delivered, so poll instead of asserting once.
async fn wait_for_llm_calls(db: &RuntimeDb, count: usize) -> Vec<HashMap<String, String>> {
    for _ in 0..100 {
        let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
        if rows.len() >= count {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    db.query_rows("llm_calls", &RowQuery::default()).unwrap()
}

async fn spawn_gateway(openai_base_url: String) -> String {
    spawn_gateway_with_preflight(openai_base_url).await
}

async fn spawn_gateway_with_preflight(openai_base_url: String) -> String {
    let (chisei_target, _) = spawn_control_plane().await;
    let config = GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::from([(
            "sk-chisei-codex-app".to_string(),
            GatewayIdentity {
                agent: "codex-app".to_string(),
                project: "default".to_string(),
                user_id: "agent:codex-app".to_string(),
                key_id: "codex-app".to_string(),
                tier: "low-risk".to_string(),
            },
        )]),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    };
    spawn_gateway_with_config(config).await
}

async fn spawn_gateway_with_timeouts(
    openai_base_url: String,
    http_timeouts: HttpTimeouts,
) -> String {
    let (chisei_target, _) = spawn_control_plane().await;
    let config = GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::from([(
            "sk-chisei-codex-app".to_string(),
            GatewayIdentity {
                agent: "codex-app".to_string(),
                project: "default".to_string(),
                user_id: "agent:codex-app".to_string(),
                key_id: "codex-app".to_string(),
                tier: "low-risk".to_string(),
            },
        )]),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    };
    spawn_gateway_with_runtime(
        config,
        GatewayRuntime::new(Duration::from_secs(DEFAULT_KEY_CACHE_TTL_SECS), None)
            .with_http_timeouts(http_timeouts),
    )
    .await
}

async fn spawn_gateway_with_config(config: GatewayConfig) -> String {
    spawn_gateway_with_runtime(config, test_gateway_runtime()).await
}

async fn spawn_gateway_with_runtime(config: GatewayConfig, mut runtime: GatewayRuntime) -> String {
    if runtime.recovery_spool_path.is_none() {
        runtime.recovery_spool_path = Some(std::env::temp_dir().join(format!(
            "chisei-gateway-recovery-{}.jsonl",
            uuid::Uuid::new_v4()
        )));
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app_with_runtime(config, runtime))
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

fn test_gateway_runtime() -> GatewayRuntime {
    GatewayRuntime::new(Duration::from_secs(DEFAULT_KEY_CACHE_TTL_SECS), None).with_resilience(
        ResilienceConfig {
            control_plane_retries: 4,
            control_plane_retry_backoff: Duration::from_millis(50),
            control_plane_timeout: Duration::from_secs(10),
            ..ResilienceConfig::default()
        },
    )
}

fn short_http_timeouts() -> HttpTimeouts {
    HttpTimeouts {
        connect_timeout: Duration::from_secs(1),
        read_timeout: Duration::from_millis(50),
        pool_idle_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(5),
    }
}

fn test_config() -> Config {
    Config {
        grpc_port: 0,
        sekai_bind: None,
        ops_port: None,
        ops_bind: "127.0.0.1".into(),
        http_port: None,
        http_bind: "127.0.0.1".into(),
        sekai_socket: None,
        db_path: ":memory:".into(),
        anthropic_api_key: Some("test-anthropic-key".into()),
        openai_api_key: Some("test-openai-key".into()),
        ollama_url: "http://127.0.0.1:11434".into(),
        native_llm_url: None,
        sample_rate: 0.0,
        sample_risk_threshold: 0.7,
        scoring_enabled: false,
        scoring_interval_secs: 60,
        scoring_model: "claude-opus-4-8".into(),
        scoring_batch_size: 16,
        default_data_class: "unclassified".into(),
        safe_egress_providers: vec![],
        gateway_provided_providers: vec![],
        gateway_receipt_principals: vec![],
        leak_review_model: None,
        tls_cert: None,
        tls_key: None,
        allow_plaintext: false,
        insecure: false,
        permit_signing_key: None,
        permit_issuer: "chisei.local".into(),
        permit_key_id: "permit-key-1".into(),
        governed_subject_provenance_signing_key: None,
        governed_subject_provenance_key_not_before_ms: 0,
        governed_subject_provenance_key_expires_at_ms: i64::MAX,
        governed_subject_provenance_ttl_ms: 24 * 60 * 60 * 1_000,
        site_id: "local".into(),
        budget_topology: Default::default(),
        assertion_issuer: None,
        assertion_audience: None,
        assertion_hmac_key: None,
        sekai_endpoint: None,
    }
}

async fn spawn_control_plane() -> (String, Arc<RuntimeDb>) {
    spawn_control_plane_with_config(test_config()).await
}

async fn spawn_control_plane_with_config(config: Config) -> (String, Arc<RuntimeDb>) {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    for (agent, project, secret) in [
        ("codex-app", "default", "sk-chisei-codex-app"),
        ("claude-code", "default", "sk-chisei-claude-code"),
        (
            "codex-app",
            "sekai-chisei",
            "sk-chisei-codex-app-sekai-chisei",
        ),
    ] {
        let _ = db.create_object(&crate::domain::Object {
            id: format!("gateway-key-{agent}-{project}"),
            kind: "gateway_key".to_string(),
            name: agent.to_string(),
            namespace: project.to_string(),
            external_id: format!("gateway_key:{agent}:{project}"),
            properties: HashMap::from([
                ("agent".to_string(), agent.to_string()),
                ("project".to_string(), project.to_string()),
                ("status".to_string(), "active".to_string()),
                ("key_hash".to_string(), hash_gateway_key(secret)),
            ]),
            created: 0,
            updated: 0,
        });
    }

    spawn_control_plane_from_db(config, db).await
}

async fn spawn_control_plane_from_db(
    config: Config,
    db: Arc<RuntimeDb>,
) -> (String, Arc<RuntimeDb>) {
    let sekai_svc = SekaiServiceImpl::new(db.clone());
    let chisei_svc = ChiseiServiceImpl::new(db.clone(), config);
    chisei_svc.seed_allow_by_default_context_admission(&["default", "sekai-chisei"]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .add_service(SekaiServiceServer::new(sekai_svc))
            .add_service(ChiseiServiceServer::new(chisei_svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    // Wait until the spawned gRPC server actually serves an RPC before
    // returning. Otherwise a fail-closed gateway started next can race the
    // server's readiness and 503 on its first policy projection (flaky under
    // CI parallelism). Any served response — success or an application-level
    // status — proves the server is accepting requests; only transport-level
    // errors mean not-ready-yet.
    let target = format!("http://{addr}");
    for _ in 0..250 {
        if let Ok(channel) = connect_sekai(&target).await {
            let served = ChiseiServiceClient::new(channel)
                .get_effective_policy_summary(GrpcRequest::new(GetEffectivePolicySummaryRequest {
                    namespace: "__readiness_probe__".to_string(),
                    provider: String::new(),
                }))
                .await
                .map(|_| true)
                .unwrap_or_else(|status| {
                    !matches!(
                        status.code(),
                        tonic::Code::Unavailable | tonic::Code::Unknown
                    )
                });
            if served {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    (target, db)
}

async fn seed_regressed_namespace(target: &str, db: &Arc<RuntimeDb>, namespace: &str) {
    let channel = connect_sekai(target).await.unwrap();
    let mut chisei = ChiseiServiceClient::new(channel);
    chisei
        .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
            namespace: namespace.to_string(),
            allowed_runtimes: vec!["openai".to_string()],
            allowed_models: vec!["gpt-5.5".to_string(), "gpt-5.5-mini".to_string()],
            default_runtime: "openai".to_string(),
            default_model: "gpt-5.5".to_string(),
            data_class: String::new(),
            context_admission_policy_json: DEFAULT_CONTEXT_ADMISSION_POLICY_JSON.to_string(),
        }))
        .await
        .unwrap();
    let eval = EvalStore::with_db(db.clone());
    eval.put_suite(InternalEvalSuite {
        id: "gateway-suite".to_string(),
        name: "Gateway suite".to_string(),
        description: String::new(),
        cases: vec![InternalEvalCase {
            id: "case-1".to_string(),
            name: "case".to_string(),
            namespace: namespace.to_string(),
            spec: "spec".to_string(),
            assertions: vec![],
        }],
    })
    .unwrap();
    for (id, score, timestamp) in [("run-1", 92, 100), ("run-2", 60, 200)] {
        eval.put_run(InternalEvalRun {
            id: id.to_string(),
            suite_id: "gateway-suite".to_string(),
            config_ref: "gpt-5.5".to_string(),
            results: vec![InternalCaseResult {
                case_id: "case-1".to_string(),
                passed: score >= 80,
                status: if score >= 80 { "done" } else { "failed" }.to_string(),
                result: "result".to_string(),
                score,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp,
        })
        .unwrap();
        eval.track_iteration("gateway-suite", id, namespace, &format!("hash-{id}"))
            .unwrap();
    }
}

#[tokio::test]
async fn responses_proxy_forwards_body_query_and_rewrites_auth() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","object":"response","status":"completed"}"#,
        "application/json",
    )
    .await;
    let gateway_base = spawn_gateway(upstream_base).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{gateway_base}/v1/responses?trace=1"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .header("x-codex-test", "yes")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.text().await.unwrap(),
        r#"{"id":"resp_1","object":"response","status":"completed"}"#
    );

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/responses");
    assert_eq!(requests[0].query.as_deref(), Some("trace=1"));
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer real-openai-key")
    );
    assert!(requests[0].body.contains(r#""model":"gpt-5.5""#));
}

#[tokio::test]
async fn invalid_models_do_not_consume_request_aliases() {
    let (chisei_target, db) = spawn_control_plane().await;
    let mut config = routing_config();
    config.chisei_grpc_target = Some(chisei_target);
    let gateway_base = spawn_gateway_with_config(config).await;
    let client = reqwest::Client::new();
    let send = || {
        client
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-chisei-request-id", "early-refusal-attempt")
            .header("x-chisei-data-class", "unclassified")
            .header("x-chisei-action-risk", "low")
            .json(&serde_json::json!({
                "model": "unknown/provider-model",
                "input": "hello"
            }))
    };

    let first = send().send().await.unwrap();
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);
    assert!(
        db.find_operation_receipt_by_lookup_request_id("early-refusal-attempt", None, None)
            .unwrap()
            .is_none()
    );
    let second = send().send().await.unwrap();
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pre_dispatch_refusals_do_not_strand_request_aliases() {
    let (chisei_target, db) = spawn_control_plane().await;
    let mut config = routing_config();
    config.chisei_grpc_target = Some(chisei_target);
    let gateway_base = spawn_gateway_with_config(config).await;
    let client = reqwest::Client::new();
    let send = || {
        client
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-chisei-request-id", "pre-dispatch-refusal")
            .json(&serde_json::json!({
                "model": "gpt-5.5",
                "input": "hello",
                "chisei_context": {
                    "objects": [{"ref": "ticker:AAPL", "fields": ["score"]}]
                }
            }))
    };

    for _ in 0..2 {
        let response = send().send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_ne!(response.status(), StatusCode::CONFLICT);
    }
    assert!(
        db.find_operation_receipt_by_lookup_request_id("pre-dispatch-refusal", None, None)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn missing_provider_credentials_do_not_strand_request_aliases() {
    let (chisei_target, _db) = spawn_control_plane().await;
    let mut config = routing_config();
    config.chisei_grpc_target = Some(chisei_target);
    config.openai_api_key = None;
    config.rewrite_openai_passthrough_auth = true;
    let gateway_base = spawn_gateway_with_config(config).await;
    let client = reqwest::Client::new();
    let send = || {
        client
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-chisei-request-id", "missing-provider-credential")
            .header("x-chisei-data-class", "unclassified")
            .header("x-chisei-action-risk", "low")
            .json(&serde_json::json!({
                "model": "openai/gpt-5.5",
                "input": "hello"
            }))
    };

    for _ in 0..2 {
        let response = send().send().await.unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert_ne!(status, StatusCode::CONFLICT, "{body}");
    }
}

#[tokio::test]
async fn upstream_timeout_returns_gateway_error() {
    let (upstream_base, _requests) = spawn_fake_upstream_with_delay(
        r#"{"id":"resp_1","object":"response","status":"completed"}"#,
        "application/json",
        Some(Duration::from_millis(200)),
    )
    .await;
    let gateway_base = spawn_gateway_with_timeouts(upstream_base, short_http_timeouts()).await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let body = resp.text().await.unwrap();
    assert!(body.contains("upstream_error"), "{body}");
    assert!(body.contains("timed out"), "{body}");
}

#[tokio::test]
async fn responses_proxy_preserves_sse_body() {
    let sse = "event: response.created\n\
               data: {\"type\":\"response.created\"}\n\n\
               event: response.completed\n\
               data: {\"type\":\"response.completed\"}\n\n";
    let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let gateway_base = spawn_gateway(upstream_base).await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello",
            "stream": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(resp.text().await.unwrap(), sse);
}

#[tokio::test]
async fn received_terminal_is_preserved_after_transport_error() {
    let upstream_base = spawn_fake_terminal_then_error_upstream().await;
    let gateway_base = spawn_gateway(upstream_base).await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello",
            "stream": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("response.completed"), "{body}");
    assert!(!body.contains("chisei.response.interrupted"), "{body}");
}

#[tokio::test]
async fn models_proxy_forwards_to_openai_upstream() {
    let upstream_body = r#"{"object":"list","data":[{"id":"gpt-5.5","object":"model"}]}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, _) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: None,
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .get(format!("{gateway_base}/v1/models?client_version=0.141.0"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "sensitive")
        .header("x-chisei-action-risk", "low")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = reqwest::Client::new()
        .get(format!("{gateway_base}/v1/models?client_version=0.141.0"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let response_body = resp.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{response_body}");
    assert_eq!(response_body, upstream_body);

    let detail = reqwest::Client::new()
        .get(format!("{gateway_base}/models/gpt-5.5"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "sensitive")
        .header("x-chisei-action-risk", "low")
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);

    let prefixed_body = reqwest::Client::new()
        .post(format!("{gateway_base}/models-export"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "sensitive")
        .header("x-chisei-action-risk", "low")
        .json(&serde_json::json!({"input": "classified"}))
        .send()
        .await
        .unwrap();
    assert_eq!(prefixed_body.status(), StatusCode::FORBIDDEN);

    let metadata_body = reqwest::Client::new()
        .get(format!("{gateway_base}/models/gpt-5.5"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "sensitive")
        .header("x-chisei-action-risk", "low")
        .body("classified")
        .send()
        .await
        .unwrap();
    assert_eq!(metadata_body.status(), StatusCode::FORBIDDEN);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/v1/models");
    assert_eq!(requests[0].query.as_deref(), Some("client_version=0.141.0"));
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer real-openai-key")
    );
    assert_eq!(requests[1].path, "/v1/models/gpt-5.5");
}

#[tokio::test]
async fn anthropic_models_proxy_uses_anthropic_path_and_api_key() {
    let upstream_body = r#"{"data":[{"id":"claude-sonnet-4-20250514","type":"model"}]}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, _) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: None,
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let response = reqwest::Client::new()
        .get(format!("{gateway_base}/v1/models"))
        .bearer_auth("sk-chisei-codex-app")
        .header("anthropic-version", "2023-06-01")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .send()
        .await
        .unwrap();

    let status = response.status();
    let response_body = response.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{response_body}");
    assert_eq!(response_body, upstream_body);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/models");
    assert_eq!(requests[0].x_api_key.as_deref(), Some("real-anthropic-key"));
    assert_eq!(requests[0].authorization, None);
}

#[tokio::test]
async fn openai_passthrough_preserves_client_auth_and_strips_chisei_headers() {
    let upstream_body = r#"{"id":"resp_1","object":"response","status":"completed"}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, _) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: None,
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: None,
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: true,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("native-openai-oauth-token")
        .header(X_CHISEI_AGENT.as_str(), "codex-app")
        .header(X_CHISEI_PROJECT.as_str(), "sekai-chisei")
        .header(X_CHISEI_DATA_CLASS.as_str(), "unclassified")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer native-openai-oauth-token")
    );
    assert_eq!(requests[0].x_api_key, None);
    assert_eq!(requests[0].chisei_agent, None);
}

#[tokio::test]
async fn openai_passthrough_rejects_requests_without_client_auth() {
    let upstream_body = r#"{"id":"resp_1","object":"response","status":"completed"}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: None,
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: None,
        chisei_grpc_target: None,
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: true,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .header(X_CHISEI_AGENT.as_str(), "codex-app")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn openai_passthrough_can_rewrite_upstream_auth_for_codex_local_login() {
    let upstream_body = r#"{"id":"resp_1","object":"response","status":"completed"}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, _) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: None,
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: true,
        rewrite_openai_passthrough_auth: true,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("codex-local-login-token")
        .header(X_CHISEI_AGENT.as_str(), "codex-app")
        .header(X_CHISEI_PROJECT.as_str(), "sekai-chisei")
        .header(X_CHISEI_DATA_CLASS.as_str(), "unclassified")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer real-openai-key")
    );
    assert_eq!(requests[0].x_api_key, None);
    assert_eq!(requests[0].chisei_agent, None);
}

#[tokio::test]
async fn anthropic_passthrough_preserves_client_auth_and_strips_chisei_headers() {
    let upstream_body = r#"{
        "id":"msg_1",
        "type":"message",
        "usage":{"input_tokens":8,"output_tokens":6}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, _) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: None,
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: None,
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: true,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("native-claude-oauth-token")
        .header(X_CHISEI_AGENT.as_str(), "claude-code")
        .header(X_CHISEI_PROJECT.as_str(), "sekai-chisei")
        .header(X_CHISEI_DATA_CLASS.as_str(), "unclassified")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer native-claude-oauth-token")
    );
    assert_eq!(requests[0].x_api_key, None);
    assert_eq!(requests[0].chisei_agent, None);
}

#[tokio::test]
async fn anthropic_messages_proxy_records_usage_and_strips_accept_encoding() {
    // Non-streaming Anthropic shape: usage lands on the llm_calls row, and
    // the gateway must strip the client's Accept-Encoding so the upstream
    // body comes back identity-encoded (parseable) rather than compressed.
    let upstream_body = r#"{
        "id":"msg_1",
        "type":"message",
        "usage":{"input_tokens":8,"output_tokens":6}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let channel = connect_sekai(&chisei_target).await.unwrap();
    ChiseiServiceClient::new(channel)
        .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
            namespace: "default".to_string(),
            allowed_runtimes: vec!["anthropic".to_string()],
            allowed_models: vec!["claude-sonnet-4-6".to_string()],
            default_runtime: "anthropic".to_string(),
            default_model: "claude-sonnet-4-6".to_string(),
            data_class: "open".to_string(),
            context_admission_policy_json: DEFAULT_CONTEXT_ADMISSION_POLICY_JSON.to_string(),
        }))
        .await
        .unwrap();
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: None,
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .header(X_CHISEI_DATA_CLASS.as_str(), "open")
        // Claude Code advertises compression; the gateway must strip it.
        .header(ACCEPT_ENCODING.as_str(), "gzip, deflate, br, zstd")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/messages");
        // Regression: Accept-Encoding must not reach the upstream.
        assert_eq!(requests[0].accept_encoding, None);
    }

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("agent").map(String::as_str),
        Some("claude-code")
    );
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("8"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("6"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("14"));
    assert_eq!(rows[0].get("data_class").map(String::as_str), Some("open"));

    let downgraded = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .header(X_CHISEI_DATA_CLASS.as_str(), "sensitive")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "classified"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(downgraded.status(), StatusCode::FORBIDDEN);
    assert_eq!(requests.lock().unwrap().len(), 1);

    let unclassified_body = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .header(X_CHISEI_DATA_CLASS.as_str(), "sensitive")
        .json(&serde_json::json!({
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "classified"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unclassified_body.status(), StatusCode::FORBIDDEN);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn anthropic_messages_streaming_records_usage() {
    // Streaming Anthropic shape (what Claude Code always sends): usage is
    // split across message_start (input_tokens) and message_delta
    // (output_tokens) and folded via merge_usage.
    let sse = "event: message_start\n\
               data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":11,\"output_tokens\":0}}}\n\n\
               event: content_block_delta\n\
               data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n\
               event: message_delta\n\
               data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n\n\
               event: message_stop\n\
               data: {\"type\":\"message_stop\"}\n\n";
    let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: None,
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 64,
            "stream": true,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), sse);

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("11"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("7"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("18"));
}

#[tokio::test]
async fn chat_completions_proxy_records_usage_and_rewrites_auth() {
    let upstream_body = r#"{
        "id":"chatcmpl_1",
        "object":"chat.completion",
        "usage":{"prompt_tokens":9,"completion_tokens":4,"total_tokens":13}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/chat/completions?trace=1"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), upstream_body);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/chat/completions");
    assert_eq!(requests[0].query.as_deref(), Some("trace=1"));
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer real-openai-key")
    );
    drop(requests);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
    assert_eq!(rows[0].get("model").map(String::as_str), Some("gpt-5.5"));
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("9"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("4"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("13"));
}

#[tokio::test]
async fn eval_regression_signal_rewrites_model_and_records_audit() {
    let upstream_body = r#"{
        "id":"resp_1",
        "object":"response",
        "status":"completed",
        "output":[{"type":"message","content":[{"type":"output_text","text":"gateway sampled answer"}]}],
        "usage":{"input_tokens":7,"output_tokens":5,"total_tokens":12}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    seed_regressed_namespace(&chisei_target, &db, "default").await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5-mini", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let forwarded: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(forwarded["model"], "gpt-5.5");
    drop(requests);

    let decisions = db
        .list_decisions(&crate::test_support::audit::DecisionFilter {
            action: Some("gateway.eval_regression".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].actor, "chisei-gateway");
    assert_eq!(decisions[0].outcome, "routed");
    assert_eq!(
        decisions[0]
            .evidence
            .get("requested_model")
            .map(String::as_str),
        Some("gpt-5.5-mini")
    );
    assert_eq!(
        decisions[0]
            .evidence
            .get("resolved_model")
            .map(String::as_str),
        Some("gpt-5.5")
    );
    assert_eq!(
        decisions[0].evidence.get("key_id").map(String::as_str),
        Some("codex-app")
    );
    assert_eq!(
        decisions[0].evidence.get("user_id").map(String::as_str),
        Some("agent:codex-app")
    );
}

#[tokio::test]
async fn gateway_key_policy_scope_rewrites_model() {
    let upstream_body = r#"{
        "id":"resp_1",
        "object":"response",
        "status":"completed",
        "output":[{"type":"message","content":[{"type":"output_text","text":"key scoped answer"}]}],
        "usage":{"input_tokens":7,"output_tokens":5,"total_tokens":12}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let channel = connect_sekai(&chisei_target).await.unwrap();
    ChiseiServiceClient::new(channel)
        .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
            namespace: "gateway_key:codex-app".to_string(),
            allowed_runtimes: vec!["openai".to_string()],
            allowed_models: vec!["gpt-5.5".to_string()],
            default_runtime: "openai".to_string(),
            default_model: "gpt-5.5".to_string(),
            data_class: String::new(),
            context_admission_policy_json: DEFAULT_CONTEXT_ADMISSION_POLICY_JSON.to_string(),
        }))
        .await
        .unwrap();
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5-mini", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let forwarded: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(forwarded["model"], "gpt-5.5");
    drop(requests);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("key_id").map(String::as_str), Some("codex-app"));
    assert_eq!(
        rows[0].get("resolved_model").map(String::as_str),
        Some("openai/gpt-5.5")
    );

    let decisions = db
        .list_decisions(&crate::test_support::audit::DecisionFilter {
            action: Some("gateway.model_rewrite".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0]
            .evidence
            .get("resolved_model")
            .map(String::as_str),
        Some("gpt-5.5")
    );
}

#[tokio::test]
async fn chat_completions_streaming_response_records_usage_after_passthrough() {
    let sse = "data: {\"id\":\"chatcmpl_1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n\
               data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n\
               data: [DONE]\n\n";
    let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/chat/completions"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true,
            "stream_options": {"include_usage": true}
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), sse);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("3"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("2"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("5"));
}

#[tokio::test]
async fn anthropic_messages_proxy_records_usage_and_rewrites_x_api_key() {
    let upstream_body = r#"{
        "id":"msg_1",
        "type":"message",
        "usage":{"input_tokens":8,"output_tokens":6}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages?trace=1"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), upstream_body);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/messages");
    assert_eq!(requests[0].query.as_deref(), Some("trace=1"));
    assert_eq!(requests[0].authorization, None);
    assert_eq!(requests[0].x_api_key.as_deref(), Some("real-anthropic-key"));
    drop(requests);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("agent").map(String::as_str),
        Some("claude-code")
    );
    assert_eq!(
        rows[0].get("provider").map(String::as_str),
        Some("anthropic")
    );
    assert_eq!(
        rows[0].get("model").map(String::as_str),
        Some("claude-sonnet-4-20250514")
    );
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("8"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("6"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("14"));
}

#[tokio::test]
async fn anthropic_cache_creation_and_savings_are_recorded_on_llm_call() {
    // Anthropic reports input_tokens as the uncached count, with cache-read
    // and cache-creation tokens tracked separately.
    let upstream_body = r#"{
        "id":"msg_1",
        "type":"message",
        "usage":{"input_tokens":10,"cache_read_input_tokens":100,"cache_creation_input_tokens":20,"output_tokens":5}
    }"#;
    let (upstream_base, _requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    // input 3 usd/1M, output 15 usd/1M, cached 0.3 usd/1M.
    let pricing = HashMap::from([(
        "claude-sonnet-4-20250514".to_string(),
        ModelPricing {
            input_usd_micros_per_million: 3_000_000,
            output_usd_micros_per_million: 15_000_000,
            cached_input_usd_micros_per_million: 300_000,
            ..Default::default()
        },
    )]);
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing,
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("10"));
    assert_eq!(
        rows[0].get("cache_read_input_tokens").map(String::as_str),
        Some("100")
    );
    assert_eq!(
        rows[0]
            .get("cache_creation_input_tokens")
            .map(String::as_str),
        Some("20")
    );
    // Anthropic cost: 10 uncached*3 + 100 cache-read*0.3 + 20 cache-write*3
    // + 5 output*15 = 30 + 30 + 60 + 75 = 195 micros.
    assert_eq!(
        rows[0].get("cost_usd_micros").map(String::as_str),
        Some("195")
    );
    // Savings: 100 cache-read tokens * (3 - 0.3) usd/1M = 270 micros.
    assert_eq!(
        rows[0].get("cache_savings_usd_micros").map(String::as_str),
        Some("270")
    );
}

#[tokio::test]
async fn foreign_model_namespace_cannot_bypass_cross_provider_gate() {
    let (upstream_base, requests) =
        spawn_fake_upstream(r#"{"id":"unexpected"}"#, "application/json").await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: None,
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let response = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "openai/gpt-5.5",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn anthropic_messages_can_translate_to_openai_chat_when_policy_routes_cross_provider() {
    let upstream_body = r#"{
        "id":"chatcmpl_1",
        "object":"chat.completion",
        "model":"gpt-5.5",
        "choices":[{"index":0,"message":{"role":"assistant","content":"translated ok"},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":11,"completion_tokens":4,"total_tokens":15}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let channel = connect_sekai(&chisei_target).await.unwrap();
    ChiseiServiceClient::new(channel)
        .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
            namespace: "default".to_string(),
            allowed_runtimes: vec!["openai".to_string()],
            allowed_models: vec!["gpt-5.5".to_string()],
            default_runtime: "openai".to_string(),
            default_model: "gpt-5.5".to_string(),
            data_class: String::new(),
            context_admission_policy_json: DEFAULT_CONTEXT_ADMISSION_POLICY_JSON.to_string(),
        }))
        .await
        .unwrap();
    let (denied_upstream_base, denied_requests) =
        spawn_fake_upstream(r#"{"id":"unexpected"}"#, "application/json").await;
    let denied_gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: denied_upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;
    let denied = reqwest::Client::new()
        .post(format!("{denied_gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "auto",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(
        denied_requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.path != "/v1/chat/completions")
    );

    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: true,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "auto",
            "max_tokens": 64,
            "system": "stay terse",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["type"], "message");
    assert_eq!(body["model"], "gpt-5.5");
    assert_eq!(body["content"][0]["text"], "translated ok");
    assert_eq!(body["usage"]["input_tokens"], 11);
    assert_eq!(body["usage"]["output_tokens"], 4);

    let requests = requests.lock().unwrap();
    let requests = requests
        .iter()
        .filter(|request| request.path == "/v1/chat/completions")
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/chat/completions");
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer real-openai-key")
    );
    assert_eq!(requests[0].x_api_key, None);
    let translated: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(translated["model"], "gpt-5.5");
    assert_eq!(translated["messages"][0]["role"], "system");
    assert_eq!(translated["messages"][0]["content"], "stay terse");
    assert_eq!(translated["messages"][1]["role"], "user");
    assert_eq!(translated["messages"][1]["content"], "hello");
    drop(requests);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    let row = rows
        .iter()
        .find(|row| row.get("resolved_model").map(String::as_str) == Some("openai/gpt-5.5"))
        .expect("allowed cross-provider call should be recorded");
    assert_eq!(row.get("provider").map(String::as_str), Some("openai"));
    assert_eq!(row.get("model").map(String::as_str), Some("auto"));
    assert_eq!(
        row.get("resolved_model").map(String::as_str),
        Some("openai/gpt-5.5")
    );
    assert_eq!(row.get("input_tokens").map(String::as_str), Some("11"));
    assert_eq!(row.get("output_tokens").map(String::as_str), Some("4"));

    let decisions = db
        .list_decisions(&crate::test_support::audit::DecisionFilter {
            action: Some("gateway.cross_provider_translate".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "translated");
}

/// Seeds a cross-provider namespace policy: Anthropic client models allowed,
/// but `auto`/default resolves to an OpenAI-family model so the gateway
/// translates. Returns nothing; caller drives the gateway.
async fn seed_cross_provider_policy(target: &str, default_model: &str, runtime: &str) {
    let channel = connect_sekai(target).await.unwrap();
    ChiseiServiceClient::new(channel)
        .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
            namespace: "default".to_string(),
            allowed_runtimes: vec![runtime.to_string()],
            allowed_models: vec![default_model.to_string()],
            default_runtime: runtime.to_string(),
            default_model: default_model.to_string(),
            data_class: String::new(),
            context_admission_policy_json: DEFAULT_CONTEXT_ADMISSION_POLICY_JSON.to_string(),
        }))
        .await
        .unwrap();
    wait_for_seeded_gateway_decision(target, default_model, runtime).await;
}

async fn wait_for_seeded_gateway_decision(target: &str, default_model: &str, runtime: &str) {
    let request = DecideGatewayExecutionRequest {
        contract_version: "gateway.decide/v2".to_string(),
        namespace: "default".to_string(),
        requested_model: default_model.to_string(),
        operation_class: "gateway.http".to_string(),
        estimated_cost_usd_micros: 0,
        correlation_operation_id: "seeded-policy-readiness".to_string(),
        correlation_attempt: 1,
        estimated_tokens: 1,
        task_class: "general".to_string(),
        preferred_runtime: runtime.to_string(),
        project: "default".to_string(),
        agent: "claude-code".to_string(),
        key_id: String::new(),
        work_unit: String::new(),
        local_free_available: true,
        user_id: "claude-code".to_string(),
        route_override: String::new(),
        capability_requirements_json: Vec::new(),
        expected_calls: 1,
        pipeline_spec: String::new(),
    };
    for _ in 0..250 {
        let channel = connect_sekai(target).await.unwrap();
        match tokio::time::timeout(
            Duration::from_secs(5),
            ChiseiServiceClient::new(channel)
                .decide_gateway_execution(gateway_request(request.clone())),
        )
        .await
        {
            Ok(Ok(response)) if response.get_ref().admitted => return,
            Ok(Ok(response)) => panic!(
                "seeded gateway policy was not admitted: {}",
                response.get_ref().deny_message
            ),
            Ok(Err(status))
                if !matches!(
                    status.code(),
                    tonic::Code::Unavailable | tonic::Code::Unknown | tonic::Code::Cancelled
                ) =>
            {
                panic!("seeded gateway policy readiness failed: {status}")
            }
            _ => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("seeded gateway policy did not become ready");
}

#[tokio::test]
async fn anthropic_streaming_translates_to_openai_chat_stream_cross_provider() {
    // Upstream OpenAI-compatible chat SSE stream.
    let sse = "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n\
               data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"translated\"}}]}\n\n\
               data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\" ok\"},\"finish_reason\":null}]}\n\n\
               data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n\
               data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4,\"total_tokens\":15}}\n\n\
               data: [DONE]\n\n";
    let (upstream_base, requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let (chisei_target, db) = spawn_control_plane().await;
    seed_cross_provider_policy(&chisei_target, "gpt-5.5", "openai").await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: true,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "stream": true,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    let body = resp.text().await.unwrap();
    // Client receives well-formed Anthropic Messages SSE events.
    assert!(body.contains("event: message_start"), "{body}");
    assert!(body.contains("\"model\":\"gpt-5.5\""), "{body}");
    assert!(!body.contains("openai/gpt-5.5"), "{body}");
    assert!(body.contains("event: content_block_start"), "{body}");
    assert!(body.contains("event: content_block_delta"), "{body}");
    assert!(body.contains("\"text\":\"translated\""), "{body}");
    assert!(body.contains("\"text\":\" ok\""), "{body}");
    assert!(body.contains("event: message_delta"), "{body}");
    assert!(body.contains("event: message_stop"), "{body}");
    // Client-facing usage carries the upstream completion tokens, not zero.
    assert!(body.contains("\"output_tokens\":4"), "{body}");

    // Upstream got a streaming chat-completions request.
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/chat/completions");
        let translated: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        assert_eq!(translated["model"], "gpt-5.5");
        assert_eq!(translated["stream"], true);
    }

    // Usage is metered from the tapped upstream OpenAI stream.
    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("11"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("4"));
}

#[tokio::test]
async fn anthropic_streaming_with_tools_is_denied_cross_provider() {
    let (upstream_base, requests) =
        spawn_fake_upstream("data: [DONE]\n\n", "text/event-stream").await;
    let (chisei_target, _db) = spawn_control_plane().await;
    seed_cross_provider_policy(&chisei_target, "gpt-5.5", "openai").await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: true,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "stream": true,
            "tools": [{"name": "get_weather", "input_schema": {"type": "object"}}],
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "capability_unsupported");
    // Nothing was forwarded upstream.
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn anthropic_non_streaming_routes_to_resolved_ollama_backend() {
    // Cross-provider resolved to an Ollama model: route to the Ollama base,
    // strip the ollama/ prefix, and send no upstream auth.
    let upstream_body = r#"{
        "id":"chatcmpl_1",
        "object":"chat.completion",
        "model":"llama3.2:latest",
        "choices":[{"index":0,"message":{"role":"assistant","content":"local ok"},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    // Point the control-plane resolver's Ollama listing at a fake /api/tags
    // so the model resolves without a live Ollama server (CI has none). A
    // distinctive name that a real local Ollama would not have guarantees
    // this test exercises the fake listing, not an ambient Ollama install.
    let ollama_tags = spawn_fake_ollama_tags("ci-fake-ollama:latest").await;
    let mut cp_config = test_config();
    cp_config.ollama_url = ollama_tags;
    let (chisei_target, db) = spawn_control_plane_with_config(cp_config).await;
    seed_cross_provider_policy(&chisei_target, "ollama/ci-fake-ollama:latest", "ollama").await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        // OpenAI base points nowhere; the request must go to the Ollama base.
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: upstream_base,
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: true,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "gateway response: {body}");
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["type"], "message");
    assert_eq!(body["content"][0]["text"], "local ok");

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/chat/completions");
    // Ollama gets no upstream auth.
    assert_eq!(requests[0].authorization, None);
    assert_eq!(requests[0].x_api_key, None);
    // The ollama/ prefix is stripped from the resolved model.
    let translated: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(translated["model"], "ci-fake-ollama:latest");
    drop(requests);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("provider").map(String::as_str), Some("ollama"));
    let decisions = db
        .list_decisions(&crate::test_support::audit::DecisionFilter {
            action: Some("gateway.cross_provider_translate".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0]
            .evidence
            .get("resolved_provider")
            .map(String::as_str),
        Some("ollama")
    );
}

#[tokio::test]
async fn cross_provider_passthrough_strips_client_anthropic_credential() {
    // Security: in passthrough mode a client presents its own Anthropic
    // credential. When policy routes cross-provider to OpenAI, that credential
    // must NOT be forwarded to api.openai.com; the gateway applies its own
    // OpenAI key instead.
    let upstream_body = r#"{
        "id":"chatcmpl_1",
        "object":"chat.completion",
        "model":"gpt-5.5",
        "choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, _db) = spawn_control_plane().await;
    seed_cross_provider_policy(&chisei_target, "gpt-5.5", "openai").await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        // Passthrough mode, no OpenAI rewrite: the client credential would be
        // forwarded verbatim if not for the cross-provider stripping.
        allow_auth_passthrough: true,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: true,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .bearer_auth("sk-ant-oat-client-subscription-secret")
        .header(X_CHISEI_AGENT.as_str(), "claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    // The upstream got the gateway's OpenAI key, never the client's token.
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer real-openai-key")
    );
    assert_ne!(
        requests[0].authorization.as_deref(),
        Some("Bearer sk-ant-oat-client-subscription-secret")
    );
    assert_eq!(requests[0].x_api_key, None);
}

#[tokio::test]
async fn anthropic_messages_streaming_merges_usage_events() {
    let sse = "event: message_start\n\
               data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":100,\"cache_creation_input_tokens\":30,\"cache_creation\":{\"ephemeral_5m_input_tokens\":20,\"ephemeral_1h_input_tokens\":10},\"output_tokens\":1}}}\n\n\
               event: content_block_delta\n\
               data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n\
               event: message_delta\n\
               data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n\n";
    let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 64,
            "stream": true,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), sse);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("provider").map(String::as_str),
        Some("anthropic")
    );
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("10"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("7"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("147"));
    assert_eq!(
        rows[0].get("cache_read_input_tokens").map(String::as_str),
        Some("100")
    );
    assert_eq!(
        rows[0]
            .get("cache_creation_5m_input_tokens")
            .map(String::as_str),
        Some("20")
    );
    assert_eq!(
        rows[0]
            .get("cache_creation_1h_input_tokens")
            .map(String::as_str),
        Some("10")
    );
}

#[tokio::test]
async fn anthropic_count_tokens_proxy_records_input_tokens() {
    let upstream_body = r#"{"input_tokens":17}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages/count_tokens"))
        .header(X_API_KEY, "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), upstream_body);
    assert_eq!(
        requests.lock().unwrap()[0].path,
        "/v1/messages/count_tokens"
    );

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("provider").map(String::as_str),
        Some("anthropic")
    );
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("17"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("0"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("17"));
}

#[tokio::test]
async fn unknown_key_is_rejected_when_allowlist_is_configured() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let mut gateway_keys = HashMap::new();
    gateway_keys.insert(
        "sk-chisei-known".to_string(),
        GatewayIdentity {
            agent: "codex-app".to_string(),
            project: "sekai-chisei".to_string(),
            user_id: "agent:codex-app".to_string(),
            key_id: "codex-app".to_string(),
            tier: DEFAULT_GATEWAY_TIER.to_string(),
        },
    );
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: None,
        default_project: "default".to_string(),
        gateway_keys,
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-unknown")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unknown_key_rejection_records_audit_decision() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let (chisei_target, db) = spawn_control_plane().await;
    let mut gateway_keys = HashMap::new();
    gateway_keys.insert(
        "sk-chisei-known".to_string(),
        GatewayIdentity {
            agent: "codex-app".to_string(),
            project: "sekai-chisei".to_string(),
            user_id: "agent:codex-app".to_string(),
            key_id: "codex-app".to_string(),
            tier: DEFAULT_GATEWAY_TIER.to_string(),
        },
    );
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys,
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-unknown")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(requests.lock().unwrap().is_empty());

    let decisions = db
        .list_decisions(&crate::test_support::audit::DecisionFilter {
            action: Some("gateway.auth_failed".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].actor, "chisei-gateway");
    assert_eq!(decisions[0].outcome, "denied");
    assert_eq!(decisions[0].target_id, "llm_calls");
    assert_eq!(decisions[0].reason, "unknown chisei gateway key");
    assert_eq!(
        decisions[0]
            .evidence
            .get("presented_key")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn admin_refresh_clears_gateway_key_cache() {
    let upstream_body = r#"{"id":"resp_1","status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_runtime(
        GatewayConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            openai_base_url: upstream_base,
            openai_api_key: Some("real-openai-key".to_string()),
            anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
            ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
            native_base_url: None,
            anthropic_api_key: Some("real-anthropic-key".to_string()),
            chisei_grpc_target: Some(chisei_target),
            default_project: "default".to_string(),
            gateway_keys: HashMap::new(),
            allow_auth_passthrough: false,
            rewrite_openai_passthrough_auth: false,
            pricing: HashMap::new(),
            allow_cross_provider: false,
        },
        GatewayRuntime::new(
            Duration::from_secs(60 * 60),
            Some("admin-secret".to_string()),
        ),
    )
    .await;
    let client = reqwest::Client::new();
    let new_key = "sk-chisei-new-worker";

    let first = client
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth(new_key)
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
    assert!(requests.lock().unwrap().is_empty());

    db.create_object(&crate::domain::Object {
        id: "gateway-key-new-worker".to_string(),
        kind: "gateway_key".to_string(),
        name: "new-worker".to_string(),
        namespace: "default".to_string(),
        external_id: "gateway_key:new-worker:default".to_string(),
        properties: HashMap::from([
            ("agent".to_string(), "new-worker".to_string()),
            ("project".to_string(), "default".to_string()),
            ("status".to_string(), "active".to_string()),
            ("key_hash".to_string(), hash_gateway_key(new_key)),
        ]),
        created: 0,
        updated: 0,
    })
    .unwrap();

    let cached_miss = client
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth(new_key)
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(cached_miss.status(), StatusCode::UNAUTHORIZED);

    let unauthorized_refresh = client
        .post(format!("{gateway_base}/_chisei/admin/refresh"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized_refresh.status(), StatusCode::UNAUTHORIZED);

    let refresh = client
        .post(format!("{gateway_base}/_chisei/admin/refresh"))
        .bearer_auth("admin-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(refresh.status(), StatusCode::OK);
    let refresh_body: serde_json::Value = refresh.json().await.unwrap();
    assert_eq!(refresh_body["refreshed"], true);
    assert_eq!(refresh_body["cleared_key_cache_entries"], 1);

    let accepted = client
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth(new_key)
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(accepted.text().await.unwrap(), upstream_body);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn fail_closed_blocks_when_chisei_preflight_is_unavailable() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some("/tmp/sekai-chisei-missing-test.sock".to_string()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn available_models_endpoint_is_authenticated_filterable_and_redacted() {
    let (upstream_base, _) =
        spawn_fake_upstream(r#"{"data":[{"id":"gpt-5.5"}]}"#, "application/json").await;
    let gateway_base = spawn_gateway(upstream_base).await;
    let client = reqwest::Client::new();

    let unauthenticated = client
        .get(format!("{gateway_base}/v1/chisei/models"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let response = client
        .get(format!("{gateway_base}/v1/chisei/models?provider=openai"))
        .bearer_auth("sk-chisei-codex-app")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["version"], "chisei.available-models/v1");
    assert!(
        value["models"]
            .as_array()
            .unwrap()
            .iter()
            .all(|model| model["provider"] == "openai")
    );
    assert!(body.contains("openai/gpt-5.5"));
    assert!(!body.contains("real-openai-key"));
    assert!(!body.contains("real-anthropic-key"));
    assert!(!body.contains("discovery_source"));
}

#[tokio::test]
async fn provider_capability_matrix_endpoint_is_versioned_and_does_not_dump_unentitled_profiles() {
    let (upstream_base, _) =
        spawn_fake_upstream(r#"{"data":[{"id":"gpt-5.5"}]}"#, "application/json").await;
    let gateway_base = spawn_gateway(upstream_base).await;
    let client = reqwest::Client::new();

    let unauthenticated = client
        .get(format!("{gateway_base}/v1/chisei/capabilities"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let response = client
        .get(format!("{gateway_base}/v1/chisei/capabilities"))
        .bearer_auth("sk-chisei-codex-app")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-chisei-capability-catalog")
            .and_then(|value| value.to_str().ok()),
        Some(CAPABILITY_MATRIX_VERSION)
    );
    let body = response.text().await.unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["version"], CAPABILITY_MATRIX_VERSION);
    assert_eq!(value["grant_semantics"], false);
    let providers = value["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|profile| profile["provider"].as_str())
        .collect::<Vec<_>>();
    assert!(providers.contains(&"openai"), "{providers:?}");
    assert!(
        !providers.contains(&"meta"),
        "experimental unconfigured meta must not appear: {providers:?}"
    );
    assert!(!body.contains("real-openai-key"));
    assert!(!body.contains("real-anthropic-key"));
    assert!(!body.contains("sekai.semantic."));
    assert!(!body.contains("authorization_context"));
}

#[tokio::test]
async fn configured_gateway_fails_closed_when_decision_is_unavailable() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some("/tmp/sekai-chisei-missing-test.sock".to_string()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::from([(
            "sk-chisei-codex-app".to_string(),
            GatewayIdentity {
                agent: "codex-app".to_string(),
                project: "default".to_string(),
                user_id: "agent:codex-app".to_string(),
                key_id: "codex-app".to_string(),
                tier: "low-risk".to_string(),
            },
        )]),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(requests.lock().unwrap().is_empty());

    let classified = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "sensitive")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(classified.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(requests.lock().unwrap().is_empty());

    let explicit = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "hello",
            "chisei_context": {
                "objects": [{"ref": "ticker:AAPL", "fields": ["score"]}]
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(explicit.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn budget_denial_records_audit_decision() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let (chisei_target, db) = spawn_control_plane().await;

    let channel = connect_sekai(&chisei_target).await.unwrap();
    ChiseiServiceClient::new(channel)
        .set_budget_limit(GrpcRequest::new(SetBudgetLimitRequest {
            user_id: String::new(),
            max_tokens: 1,
            period_type: "day".to_string(),
            subject: String::new(),
            project: "default".to_string(),
            agent: "codex-app".to_string(),
            key_id: String::new(),
            work_unit: String::new(),
            metric: String::new(),
        }))
        .await
        .unwrap();

    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: String::new(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(requests.lock().unwrap().is_empty());

    let decisions = db
        .list_decisions(&crate::test_support::audit::DecisionFilter {
            action: Some("gateway.budget_denied".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].actor, "chisei-gateway");
    assert_eq!(decisions[0].outcome, "denied");
    assert_eq!(decisions[0].target_id, "llm_calls");
    assert_eq!(
        decisions[0].evidence.get("user_id").map(String::as_str),
        Some("agent:codex-app")
    );

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("status").map(String::as_str), Some("429"));
    assert_eq!(
        rows[0].get("error_type").map(String::as_str),
        Some("budget_exceeded")
    );
    assert_eq!(
        rows[0]
            .get("refusal_reason")
            .map(|reason| reason.contains("budget exceeded")),
        Some(true)
    );
    assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
    assert_eq!(rows[0].get("provider").map(String::as_str), Some("openai"));
}

#[tokio::test]
async fn project_budget_denial_blocks_gateway_call() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let (chisei_target, db) = spawn_control_plane().await;

    let channel = connect_sekai(&chisei_target).await.unwrap();
    ChiseiServiceClient::new(channel)
        .set_budget_limit(GrpcRequest::new(SetBudgetLimitRequest {
            user_id: "project:default".to_string(),
            max_tokens: 1,
            period_type: "day".to_string(),
            subject: "project:default".to_string(),
            project: "default".to_string(),
            agent: String::new(),
            key_id: String::new(),
            work_unit: String::new(),
            metric: String::new(),
        }))
        .await
        .unwrap();

    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: String::new(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(requests.lock().unwrap().is_empty());

    let decisions = db
        .list_decisions(&crate::test_support::audit::DecisionFilter {
            action: Some("gateway.budget_denied".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0]
            .evidence
            .get("budget_subject")
            .map(String::as_str),
        Some("project:default")
    );

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("status").map(String::as_str), Some("429"));
    assert_eq!(
        rows[0]
            .get("refusal_reason")
            .map(|reason| reason.contains("project:default")),
        Some(true)
    );
}

#[tokio::test]
async fn referenced_object_context_records_egress_audit() {
    let upstream_body = r#"{
        "id":"resp_1",
        "object":"response",
        "status":"completed",
        "output":[{"type":"message","content":[{"type":"output_text","text":"gateway sampled answer"}]}],
        "usage":{"input_tokens":7,"output_tokens":5,"total_tokens":12}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    db.create_object(&crate::domain::Object {
        id: "ticker-aapl".to_string(),
        kind: "ticker".to_string(),
        name: "AAPL".to_string(),
        namespace: "sekai-chisei".to_string(),
        external_id: "ticker:AAPL".to_string(),
        properties: HashMap::from([
            ("verdict".to_string(), "bullish".to_string()),
            (
                crate::egress::EXTERNAL_PROPERTIES_KEY.to_string(),
                "score".to_string(),
            ),
            ("score".to_string(), "0.82".to_string()),
        ]),
        created: 0,
        updated: 0,
    })
    .unwrap();
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "sekai-chisei".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-work-unit", "gateway-egress-work")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "analyze ticker:{AAPL}"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let forwarded: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    let forwarded_input = forwarded["input"].as_str().unwrap();
    assert!(forwarded_input.contains("[Object context]"));
    assert!(forwarded_input.contains("score: 0.82"));
    assert!(!forwarded_input.contains("bullish"));
    drop(requests);

    let decisions = db
        .list_decisions(&crate::test_support::audit::DecisionFilter {
            action: Some("gateway.egress".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].actor, "chisei-gateway");
    assert_eq!(decisions[0].outcome, "redacted");
    assert!(!decisions[0].evidence["request_id"].is_empty());
    assert_eq!(decisions[0].evidence["work_unit"], "gateway-egress-work");
    assert_eq!(
        decisions[0].evidence.get("object_refs").map(String::as_str),
        Some("ticker:AAPL")
    );
    assert_eq!(
        decisions[0]
            .evidence
            .get("included_count")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        decisions[0]
            .evidence
            .get("redacted_count")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        decisions[0]
            .evidence
            .get("payload_rewritten")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn explicit_context_manifest_injects_only_selected_fields() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let (chisei_target, db) = spawn_control_plane().await;
    db.create_object(&crate::domain::Object {
        id: "ticker-aapl".to_string(),
        kind: "ticker".to_string(),
        name: "AAPL".to_string(),
        namespace: "sekai-chisei".to_string(),
        external_id: "ticker:AAPL".to_string(),
        properties: HashMap::from([
            ("verdict".to_string(), "bullish".to_string()),
            ("score".to_string(), "0.82".to_string()),
            ("secret_note".to_string(), "do not forward".to_string()),
            (
                crate::egress::EXTERNAL_PROPERTIES_KEY.to_string(),
                "score,verdict".to_string(),
            ),
        ]),
        created: 0,
        updated: 0,
    })
    .unwrap();
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "sekai-chisei".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "analyze the selected context",
            "chisei_context": {
                "objects": [{"ref": "ticker:AAPL", "fields": ["score", "secret_note"]}]
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let forwarded: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert!(forwarded.get("chisei_context").is_none());
    let forwarded_input = forwarded["input"].as_str().unwrap();
    assert!(forwarded_input.contains("score: 0.82"));
    assert!(!forwarded_input.contains("bullish"));
    assert!(!forwarded_input.contains("do not forward"));
    drop(requests);

    let decisions = db
        .list_decisions(&crate::test_support::audit::DecisionFilter {
            action: Some("gateway.egress".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    let evidence = &decisions[0].evidence;
    assert_eq!(
        evidence.get("context_selection").map(String::as_str),
        Some("explicit")
    );
    assert_eq!(
        evidence.get("injected_context_source").map(String::as_str),
        Some("sekai_graph")
    );
    assert_eq!(
        evidence.get("injected_context_trust").map(String::as_str),
        Some("untrusted")
    );
    assert_eq!(
        evidence.get("requested_field_count").map(String::as_str),
        Some("2")
    );
    assert_eq!(
        evidence.get("omitted_field_count").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        evidence.get("redacted_count").map(String::as_str),
        Some("1")
    );
    assert_eq!(decisions[0].outcome, "redacted");
    assert!(
        evidence
            .get("estimated_tokens_avoided")
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|value| value > 0)
    );
}

#[tokio::test]
async fn explicit_context_manifest_merges_fields_for_duplicate_roots() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let (chisei_target, db) = spawn_control_plane().await;
    db.create_object(&crate::domain::Object {
        id: "ticker-aapl".to_string(),
        kind: "ticker".to_string(),
        name: "AAPL".to_string(),
        namespace: "sekai-chisei".to_string(),
        external_id: "ticker:AAPL".to_string(),
        properties: HashMap::from([
            ("score".to_string(), "0.82".to_string()),
            ("verdict".to_string(), "bullish".to_string()),
            (
                crate::egress::EXTERNAL_PROPERTIES_KEY.to_string(),
                "score,verdict".to_string(),
            ),
        ]),
        created: 0,
        updated: 0,
    })
    .unwrap();
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "sekai-chisei".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let response = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "analyze the selected context",
            "chisei_context": {
                "objects": [
                    {"id": "ticker-aapl", "fields": ["score"]},
                    {"ref": "ticker:AAPL", "fields": ["verdict"]}
                ]
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let forwarded: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    let forwarded_input = forwarded["input"].as_str().unwrap();
    assert!(forwarded_input.contains("score: 0.82"));
    assert!(forwarded_input.contains("verdict: bullish"));
}

#[tokio::test]
async fn explicit_context_manifest_enforces_the_authenticated_callers_acl() {
    let (upstream_base, requests) = spawn_fake_upstream(
        r#"{"id":"resp_1","status":"completed"}"#,
        "application/json",
    )
    .await;
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    db.create_object(&crate::domain::Object {
        id: "private-ticker".to_string(),
        kind: "ticker".to_string(),
        name: "PRIVATE".to_string(),
        namespace: "sekai-chisei".to_string(),
        external_id: "ticker:PRIVATE".to_string(),
        properties: HashMap::from([
            ("score".to_string(), "0.99".to_string()),
            (
                crate::egress::EXTERNAL_PROPERTIES_KEY.to_string(),
                "score".to_string(),
            ),
        ]),
        created: 0,
        updated: 0,
    })
    .unwrap();
    db.create_grant(&crate::test_support::security::Grant {
        id: "private-ticker-grant".to_string(),
        object_id: "private-ticker".to_string(),
        principal: "agent:other".to_string(),
        role: crate::test_support::security::Role::Viewer,
        created: 0,
    })
    .unwrap();
    let (chisei_target, _) = spawn_control_plane_from_db(test_config(), db).await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "sekai-chisei".to_string(),
        gateway_keys: HashMap::from([(
            "caller-key".to_string(),
            GatewayIdentity {
                agent: "codex-app".to_string(),
                project: "sekai-chisei".to_string(),
                user_id: "agent:codex-app".to_string(),
                key_id: "codex-app".to_string(),
                tier: DEFAULT_GATEWAY_TIER.to_string(),
            },
        )]),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let response = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("caller-key")
        .json(&serde_json::json!({
            "model": "gpt-5.5",
            "input": "analyze private context",
            "chisei_context": {
                "objects": [{"ref": "ticker:PRIVATE", "fields": ["score"]}]
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn explicit_context_manifest_reports_a_missing_external_root() {
    let (chisei_target, _) = spawn_control_plane().await;
    let mut config = routing_config();
    config.chisei_grpc_target = Some(chisei_target);
    let identity = GatewayIdentity {
        agent: "codex-app".into(),
        project: "default".into(),
        user_id: "agent:codex-app".into(),
        key_id: "codex-app".into(),
        tier: DEFAULT_GATEWAY_TIER.into(),
    };
    let runtime = GatewayRuntime::new(Duration::from_secs(DEFAULT_KEY_CACHE_TTL_SECS), None);
    let request = GatewayContextRequest {
        objects: vec![GatewayContextObject {
            root: GatewayContextRoot::External("ticker:missing".into()),
            fields: vec!["score".into()],
        }],
        retrieval: None,
    };

    let response = apply_context_egress(
        &config,
        &runtime,
        &identity,
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        br#"{"model":"gpt-5.5","input":"analyze"}"#,
        Some(&request),
        Some("gpt-5.5"),
        Some("gpt-5.5"),
        "request-missing-context",
        None,
    )
    .await
    .unwrap_err();

    assert_eq!(response.status, StatusCode::NOT_FOUND);

    let retrieval_request = GatewayContextRequest {
        objects: vec![GatewayContextObject {
            root: GatewayContextRoot::Object("missing-object".into()),
            fields: vec!["score".into()],
        }],
        retrieval: Some(GatewayContextRetrieval {
            relations: vec!["touches".into()],
            direction: "both".into(),
            max_depth: 1,
            max_objects: 4,
            max_links: 4,
            kinds: vec!["ticker".into()],
            fields: vec!["score".into()],
        }),
    };
    let response = apply_context_egress(
        &config,
        &runtime,
        &identity,
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        br#"{"model":"gpt-5.5","input":"analyze"}"#,
        Some(&retrieval_request),
        Some("gpt-5.5"),
        Some("gpt-5.5"),
        "request-missing-retrieval",
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(response.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn egress_uses_client_shape_and_resolved_provider_attribution() {
    let (chisei_target, db) = spawn_control_plane().await;
    db.create_object(&crate::domain::Object {
        id: "ticker-aapl".into(),
        kind: "ticker".into(),
        name: "AAPL".into(),
        namespace: "default".into(),
        external_id: "ticker:AAPL".into(),
        properties: HashMap::from([
            ("score".into(), "0.82".into()),
            (
                crate::egress::EXTERNAL_PROPERTIES_KEY.into(),
                "score".into(),
            ),
        ]),
        created: 0,
        updated: 0,
    })
    .unwrap();
    let mut config = routing_config();
    config.chisei_grpc_target = Some(chisei_target);
    let runtime = GatewayRuntime::new(Duration::from_secs(DEFAULT_KEY_CACHE_TTL_SECS), None);
    let identity = GatewayIdentity {
        agent: "codex-app".into(),
        project: "default".into(),
        user_id: "agent:codex-app".into(),
        key_id: "codex-app".into(),
        tier: DEFAULT_GATEWAY_TIER.into(),
    };

    let egress = apply_context_egress(
        &config,
        &runtime,
        &identity,
        ProviderKind::OpenAi(OpenAiRuntime::OpenAi),
        ProviderKind::OpenAi(OpenAiRuntime::Ollama),
        br#"{"model":"gpt-5.5","input":"analyze ticker:{AAPL}"}"#,
        None,
        Some("gpt-5.5"),
        Some("ollama/qwen:14b"),
        "request-split-provider-egress",
        None,
    )
    .await
    .unwrap();

    let body: serde_json::Value = serde_json::from_slice(&egress.body).unwrap();
    assert!(body["input"].as_str().unwrap().contains("[Object context]"));
    let decisions = db
        .list_decisions(&crate::test_support::audit::DecisionFilter {
            action: Some("gateway.egress".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].evidence["provider"], "ollama");
}

#[tokio::test]
async fn anthropic_object_context_is_injected_as_system_text() {
    let upstream_body = r#"{
        "id":"msg_1",
        "type":"message",
        "usage":{"input_tokens":7,"output_tokens":5}
    }"#;
    let (upstream_base, requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    db.create_object(&crate::domain::Object {
        id: "ticker-msft".to_string(),
        kind: "ticker".to_string(),
        name: "MSFT".to_string(),
        namespace: "default".to_string(),
        external_id: "ticker:MSFT".to_string(),
        properties: HashMap::from([
            ("verdict".to_string(), "do not forward".to_string()),
            (
                crate::egress::EXTERNAL_PROPERTIES_KEY.to_string(),
                "score".to_string(),
            ),
            ("score".to_string(), "0.91".to_string()),
        ]),
        created: 0,
        updated: 0,
    })
    .unwrap();
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: "http://127.0.0.1:9/v1".to_string(),
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: upstream_base,
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/messages"))
        .header(X_API_KEY.as_str(), "sk-chisei-claude-code")
        .json(&serde_json::json!({
            "model": "claude-sonnet-4-8",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "analyze ticker:{MSFT}"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let forwarded: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    let system = forwarded["system"].as_str().unwrap();
    assert!(system.contains("[Object context]"));
    assert!(system.contains("score: 0.91"));
    assert!(!system.contains("do not forward"));
}

#[tokio::test]
async fn non_streaming_response_records_usage_and_appends_llm_call() {
    let upstream_body = r#"{
        "id":"resp_1",
        "object":"response",
        "status":"completed",
        "output":[{"type":"message","content":[{"type":"output_text","text":"gateway sampled answer"}]}],
        "usage":{"input_tokens":7,"output_tokens":5,"total_tokens":12}
    }"#;
    let (upstream_base, _requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let mut config = test_config();
    config.sample_rate = 1.0;
    config.scoring_enabled = true;
    let (chisei_target, db) = spawn_control_plane_with_config(config).await;
    let pricing = HashMap::from([(
        "gpt-5.5".to_string(),
        ModelPricing {
            input_usd_micros_per_million: 1_000_000,
            output_usd_micros_per_million: 2_000_000,
            cached_input_usd_micros_per_million: 1_000_000,
            ..Default::default()
        },
    )]);
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing,
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-work-unit", "wu-cost-1")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), upstream_body);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
    assert_eq!(rows[0].get("project").map(String::as_str), Some("default"));
    assert_eq!(rows[0].get("model").map(String::as_str), Some("gpt-5.5"));
    assert_eq!(
        rows[0].get("resolved_model").map(String::as_str),
        Some("openai/gpt-5.5")
    );
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("7"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("5"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("12"));
    // No cache tokens in this response, so the cache keys are omitted.
    assert_eq!(rows[0].get("cache_read_input_tokens"), None);
    assert_eq!(rows[0].get("cache_creation_input_tokens"), None);
    assert_eq!(rows[0].get("cache_savings_usd_micros"), None);
    assert_eq!(
        rows[0].get("cost_usd_micros").map(String::as_str),
        Some("17")
    );
    assert_eq!(
        rows[0].get("cost_usd").map(String::as_str),
        Some("0.000017")
    );
    assert_eq!(
        rows[0].get("work_unit_id").map(String::as_str),
        Some("wu-cost-1")
    );
    assert_eq!(
        rows[0].get("pipeline_sampled").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        rows[0].get("sample_reason").map(String::as_str),
        Some("base")
    );
    assert_eq!(rows[0].get("sample_rate").map(String::as_str), Some("1"));

    let work_unit = db
        .find_by_external_id("work_unit:wu-cost-1")
        .unwrap()
        .unwrap();
    let request_id = rows[0].get("request_id").unwrap();
    let llm_call = db
        .find_by_external_id(&format!("llm_call:{request_id}"))
        .unwrap()
        .unwrap();
    let links = db
        .get_links(
            &work_unit.id,
            "incurs_usage",
            &crate::domain::Direction::Outgoing,
        )
        .unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].to_id, llm_call.id);

    let decisions = db
        .list_decisions(&crate::test_support::audit::DecisionFilter {
            action: Some("gateway.sampled".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].reason, "base");

    let observations = db.list_unscored_observations(10).unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].request_id, *request_id);
    assert_eq!(observations[0].namespace, "default");
    assert_eq!(observations[0].output_content, "gateway sampled answer");
    assert_eq!(observations[0].sample_reason, "base");
}

#[tokio::test]
async fn cache_tokens_and_savings_are_recorded_on_llm_call() {
    // OpenAI reports cached tokens as a subset of prompt/input tokens.
    let upstream_body = r#"{
        "id":"resp_1",
        "object":"response",
        "status":"completed",
        "output":[{"type":"message","content":[{"type":"output_text","text":"cached answer"}]}],
        "usage":{"input_tokens":100,"output_tokens":5,"total_tokens":105,"prompt_tokens_details":{"cached_tokens":80}}
    }"#;
    let (upstream_base, _requests) = spawn_fake_upstream(upstream_body, "application/json").await;
    let (chisei_target, db) = spawn_control_plane().await;
    // input 1 usd/1M, output 2 usd/1M, cached 0.1 usd/1M.
    let pricing = HashMap::from([(
        "gpt-5.5".to_string(),
        ModelPricing {
            input_usd_micros_per_million: 1_000_000,
            output_usd_micros_per_million: 2_000_000,
            cached_input_usd_micros_per_million: 100_000,
            ..Default::default()
        },
    )]);
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target.clone()),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing,
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("100"));
    assert_eq!(
        rows[0].get("cache_read_input_tokens").map(String::as_str),
        Some("80")
    );
    // No cache-creation tokens in this response.
    assert_eq!(rows[0].get("cache_creation_input_tokens"), None);
    // Cost = 20 uncached * 1 + 80 cached * 0.1 + 5 output * 2 = 38 micros.
    assert_eq!(
        rows[0].get("cost_usd_micros").map(String::as_str),
        Some("38")
    );
    // Savings = 80 cache-read tokens * (1 - 0.1) usd/1M = 72 micros.
    assert_eq!(
        rows[0].get("cache_savings_usd_micros").map(String::as_str),
        Some("72")
    );
    assert_eq!(
        rows[0].get("cache_savings_usd").map(String::as_str),
        Some("0.000072")
    );
}

#[tokio::test]
async fn streaming_response_records_usage_after_passthrough() {
    let sse = "event: response.created\n\
               data: {\"type\":\"response.created\"}\n\n\
               event: response.completed\n\
               data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":13,\"total_tokens\":24}}}\n\n";
    let (upstream_base, _requests) = spawn_fake_upstream(sse, "text/event-stream").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello", "stream": true}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), sse);

    let rows = db.query_rows("llm_calls", &RowQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("11"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("13"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("24"));
}

// Captured from chatgpt.com/backend-api/codex/responses: the ChatGPT Codex
// backend streams SSE with no Content-Type header, emits "usage": null on
// response.created, and carries real usage on response.completed.
const CODEX_BACKEND_SSE: &str = "event: response.created\n\
data: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp_codex\",\"status\":\"in_progress\",\"usage\":null,\"tool_usage\":{\"image_gen\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0},\"web_search\":{\"num_requests\":0}}}}\n\n\
event: response.output_text.delta\n\
data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n\
event: response.completed\n\
data: {\"type\":\"response.completed\",\"sequence_number\":9,\"response\":{\"id\":\"resp_codex\",\"status\":\"completed\",\"output\":[{\"id\":\"msg_1\",\"type\":\"message\",\"status\":\"completed\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi\"}],\"role\":\"assistant\"}],\"usage\":{\"input_tokens\":45,\"input_tokens_details\":{\"cached_tokens\":0},\"output_tokens\":5,\"output_tokens_details\":{\"reasoning_tokens\":0},\"total_tokens\":50},\"tool_usage\":{\"image_gen\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0},\"web_search\":{\"num_requests\":0}}}}\n\n";

#[tokio::test]
async fn codex_backend_sse_without_content_type_records_usage() {
    let (upstream_base, _requests) = spawn_fake_upstream(CODEX_BACKEND_SSE, "").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello", "stream": true}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), CODEX_BACKEND_SSE);

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("agent").map(String::as_str), Some("codex-app"));
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("45"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("5"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("50"));
}

#[tokio::test]
async fn codex_backend_sse_without_content_type_streams_incrementally() {
    const CHUNKS: &[&str] = &[
        "event: response.created\n\
         data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_codex\",\"status\":\"in_progress\",\"usage\":null}}\n\n",
        "event: response.output_text.delta\n\
         data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n",
        "event: response.completed\n\
         data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_codex\",\"status\":\"completed\",\"usage\":{\"input_tokens\":45,\"output_tokens\":5,\"total_tokens\":50}}}\n\n",
    ];
    let upstream_base = spawn_fake_chunked_upstream(CHUNKS, Duration::from_millis(150)).await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let mut resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello", "stream": true}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let first = resp.chunk().await.unwrap().unwrap();
    let mut body = String::from_utf8(first.to_vec()).unwrap();
    assert!(body.contains("response.created"));
    assert!(
        !body.contains("response.completed"),
        "gateway buffered the SSE body instead of streaming it: {body}"
    );
    while let Some(chunk) = resp.chunk().await.unwrap() {
        body.push_str(std::str::from_utf8(&chunk).unwrap());
    }
    assert_eq!(body, CHUNKS.concat());

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("45"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("5"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("50"));
}

#[tokio::test]
async fn json_body_without_content_type_streams_and_records_usage() {
    // The blank line between fields must survive the SSE usage tap: a
    // non-SSE body split on event boundaries would lose its usage.
    let upstream_body = "{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\n\n\"usage\":{\"input_tokens\":8,\"output_tokens\":6,\"total_tokens\":14},\n\n\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi\"}]}]}";
    let (upstream_base, _requests) = spawn_fake_upstream(upstream_body, "").await;
    let (chisei_target, db) = spawn_control_plane().await;
    let gateway_base = spawn_gateway_with_config(GatewayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        openai_base_url: upstream_base,
        openai_api_key: Some("real-openai-key".to_string()),
        anthropic_base_url: "http://127.0.0.1:9/v1".to_string(),
        ollama_base_url: "http://127.0.0.1:11434/v1".to_string(),
        native_base_url: None,
        anthropic_api_key: Some("real-anthropic-key".to_string()),
        chisei_grpc_target: Some(chisei_target),
        default_project: "default".to_string(),
        gateway_keys: HashMap::new(),
        allow_auth_passthrough: false,
        rewrite_openai_passthrough_auth: false,
        pricing: HashMap::new(),
        allow_cross_provider: false,
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), upstream_body);

    let rows = wait_for_llm_calls(&db, 1).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("input_tokens").map(String::as_str), Some("8"));
    assert_eq!(rows[0].get("output_tokens").map(String::as_str), Some("6"));
    assert_eq!(rows[0].get("total_tokens").map(String::as_str), Some("14"));
    assert_eq!(rows[0].get("terminal_outcome").map(String::as_str), None);
}

#[tokio::test]
async fn responses_errors_without_content_type_are_normalized() {
    for upstream_body in [
        r#"{"error":{"message":"provider rejected request"}}"#,
        "",
        "data: {\"error\":{\"message\":\"provider rejected request\"}}\n\n",
    ] {
        let (upstream_base, _requests) =
            spawn_fake_upstream_with_status(upstream_body, "", StatusCode::BAD_REQUEST, None).await;
        let gateway_base = spawn_gateway_with_preflight(upstream_base).await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-chisei-data-class", "unclassified")
            .header("x-chisei-action-risk", "low")
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();

        let status = resp.status();
        let body = resp.text().await.unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["error"]["code"], "invalid_request");
    }
}

#[tokio::test]
async fn responses_client_errors_use_stable_error_codes() {
    for (status, expected_code) in [
        (StatusCode::UNAUTHORIZED, "authentication_error"),
        (StatusCode::PAYMENT_REQUIRED, "upstream_unavailable"),
        (StatusCode::FORBIDDEN, "authentication_error"),
        (StatusCode::CONFLICT, "invalid_request"),
    ] {
        let (upstream_base, _requests) = spawn_fake_upstream_with_status(
            r#"{"error":{"code":"vendor_specific","message":"rejected"}}"#,
            "application/json",
            status,
            None,
        )
        .await;
        let gateway_base = spawn_gateway_with_preflight(upstream_base).await;

        let resp = reqwest::Client::new()
            .post(format!("{gateway_base}/v1/responses"))
            .bearer_auth("sk-chisei-codex-app")
            .header("x-chisei-data-class", "unclassified")
            .header("x-chisei-action-risk", "low")
            .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), status);
        assert_eq!(resp.headers()[&X_CHISEI_RETRY_SAFETY], "safe");
        let body: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["error"]["code"], expected_code);
        assert_eq!(body["error"]["message"], "rejected");
    }
}

#[tokio::test]
async fn retryable_responses_errors_are_normalized() {
    let upstream_body = r#"{"error":{"code":"vendor_busy","message":"try later"}}"#;
    let (upstream_base, _requests) = spawn_fake_upstream_with_status(
        upstream_body,
        "application/json",
        StatusCode::TOO_MANY_REQUESTS,
        None,
    )
    .await;
    let gateway_base = spawn_gateway_with_preflight(upstream_base).await;
    let resp = reqwest::Client::new()
        .post(format!("{gateway_base}/v1/responses"))
        .bearer_auth("sk-chisei-codex-app")
        .header("x-chisei-data-class", "unclassified")
        .header("x-chisei-action-risk", "low")
        .json(&serde_json::json!({"model": "gpt-5.5", "input": "hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp.headers()[&X_CHISEI_RETRY_SAFETY], "safe");
    let body: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "rate_limited");
    assert_eq!(body["error"]["message"], "try later");
}

#[test]
fn buffered_body_usage_falls_back_to_sse_parsing() {
    let (usage, observation) = extract_buffered_body_usage(CODEX_BACKEND_SSE.as_bytes());
    assert_eq!(
        usage,
        Some(ResponseUsage {
            input_tokens: 45,
            output_tokens: 5,
            total_tokens: 50,
            provider_total_tokens: Some(50),
            ..Default::default()
        })
    );
    assert!(
        observation
            .as_ref()
            .is_some_and(|observation| observation.output_content.contains("hi"))
    );

    let json = br#"{"id":"resp_1","usage":{"input_tokens":8,"output_tokens":6}}"#;
    let (usage, _) = extract_buffered_body_usage(json);
    assert_eq!(
        usage,
        Some(ResponseUsage {
            input_tokens: 8,
            output_tokens: 6,
            total_tokens: 14,
            ..Default::default()
        })
    );

    let (usage, observation) = extract_buffered_body_usage(b"neither json nor an event stream");
    assert_eq!(usage, None);
    assert_eq!(observation, None);
}

#[test]
fn extract_response_usage_parses_anthropic_cache_tokens() {
    let body = br#"{"type":"message","usage":{"input_tokens":10,"cache_read_input_tokens":120,"cache_creation_input_tokens":30,"output_tokens":7}}"#;
    let usage = extract_response_usage(body).expect("usage");
    assert_eq!(usage.input_tokens, 10);
    assert_eq!(usage.output_tokens, 7);
    assert_eq!(usage.cache_read_input_tokens, 120);
    assert_eq!(usage.cache_creation_input_tokens, 30);
    assert_eq!(usage.total_tokens, 167);
    assert_eq!(usage.provider_total_tokens, None);
}

#[test]
fn extract_response_usage_preserves_anthropic_cache_write_classes() {
    let body = br#"{"usage":{"input_tokens":10,"cache_read_input_tokens":100,"cache_creation_input_tokens":30,"cache_creation":{"ephemeral_5m_input_tokens":20,"ephemeral_1h_input_tokens":10},"output_tokens":5,"total_tokens":145}}"#;
    let usage = extract_response_usage(body).expect("usage");
    assert_eq!(usage.total_tokens, 145);
    assert_eq!(usage.provider_total_tokens, Some(145));
    assert_eq!(usage.cache_creation_5m_input_tokens, 20);
    assert_eq!(usage.cache_creation_1h_input_tokens, 10);
    assert!(usage.cache_creation_5m_reported);
    assert!(usage.cache_creation_1h_reported);
}

#[test]
fn malformed_or_absent_cache_fields_remain_unknown() {
    let malformed = br#"{"usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":"many","cache_creation":{"ephemeral_5m_input_tokens":-1}}}"#;
    let usage = extract_response_usage(malformed).expect("usage");
    assert!(!usage.cache_read_reported);
    assert!(!usage.cache_creation_reported);
    assert!(!usage.cache_creation_5m_reported);
    let mut values = HashMap::new();
    insert_normalized_usage_values(&mut values, &usage);
    assert!(!values.contains_key("cache_read_input_tokens"));
    assert!(!values.contains_key("cache_creation_5m_input_tokens"));
}

#[test]
fn extract_response_usage_parses_openai_cached_tokens() {
    let body = br#"{"usage":{"prompt_tokens":200,"completion_tokens":40,"prompt_tokens_details":{"cached_tokens":150}}}"#;
    let usage = extract_response_usage(body).expect("usage");
    assert_eq!(usage.input_tokens, 200);
    assert_eq!(usage.output_tokens, 40);
    assert_eq!(usage.cache_read_input_tokens, 150);
    assert_eq!(usage.total_tokens, 240);
    assert!(usage.cache_read_included_in_input);
    assert_eq!(usage.cache_creation_input_tokens, 0);
}

#[test]
fn extract_response_usage_defaults_cache_tokens_to_zero() {
    let body = br#"{"usage":{"input_tokens":8,"output_tokens":6}}"#;
    let usage = extract_response_usage(body).expect("usage");
    assert_eq!(usage.cache_read_input_tokens, 0);
    assert_eq!(usage.cache_creation_input_tokens, 0);
}

#[test]
fn sse_usage_tap_captures_anthropic_cache_tokens() {
    let mut tap = SseUsageTap::new();
    tap.push(
        b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":120,\"cache_creation_input_tokens\":30,\"output_tokens\":1}}}\n\n",
    );
    tap.push(
        b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":25}}\n\n",
    );
    let (usage, _) = tap.finish();
    let usage = usage.expect("usage");
    assert_eq!(usage.input_tokens, 10);
    assert_eq!(usage.output_tokens, 25);
    assert_eq!(usage.cache_read_input_tokens, 120);
    assert_eq!(usage.cache_creation_input_tokens, 30);
}

#[test]
fn streaming_and_non_streaming_cache_accounting_are_equivalent() {
    let body = br#"{"usage":{"input_tokens":10,"cache_read_input_tokens":120,"cache_creation_input_tokens":30,"cache_creation":{"ephemeral_5m_input_tokens":20,"ephemeral_1h_input_tokens":10},"output_tokens":25,"total_tokens":185}}"#;
    let buffered = extract_response_usage(body).unwrap();
    let mut tap = SseUsageTap::new();
    tap.push(
        b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":120,\"cache_creation_input_tokens\":30,\"cache_creation\":{\"ephemeral_5m_input_tokens\":20,\"ephemeral_1h_input_tokens\":10},\"output_tokens\":0}}}\n\n",
    );
    tap.push(
        b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":25,\"total_tokens\":185}}\n\n",
    );
    let streamed = tap.finish().0.unwrap();
    assert_eq!(streamed, buffered);
}

#[test]
fn merge_usage_carries_cache_tokens_from_earlier_event() {
    let start = ResponseUsage {
        input_tokens: 10,
        output_tokens: 1,
        total_tokens: 11,
        cache_read_input_tokens: 120,
        cache_creation_input_tokens: 30,
        cache_read_reported: true,
        cache_creation_reported: true,
        ..Default::default()
    };
    let delta = ResponseUsage {
        output_tokens: 25,
        ..Default::default()
    };
    let merged = merge_usage(Some(start), delta);
    assert_eq!(merged.input_tokens, 10);
    assert_eq!(merged.output_tokens, 25);
    assert_eq!(merged.cache_read_input_tokens, 120);
    assert_eq!(merged.cache_creation_input_tokens, 30);
}

#[test]
fn sse_usage_tap_preserves_non_sse_bodies_with_blank_lines() {
    let mut tap = SseUsageTap::new();
    tap.push(b"{\"id\":\"resp_1\",\n\n\"usage\":{\"input_tokens\":8,");
    tap.push(b"\"output_tokens\":6},\n\n\"object\":\"response\"}");
    let (usage, _) = tap.finish();
    assert_eq!(
        usage,
        Some(ResponseUsage {
            input_tokens: 8,
            output_tokens: 6,
            total_tokens: 14,
            ..Default::default()
        })
    );
}

#[test]
fn sse_usage_tap_detects_sse_after_leading_comment() {
    let mut tap = SseUsageTap::new();
    tap.push(b": keepalive\n\n");
    tap.push(b"data: {\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}\n\n");
    let (usage, _) = tap.finish();
    assert_eq!(
        usage,
        Some(ResponseUsage {
            input_tokens: 3,
            output_tokens: 2,
            total_tokens: 5,
            ..Default::default()
        })
    );
}

#[test]
fn body_prefix_is_sse_waits_for_enough_bytes() {
    assert_eq!(body_prefix_is_sse(b""), None);
    assert_eq!(body_prefix_is_sse(b"\n\n"), None);
    assert_eq!(body_prefix_is_sse(b"dat"), None);
    assert_eq!(body_prefix_is_sse(b"data:"), Some(true));
    assert_eq!(body_prefix_is_sse(b"event: response.created"), Some(true));
    assert_eq!(body_prefix_is_sse(b": comment"), Some(true));
    assert_eq!(body_prefix_is_sse(b"\n\ndata: {}"), Some(true));
    assert_eq!(body_prefix_is_sse(b"{\"id\":\"resp_1\"}"), Some(false));
    assert_eq!(body_prefix_is_sse(b"plain text"), Some(false));
}

#[test]
fn context_manifest_is_removed_and_duplicate_refs_are_merged() {
    let body = serde_json::to_vec(&serde_json::json!({
        "model": "gpt-5.5",
        "input": "analyze",
        "chisei_context": {
            "objects": [
                {"ref": "ticker:AAPL", "fields": ["score", "score"]},
                {"ref": "ticker:AAPL", "fields": ["verdict"]}
            ]
        }
    }))
    .unwrap();

    let (cleaned, request) = extract_gateway_context_request(&body).unwrap();
    let cleaned: serde_json::Value = serde_json::from_slice(&cleaned).unwrap();
    assert!(cleaned.get("chisei_context").is_none());
    assert_eq!(cleaned["input"], "analyze");
    assert_eq!(
        request.unwrap().objects,
        vec![GatewayContextObject {
            root: GatewayContextRoot::External("ticker:AAPL".into()),
            fields: vec!["score".into(), "verdict".into()],
        }]
    );
}

#[test]
fn context_manifest_rejects_implicit_or_empty_field_selection() {
    let missing_fields = br#"{
        "model":"gpt-5.5",
        "chisei_context":{"objects":[{"ref":"ticker:AAPL","fields":[]}]}
    }"#;
    assert!(
        extract_gateway_context_request(missing_fields)
            .unwrap_err()
            .contains("at least one field")
    );

    let malformed_ref = br#"{
        "model":"gpt-5.5",
        "chisei_context":{"objects":[{"ref":"ticker:{AAPL}","fields":["score"]}]}
    }"#;
    assert!(
        extract_gateway_context_request(malformed_ref)
            .unwrap_err()
            .contains("invalid object ref")
    );
}

#[test]
fn context_manifest_enforces_field_cap_after_duplicate_ref_merge() {
    let first_fields = (0..MAX_CONTEXT_FIELDS_PER_OBJECT)
        .map(|index| format!("field_{index}"))
        .collect::<Vec<_>>();
    let body = serde_json::to_vec(&serde_json::json!({
        "model": "gpt-5.5",
        "chisei_context": {
            "objects": [
                {"ref": "ticker:AAPL", "fields": first_fields},
                {"ref": "ticker:AAPL", "fields": ["one_more_field"]}
            ]
        }
    }))
    .unwrap();

    assert!(
        extract_gateway_context_request(&body)
            .unwrap_err()
            .contains("selects more than 32 fields")
    );
}

#[test]
fn context_manifest_parses_object_and_link_ids_with_bounded_retrieval() {
    let body = serde_json::to_vec(&serde_json::json!({
        "model": "gpt-5.5",
        "chisei_context": {
            "objects": [
                {"id": "service-api", "fields": ["status"]},
                {"link_id": "learning-1->service-api", "fields": ["title"]}
            ],
            "retrieval": {
                "relations": ["touches", "produces"],
                "direction": "both",
                "max_depth": 2,
                "max_objects": 8,
                "max_links": 16,
                "kinds": ["learning"],
                "fields": ["title", "prevention"]
            }
        }
    }))
    .unwrap();

    let (_, request) = extract_gateway_context_request(&body).unwrap();
    let request = request.unwrap();
    assert_eq!(
        request.objects[0].root,
        GatewayContextRoot::Object("service-api".into())
    );
    assert_eq!(
        request.objects[1].root,
        GatewayContextRoot::Link("learning-1->service-api".into())
    );
    assert_eq!(
        request.retrieval,
        Some(GatewayContextRetrieval {
            relations: vec!["touches".into(), "produces".into()],
            direction: "both".into(),
            max_depth: 2,
            max_objects: 8,
            max_links: 16,
            kinds: vec!["learning".into()],
            fields: vec!["title".into(), "prevention".into()],
        })
    );
}

#[test]
fn context_manifest_rejects_ambiguous_roots_and_unbounded_retrieval() {
    let ambiguous = br#"{
        "model":"gpt-5.5",
        "chisei_context":{"objects":[{
            "ref":"ticker:AAPL","id":"ticker-aapl","fields":["score"]
        }]}
    }"#;
    assert!(
        extract_gateway_context_request(ambiguous)
            .unwrap_err()
            .contains("exactly one")
    );

    let unbounded = br#"{
        "model":"gpt-5.5",
        "chisei_context":{
            "objects":[{"id":"service-api","fields":["status"]}],
            "retrieval":{
                "relations":["touches"],"direction":"both","max_depth":4,
                "max_objects":8,"max_links":16,"kinds":["learning"],
                "fields":["title"]
            }
        }
    }"#;
    assert!(
        extract_gateway_context_request(unbounded)
            .unwrap_err()
            .contains("max_depth")
    );
}

#[test]
fn schema_restricted_context_field_stays_redacted_when_allowlisted() {
    let object = crate::domain::Object {
        id: "account-1".into(),
        kind: "account".into(),
        name: "account".into(),
        namespace: "default".into(),
        external_id: "account:1".into(),
        properties: HashMap::from([
            ("secret_note".into(), "do not forward".into()),
            (
                crate::egress::EXTERNAL_PROPERTIES_KEY.into(),
                "secret_note".into(),
            ),
        ]),
        created: 0,
        updated: 0,
    };
    let restricted = restricted_gateway_fields(vec![sekai_proto::sekai::ObjectType {
        kind: "account".into(),
        properties: vec![sekai_proto::sekai::PropertyDef {
            name: "secret_note".into(),
            classification: "sensitive".into(),
            ..Default::default()
        }],
        ..Default::default()
    }]);
    let mut record = crate::egress::new_record(&object);

    assert_eq!(
        filter_gateway_context_property(
            &object,
            "secret_note",
            restricted.get("account"),
            &mut record,
        ),
        None
    );
    assert_eq!(record.redacted_fields, vec!["secret_note"]);
    assert!(record.reasons[0].contains("schema classification"));
}

#[test]
fn resolve_task_class_uses_header_then_small_fast_heuristic() {
    // Explicit header wins and is normalized to lowercase.
    let mut headers = HeaderMap::new();
    headers.insert(X_CHISEI_TASK_CLASS, "Background".parse().unwrap());
    assert_eq!(
        resolve_task_class(&headers, Some("gpt-5.5")),
        "background".to_string()
    );

    // No header: small/fast models classify as background.
    let empty = HeaderMap::new();
    assert_eq!(
        resolve_task_class(&empty, Some("claude-haiku-4-5")),
        "background".to_string()
    );
    assert_eq!(
        resolve_task_class(&empty, Some("gpt-5.5-mini")),
        "background".to_string()
    );
    // Primary/reasoning models (and unknown) default to primary.
    assert_eq!(
        resolve_task_class(&empty, Some("gpt-5.5")),
        "primary".to_string()
    );
    assert_eq!(resolve_task_class(&empty, None), "primary".to_string());
}

#[test]
fn cap_injectable_objects_bounds_by_char_budget() {
    let obj = |line: &str| InjectableObject {
        line: line.to_string(),
        included_fields: 1,
        object_ref: line.to_string(),
    };
    // Two 10-char lines fit in a 25-char budget (10 + 1 separator + 10 = 21).
    let (kept, dropped) =
        cap_injectable_objects(vec![obj(&"a".repeat(10)), obj(&"b".repeat(10))], 25);
    assert_eq!(kept.len(), 2);
    assert_eq!(dropped, 0);

    // A tighter budget drops the second object.
    let (kept, dropped) =
        cap_injectable_objects(vec![obj(&"a".repeat(10)), obj(&"b".repeat(10))], 15);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].line, "a".repeat(10));
    assert_eq!(dropped, 1);
}

#[test]
fn cap_injectable_objects_truncates_oversized_first_line() {
    // A single object whose line is larger than the budget is truncated so
    // the total is always bounded, but at least one object is injected.
    let objects = vec![InjectableObject {
        line: "x".repeat(100),
        included_fields: 2,
        object_ref: "obj:1".to_string(),
    }];
    let (kept, dropped) = cap_injectable_objects(objects, 20);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].line.chars().count(), 20);
    assert_eq!(dropped, 0);
}

#[test]
fn rewrite_request_model_updates_only_model_value() {
    let rewritten =
        rewrite_request_model(br#"{"model":"gpt-5.5","input":"hello"}"#, "gpt-5.5-mini").unwrap();
    let value: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
    assert_eq!(value["model"], "gpt-5.5-mini");
    assert_eq!(value["input"], "hello");
}

#[test]
fn rewrite_request_model_preserves_cache_control_prefix() {
    let body = br#"{
        "model":"claude-sonnet-4-8",
        "system":[{"type":"text","text":"big cached prefix","cache_control":{"type":"ephemeral"}}],
        "messages":[{"role":"user","content":"hi"}]
    }"#;
    let original: serde_json::Value = serde_json::from_slice(body).unwrap();
    let rewritten = rewrite_request_model(body, "claude-opus-4-8").unwrap();
    let value: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
    // Only the model changes; the cached system prefix is byte-for-byte
    // identical (deep-equal, and identical when re-serialized).
    assert_eq!(value["model"], "claude-opus-4-8");
    assert_eq!(value["system"], original["system"]);
    assert_eq!(value["messages"], original["messages"]);
    assert_eq!(
        serde_json::to_vec(&value["system"]).unwrap(),
        serde_json::to_vec(&original["system"]).unwrap()
    );
}

#[test]
fn inject_context_preserves_anthropic_cache_control_prefix() {
    // System array carries the cache_control breakpoint; the client also
    // marks the last message. Injection must not touch either.
    let body = br#"{
        "model":"claude-sonnet-4-8",
        "system":[{"type":"text","text":"tooling + rules","cache_control":{"type":"ephemeral"}}],
        "messages":[
            {"role":"user","content":[{"type":"text","text":"earlier","cache_control":{"type":"ephemeral"}}]},
            {"role":"assistant","content":"ok"},
            {"role":"user","content":"analyze ticker:{MSFT}"}
        ]
    }"#;
    let original: serde_json::Value = serde_json::from_slice(body).unwrap();
    let injected = inject_gateway_context(ProviderKind::Anthropic, body, "score: 0.91")
        .unwrap()
        .expect("context injected");
    let value: serde_json::Value = serde_json::from_slice(&injected).unwrap();

    // The cached prefix (system + all earlier messages) is unchanged.
    assert_eq!(value["system"], original["system"]);
    let messages = value["messages"].as_array().unwrap();
    let original_messages = original["messages"].as_array().unwrap();
    assert_eq!(messages.len(), original_messages.len());
    assert_eq!(messages[0], original_messages[0]);
    assert_eq!(messages[1], original_messages[1]);

    // The context is appended to the final message, after its original
    // text, and carries no cache_control (uncached suffix).
    let last_content = messages[2]["content"].as_array().unwrap();
    assert_eq!(last_content[0]["text"], "analyze ticker:{MSFT}");
    assert_eq!(last_content.len(), 2);
    assert!(
        last_content[1]["text"]
            .as_str()
            .unwrap()
            .contains("score: 0.91")
    );
    assert!(last_content[1].get("cache_control").is_none());
    // No new leading system was inserted before the cached messages.
    assert_eq!(
        value["system"].as_array().unwrap().len(),
        original["system"].as_array().unwrap().len()
    );
}

#[test]
fn inject_context_without_cache_control_still_uses_system() {
    // Regression: without a cache_control breakpoint the existing
    // system-injection behavior is preserved.
    let body = br#"{"model":"claude-sonnet-4-8","messages":[{"role":"user","content":"hi"}]}"#;
    let injected = inject_gateway_context(ProviderKind::Anthropic, body, "score: 0.91")
        .unwrap()
        .expect("context injected");
    let value: serde_json::Value = serde_json::from_slice(&injected).unwrap();
    assert!(value["system"].as_str().unwrap().contains("score: 0.91"));
    // The user message is untouched.
    assert_eq!(value["messages"][0]["content"], "hi");
}

#[test]
fn inject_context_does_not_mutate_assistant_prefill() {
    // Last message is an assistant prefill; appending context to it would
    // corrupt the model's continuation. With a cache_control breakpoint
    // present, the context must go to the system array instead, leaving the
    // prefill byte-identical.
    let body = br#"{
        "model":"claude-sonnet-4-8",
        "system":[{"type":"text","text":"cached rules","cache_control":{"type":"ephemeral"}}],
        "messages":[
            {"role":"user","content":"analyze ticker:{MSFT}"},
            {"role":"assistant","content":"{"}
        ]
    }"#;
    let original: serde_json::Value = serde_json::from_slice(body).unwrap();
    let injected = inject_gateway_context(ProviderKind::Anthropic, body, "score: 0.91")
        .unwrap()
        .expect("context injected");
    let value: serde_json::Value = serde_json::from_slice(&injected).unwrap();

    // The assistant prefill and the user message are untouched.
    assert_eq!(value["messages"], original["messages"]);
    // Context lands on the system array (still cache-safe: appended after
    // the system breakpoint), not on the prefill.
    let system = value["system"].as_array().unwrap();
    assert_eq!(system.len(), 2);
    assert_eq!(system[0], original["system"][0]);
    assert!(system[1]["text"].as_str().unwrap().contains("score: 0.91"));
    assert!(system[1].get("cache_control").is_none());
}

#[test]
fn inject_context_still_delivered_for_prefill_without_system() {
    // cache_control on a message, an assistant prefill last, and no system:
    // there is no fully cache-safe slot, but the governed context must still
    // be delivered (not silently dropped).
    let body = br#"{
        "model":"claude-sonnet-4-8",
        "messages":[
            {"role":"user","content":[{"type":"text","text":"analyze ticker:{MSFT}","cache_control":{"type":"ephemeral"}}]},
            {"role":"assistant","content":"{"}
        ]
    }"#;
    let injected = inject_gateway_context(ProviderKind::Anthropic, body, "score: 0.91")
        .unwrap()
        .expect("context injected");
    let value: serde_json::Value = serde_json::from_slice(&injected).unwrap();
    // Delivered via a new system; the prefill is untouched.
    assert!(value["system"].as_str().unwrap().contains("score: 0.91"));
    assert_eq!(value["messages"][1]["content"], "{");
}

#[test]
fn cache_control_detection_ignores_tool_schema_properties() {
    // A tool input schema with a property literally named `cache_control`
    // must not be treated as a prompt-cache breakpoint.
    let body = br#"{
        "model":"claude-sonnet-4-8",
        "tools":[{"name":"t","input_schema":{"type":"object","properties":{"cache_control":{"type":"string"}}}}],
        "messages":[{"role":"user","content":"analyze ticker:{MSFT}"}]
    }"#;
    let injected = inject_gateway_context(ProviderKind::Anthropic, body, "score: 0.91")
        .unwrap()
        .expect("context injected");
    let value: serde_json::Value = serde_json::from_slice(&injected).unwrap();
    // No real breakpoint, so the normal system-injection path is used.
    assert!(value["system"].as_str().unwrap().contains("score: 0.91"));
    assert_eq!(value["messages"][0]["content"], "analyze ticker:{MSFT}");
}

#[test]
fn automatic_cache_attempt_requires_profile_support_and_minimum_size() {
    let registry = crate::provider_profile::ProviderRegistry::built_in();
    let openai = registry.effective_profile("openai");
    let anthropic = registry.effective_profile("anthropic");
    assert!(!automatic_cache_attempted(openai.as_ref(), &[b'x'; 1_000]));
    assert!(automatic_cache_attempted(
        openai.as_ref(),
        &[b'x'; 4 * 4_096]
    ));
    let dense = serde_json::json!({"input": vec!["x"; 1_024]}).to_string();
    assert!(automatic_cache_attempted(openai.as_ref(), dense.as_bytes()));
    assert!(!automatic_cache_attempted(
        anthropic.as_ref(),
        &[b'x'; 4 * 4_096]
    ));
}
