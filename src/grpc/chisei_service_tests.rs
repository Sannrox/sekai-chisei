use super::*;
use crate::chisei::evaluation_execution::{
    DeterministicEvaluator, DeterministicEvaluatorOutput, EVALUATOR_RESULT_CONTRACT, STATUS_PASS,
};
use crate::domain::Object;
use crate::sekai::security::{Grant, Role};
use axum::body::Body;
use axum::extract::State;
use axum::response::Response as AxumResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn user_message(content: &str) -> ChatMessage {
    ChatMessage {
        role: "user".into(),
        content: content.into(),
        ..Default::default()
    }
}

#[test]
fn prepared_messages_deliver_a_non_empty_spec_exactly_once() {
    let input = ExecutionInput {
        spec: "original task".into(),
        ..Default::default()
    };
    assert_eq!(
        build_prepared_messages(&input, "original task"),
        vec![user_message("original task")]
    );
    assert_eq!(
        build_prepared_messages(&input, "enriched task"),
        vec![user_message("enriched task")]
    );

    let input = ExecutionInput {
        spec: "original task".into(),
        messages: vec![user_message("conversation context")],
        ..Default::default()
    };
    assert_eq!(
        build_prepared_messages(&input, "original task"),
        vec![
            user_message("conversation context"),
            user_message("[Task spec]\noriginal task"),
        ]
    );
    assert_eq!(
        build_prepared_messages(&input, "enriched task"),
        vec![
            user_message("conversation context"),
            user_message("[Task spec]\nenriched task"),
        ]
    );
    assert_eq!(
        build_prepared_messages(&input, ""),
        vec![
            user_message("conversation context"),
            user_message("[Task spec]\noriginal task"),
        ]
    );
}

#[test]
fn prepared_spec_preserves_pending_tool_call_order() {
    let assistant_message = ChatMessage {
        role: "assistant".into(),
        tool_calls: vec![ToolCall {
            id: "call-1".into(),
            name: "lookup".into(),
            args_json: r#"{"value":1}"#.into(),
        }],
        ..Default::default()
    };
    let input = ExecutionInput {
        spec: "original task".into(),
        messages: vec![assistant_message.clone()],
        ..Default::default()
    };

    assert_eq!(
        build_prepared_messages(&input, "original task"),
        vec![
            user_message("[Task spec]\noriginal task"),
            assistant_message
        ]
    );
}

#[test]
fn prepared_messages_do_not_add_an_empty_spec_message() {
    let input = ExecutionInput {
        messages: vec![user_message("conversation context")],
        ..Default::default()
    };

    assert_eq!(
        build_prepared_messages(&input, ""),
        vec![user_message("conversation context")]
    );
}

#[tokio::test]
async fn gunshi_issuance_rejects_an_empty_authorization_scope() {
    let svc = memory_service();
    let input = serde_json::json!({
        "contract_version": crate::chisei::gunshi::RECOMMENDATION_INPUT_VERSION,
        "request": {
            "capacity": {
                "captured_at_ms": 1,
                "policy_version": "policy",
                "agents": [],
                "model_profiles": [],
                "budget_remaining_usd_micros": 0,
                "max_parallel_attempts": 0,
                "human_attention_minutes": 0
            },
            "operations": [],
            "strategy": {
                "strategy_id": "baseline",
                "version": "1",
                "baseline": "conservative"
            }
        },
        "advisory_policy": {
            "max_memory_age_ms": 0,
            "min_score": 0.0,
            "max_evidence_references": 1
        },
        "kioku_evidence": []
    });
    let mut request = Request::new(IssueGunshiRecommendationsRequest {
        input_json: input.to_string(),
        issuance_id: "empty-scope".into(),
    });
    request
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());

    let error = svc.issue_gunshi_recommendations(request).await.unwrap_err();

    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(
        svc.db
            .list_decisions(&Default::default())
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn gunshi_issuance_returns_aligned_dispatch_decisions() {
    let svc = memory_service();
    let input = serde_json::json!({
        "contract_version": crate::chisei::gunshi::RECOMMENDATION_INPUT_VERSION,
        "request": {
            "capacity": {
                "captured_at_ms": 2_000,
                "policy_version": "policy-v1",
                "agents": [{
                    "agent_id": "agent-a",
                    "runtime": "native",
                    "models": ["native-default"],
                    "tools": ["search"],
                    "operation_classes": ["triage"],
                    "available_slots": 1,
                    "healthy": true
                }],
                "model_profiles": [{
                    "model": "native-default",
                    "quality": 0.9,
                    "cost_per_attempt_usd_micros": 20,
                    "latency_ms": 30,
                    "uncertainty": 0.1
                }],
                "budget_remaining_usd_micros": 40,
                "max_parallel_attempts": 1,
                "human_attention_minutes": 5
            },
            "operations": [{
                "operation_id": "op-1",
                "namespace": "support",
                "operation_class": "triage",
                "priority": 10,
                "risk": "low",
                "submitted_at_ms": 1_000,
                "required_tools": ["search"],
                "allowed_models": ["native-default"],
                "max_attempts": 1,
                "budget_ceiling_usd_micros": 40,
                "acceptance_criteria": ["classified"],
                "approval_required": false,
                "human_attention_minutes_required": 0
            }],
            "strategy": {
                "strategy_id": "priority",
                "version": "1",
                "baseline": "priority_first"
            }
        },
        "advisory_policy": {
            "max_memory_age_ms": 2_000,
            "min_score": 0.5,
            "max_evidence_references": 4
        },
        "kioku_evidence": []
    });

    let response = svc
        .issue_gunshi_recommendations(Request::new(IssueGunshiRecommendationsRequest {
            input_json: input.to_string(),
            issuance_id: "aligned-dispatch".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    let allocation: crate::chisei::gunshi::BaselineAllocation =
        serde_json::from_str(&response.allocation_json).unwrap();

    assert_eq!(allocation.plans.len(), 1);
    assert_eq!(response.auto_dispatch_authorization_json.len(), 1);
    assert_eq!(response.receipt_attributes_json.len(), 1);
    let authorization: crate::chisei::gunshi_dispatch::DispatchAuthorization =
        serde_json::from_str(&response.auto_dispatch_authorization_json[0]).unwrap();
    assert!(!authorization.authorized);
    assert_eq!(authorization.operation_id, "op-1");
}

#[test]
fn receipt_hash_preserves_part_boundaries() {
    assert_ne!(
        content_hash([b"a\0b".as_slice()]),
        content_hash([b"a".as_slice(), b"b".as_slice()])
    );
}

#[test]
fn native_cost_uses_gateway_pricing_alias_resolution() {
    let plan = ExecutionPlan {
        resolved_model: "openai/gpt-5.5".into(),
        ..Default::default()
    };
    let response = PlannedChatResponse {
        input_tokens: 100,
        output_tokens: 10,
        ..Default::default()
    };
    let pricing = crate::pricing::parse_pricing_table("gpt-5.5=3:15").unwrap();
    assert_eq!(native_execution_cost(&plan, &response, &pricing), Some(450));
}

#[test]
fn response_artifact_hash_covers_tool_calls() {
    let response = |name: &str| PlannedChatResponse {
        content: String::new(),
        tool_calls: vec![ToolCall {
            id: "call-1".into(),
            name: name.into(),
            args_json: r#"{"value":1}"#.into(),
        }],
        input_tokens: 1,
        output_tokens: 1,
        stop_reason: "tool_use".into(),
        provider: "native".into(),
        cache_read_input_tokens: 0,
        cache_creation_input_tokens: 0,
    };
    assert_ne!(
        planned_response_hash(&response("read")),
        planned_response_hash(&response("write"))
    );
}

#[test]
fn cheap_route_bias_only_for_bulk_classes_and_not_when_regressed() {
    // Explicit bulk classes route to the cheaper tier.
    for class in [
        "background",
        "bulk",
        "batch",
        "small_fast",
        "small-fast",
        "Background",
    ] {
        assert_eq!(cheap_route_bias(class, false), Some("cheap"), "{class}");
    }
    // Primary/unknown/empty never route cheap (fail safe to capable).
    for class in ["primary", "reasoning", "", "unknown"] {
        assert_eq!(cheap_route_bias(class, false), None, "{class}");
    }
    // An active eval regression reverts every class to the capable tier.
    assert_eq!(cheap_route_bias("background", true), None);
    assert_eq!(cheap_route_bias("bulk", true), None);
}

#[test]
fn portfolio_cross_provider_runtime_requires_explicit_policy_allowance() {
    let mut policy = crate::chisei::policy::Policy {
        allowed_runtimes: vec!["anthropic".into()],
        allowed_models: vec!["claude-sonnet-4-20250514".into(), "gpt-5.5".into()],
        default_runtime: "anthropic".into(),
        default_model: "claude-sonnet-4-20250514".into(),
        data_class: String::new(),
    };
    assert_eq!(
        portfolio_runtime_for_model(Some(&policy), "anthropic", "gpt-5.5"),
        None
    );
    assert!(final_runtime_for_model(Some(&policy), "anthropic", "openai/gpt-5.5").is_err());
    policy.allowed_runtimes.push("openai".into());
    assert_eq!(
        portfolio_runtime_for_model(Some(&policy), "anthropic", "gpt-5.5"),
        Some("openai".into())
    );
    assert_eq!(
        final_runtime_for_model(Some(&policy), "anthropic", "openai/gpt-5.5").unwrap(),
        "openai"
    );
    policy.allowed_runtimes.clear();
    assert_eq!(
        portfolio_runtime_for_model(Some(&policy), "anthropic", "gpt-5.5"),
        Some("openai".into())
    );
}

#[test]
fn final_runtime_tracks_live_model_provider() {
    let policy = crate::chisei::policy::Policy {
        allowed_runtimes: vec![
            "openai".into(),
            "anthropic".into(),
            "native".into(),
            "ollama".into(),
        ],
        allowed_models: vec!["gpt-5.5".into(), "claude-sonnet-4".into()],
        default_runtime: String::new(),
        default_model: "gpt-5.5".into(),
        data_class: String::new(),
    };

    assert_eq!(
        final_runtime_for_model(Some(&policy), "openai", "anthropic/claude-sonnet-4").unwrap(),
        "anthropic"
    );
    assert_eq!(
        final_runtime_for_model(Some(&policy), "anthropic", "openai/gpt-5.5").unwrap(),
        "openai"
    );
    assert_eq!(
        final_runtime_for_model(Some(&policy), "kiro", "native/native-default").unwrap(),
        "native"
    );
    assert_eq!(
        final_runtime_for_model(Some(&policy), "kiro", "ollama/qwen:14b").unwrap(),
        "ollama"
    );
    assert_eq!(
        final_runtime_for_model(Some(&policy), "kiro", "gpt-5.5").unwrap(),
        "openai"
    );
    assert!(final_runtime_for_model(Some(&policy), "kiro", "kiro/claude-sonnet-4").is_err());
}

#[test]
fn policy_validation_handles_empty_and_opaque_runtimes() {
    let invalid_implicit = crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec!["native-default".into()],
        default_runtime: String::new(),
        default_model: "native-default".into(),
        data_class: String::new(),
    };
    assert!(validate_policy_provider_pairs(&invalid_implicit).is_err());

    let opaque = crate::chisei::policy::Policy {
        allowed_runtimes: vec!["kiro".into()],
        allowed_models: vec!["kiro/private-model".into()],
        default_runtime: "kiro".into(),
        default_model: "kiro/private-model".into(),
        data_class: String::new(),
    };
    assert!(validate_policy_provider_pairs(&opaque).is_err());
    let unknown_runtime = crate::chisei::policy::Policy {
        allowed_runtimes: vec!["bogus".into()],
        allowed_models: vec![],
        default_runtime: "bogus".into(),
        default_model: String::new(),
        data_class: String::new(),
    };
    assert!(validate_explicit_requested_model("bogus/model").is_err());
    assert!(validate_policy_provider_pairs(&unknown_runtime).is_err());

    let mut disallowed_opaque = opaque;
    disallowed_opaque.allowed_runtimes = vec!["openai".into()];
    assert!(validate_policy_provider_pairs(&disallowed_opaque).is_err());
    disallowed_opaque.default_model.clear();
    assert!(validate_policy_provider_pairs(&disallowed_opaque).is_err());

    let unroutable_allowlist = crate::chisei::policy::Policy {
        allowed_runtimes: vec!["kiro".into()],
        allowed_models: vec!["gpt-5.5".into()],
        default_runtime: "kiro".into(),
        default_model: String::new(),
        data_class: String::new(),
    };
    assert!(validate_policy_provider_pairs(&unroutable_allowlist).is_err());

    let default_outside_allowlist = crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec!["gpt-5.5-mini".into()],
        default_runtime: "openai".into(),
        default_model: "gpt-5.5".into(),
        data_class: String::new(),
    };
    assert!(validate_policy_provider_pairs(&default_outside_allowlist).is_err());

    let canonical_alias = crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec!["openai/gpt-5.5".into()],
        default_runtime: "openai".into(),
        default_model: "gpt-5.5".into(),
        data_class: String::new(),
    };
    assert_eq!(validate_policy_provider_pairs(&canonical_alias), Ok(()));

    let hosted = crate::chisei::policy::Policy {
        allowed_runtimes: vec!["xai".into()],
        allowed_models: vec!["xai/grok-4.5".into()],
        default_runtime: "xai".into(),
        default_model: "xai/grok-4.5".into(),
        data_class: String::new(),
    };
    assert_eq!(validate_policy_provider_pairs(&hosted), Ok(()));
}

#[test]
fn legacy_openai_family_policies_normalize_to_exact_providers() {
    let normalized = normalize_legacy_policy_provider_pairs(crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec![
            "gpt-5.5".into(),
            "native-default".into(),
            "fallback:cheap".into(),
            "ollama/qwen:14b".into(),
        ],
        default_runtime: "openai".into(),
        default_model: "native-default".into(),
        data_class: String::new(),
    });

    assert_eq!(normalized.default_runtime, "native");
    assert!(normalized.allowed_runtimes.contains(&"openai".to_string()));
    assert!(normalized.allowed_runtimes.contains(&"native".to_string()));
    assert!(normalized.allowed_runtimes.contains(&"ollama".to_string()));
    assert_eq!(validate_policy_provider_pairs(&normalized), Ok(()));

    let fallback = normalize_legacy_policy_provider_pairs(crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec!["fallback:cheap".into()],
        default_runtime: "openai".into(),
        default_model: "fallback:cheap".into(),
        data_class: String::new(),
    });
    assert_eq!(fallback.default_runtime, "native");
    assert!(fallback.allowed_runtimes.contains(&"native".to_string()));
    assert_eq!(validate_policy_provider_pairs(&fallback), Ok(()));

    let kiro = normalize_legacy_policy_provider_pairs(crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec!["kiro".into()],
        default_runtime: "openai".into(),
        default_model: "kiro".into(),
        data_class: String::new(),
    });
    assert_eq!(kiro.default_runtime, "openai");
    assert_eq!(kiro.allowed_runtimes, vec!["openai"]);
    assert!(validate_policy_provider_pairs(&kiro).is_err());

    let mixed = normalize_legacy_policy_provider_pairs(crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec!["fallback:cheap".into(), "Kiro".into()],
        default_runtime: "openai".into(),
        default_model: "fallback:cheap".into(),
        data_class: String::new(),
    });
    assert!(mixed.allowed_runtimes.contains(&"native".to_string()));
    assert!(validate_policy_provider_pairs(&mixed).is_err());
}

#[test]
fn persisted_bare_native_models_are_canonicalized_without_accepting_kiro() {
    let migrated = normalize_persisted_legacy_policy(crate::chisei::policy::Policy {
        allowed_runtimes: vec!["kiro".into()],
        allowed_models: vec!["mistral".into(), "Kiro".into()],
        default_runtime: "kiro".into(),
        default_model: "mistral".into(),
        data_class: String::new(),
    });

    assert_eq!(migrated.default_runtime, "native");
    assert_eq!(migrated.default_model, "native/mistral");
    assert!(migrated.allowed_models.contains(&"native/mistral".into()));
    assert!(migrated.allowed_models.contains(&"Kiro".into()));
    assert!(validate_policy_provider_pairs(&migrated).is_err());

    let model_only = normalize_persisted_legacy_policy(crate::chisei::policy::Policy {
        allowed_runtimes: vec![],
        allowed_models: vec!["mistral".into()],
        default_runtime: String::new(),
        default_model: "mistral".into(),
        data_class: String::new(),
    });
    assert_eq!(model_only.default_model, "native/mistral");
    assert_eq!(model_only.allowed_models, vec!["native/mistral"]);
    assert_eq!(validate_policy_provider_pairs(&model_only), Ok(()));

    let openai = normalize_persisted_legacy_policy(crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec!["mistral-large".into()],
        default_runtime: "openai".into(),
        default_model: "mistral-large".into(),
        data_class: String::new(),
    });
    assert_eq!(openai.default_model, "openai/mistral-large");
    assert_eq!(openai.allowed_models, vec!["openai/mistral-large"]);
    assert_eq!(validate_policy_provider_pairs(&openai), Ok(()));

    let duplicate_openai = normalize_persisted_legacy_policy(crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into(), "openai".into()],
        allowed_models: vec!["mistral-large".into()],
        default_runtime: String::new(),
        default_model: "mistral-large".into(),
        data_class: String::new(),
    });
    assert_eq!(duplicate_openai.default_model, "openai/mistral-large");
    assert_eq!(
        duplicate_openai.allowed_models,
        vec!["openai/mistral-large"]
    );
    assert_eq!(duplicate_openai.allowed_runtimes, vec!["openai"]);
    assert_eq!(validate_policy_provider_pairs(&duplicate_openai), Ok(()));
}

#[test]
fn budget_metric_accepts_tokens_and_requests_case_insensitive() {
    assert_eq!(budget_metric("").unwrap(), METRIC_TOKENS);
    assert_eq!(budget_metric("tokens").unwrap(), METRIC_TOKENS);
    assert_eq!(budget_metric("Tokens").unwrap(), METRIC_TOKENS);
    assert_eq!(budget_metric("requests").unwrap(), METRIC_REQUESTS);
    assert_eq!(budget_metric("REQUESTS").unwrap(), METRIC_REQUESTS);
}

#[test]
fn budget_metric_rejects_unknown_values() {
    let err = budget_metric("characters").unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message()
            .contains("unsupported budget metric; use tokens or requests")
    );
}

#[test]
fn local_free_runtime_is_allowed_without_policy_and_respects_explicit_policy() {
    assert_eq!(
        local_free_runtime_for_model(None, "ollama/qwen:14b"),
        Some("ollama".to_string())
    );
    assert_eq!(local_free_runtime_for_model(None, "gpt-5.5"), None);
    let cloud_only = crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec![],
        default_runtime: "openai".into(),
        default_model: "gpt-5.5".into(),
        data_class: String::new(),
    };
    assert_eq!(
        local_free_runtime_for_model(Some(&cloud_only), "ollama/qwen:14b"),
        None
    );
}

#[tokio::test]
async fn resolve_policy_rejects_unknown_explicit_provider_without_policy() {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let svc = ChiseiServiceImpl::new(db, config(":memory:"));
    let request = resolve_policy_request("unscoped", "bogus", "bogus/model");

    let error = svc.resolve_policy(Request::new(request)).await.unwrap_err();

    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(error.message().contains("unknown provider namespace"));

    svc.policy.set_namespace_policy(
        "unscoped",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec![],
            allowed_models: vec![],
            default_runtime: String::new(),
            default_model: String::new(),
            data_class: String::new(),
        },
    );
    let request = resolve_policy_request("unscoped", "bogus", "bogus/model");
    let error = svc.resolve_policy(Request::new(request)).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(error.message().contains("unknown provider namespace"));
}

#[tokio::test]
async fn resolve_policy_keeps_auto_provider_compatible_without_policy() {
    let svc = memory_service();

    let resolution = svc
        .resolve_policy(Request::new(resolve_policy_request(
            "unscoped", "openai", "auto",
        )))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();

    assert_eq!(resolution.runtime, "openai");
    assert_eq!(resolution.model, "openai/gpt-5.5");
}

#[tokio::test]
async fn resolve_policy_refreshes_registry_before_policy_validation() {
    let directory = std::env::temp_dir().join(format!(
        "sekai-chisei-provider-registry-{}",
        uuid::Uuid::new_v4()
    ));
    let db_path = directory.join("sekai.db");
    let db_path = db_path.to_str().expect("temporary database path is UTF-8");
    let registry_path = crate::provider_profile::provider_registry_state_path(db_path);
    crate::provider_profile::refresh_provider_registry(&registry_path).unwrap();
    let svc = file_service(db_path);
    std::fs::remove_file(&registry_path).unwrap();

    let error = svc
        .resolve_policy(Request::new(resolve_policy_request(
            "unscoped",
            "bogus",
            "bogus/model",
        )))
        .await
        .unwrap_err();

    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert!(error.message().contains("provider registry unavailable"));
    drop(svc);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn live_model_resolution_rejects_unknown_explicit_provider() {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let svc = ChiseiServiceImpl::new(db, config(":memory:"));

    let error = svc
        .resolve_live_model(
            "bogus/model",
            None,
            None,
            false,
            &std::collections::HashSet::new(),
            None,
        )
        .await
        .unwrap_err();

    assert!(error.contains("unknown provider namespace"));
}

#[tokio::test]
async fn resolve_policy_normalizes_loaded_legacy_native_runtime() {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let svc = ChiseiServiceImpl::new(db, config(":memory:"));
    svc.policy.set_namespace_policy(
        "private",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["kiro".into()],
            allowed_models: vec!["native-default".into()],
            default_runtime: "kiro".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        },
    );
    let request = resolve_policy_request("private", "kiro", "native-default");

    let resolution = svc
        .resolve_policy(Request::new(request))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();

    assert_eq!(resolution.runtime, "native");
    assert_eq!(resolution.model, "native-default");

    let request = resolve_policy_request("private", "native", "native/native-default");
    let resolution = svc
        .resolve_policy(Request::new(request))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    assert_eq!(resolution.runtime, "native");
    assert_eq!(resolution.model, "native/native-default");
}

#[tokio::test]
async fn resolve_policy_routes_bulk_task_class_to_cheaper_model() {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let mut cfg = config(":memory:");
    // Treat openai as available without a key so routing can resolve.
    cfg.gateway_provided_providers = vec!["openai".into()];
    let svc = ChiseiServiceImpl::new(db, cfg);
    svc.policy.set_namespace_policy(
        "proj",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into(), "gpt-5.5-mini".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
        },
    );

    // Primary work stays on the capable default model, no bias.
    let mut primary = resolve_policy_request("proj", "openai", "gpt-5.5");
    primary.task_class = "primary".into();
    let resolution = svc
        .resolve_policy(Request::new(primary))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    assert_eq!(resolution.model, "gpt-5.5");
    assert_eq!(resolution.route_bias, "");

    // Bulk/background work routes to the cheaper allowed model and records
    // the cheap bias.
    let mut background = resolve_policy_request("proj", "openai", "gpt-5.5");
    background.task_class = "background".into();
    let resolution = svc
        .resolve_policy(Request::new(background))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    assert_eq!(resolution.model, "gpt-5.5-mini");
    assert_eq!(resolution.route_bias, "cheap");
    assert_eq!(resolution.runtime, "openai");
}

#[tokio::test]
async fn resolve_policy_reverts_only_the_regressed_task_class_to_capable() {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let mut cfg = config(":memory:");
    cfg.gateway_provided_providers = vec!["openai".into()];
    let svc = ChiseiServiceImpl::new(db, cfg);
    svc.policy.set_namespace_policy(
        "proj",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into(), "gpt-5.5-mini".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
        },
    );
    create_suite(&svc, "proj");
    for (id, score, timestamp) in [("class-run-1", 95, 100), ("class-run-2", 50, 200)] {
        seed_eval_run(&svc, eval_run(id, "suite-1", score, timestamp), "proj", id);
    }
    assert!(
        svc.eval
            .namespace_regression_signal("proj")
            .unwrap()
            .regressed
    );
    let now = chrono::Utc::now().timestamp_millis();
    for (task_class, delta, regressed) in [("background", -80.0, true), ("bulk", 0.0, false)] {
        svc.db
            .record_decision(&crate::sekai::audit::Decision {
                id: format!("class-signal-{task_class}"),
                timestamp: now,
                actor: "chisei.scoring".into(),
                action: "task_class_signal".into(),
                reason: format!("test signal for {task_class}"),
                evidence: HashMap::from([
                    ("delta".into(), format!("{delta:.1}")),
                    ("regressed".into(), regressed.to_string()),
                ]),
                target_id: serde_json::to_string(&("proj", task_class)).unwrap(),
                outcome: if regressed {
                    "regressed".into()
                } else {
                    "stable".into()
                },
            })
            .unwrap();
    }
    let mut background = resolve_policy_request("proj", "openai", "gpt-5.5");
    background.task_class = "background".into();
    let reverted = svc
        .resolve_policy(Request::new(background))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    assert_eq!(reverted.model, "gpt-5.5");
    assert_eq!(reverted.route_bias, "");
    assert!(reverted.eval_regressed);
    assert!(reverted.eval_regression_reason.contains("background"));

    let mut invalid = resolve_policy_request("proj", "openai", "bad model");
    invalid.task_class = "background".into();
    let error = svc.resolve_policy(Request::new(invalid)).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);

    let mut bulk = resolve_policy_request("proj", "openai", "gpt-5.5");
    bulk.task_class = "bulk".into();
    let healthy = svc
        .resolve_policy(Request::new(bulk))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    assert_eq!(healthy.model, "gpt-5.5-mini");
    assert_eq!(healthy.route_bias, "cheap");
    assert!(!healthy.eval_regressed);
}

#[tokio::test]
async fn request_namespace_regression_is_not_masked_by_stable_policy_scope() {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let mut cfg = config(":memory:");
    cfg.gateway_provided_providers = vec!["openai".into()];
    let svc = ChiseiServiceImpl::new(db, cfg);
    svc.policy.set_namespace_policy(
        "project-scope",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into(), "gpt-5.5-mini".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
        },
    );
    let now = chrono::Utc::now().timestamp_millis();
    for (scope, delta, regressed) in [("project-scope", 0.0, false), ("request-ns", -80.0, true)] {
        svc.db
            .record_decision(&crate::sekai::audit::Decision {
                id: format!("class-signal-{scope}"),
                timestamp: now,
                actor: "chisei.scoring".into(),
                action: "task_class_signal".into(),
                reason: format!("test signal for {scope}"),
                evidence: HashMap::from([
                    ("delta".into(), format!("{delta:.1}")),
                    ("regressed".into(), regressed.to_string()),
                ]),
                target_id: serde_json::to_string(&(scope, "background")).unwrap(),
                outcome: if regressed {
                    "regressed".into()
                } else {
                    "stable".into()
                },
            })
            .unwrap();
    }

    let mut request = resolve_policy_request("request-ns", "openai", "gpt-5.5");
    request.project = "project-scope".into();
    request.task_class = "background".into();
    let resolved = svc
        .resolve_policy(Request::new(request))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    assert_eq!(resolved.model, "gpt-5.5");
    assert_eq!(resolved.route_bias, "");
    assert!(resolved.eval_regressed);
    assert!(resolved.eval_regression_reason.contains("request-ns"));
}

#[tokio::test]
async fn resolve_policy_respects_a_promoted_capable_override() {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let mut cfg = config(":memory:");
    cfg.gateway_provided_providers = vec!["openai".into()];
    let svc = ChiseiServiceImpl::new(db, cfg);
    svc.policy.set_namespace_policy(
        "proj",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into(), "gpt-5.5-mini".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
        },
    );

    // Promote a "capable" revert for (proj, background) directly through the service's own
    // candidate store/active-promotions registry, exactly as a promotion controller would.
    let candidate = crate::chisei::promotion::Candidate {
        id: "candidate-1".into(),
        kind: crate::chisei::promotion::KIND_ROUTING_BIAS.to_string(),
        namespace: "proj".into(),
        task_class: "background".into(),
        payload: serde_json::to_string(&crate::chisei::promotion::RoutingBiasPayload {
            bias: "capable".into(),
        })
        .unwrap(),
        rationale: "test".into(),
        status: crate::chisei::promotion::STATUS_GATE_PASSED.to_string(),
        source_ref: "test".into(),
        created: 1,
    };
    svc.candidate_store().upsert(candidate.clone());
    crate::chisei::controller::promote_candidate(
        &svc.candidate_store(),
        &svc.active_promotions(),
        &svc.db,
        &candidate.id,
    )
    .expect("gate_passed candidate should promote");

    // Without the override, background would route to the cheaper model (as the sibling test
    // above confirms); the active "capable" promotion must force the capable model instead.
    // Non-canonical casing/whitespace on the request's task_class must still hit the
    // (normalized) override - `cheap_route_bias` normalizes internally, so an unnormalized
    // lookup here would otherwise miss the override and route cheap right past it.
    let mut background = resolve_policy_request("proj", "openai", "gpt-5.5");
    background.task_class = " Background ".into();
    let resolution = svc
        .resolve_policy(Request::new(background))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    assert_eq!(resolution.model, "gpt-5.5");
    assert_eq!(resolution.route_bias, "");

    let mut local_free = resolve_policy_request("proj", "openai", "gpt-5.5");
    local_free.task_class = "background".into();
    local_free.budget_route_bias = "local_free".into();
    let error = svc
        .resolve_policy(Request::new(local_free))
        .await
        .expect_err("capable override must block local-free degradation");
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    assert!(error.message().contains("active capable-tier override"));
}

#[tokio::test]
async fn resolve_policy_records_no_bias_when_no_cheaper_model_exists() {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let mut cfg = config(":memory:");
    cfg.gateway_provided_providers = vec!["openai".into()];
    let svc = ChiseiServiceImpl::new(db, cfg);
    // Only one allowed model, so the cheap tier resolves to the same model.
    svc.policy.set_namespace_policy(
        "proj",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
        },
    );
    let mut background = resolve_policy_request("proj", "openai", "gpt-5.5");
    background.task_class = "background".into();
    let resolution = svc
        .resolve_policy(Request::new(background))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    // No actual demotion happened, so no cheap bias is recorded.
    assert_eq!(resolution.model, "gpt-5.5");
    assert_eq!(resolution.route_bias, "");
}

#[tokio::test]
async fn resolve_policy_records_no_bias_for_equal_cost_models() {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let mut cfg = config(":memory:");
    cfg.gateway_provided_providers = vec!["openai".into()];
    let svc = ChiseiServiceImpl::new(db, cfg);
    // Both allowed models are the same cost tier ("mini"), so the cheap
    // alias finds nothing strictly cheaper than the capable default.
    svc.policy.set_namespace_policy(
        "proj",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5-mini".into(), "gpt-4.1-mini".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5-mini".into(),
            data_class: String::new(),
        },
    );
    let mut background = resolve_policy_request("proj", "openai", "gpt-5.5-mini");
    background.task_class = "background".into();
    let resolution = svc
        .resolve_policy(Request::new(background))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    // Capable default is kept; no equal-cost swap is recorded as a demotion.
    assert_eq!(resolution.model, "gpt-5.5-mini");
    assert_eq!(resolution.route_bias, "");
}

#[tokio::test]
async fn resolve_policy_skips_cheap_routing_for_native_runtime() {
    // native/ollama runtimes are excluded from automatic cheap tiering
    // (their cost tiers are not name-rankable), so a bulk task class stays
    // on the capable tier with no bias even without an eval regression.
    let svc = memory_service();
    svc.policy.set_namespace_policy(
        "proj",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["native".into()],
            allowed_models: vec!["native-default".into(), "native-cheap".into()],
            default_runtime: "native".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        },
    );
    let mut background = resolve_policy_request("proj", "native", "native-default");
    background.task_class = "background".into();
    let resolution = svc
        .resolve_policy(Request::new(background))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    assert_eq!(resolution.model, "native-default");
    assert_eq!(resolution.route_bias, "");
}

fn config(db_path: &str) -> Config {
    Config {
        grpc_port: 0,
        sekai_bind: None,
        ops_port: None,
        ops_bind: "127.0.0.1".into(),
        sekai_socket: None,
        db_path: db_path.to_string(),
        anthropic_api_key: None,
        openai_api_key: None,
        ollama_url: "http://127.0.0.1:11434".into(),
        native_llm_url: Some("http://127.0.0.1:9999".into()),
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
        permit_signing_key: Some("07".repeat(32)),
        permit_issuer: "issuer:test".into(),
        permit_key_id: "key-1".into(),
        governed_subject_provenance_signing_key: Some("09".repeat(32)),
        governed_subject_provenance_key_not_before_ms: 0,
        governed_subject_provenance_key_expires_at_ms: i64::MAX,
        governed_subject_provenance_ttl_ms: 24 * 60 * 60 * 1_000,
        site_id: "local".into(),
        budget_topology: Default::default(),
    }
}

fn stochastic_admission_manifest(
    provider: &str,
    egress_policy: &str,
    max_total_tokens: u32,
) -> evaluation_manifest_domain::ResolvedEvaluationManifest {
    let digest = |byte: char| format!("sha256:{}", byte.to_string().repeat(64));
    evaluation_manifest_domain::ResolvedEvaluationManifest {
        contract_version: evaluation_manifest_domain::MANIFEST_CONTRACT.into(),
        resolver_version: evaluation_manifest_domain::RESOLVER_VERSION.into(),
        manifest_id: "manifest:stochastic-admission".into(),
        manifest_digest: digest('a'),
        namespace: "acme".into(),
        plan_version_id: "plan:stochastic-admission".into(),
        plan_digest: digest('b'),
        subject_profile: "document/v1".into(),
        subject_identity: "document:42".into(),
        subject_content_digest: digest('c'),
        invariant_set_id: "set:stochastic-admission".into(),
        invariant_set_digest: digest('d'),
        invariant_profile_digest: digest('e'),
        evaluation_time_ms: 1,
        resolved_by: "operator".into(),
        requirements: vec![],
        nodes: vec![evaluation_manifest_domain::ResolvedEvaluationNode {
            node_id: "model-review".into(),
            evaluator: evaluation_manifest_domain::ResolvedEvaluatorBinding {
                definition_id: "definition:model-review".into(),
                definition_digest: digest('f'),
                implementation_digest: digest('1'),
                stochastic_policy: Some(evaluation_plan_domain::StochasticEvaluatorPolicy {
                    provider: provider.into(),
                    model: format!("{provider}/fixture"),
                    prompt_profile: "chisei.fixture/v1".into(),
                    prompt_profile_digest: digest('2'),
                    result_schema: "chisei.stochastic-trial-result/v1".into(),
                    trial_count: 2,
                    temperature_millis: 200,
                    top_p_millionths: 900_000,
                    seed_supported: provider != "anthropic",
                    base_seed: if provider == "anthropic" { 0 } else { 7 },
                    aggregation_rule: evaluation_plan_domain::STOCHASTIC_AGGREGATION_MEAN_VARIANCE
                        .into(),
                    minimum_mean_score_micros: 0,
                    minimum_pass_rate_basis_points: 0,
                    maximum_score_variance_micros_squared: 1_000_000_000_000,
                    gate_eligible: false,
                    max_retries_per_trial: 0,
                    max_tokens_per_trial: 1,
                    max_total_tokens,
                    egress_policy: egress_policy.into(),
                    raw_response_retention: evaluation_plan_domain::STOCHASTIC_RAW_RETENTION_NONE
                        .into(),
                }),
            },
            depends_on_node_ids: vec![],
            input_bindings: vec![],
            parameters_json: "{}".into(),
            invariants: vec![],
            evidence_object_ids: vec![],
            classification: evaluation_plan_domain::NODE_ADVISORY.into(),
        }],
        evidence: vec![],
        waivers: vec![],
        created_at_ms: 1,
    }
}

#[test]
fn stochastic_admission_fails_closed_before_external_or_unbudgetable_calls() {
    let svc = memory_service();
    let denied = stochastic_admission_manifest(
        "openai",
        evaluation_plan_domain::STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL,
        2,
    );
    assert_eq!(
        svc.evaluation_execution_lifecycle
            .stochastic_egress_reasons_for_test(&denied)
            .get("model-review")
            .map(String::as_str),
        Some(evaluation_execution_domain::REASON_STOCHASTIC_EGRESS_DENIED)
    );

    let mut allowed_config = config(":memory:");
    allowed_config.safe_egress_providers = vec!["openai".into()];
    let allowed = ChiseiServiceImpl::new(svc.db.clone(), allowed_config);
    let unbudgetable = stochastic_admission_manifest(
        "openai",
        evaluation_plan_domain::STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL,
        u32::MAX,
    );
    assert_eq!(
        evaluation_execution_lifecycle::EvaluationExecutionLifecycle::stochastic_budget_reason(
            &allowed.budget,
            &unbudgetable,
            &unbudgetable.nodes[0],
        )
        .as_deref(),
        Some(evaluation_execution_domain::REASON_STOCHASTIC_TOKEN_BUDGET)
    );
}

fn memory_service() -> ChiseiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    ChiseiServiceImpl::new(db, config(":memory:"))
}

fn gunshi_planning_service() -> ChiseiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let mut config = config(":memory:");
    config.gateway_provided_providers = vec!["openai".into()];
    ChiseiServiceImpl::new(db, config)
}

fn issue_native_gunshi_plan(
    service: &ChiseiServiceImpl,
    issuance_id: &str,
    policy_version: &str,
) -> crate::chisei::gunshi::AllocationPlan {
    use crate::chisei::gunshi::{
        AgentCapacity, AllocationRequest, BaselineStrategy, CapacityEnvelope, ModelProfile,
        OperationRisk, PendingOperation, Strategy,
    };

    let plan = crate::chisei::gunshi::recommend_baseline(&AllocationRequest {
        capacity: CapacityEnvelope {
            captured_at_ms: 1,
            policy_version: policy_version.into(),
            agents: vec![AgentCapacity {
                agent_id: "agent:local".into(),
                runtime: "openai".into(),
                models: BTreeSet::from(["openai/gpt-5.5".into()]),
                tools: BTreeSet::new(),
                operation_classes: BTreeSet::from(["triage".into()]),
                available_slots: 1,
                healthy: true,
            }],
            model_profiles: vec![ModelProfile {
                model: "openai/gpt-5.5".into(),
                quality: 0.8,
                cost_per_attempt_usd_micros: 10,
                latency_ms: 20,
                uncertainty: 0.1,
            }],
            budget_remaining_usd_micros: 10,
            max_parallel_attempts: 1,
            human_attention_minutes: 1,
        },
        operations: vec![PendingOperation {
            operation_id: "operation:triage-1".into(),
            namespace: "support".into(),
            operation_class: "triage".into(),
            priority: 7,
            risk: OperationRisk::Low,
            submitted_at_ms: 1,
            required_tools: BTreeSet::new(),
            allowed_models: BTreeSet::new(),
            max_attempts: 1,
            budget_ceiling_usd_micros: 10,
            acceptance_criteria: vec!["receipt is complete".into()],
            approval_required: false,
            human_attention_minutes_required: 0,
        }],
        strategy: Strategy {
            strategy_id: "baseline".into(),
            version: "1".into(),
            baseline: BaselineStrategy::Conservative,
        },
    })
    .unwrap()
    .plans
    .remove(0);
    crate::chisei::gunshi_feedback::record_issued_recommendations(
        &service.db,
        "local",
        issuance_id,
        "request-digest",
        std::slice::from_ref(&plan),
        1,
        1,
    )
    .unwrap();
    plan
}

fn gunshi_plan_request(
    issuance_id: &str,
    plan: &crate::chisei::gunshi::AllocationPlan,
) -> PlanExecutionRequest {
    PlanExecutionRequest {
        input: Some(ExecutionInput {
            request_id: "request:triage-1".into(),
            namespace: plan.namespace.clone(),
            spec: "Triage the governed operation.".into(),
            max_tokens: 64,
            ..Default::default()
        }),
        gunshi_allocation: Some(GunshiAllocationBinding {
            issuance_id: issuance_id.into(),
            allocation_json: serde_json::to_string(plan).unwrap(),
        }),
    }
}

#[tokio::test]
async fn issued_gunshi_allocation_feeds_native_planning_before_kioku_enrichment() {
    let service = gunshi_planning_service();
    let policy = crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec!["openai/gpt-5.5".into()],
        default_runtime: "openai".into(),
        default_model: "openai/gpt-5.5".into(),
        data_class: String::new(),
    };
    let policy_version = policy.version();
    service.policy.set_namespace_policy("support", policy);
    let allocation = issue_native_gunshi_plan(&service, "issuance:triage-1", &policy_version);

    let plan = service
        .plan_execution(Request::new(gunshi_plan_request(
            "issuance:triage-1",
            &allocation,
        )))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();

    assert_eq!(plan.resolved_runtime, allocation.selection.runtime);
    assert_eq!(plan.resolved_model, allocation.selection.model);
    assert_eq!(plan.gunshi_issuance_id, "issuance:triage-1");
    assert_eq!(plan.gunshi_allocation_id, allocation.allocation_id);
    assert_eq!(plan.gunshi_agent_id, allocation.selection.agent_id);
    assert_eq!(plan.gunshi_policy_version, policy_version);
    assert_eq!(plan.gunshi_input_fingerprint, allocation.input_fingerprint);
    assert_eq!(plan.gunshi_budget_ceiling_usd_micros, 10);
    assert_eq!(plan.gunshi_max_attempts, 1);
    assert!(plan.steps.iter().any(|step| step.step == "kioku_enrich"));
    let input = plan.input.as_ref().unwrap();
    assert_eq!(input.logical_operation_id, allocation.operation_id);
    assert_eq!(input.task_class, allocation.operation_class);
    assert_eq!(input.priority, i32::from(allocation.priority));

    let receipt = service
        .db
        .get_operation_receipt(&plan.plan_id)
        .unwrap()
        .unwrap();
    let intent = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .unwrap();
    assert_eq!(
        intent.attributes.get("logical_operation_id"),
        Some(&allocation.operation_id)
    );
    assert_eq!(
        intent.attributes.get("gunshi_allocation_id"),
        Some(&allocation.allocation_id)
    );
    let budget = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::BudgetDecided)
        .unwrap();
    assert_eq!(
        budget
            .attributes
            .get("gunshi_budget_ceiling_usd_micros")
            .map(String::as_str),
        Some("10")
    );
}

#[tokio::test]
async fn gunshi_binding_rejects_a_modified_issued_allocation() {
    let service = gunshi_planning_service();
    let policy = crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec!["openai/gpt-5.5".into()],
        default_runtime: "openai".into(),
        default_model: "openai/gpt-5.5".into(),
        data_class: String::new(),
    };
    let policy_version = policy.version();
    service.policy.set_namespace_policy("support", policy);
    let issued = issue_native_gunshi_plan(&service, "issuance:tamper", &policy_version);
    let mut modified = issued.clone();
    modified.selection.agent_id = "agent:forged".into();

    let error = service
        .plan_execution(Request::new(gunshi_plan_request(
            "issuance:tamper",
            &modified,
        )))
        .await
        .unwrap_err();

    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("does not match"));
}

#[tokio::test]
async fn gunshi_binding_rejects_an_allocation_after_policy_changes() {
    let service = gunshi_planning_service();
    let policy = crate::chisei::policy::Policy {
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec!["openai/gpt-5.5".into()],
        default_runtime: "openai".into(),
        default_model: "openai/gpt-5.5".into(),
        data_class: String::new(),
    };
    let policy_version = policy.version();
    service.policy.set_namespace_policy("support", policy);
    let allocation = issue_native_gunshi_plan(&service, "issuance:stale", &policy_version);
    service.policy.set_namespace_policy(
        "support",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["openai/gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "openai/gpt-5.5".into(),
            data_class: "internal".into(),
        },
    );

    let error = service
        .plan_execution(Request::new(gunshi_plan_request(
            "issuance:stale",
            &allocation,
        )))
        .await
        .unwrap_err();

    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("policy version"));
}

struct ManagedExecutionExtension;

impl crate::enterprise::EnterpriseExtension for ManagedExecutionExtension {
    fn authenticate_bearer(
        &self,
        _bearer_token: &str,
    ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError> {
        Err(crate::enterprise::ExtensionError::CredentialNotFound)
    }

    fn authenticate_context(
        &self,
        _bearer_token: &str,
    ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError> {
        Err(crate::enterprise::ExtensionError::CredentialNotFound)
    }

    fn tenant_context(
        &self,
        _principal: &crate::enterprise::AuthenticatedPrincipal,
    ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError> {
        Err(crate::enterprise::ExtensionError::Unauthenticated)
    }

    fn authorize_namespace(
        &self,
        _context: &crate::enterprise::TenantContext,
        _namespace: &str,
        _action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        Err(crate::enterprise::ExtensionError::PermissionDenied)
    }

    fn authorize_unscoped_namespace(
        &self,
        _principal: &crate::enterprise::AuthenticatedPrincipal,
        _namespace: &str,
        _action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        Err(crate::enterprise::ExtensionError::PermissionDenied)
    }

    fn authorize_authenticated_context(
        &self,
        context: &crate::enterprise::AuthenticatedContext,
        namespace: &str,
        _action: crate::enterprise::NamespaceAction,
    ) -> Result<(), crate::enterprise::ExtensionError> {
        context.validate(
            chrono::Utc::now().timestamp(),
            "https://issuer.test",
            "sekai:control-plane",
        )?;
        if context.credential_kind != crate::enterprise::CredentialKind::Machine
            || context
                .tenant
                .as_ref()
                .is_none_or(|tenant| !tenant.tenant_id.starts_with("tenant-managed"))
            || namespace != "managed-conformance"
        {
            return Err(crate::enterprise::ExtensionError::PermissionDenied);
        }
        Ok(())
    }
}

fn managed_execution_context(
    scopes: Vec<String>,
    resource: &str,
    expires_at: i64,
) -> crate::enterprise::AuthenticatedContext {
    managed_execution_context_for_tenant(scopes, resource, expires_at, "tenant-managed")
}

fn managed_execution_context_for_tenant(
    scopes: Vec<String>,
    resource: &str,
    expires_at: i64,
    tenant_id: &str,
) -> crate::enterprise::AuthenticatedContext {
    crate::enterprise::AuthenticatedContext {
        contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
        principal: crate::enterprise::AuthenticatedPrincipal {
            subject: "service:managed-shikigami".into(),
            credential_id: "credential:managed-shikigami".into(),
        },
        credential_kind: crate::enterprise::CredentialKind::Machine,
        tenant: Some(crate::enterprise::TenantContext {
            tenant_id: tenant_id.into(),
            subject: "service:managed-shikigami".into(),
        }),
        scopes,
        issuer: "https://issuer.test".into(),
        resource: resource.into(),
        expires_at,
    }
}

fn attach_managed_context<T>(
    request: &mut Request<T>,
    context: crate::enterprise::AuthenticatedContext,
) {
    request.metadata_mut().insert(
        AUTH_SOURCE_HEADER,
        tonic::metadata::MetadataValue::from_static("enterprise"),
    );
    request.extensions_mut().insert(context);
}

fn managed_execution_service() -> ChiseiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(
            ":memory:",
            Some(Arc::new(ManagedExecutionExtension)),
        )
        .unwrap(),
    )));
    let mut managed_config = config(":memory:");
    managed_config.openai_api_key = Some("synthetic-server-side-key".into());
    let service = ChiseiServiceImpl::new(db, managed_config);
    service.policy.set_namespace_policy(
        "managed-conformance",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["openai/gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "openai/gpt-5.5".into(),
            data_class: "unclassified".into(),
        },
    );
    service
}

fn managed_plan_request(request_id: &str) -> PlanExecutionRequest {
    PlanExecutionRequest {
        input: Some(ExecutionInput {
            request_id: request_id.into(),
            namespace: "managed-conformance".into(),
            spec: "Use the governed tool loop.".into(),
            max_tokens: 64,
            tools: vec![ToolDef {
                name: "read".into(),
                description: "Read a synthetic fixture.".into(),
                input_schema_json: r#"{"type":"object"}"#.into(),
            }],
            ..Default::default()
        }),
        gunshi_allocation: None,
    }
}

#[tokio::test]
async fn managed_machine_context_owns_plan_identity_and_namespace_authority() {
    let service = managed_execution_service();
    let mut valid = Request::new(managed_plan_request("managed-plan-valid"));
    valid
        .metadata_mut()
        .insert("x-principal", "attacker".parse().unwrap());
    attach_managed_context(
        &mut valid,
        managed_execution_context(
            vec!["chisei.execute".into()],
            "sekai:control-plane",
            i64::MAX,
        ),
    );

    let plan = service
        .plan_execution(valid)
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    assert_eq!(plan.planning_actor, "service:managed-shikigami");
    assert_eq!(plan.resolved_runtime, "openai");
    assert_eq!(plan.resolved_model, "openai/gpt-5.5");
    assert!(plan.input.unwrap().route_override.is_empty());

    let mut injected_route = managed_plan_request("managed-plan-route-injection");
    injected_route.input.as_mut().unwrap().route_override = "openai/gpt-5.5".into();
    let mut injected_route = Request::new(injected_route);
    attach_managed_context(
        &mut injected_route,
        managed_execution_context(
            vec!["chisei.execute".into()],
            "sekai:control-plane",
            i64::MAX,
        ),
    );
    assert_eq!(
        service
            .plan_execution(injected_route)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );

    for (request_id, context, expected_code) in [
        (
            "managed-plan-missing-scope",
            managed_execution_context(Vec::new(), "sekai:control-plane", i64::MAX),
            tonic::Code::PermissionDenied,
        ),
        (
            "managed-plan-wrong-resource",
            managed_execution_context(vec!["chisei.execute".into()], "sekai:other-plane", i64::MAX),
            tonic::Code::Unauthenticated,
        ),
        (
            "managed-plan-expired",
            managed_execution_context(
                vec!["chisei.execute".into()],
                "sekai:control-plane",
                chrono::Utc::now().timestamp() - 1,
            ),
            tonic::Code::Unauthenticated,
        ),
    ] {
        let receipts_before = service
            .db
            .list_operation_receipts_in_window("managed-conformance", 0, i64::MAX, 100)
            .unwrap()
            .len();
        let mut denied = Request::new(managed_plan_request(request_id));
        attach_managed_context(&mut denied, context);
        assert_eq!(
            service.plan_execution(denied).await.unwrap_err().code(),
            expected_code
        );
        assert_eq!(
            service
                .db
                .list_operation_receipts_in_window("managed-conformance", 0, i64::MAX, 100,)
                .unwrap()
                .len(),
            receipts_before,
            "denied request created a receipt",
        );
    }
}

#[tokio::test]
async fn managed_context_without_enterprise_extension_fails_closed() {
    let service = memory_service();
    let mut request = Request::new(managed_plan_request("managed-context-without-extension"));
    attach_managed_context(
        &mut request,
        managed_execution_context(
            vec!["chisei.execute".into()],
            "sekai:control-plane",
            i64::MAX,
        ),
    );

    assert_eq!(
        service.plan_execution(request).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
}

#[test]
fn community_machine_context_keeps_legacy_execution_authorization() {
    let principal = crate::enterprise::AuthenticatedPrincipal {
        subject: "agent:community".into(),
        credential_id: "credential:community".into(),
    };
    let mut request = Request::new(());
    request.metadata_mut().insert(
        AUTH_SOURCE_HEADER,
        tonic::metadata::MetadataValue::from_static("token"),
    );
    request
        .extensions_mut()
        .insert(crate::enterprise::AuthenticatedContext::machine(principal));

    assert!(
        enterprise_authenticated_context(&request)
            .unwrap()
            .is_none()
    );
}

#[test]
fn enterprise_execution_marker_without_context_fails_closed() {
    let mut request = Request::new(());
    request.metadata_mut().insert(
        AUTH_SOURCE_HEADER,
        tonic::metadata::MetadataValue::from_static("enterprise"),
    );

    assert_eq!(
        enterprise_authenticated_context(&request)
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
}

async fn synthetic_native_tool_stream() -> AxumResponse {
    let body = concat!(
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"read\",\"arguments\":\"{\\\"path\\\":\"}}]},\"finish_reason\":null}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"fixture.txt\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3}}\n\n",
        "data: [DONE]\n\n"
    );
    AxumResponse::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from(body))
        .unwrap()
}

async fn synthetic_native_chat(Json(request): Json<serde_json::Value>) -> AxumResponse {
    if request["stream"].as_bool() == Some(true) {
        return synthetic_native_tool_stream().await;
    }
    AxumResponse::builder()
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"choices":[{"message":{"content":"","tool_calls":[{"id":"call_1","function":{"name":"read","arguments":"{\"path\":\"fixture.txt\"}"}}]}}],"usage":{"prompt_tokens":7,"completion_tokens":3}}"#,
        ))
        .unwrap()
}

async fn synthetic_ollama_models() -> AxumResponse {
    AxumResponse::builder()
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"models":[{"name":"mistral","details":{"parameter_size":"7B","context_length":32768},"capabilities":["tools"]}]}"#,
        ))
        .unwrap()
}

async fn spawn_synthetic_ollama_provider() -> String {
    let app = Router::new()
        .route("/api/tags", get(synthetic_ollama_models))
        .route("/v1/chat/completions", post(synthetic_native_chat));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{address}")
}

fn managed_ollama_execution_service(provider_url: String) -> ChiseiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new_with_enterprise_extension(
            ":memory:",
            Some(Arc::new(ManagedExecutionExtension)),
        )
        .unwrap(),
    )));
    let mut managed_config = config(":memory:");
    managed_config.ollama_url = provider_url;
    let service = ChiseiServiceImpl::new(db, managed_config);
    service.policy.set_namespace_policy(
        "managed-conformance",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["ollama".into()],
            allowed_models: vec!["ollama/mistral".into()],
            default_runtime: "ollama".into(),
            default_model: "ollama/mistral".into(),
            data_class: "unclassified".into(),
        },
    );
    service
}

#[tokio::test]
async fn managed_stream_preserves_tool_calls_usage_and_receipt_without_route_override() {
    let provider_url = spawn_synthetic_ollama_provider().await;
    let service = managed_ollama_execution_service(provider_url);
    let context = managed_execution_context(
        vec!["chisei.execute".into()],
        "sekai:control-plane",
        i64::MAX,
    );
    let mut plan_request = Request::new(managed_plan_request("managed-stream"));
    attach_managed_context(&mut plan_request, context.clone());
    let plan = service
        .plan_execution(plan_request)
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    assert_eq!(plan.resolved_model, "ollama/mistral");
    assert!(plan.input.as_ref().unwrap().route_override.is_empty());
    let plan_id = plan.plan_id.clone();

    let mut denied_execute = Request::new(ExecutePlanRequest {
        plan: Some(plan.clone()),
    });
    attach_managed_context(
        &mut denied_execute,
        managed_execution_context(Vec::new(), "sekai:control-plane", i64::MAX),
    );
    let denied = match service.execute_plan_stream(denied_execute).await {
        Ok(_) => panic!("unauthorized execution unexpectedly started a stream"),
        Err(error) => error,
    };
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    let mut execute_request = Request::new(ExecutePlanRequest { plan: Some(plan) });
    attach_managed_context(&mut execute_request, context);
    let mut stream = service
        .execute_plan_stream(execute_request)
        .await
        .unwrap()
        .into_inner();
    let mut terminal = None;
    while let Some(event) = stream.next().await {
        let event = event.unwrap();
        if event.done {
            terminal = event.response;
        }
    }
    let response = terminal.expect("terminal normalized response");
    assert_eq!(response.provider, "ollama");
    assert_eq!(response.input_tokens, 7);
    assert_eq!(response.output_tokens, 3);
    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].id, "call_1");
    assert_eq!(response.tool_calls[0].name, "read");
    assert_eq!(
        response.tool_calls[0].args_json,
        r#"{"path":"fixture.txt"}"#
    );

    let receipt = service
        .db
        .get_operation_receipt(&plan_id)
        .unwrap()
        .expect("operation receipt");
    assert!(receipt.completeness().complete);
    let attributes = receipt
        .events
        .iter()
        .flat_map(|event| event.attributes.values())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!attributes.contains("credential:managed-shikigami"));
    assert!(!attributes.contains("synthetic-secret"));
}

#[tokio::test]
async fn managed_cached_plan_is_bound_to_authenticated_tenant() {
    let provider_url = spawn_synthetic_ollama_provider().await;
    let service = managed_ollama_execution_service(provider_url);
    let tenant_a = managed_execution_context_for_tenant(
        vec!["chisei.execute".into()],
        "sekai:control-plane",
        i64::MAX,
        "tenant-managed-a",
    );
    let tenant_b = managed_execution_context_for_tenant(
        vec!["chisei.execute".into()],
        "sekai:control-plane",
        i64::MAX,
        "tenant-managed-b",
    );
    let mut plan_request = Request::new(managed_plan_request("managed-tenant-bound-plan"));
    attach_managed_context(&mut plan_request, tenant_a.clone());
    let plan = service
        .plan_execution(plan_request)
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();

    let mut wrong_tenant = Request::new(ExecutePlanRequest {
        plan: Some(plan.clone()),
    });
    attach_managed_context(&mut wrong_tenant, tenant_b);
    let error = match service.execute_plan_stream(wrong_tenant).await {
        Ok(_) => panic!("another tenant unexpectedly acquired the cached plan"),
        Err(error) => error,
    };
    assert_eq!(error.code(), tonic::Code::PermissionDenied);

    let mut owning_tenant = Request::new(ExecutePlanRequest { plan: Some(plan) });
    attach_managed_context(&mut owning_tenant, tenant_a);
    let mut stream = service
        .execute_plan_stream(owning_tenant)
        .await
        .unwrap()
        .into_inner();
    while let Some(event) = stream.next().await {
        event.unwrap();
    }
}

#[tokio::test]
async fn managed_unary_execution_accepts_machine_context_and_normalizes_receipt() {
    let provider_url = spawn_synthetic_ollama_provider().await;
    let service = managed_ollama_execution_service(provider_url);
    let context = managed_execution_context(
        vec!["chisei.execute".into()],
        "sekai:control-plane",
        i64::MAX,
    );
    let mut plan_request = Request::new(managed_plan_request("managed-unary"));
    attach_managed_context(&mut plan_request, context.clone());
    let plan = service
        .plan_execution(plan_request)
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    let plan_id = plan.plan_id.clone();

    let mut execute_request = Request::new(ExecutePlanRequest { plan: Some(plan) });
    attach_managed_context(&mut execute_request, context);
    let response = service
        .execute_plan(execute_request)
        .await
        .unwrap()
        .into_inner()
        .response
        .expect("normalized unary response");
    assert_eq!(response.provider, "ollama");
    assert_eq!(response.input_tokens, 7);
    assert_eq!(response.output_tokens, 3);
    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].id, "call_1");
    assert_eq!(response.tool_calls[0].name, "read");
    assert_eq!(
        response.tool_calls[0].args_json,
        r#"{"path":"fixture.txt"}"#
    );

    let receipt = service
        .db
        .get_operation_receipt(&plan_id)
        .unwrap()
        .expect("completed unary receipt");
    assert!(receipt.completeness().complete);
}

async fn synthetic_failed_chat(State(requests): State<Arc<AtomicUsize>>) -> AxumResponse {
    requests.fetch_add(1, Ordering::SeqCst);
    AxumResponse::builder()
        .status(503)
        .body(Body::from("synthetic provider unavailable"))
        .unwrap()
}

async fn spawn_synthetic_failing_ollama_provider() -> (String, Arc<AtomicUsize>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/api/tags", get(synthetic_ollama_models))
        .route("/v1/chat/completions", post(synthetic_failed_chat))
        .with_state(requests.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), requests)
}

async fn synthetic_invalid_tool_stream(State(requests): State<Arc<AtomicUsize>>) -> AxumResponse {
    requests.fetch_add(1, Ordering::SeqCst);
    let body = concat!(
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"read\",\"arguments\":\"{\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    AxumResponse::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from(body))
        .unwrap()
}

async fn spawn_synthetic_invalid_stream_ollama_provider() -> (String, Arc<AtomicUsize>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/api/tags", get(synthetic_ollama_models))
        .route("/v1/chat/completions", post(synthetic_invalid_tool_stream))
        .with_state(requests.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), requests)
}

#[tokio::test]
async fn managed_provider_failure_records_failed_receipt_without_route_switch() {
    let (provider_url, requests) = spawn_synthetic_failing_ollama_provider().await;
    let service = managed_ollama_execution_service(provider_url);
    let context = managed_execution_context(
        vec!["chisei.execute".into()],
        "sekai:control-plane",
        i64::MAX,
    );
    let mut plan_request = Request::new(managed_plan_request("managed-provider-failure"));
    attach_managed_context(&mut plan_request, context.clone());
    let plan = service
        .plan_execution(plan_request)
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    let plan_id = plan.plan_id.clone();
    assert_eq!(plan.resolved_model, "ollama/mistral");

    let mut execute_request = Request::new(ExecutePlanRequest { plan: Some(plan) });
    attach_managed_context(&mut execute_request, context);
    let error = match service.execute_plan_stream(execute_request).await {
        Ok(_) => panic!("synthetic provider failure unexpectedly started a stream"),
        Err(error) => error,
    };
    assert_eq!(error.code(), tonic::Code::Internal);
    assert_eq!(requests.load(Ordering::SeqCst), 1);

    let receipt = service
        .db
        .get_operation_receipt(&plan_id)
        .unwrap()
        .expect("failed operation receipt");
    assert!(receipt.completeness().complete);
    let outcome = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        .expect("failed outcome");
    assert_eq!(outcome.attributes["status"], "denied");
    assert_eq!(
        outcome.attributes["completion_reason"],
        "model_stream_start_failed"
    );
    let route = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::RouteSelected)
        .expect("recorded route");
    assert_eq!(route.attributes["runtime"], "ollama");
    assert_eq!(route.attributes["model"], "ollama/mistral");
}

#[tokio::test]
async fn managed_stream_read_failure_records_failed_receipt_without_route_switch() {
    let (provider_url, requests) = spawn_synthetic_invalid_stream_ollama_provider().await;
    let service = managed_ollama_execution_service(provider_url);
    let context = managed_execution_context(
        vec!["chisei.execute".into()],
        "sekai:control-plane",
        i64::MAX,
    );
    let mut plan_request = Request::new(managed_plan_request("managed-stream-read-failure"));
    attach_managed_context(&mut plan_request, context.clone());
    let plan = service
        .plan_execution(plan_request)
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    let plan_id = plan.plan_id.clone();

    let mut execute_request = Request::new(ExecutePlanRequest { plan: Some(plan) });
    attach_managed_context(&mut execute_request, context);
    let mut stream = service
        .execute_plan_stream(execute_request)
        .await
        .unwrap()
        .into_inner();
    let error = stream
        .next()
        .await
        .expect("stream failure event")
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    assert_eq!(requests.load(Ordering::SeqCst), 1);

    let receipt = service
        .db
        .get_operation_receipt(&plan_id)
        .unwrap()
        .expect("failed stream receipt");
    assert!(receipt.completeness().complete);
    let outcome = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        .expect("failed outcome");
    assert_eq!(outcome.attributes["status"], "denied");
    assert_eq!(
        outcome.attributes["completion_reason"],
        "model_stream_failed"
    );
    let route = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::RouteSelected)
        .expect("recorded route");
    assert_eq!(route.attributes["model"], "ollama/mistral");
}

#[tokio::test]
async fn managed_explicit_retry_creates_distinct_correlated_attempts() {
    let service = managed_execution_service();
    let context = managed_execution_context(
        vec!["chisei.execute".into()],
        "sekai:control-plane",
        i64::MAX,
    );
    let mut plan_ids = Vec::new();

    for attempt_id in ["attempt-1", "attempt-2"] {
        let mut input = managed_plan_request(&format!("managed-retry-{attempt_id}"));
        let execution = input.input.as_mut().unwrap();
        execution.logical_operation_id = "managed-logical-operation".into();
        execution.attempt_id = attempt_id.into();
        let mut request = Request::new(input);
        attach_managed_context(&mut request, context.clone());
        let plan = service
            .plan_execution(request)
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        let receipt = service
            .db
            .get_operation_receipt(&plan.plan_id)
            .unwrap()
            .expect("planned retry receipt");
        let intent = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
            .expect("retry intent");
        assert_eq!(
            intent.attributes["logical_operation_id"],
            "managed-logical-operation"
        );
        assert_eq!(intent.attributes["attempt_id"], attempt_id);
        plan_ids.push(plan.plan_id);
    }

    assert_ne!(plan_ids[0], plan_ids[1]);
}

#[derive(Debug)]
struct SchemaFixtureEvaluator {
    delay_ms: u64,
}

impl DeterministicEvaluator for SchemaFixtureEvaluator {
    fn evaluate(
        &self,
        input: &evaluation_execution_domain::DeterministicEvaluatorInput,
    ) -> Result<DeterministicEvaluatorOutput, String> {
        if self.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(self.delay_ms));
        }
        let strict = input
            .parameters
            .get("strict")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        Ok(DeterministicEvaluatorOutput {
            contract_version: EVALUATOR_RESULT_CONTRACT.into(),
            status: if strict { STATUS_PASS } else { "fail" }.into(),
            reason_code: if strict {
                "schema_conforms"
            } else {
                "strict_mode_required"
            }
            .into(),
            result: serde_json::json!({"conforms": strict}),
        })
    }
}

fn evaluation_execution_service(delay_ms: u64) -> ChiseiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let registry = Arc::new(evaluation_execution_domain::DeterministicEvaluatorRegistry::default());
    registry
        .register(
            &format!("sha256:{}", "a".repeat(64)),
            Arc::new(SchemaFixtureEvaluator { delay_ms }),
        )
        .unwrap();
    ChiseiServiceImpl::new_with_evaluator_registry(db, config(":memory:"), registry)
}

fn evaluator_definition_request(namespace: &str) -> PutEvaluatorDefinitionRequest {
    PutEvaluatorDefinitionRequest {
        definition: Some(EvaluatorDefinition {
            contract_version: evaluation_plan_domain::EVALUATOR_DEFINITION_CONTRACT.into(),
            namespace: namespace.into(),
            evaluator_id: "schema-check".into(),
            version: "1.0.0".into(),
            implementation_digest: format!("sha256:{}", "a".repeat(64)),
            execution_class: evaluation_plan_domain::DETERMINISTIC_EXECUTION_CLASS.into(),
            supported_predicate_kinds: vec!["schema_conforms".into()],
            supported_input_schemas: vec!["schema://document/v1".into()],
            supported_result_schemas: vec!["schema://pass-fail/v1".into()],
            parameter_schema_json: r#"{"type":"object","properties":{"strict":{"type":"boolean"}},"required":["strict"],"additionalProperties":false}"#.into(),
            evidence_classifications: vec!["internal".into()],
            resource_limits: Some(EvaluatorResourceLimits {
                timeout_ms: 1_000,
                max_input_bytes: 4_096,
                max_output_bytes: 1_024,
                max_evidence_items: 8,
            }),
            source_ref: "repo://evaluators/schema-check@1".into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn install_invariant(svc: &ChiseiServiceImpl, namespace: &str) -> String {
    install_invariant_with_subject_refs(svc, namespace, "document-schema", vec![])
}

fn install_invariant_with_subject_refs(
    svc: &ChiseiServiceImpl,
    namespace: &str,
    fact_id: &str,
    subject_refs: Vec<String>,
) -> String {
    install_invariant_with_references(svc, namespace, fact_id, subject_refs, vec![])
}

fn install_invariant_with_references(
    svc: &ChiseiServiceImpl,
    namespace: &str,
    fact_id: &str,
    subject_refs: Vec<String>,
    evidence_refs: Vec<String>,
) -> String {
    install_invariant_with_contract(
        svc,
        namespace,
        fact_id,
        subject_refs,
        evidence_refs,
        vec![],
        vec![],
    )
}

fn install_invariant_with_contract(
    svc: &ChiseiServiceImpl,
    namespace: &str,
    fact_id: &str,
    subject_refs: Vec<String>,
    evidence_refs: Vec<String>,
    evidence_types: Vec<String>,
    requirement_version_ids: Vec<String>,
) -> String {
    governed_fact_domain::apply_profile(
        &svc.db,
        namespace,
        governed_fact_domain::PROFILE_CONTRACT_VERSION,
        "root",
        1,
    )
    .unwrap();
    governed_fact_domain::put_fact(
        &svc.db,
        governed_fact_domain::GovernedFactInput {
            contract_version: governed_fact_domain::PROFILE_CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            fact_id: fact_id.into(),
            version: "1.0.0".into(),
            fact_type: GovernedFactType::Invariant,
            status: "active".into(),
            statement: "The document conforms to the declared schema.".into(),
            applicability: governed_fact_domain::FactApplicability {
                subject_profiles: vec!["document/v1".into()],
                subject_refs,
            },
            verification: governed_fact_domain::VerificationContract {
                predicate_kind: "schema_conforms".into(),
                input_schema: "schema://document/v1".into(),
                result_schema: "schema://pass-fail/v1".into(),
                evidence_types,
            },
            requirement_version_ids,
            evidence_refs,
            source_ref: "repo://requirements/document-schema@1".into(),
            effective_from_ms: 1,
            supersedes_object_id: String::new(),
            access_marking: String::new(),
        },
        "root",
        2,
    )
    .unwrap()
    .object_id
}

fn install_requirement_with_evidence(
    svc: &ChiseiServiceImpl,
    namespace: &str,
    fact_id: &str,
    evidence_refs: Vec<String>,
) -> String {
    governed_fact_domain::apply_profile(
        &svc.db,
        namespace,
        governed_fact_domain::PROFILE_CONTRACT_VERSION,
        "root",
        1,
    )
    .unwrap();
    governed_fact_domain::put_fact(
        &svc.db,
        governed_fact_domain::GovernedFactInput {
            contract_version: governed_fact_domain::PROFILE_CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            fact_id: fact_id.into(),
            version: "1.0.0".into(),
            fact_type: GovernedFactType::Requirement,
            status: "active".into(),
            statement: "The document has attributable schema verification provenance.".into(),
            applicability: governed_fact_domain::FactApplicability {
                subject_profiles: vec!["document/v1".into()],
                subject_refs: vec![],
            },
            verification: governed_fact_domain::VerificationContract::default(),
            requirement_version_ids: vec![],
            evidence_refs,
            source_ref: "repo://requirements/schema-provenance@1".into(),
            effective_from_ms: 1,
            supersedes_object_id: String::new(),
            access_marking: String::new(),
        },
        "root",
        2,
    )
    .unwrap()
    .object_id
}

fn project_evaluation_evidence(
    svc: &ChiseiServiceImpl,
    target_external_id: &str,
    classification: crate::sekai::evidence::EvidenceClassification,
    expires_at_ms: i64,
    idempotency_key: &str,
) -> String {
    use crate::sekai::evidence::{
        EVIDENCE_ENVELOPE_VERSION, EvidenceEnvelope, EvidenceIntent, EvidenceSignal,
        EvidenceTarget, SchemaCompatibility,
    };
    use crate::sekai::evidence_store::{
        EvidenceProducerCapability, EvidenceSchemaDefinition, canonical_content_digest,
    };

    let producer_identity = format!("producer:evaluation:{idempotency_key}");
    let source_instance = format!("evaluation-fixture:{idempotency_key}");
    let target_id = format!("target:{}", target_external_id.replace(':', "-"));
    if svc
        .db
        .find_by_external_id(target_external_id)
        .unwrap()
        .is_none()
    {
        svc.db
            .create_object(&Object {
                id: target_id,
                kind: "document".into(),
                name: target_external_id.into(),
                namespace: "acme".into(),
                external_id: target_external_id.into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
    }
    svc.db
        .upsert_evidence_producer(
            &EvidenceProducerCapability {
                producer_identity: producer_identity.clone(),
                config_version: 1,
                source_types: vec!["verification_system".into()],
                source_instances: vec![source_instance.clone()],
                namespaces: vec!["acme".into()],
                evidence_types: vec!["schema-check.record".into()],
                target_kinds: vec!["document".into()],
                classification_ceiling: classification,
                allowed_intents: vec![EvidenceIntent::Upsert],
                allow_operation_attachment: false,
                replay_window_ms: 60_000,
                max_clock_skew_ms: 1_000,
                max_payload_bytes: 1_024,
                max_relationships: 4,
                rate_limit_per_minute: 20,
                max_retained_submissions: 100_000,
                revoked: false,
            },
            1,
        )
        .unwrap();
    svc.db
        .register_evidence_schema(
            &EvidenceSchemaDefinition {
                schema_id: "schema://evidence/schema-check/v1".into(),
                schema_version: "1.0.0".into(),
                evidence_type: "schema-check.record".into(),
                compatible_versions: vec![],
            },
            1,
        )
        .unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let content = serde_json::json!({"result": "passed"});
    let envelope = EvidenceEnvelope {
        contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
        source_type: "verification_system".into(),
        source_instance,
        source_record_id: idempotency_key.into(),
        source_version: "1".into(),
        source_sequence: 1,
        target: EvidenceTarget {
            namespace: "acme".into(),
            object_external_id: target_external_id.into(),
            object_kind: "document".into(),
        },
        evidence_type: "schema-check.record".into(),
        signal: EvidenceSignal::Verification,
        schema_id: "schema://evidence/schema-check/v1".into(),
        schema_version: "1.0.0".into(),
        schema_compatibility: SchemaCompatibility::Exact,
        observed_at_ms: now - 1,
        collected_at_ms: now,
        expires_at_ms: Some(expires_at_ms),
        content_digest: canonical_content_digest(&content).unwrap(),
        content,
        relationships: vec![],
        producer_identity: producer_identity.clone(),
        confidence_bps: 10_000,
        classification,
        provenance: BTreeMap::new(),
        idempotency_key: idempotency_key.into(),
        intent: EvidenceIntent::Upsert,
        causality: None,
    };
    crate::sekai::evidence_admission_lifecycle::EvidenceAdmissionLifecycle::new(&svc.db)
        .admit(&envelope, &producer_identity, now)
        .unwrap()
        .projection
        .unwrap()
        .evidence_object_id
        .unwrap()
}

fn evaluation_plan_request(
    namespace: &str,
    definition_id: &str,
    invariant_id: &str,
    version: &str,
) -> PutEvaluationPlanRequest {
    PutEvaluationPlanRequest {
        plan: Some(EvaluationPlan {
            contract_version: evaluation_plan_domain::EVALUATION_PLAN_CONTRACT.into(),
            namespace: namespace.into(),
            plan_id: "document-review".into(),
            version: version.into(),
            accepted_subject_profiles: vec!["document/v1".into()],
            nodes: vec![EvaluationPlanNode {
                node_id: "schema".into(),
                evaluator_definition_id: definition_id.into(),
                input_bindings: vec![EvaluationInputBinding {
                    name: "document".into(),
                    source_kind: evaluation_plan_domain::INPUT_INVARIANT.into(),
                    schema_id: "schema://document/v1".into(),
                }],
                parameters_json: r#"{"strict":true}"#.into(),
                invariant_version_ids: vec![invariant_id.into()],
                classification: evaluation_plan_domain::NODE_REQUIRED.into(),
                ..Default::default()
            }],
            reducer: evaluation_plan_domain::FIXED_REDUCER.into(),
            source_ref: "repo://plans/document-review@1".into(),
            ..Default::default()
        }),
    }
}

fn evaluation_resolution_request(
    namespace: &str,
    request_id: &str,
    plan_version_id: &str,
    evaluation_time_ms: i64,
) -> ResolveEvaluationPlanRequest {
    ResolveEvaluationPlanRequest {
        resolution: Some(EvaluationResolutionRequest {
            contract_version: evaluation_manifest_domain::RESOLUTION_REQUEST_CONTRACT.into(),
            resolver_version: evaluation_manifest_domain::RESOLVER_VERSION.into(),
            namespace: namespace.into(),
            request_id: request_id.into(),
            plan_version_id: plan_version_id.into(),
            subject_profile: "document/v1".into(),
            subject_identity: "document:42".into(),
            subject_content_digest: format!("sha256:{}", "b".repeat(64)),
            evidence_object_ids: vec![],
            evaluation_time_ms,
        }),
    }
}

async fn resolved_execution_fixture(
    svc: &ChiseiServiceImpl,
    request_id: &str,
) -> ResolvedEvaluationManifest {
    let invariant_id = install_invariant(svc, "acme");
    let definition = svc
        .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .definition
        .unwrap();
    let plan = svc
        .put_evaluation_plan(Request::new(evaluation_plan_request(
            "acme",
            &definition.definition_id,
            &invariant_id,
            "1.0.0",
        )))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    svc.resolve_evaluation_plan(Request::new(evaluation_resolution_request(
        "acme",
        request_id,
        &plan.plan_version_id,
        10,
    )))
    .await
    .unwrap()
    .into_inner()
    .manifest
    .unwrap()
}

#[tokio::test]
async fn evaluation_plans_bind_exact_compatible_resources_and_preserve_history() {
    let svc = memory_service();
    let invariant_id = install_invariant(&svc, "acme");
    let definition = svc
        .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .definition
        .unwrap();
    let stored = svc
        .put_evaluation_plan(Request::new(evaluation_plan_request(
            "acme",
            &definition.definition_id,
            &invariant_id,
            "1.0.0",
        )))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    let replay = svc
        .put_evaluation_plan(Request::new(evaluation_plan_request(
            "acme",
            &definition.definition_id,
            &invariant_id,
            "1.0.0",
        )))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    assert_eq!(stored.content_digest, replay.content_digest);

    let disabled = svc
        .put_evaluator_definition(Request::new(PutEvaluatorDefinitionRequest {
            definition_id: definition.definition_id.clone(),
            availability_state: evaluation_plan_domain::AVAILABILITY_DISABLED.into(),
            reason: "maintenance".into(),
            request_id: "disable-1".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .availability
        .unwrap();
    assert_eq!(
        disabled.state,
        evaluation_plan_domain::AVAILABILITY_DISABLED
    );
    assert_eq!(disabled.request_id, "disable-1");
    assert_eq!(disabled.reason, "maintenance");
    let historical_replay = svc
        .put_evaluation_plan(Request::new(evaluation_plan_request(
            "acme",
            &definition.definition_id,
            &invariant_id,
            "1.0.0",
        )))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    assert_eq!(historical_replay.plan_version_id, stored.plan_version_id);
    let error = svc
        .put_evaluation_plan(Request::new(evaluation_plan_request(
            "acme",
            &definition.definition_id,
            &invariant_id,
            "2.0.0",
        )))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn evaluation_plan_rejects_evidence_outside_evaluator_classifications() {
    let svc = memory_service();
    let evidence_id = "evidence-confidential";
    svc.db
        .create_object(&Object {
            id: evidence_id.into(),
            kind: crate::domain::KIND_EXTERNAL_EVIDENCE.into(),
            name: "confidential evidence".into(),
            namespace: "acme".into(),
            external_id: "evidence:confidential".into(),
            properties: HashMap::from([("classification".into(), "confidential".into())]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    let invariant_id = install_invariant_with_references(
        &svc,
        "acme",
        "document-schema",
        vec![],
        vec![evidence_id.into()],
    );
    let definition = svc
        .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .definition
        .unwrap();

    let mut request =
        evaluation_plan_request("acme", &definition.definition_id, &invariant_id, "1.0.0");
    request.plan.as_mut().unwrap().nodes[0]
        .input_bindings
        .push(EvaluationInputBinding {
            name: "evidence".into(),
            source_kind: evaluation_plan_domain::INPUT_EVIDENCE.into(),
            schema_id: "schema://document/v1".into(),
        });
    let error = svc
        .put_evaluation_plan(Request::new(request))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        error.message(),
        "evaluator definition does not admit the invariant evidence classification"
    );
}

#[tokio::test]
async fn evaluation_plan_validation_rejects_unknown_reducers_and_bad_parameters() {
    let svc = memory_service();
    let invariant_id = install_invariant(&svc, "acme");
    let definition = svc
        .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .definition
        .unwrap();
    let mut unknown =
        evaluation_plan_request("acme", &definition.definition_id, &invariant_id, "1.0.0");
    unknown.plan.as_mut().unwrap().reducer = "custom-expression".into();
    assert_eq!(
        svc.put_evaluation_plan(Request::new(unknown))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    let mut bad_parameters =
        evaluation_plan_request("acme", &definition.definition_id, &invariant_id, "1.0.0");
    bad_parameters.plan.as_mut().unwrap().nodes[0].parameters_json = r#"{"strict":"yes"}"#.into();
    assert_eq!(
        svc.put_evaluation_plan(Request::new(bad_parameters))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    let unknown = evaluation_plan_request(
        "acme",
        "evaluator-definition:unknown",
        &invariant_id,
        "1.0.0",
    );
    assert_eq!(
        svc.put_evaluation_plan(Request::new(unknown))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let subject_specific = install_invariant_with_subject_refs(
        &svc,
        "acme",
        "subject-specific-schema",
        vec!["document:one".into()],
    );
    let subject_specific_plan = evaluation_plan_request(
        "acme",
        &definition.definition_id,
        &subject_specific,
        "1.0.0",
    );
    let error = svc
        .put_evaluation_plan(Request::new(subject_specific_plan))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("subject-specific"));
}

#[tokio::test]
async fn evaluation_resource_reads_are_namespace_and_reference_authorized() {
    let svc = memory_service();
    let invariant_id = install_invariant(&svc, "acme");
    let definition = svc
        .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .definition
        .unwrap();
    let _plan = svc
        .put_evaluation_plan(Request::new(evaluation_plan_request(
            "acme",
            &definition.definition_id,
            &invariant_id,
            "1.0.0",
        )))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    svc.db
        .create_object(&Object {
            id: "evaluation-namespace-acme".into(),
            kind: "namespace".into(),
            name: "Acme".into(),
            namespace: String::new(),
            external_id: "namespace:acme".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
    svc.db
        .create_grant(&Grant {
            id: "alice-evaluation-acme".into(),
            object_id: "evaluation-namespace-acme".into(),
            principal: "alice".into(),
            role: Role::Admin,
            created: 1,
        })
        .unwrap();

    svc.db
        .create_grant(&Grant {
            id: "root-only-invariant".into(),
            object_id: invariant_id,
            principal: "root".into(),
            role: Role::Viewer,
            created: 2,
        })
        .unwrap();
    let mut alice_put = Request::new(evaluator_definition_request("acme"));
    alice_put
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());
    assert_eq!(
        svc.put_evaluator_definition(alice_put)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
}

#[tokio::test]
async fn evaluation_resolution_freezes_exact_inputs_and_replays_history() {
    let svc = memory_service();
    let invariant_id = install_invariant(&svc, "acme");
    let definition = svc
        .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .definition
        .unwrap();
    let plan = svc
        .put_evaluation_plan(Request::new(evaluation_plan_request(
            "acme",
            &definition.definition_id,
            &invariant_id,
            "1.0.0",
        )))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    let request = evaluation_resolution_request("acme", "resolve-1", &plan.plan_version_id, 10);
    let first = svc
        .resolve_evaluation_plan(Request::new(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        first.status,
        evaluation_manifest_domain::RESOLUTION_RESOLVED
    );
    assert!(first.findings.is_empty());
    let manifest = first.manifest.unwrap();
    assert_eq!(manifest.plan_version_id, plan.plan_version_id);
    assert_eq!(manifest.plan_digest, plan.content_digest);
    assert_eq!(manifest.subject_identity, "document:42");
    assert_eq!(manifest.resolved_by, "local");
    assert_eq!(manifest.nodes.len(), 1);
    assert_eq!(
        manifest.nodes[0]
            .evaluator
            .as_ref()
            .unwrap()
            .implementation_digest,
        definition.implementation_digest
    );
    assert_eq!(
        manifest.nodes[0].invariants[0].invariant_version_id,
        invariant_id
    );

    let replay = svc
        .resolve_evaluation_plan(Request::new(request))
        .await
        .unwrap()
        .into_inner()
        .manifest
        .unwrap();
    assert_eq!(replay.manifest_digest, manifest.manifest_digest);
    assert_eq!(replay.created_at_ms, manifest.created_at_ms);

    svc.put_evaluator_definition(Request::new(PutEvaluatorDefinitionRequest {
        definition_id: definition.definition_id,
        availability_state: evaluation_plan_domain::AVAILABILITY_DISABLED.into(),
        reason: "maintenance".into(),
        request_id: "disable-after-resolution".into(),
        ..Default::default()
    }))
    .await
    .unwrap();

    let historical = svc
        .resolve_evaluation_plan(Request::new(evaluation_resolution_request(
            "acme",
            "resolve-1",
            &plan.plan_version_id,
            10,
        )))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        historical.manifest.unwrap().manifest_digest,
        manifest.manifest_digest
    );
    let unavailable = svc
        .resolve_evaluation_plan(Request::new(evaluation_resolution_request(
            "acme",
            "resolve-2",
            &plan.plan_version_id,
            10,
        )))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        unavailable.status,
        evaluation_manifest_domain::RESOLUTION_UNAVAILABLE
    );
    assert!(unavailable.manifest.is_none());
    assert_eq!(unavailable.findings[0].code, "evaluator_unavailable");
}

#[tokio::test]
async fn deterministic_manifest_execution_is_receipt_authoritative_and_idempotent() {
    let svc = evaluation_execution_service(0);
    let manifest = resolved_execution_fixture(&svc, "execute-resolve").await;
    let definition_id = manifest.nodes[0]
        .evaluator
        .as_ref()
        .unwrap()
        .definition_id
        .clone();
    svc.put_evaluator_definition(Request::new(PutEvaluatorDefinitionRequest {
        definition_id,
        availability_state: evaluation_plan_domain::AVAILABILITY_DISABLED.into(),
        reason: "disabled after manifest resolution".into(),
        request_id: "disable-before-historical-execution".into(),
        ..Default::default()
    }))
    .await
    .unwrap();
    let request = ExecuteEvaluationManifestRequest {
        execution: Some(EvaluationExecutionRequest {
            contract_version: evaluation_execution_domain::EXECUTION_REQUEST_CONTRACT.into(),
            executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
            namespace: "acme".into(),
            manifest_digest: manifest.manifest_digest.clone(),
            max_total_duration_ms: 1_000,
        }),
    };
    let first = svc
        .execute_evaluation_manifest(Request::new(request.clone()))
        .await
        .unwrap()
        .into_inner()
        .execution
        .unwrap();
    let mut forged_report = Request::new(ReportOperationEventRequest {
        operation_id: first.operation_id.clone(),
        event_id: format!("report:{}:forged-step", first.operation_id),
        parent_event_id: format!("{}:budget", first.operation_id),
        timestamp_ms: 0,
        kind: "verification_recorded".into(),
        attributes: HashMap::from([("evaluation_step_receipt".into(), "{}".into())]),
        references: vec![],
    });
    forged_report
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    forged_report
        .metadata_mut()
        .insert(AUTH_SOURCE_HEADER, "local".parse().unwrap());
    assert_eq!(
        svc.report_operation_event(forged_report)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(first.status, evaluation_execution_domain::VERDICT_ALLOW);
    assert_eq!(first.steps.len(), 1);
    assert_eq!(
        first.steps[0].status,
        evaluation_execution_domain::STATUS_PASS
    );
    assert!(
        first
            .decision
            .as_ref()
            .unwrap()
            .decision_digest
            .starts_with("sha256:")
    );

    let mut replay_request = request;
    replay_request
        .execution
        .as_mut()
        .unwrap()
        .max_total_duration_ms = 2_000;
    let replay = svc
        .execute_evaluation_manifest(Request::new(replay_request))
        .await
        .unwrap()
        .into_inner()
        .execution
        .unwrap();
    assert_eq!(replay, first);
    let tighter = svc
        .execute_evaluation_manifest(Request::new(ExecuteEvaluationManifestRequest {
            execution: Some(EvaluationExecutionRequest {
                contract_version: evaluation_execution_domain::EXECUTION_REQUEST_CONTRACT.into(),
                executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
                namespace: "acme".into(),
                manifest_digest: manifest.manifest_digest.clone(),
                max_total_duration_ms: 500,
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(tighter.code(), tonic::Code::FailedPrecondition);
    let receipt = svc
        .db
        .get_operation_receipt(&first.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(evaluation_total_budget_ms(&receipt).unwrap(), 1_000);
    assert_eq!(
        evaluation_cancellation_event(&receipt, "different-writer", 42).actor,
        "different-writer"
    );
    assert!(receipt.completeness().complete);
    assert!(receipt.events.iter().any(|event| {
        event.kind == ReceiptEventKind::VerificationRecorded
            && event.attributes.contains_key("evaluation_step_receipt")
    }));
    assert!(receipt.events.iter().any(|event| {
        event.kind == ReceiptEventKind::OutcomeRecorded
            && event.attributes.contains_key("evaluation_gate_decision")
    }));
    let quality = crate::quality_trend::query_quality_trends(
        &svc.db,
        "local",
        "acme",
        receipt.started_at_ms.saturating_sub(1),
        receipt
            .completed_at_ms
            .unwrap_or(receipt.started_at_ms)
            .saturating_add(1),
    )
    .unwrap();
    assert_eq!(quality.totals.evaluation_receipts, 1);
    assert_eq!(quality.totals.valid_executions, 1);
    assert_eq!(quality.totals.allow, 1);
    assert_eq!(quality.totals.baseline_missing, 1);
    let mut trend_req = Request::new(GetQualityTrendRequest {
        namespace: "acme".into(),
        since_ms: receipt.started_at_ms.saturating_sub(1),
        until_ms: receipt
            .completed_at_ms
            .unwrap_or(receipt.started_at_ms)
            .saturating_add(1),
    });
    trend_req
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let remote = svc
        .get_quality_trend(trend_req)
        .await
        .unwrap()
        .into_inner()
        .report
        .unwrap();
    assert_eq!(remote.semantic_digest, quality.semantic_digest);
    assert_eq!(remote.version, crate::quality_trend::QUALITY_TREND_VERSION);
    assert!(!remote.semantic_digest.is_empty());
}

#[tokio::test]
async fn get_quality_trend_denies_hidden_namespaces_and_invalid_windows() {
    let svc = evaluation_execution_service(0);
    let mut denied = Request::new(GetQualityTrendRequest {
        namespace: "secret".into(),
        since_ms: 0,
        until_ms: 100,
    });
    denied
        .metadata_mut()
        .insert("x-principal", "mallory".parse().unwrap());
    let error = svc.get_quality_trend(denied).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(error.message(), "namespace access denied");
    assert!(!error.message().contains("secret"));

    let mut invalid = Request::new(GetQualityTrendRequest {
        namespace: "acme".into(),
        since_ms: 100,
        until_ms: 100,
    });
    invalid
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let error = svc.get_quality_trend(invalid).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn get_quality_trend_matches_canonical_reducer_digest() {
    let svc = evaluation_execution_service(0);
    let canonical =
        crate::quality_trend::query_quality_trends(&svc.db, "local", "acme", 0, 100).unwrap();
    let mut authorized = Request::new(GetQualityTrendRequest {
        namespace: "acme".into(),
        since_ms: 0,
        until_ms: 100,
    });
    authorized
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let response = svc
        .get_quality_trend(authorized)
        .await
        .unwrap()
        .into_inner()
        .report
        .unwrap();
    assert_eq!(response.semantic_digest, canonical.semantic_digest);
    assert_eq!(response.version, canonical.version);
    assert_eq!(response.namespace, "acme");

    let mut denied = Request::new(GetQualityTrendRequest {
        namespace: "acme".into(),
        since_ms: 0,
        until_ms: 100,
    });
    denied
        .metadata_mut()
        .insert("x-principal", "mallory".parse().unwrap());
    let error = svc.get_quality_trend(denied).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(error.message(), "namespace access denied");

    let mut invalid = Request::new(GetQualityTrendRequest {
        namespace: "acme".into(),
        since_ms: 100,
        until_ms: 100,
    });
    invalid
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let invalid = svc.get_quality_trend(invalid).await.unwrap_err();
    assert_eq!(invalid.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn evaluation_execution_authorizes_namespace_before_manifest_lookup() {
    let svc = evaluation_execution_service(0);
    let mut request = Request::new(ExecuteEvaluationManifestRequest {
        execution: Some(EvaluationExecutionRequest {
            contract_version: evaluation_execution_domain::EXECUTION_REQUEST_CONTRACT.into(),
            executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
            namespace: "secret".into(),
            manifest_digest: format!("sha256:{}", "9".repeat(64)),
            max_total_duration_ms: 1_000,
        }),
    });
    request
        .metadata_mut()
        .insert("x-principal", "mallory".parse().unwrap());
    let error = svc.execute_evaluation_manifest(request).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert!(!error.message().contains("manifest"));
}

#[tokio::test]
async fn concurrent_cancellation_reconciles_to_the_first_durable_actor() {
    let svc = evaluation_execution_service(0);
    let manifest = resolved_execution_fixture(&svc, "cancel-race-resolve").await;
    let manifest = svc
        .db
        .get_evaluation_manifest(&manifest.manifest_digest)
        .unwrap()
        .unwrap();
    let index = svc
        .evaluation_execution_lifecycle
        .ensure_execution_for_test(&manifest, "starter", 1_000)
        .unwrap();
    let stale_receipt = svc
        .db
        .get_operation_receipt(&index.operation_id)
        .unwrap()
        .unwrap();

    svc.evaluation_execution_lifecycle
        .request_cancellation_for_test(&index, &stale_receipt, "first-writer")
        .unwrap();
    svc.evaluation_execution_lifecycle
        .request_cancellation_for_test(&index, &stale_receipt, "second-writer")
        .unwrap();

    let receipt = svc
        .db
        .get_operation_receipt(&index.operation_id)
        .unwrap()
        .unwrap();
    let cancellation = receipt
        .events
        .iter()
        .find(|event| {
            event
                .attributes
                .get("evaluation_cancel_requested")
                .is_some_and(|value| value == "true")
        })
        .unwrap();
    assert_eq!(cancellation.actor, "first-writer");
    let quality = crate::quality_trend::query_quality_trends(
        &svc.db,
        "local",
        "acme",
        receipt.started_at_ms.saturating_sub(1),
        receipt.started_at_ms.saturating_add(1),
    )
    .unwrap();
    assert_eq!(quality.totals.cancelled, 1);
    assert_eq!(quality.totals.partial_executions, 1);
    assert_eq!(quality.totals.allow, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn cancellation_is_durable_and_reduces_fail_closed() {
    let svc = Arc::new(evaluation_execution_service(250));
    let cancellation_replica = Arc::new(ChiseiServiceImpl::new_with_evaluator_registry(
        svc.db.clone(),
        svc.config.clone(),
        svc.evaluation_execution_lifecycle
            .evaluator_registry()
            .clone(),
    ));
    let manifest = resolved_execution_fixture(&svc, "cancel-resolve").await;
    let execute_request = ExecuteEvaluationManifestRequest {
        execution: Some(EvaluationExecutionRequest {
            contract_version: evaluation_execution_domain::EXECUTION_REQUEST_CONTRACT.into(),
            executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
            namespace: "acme".into(),
            manifest_digest: manifest.manifest_digest.clone(),
            max_total_duration_ms: 2_000,
        }),
    };
    let executor = {
        let svc = svc.clone();
        tokio::spawn(async move {
            svc.execute_evaluation_manifest(Request::new(execute_request))
                .await
                .unwrap()
                .into_inner()
                .execution
                .unwrap()
        })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    let cancelled = cancellation_replica
        .cancel_evaluation_execution(Request::new(CancelEvaluationExecutionRequest {
            namespace: "acme".into(),
            manifest_digest: manifest.manifest_digest,
        }))
        .await
        .unwrap()
        .into_inner()
        .execution
        .unwrap();
    let executed = executor.await.unwrap();
    assert_eq!(cancelled, executed);
    assert_eq!(
        cancelled.status,
        evaluation_execution_domain::VERDICT_UNAVAILABLE
    );
    assert_eq!(
        cancelled.decision.as_ref().unwrap().reason_code,
        evaluation_execution_domain::REASON_EXECUTION_CANCELLED
    );
    assert_eq!(
        cancelled.steps[0].reason_code,
        evaluation_execution_domain::REASON_EXECUTION_CANCELLED
    );
    let receipt = svc
        .db
        .get_operation_receipt(&cancelled.operation_id)
        .unwrap()
        .unwrap();
    assert!(evaluation_cancellation_requested(&receipt));
    assert!(receipt.completeness().complete);
}

#[tokio::test]
async fn evaluation_resolution_fails_closed_for_uncovered_invariants() {
    let svc = memory_service();
    let covered_id = install_invariant(&svc, "acme");
    let definition = svc
        .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .definition
        .unwrap();
    let plan = svc
        .put_evaluation_plan(Request::new(evaluation_plan_request(
            "acme",
            &definition.definition_id,
            &covered_id,
            "1.0.0",
        )))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    let uncovered_id = install_invariant_with_subject_refs(&svc, "acme", "added-later", vec![]);

    let outcome = svc
        .resolve_evaluation_plan(Request::new(evaluation_resolution_request(
            "acme",
            "resolve-uncovered",
            &plan.plan_version_id,
            10,
        )))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        outcome.status,
        evaluation_manifest_domain::RESOLUTION_UNKNOWN
    );
    assert!(outcome.manifest.is_none());
    assert_eq!(outcome.findings[0].code, "invariant_uncovered");
    assert_eq!(outcome.findings[0].invariant_version_id, uncovered_id);

    let waiver = governed_fact_domain::put_waiver(
        &svc.db,
        governed_fact_domain::GovernedWaiverInput {
            contract_version: governed_fact_domain::PROFILE_CONTRACT_VERSION.into(),
            namespace: "acme".into(),
            waiver_id: "added-later-exception".into(),
            version: "1.0.0".into(),
            invariant_version_ids: vec![uncovered_id.clone()],
            applicability: governed_fact_domain::FactApplicability {
                subject_profiles: vec!["document/v1".into()],
                subject_refs: vec![],
            },
            reason: "Bounded test exception.".into(),
            evidence_refs: vec![],
            source_ref: "decision:test-waiver".into(),
            valid_from_ms: 3,
            expires_at_ms: 20,
            supersedes_object_id: String::new(),
            access_marking: String::new(),
        },
        "root",
        3,
    )
    .unwrap();
    let resolved = svc
        .resolve_evaluation_plan(Request::new(evaluation_resolution_request(
            "acme",
            "resolve-waived",
            &plan.plan_version_id,
            10,
        )))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        resolved.status,
        evaluation_manifest_domain::RESOLUTION_RESOLVED
    );
    let waiver_binding = resolved
        .manifest
        .unwrap()
        .waivers
        .into_iter()
        .find(|binding| binding.waiver_version_id == waiver.object_id)
        .unwrap();
    assert_eq!(waiver_binding.invariant_version_ids, vec![uncovered_id]);
}

#[tokio::test]
async fn evaluation_resolution_authorizes_before_resource_lookup() {
    let svc = memory_service();
    let mut request = Request::new(evaluation_resolution_request(
        "acme",
        "resolve-denied",
        "evaluation-plan:secret",
        10,
    ));
    request
        .metadata_mut()
        .insert("x-principal", "mallory".parse().unwrap());
    let error = svc.resolve_evaluation_plan(request).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert!(!error.message().contains("plan"));
}

#[tokio::test]
async fn evaluation_resolution_binds_only_fresh_subject_matched_evidence() {
    use crate::sekai::evidence::EvidenceClassification;

    let svc = memory_service();
    let invariant_id = install_invariant_with_contract(
        &svc,
        "acme",
        "document-schema-with-evidence",
        vec![],
        vec![],
        vec!["schema-check.record".into()],
        vec![],
    );
    let mut definition_request = evaluator_definition_request("acme");
    definition_request
        .definition
        .as_mut()
        .unwrap()
        .supported_input_schemas
        .push("schema://evidence/schema-check/v1".into());
    let definition = svc
        .put_evaluator_definition(Request::new(definition_request))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .definition
        .unwrap();
    let mut plan_request =
        evaluation_plan_request("acme", &definition.definition_id, &invariant_id, "1.0.0");
    plan_request.plan.as_mut().unwrap().nodes[0]
        .input_bindings
        .push(EvaluationInputBinding {
            name: "verification".into(),
            source_kind: evaluation_plan_domain::INPUT_EVIDENCE.into(),
            schema_id: "schema://evidence/schema-check/v1".into(),
        });
    let plan = svc
        .put_evaluation_plan(Request::new(plan_request))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();

    let base_time = chrono::Utc::now().timestamp_millis();
    let evidence_id = project_evaluation_evidence(
        &svc,
        "document:42",
        EvidenceClassification::Internal,
        base_time + 60_000,
        "evaluation-evidence-1",
    );
    let evaluation_time = chrono::Utc::now().timestamp_millis();
    let mut request = evaluation_resolution_request(
        "acme",
        "resolve-evidence",
        &plan.plan_version_id,
        evaluation_time,
    );
    request.resolution.as_mut().unwrap().evidence_object_ids = vec![evidence_id.clone()];
    let resolved = svc
        .resolve_evaluation_plan(Request::new(request))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        resolved.status,
        evaluation_manifest_domain::RESOLUTION_RESOLVED
    );
    let manifest = resolved.manifest.unwrap();
    assert_eq!(manifest.evidence.len(), 1);
    assert_eq!(manifest.evidence[0].evidence_object_id, evidence_id);
    assert_eq!(manifest.evidence[0].evidence_type, "schema-check.record");
    assert_eq!(
        manifest.nodes[0].evidence_object_ids,
        vec![evidence_id.clone()]
    );

    let stale_base_time = chrono::Utc::now().timestamp_millis();
    let stale_evidence_id = project_evaluation_evidence(
        &svc,
        "document:42",
        EvidenceClassification::Internal,
        stale_base_time + 250,
        "evaluation-evidence-stale",
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let mut stale_request = evaluation_resolution_request(
        "acme",
        "resolve-stale-evidence",
        &plan.plan_version_id,
        chrono::Utc::now().timestamp_millis(),
    );
    stale_request
        .resolution
        .as_mut()
        .unwrap()
        .evidence_object_ids = vec![stale_evidence_id];
    let stale = svc
        .resolve_evaluation_plan(Request::new(stale_request))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(stale.status, evaluation_manifest_domain::RESOLUTION_UNKNOWN);
    assert_eq!(stale.findings[0].code, "evidence_stale");

    let mismatched_id = project_evaluation_evidence(
        &svc,
        "document:other",
        EvidenceClassification::Internal,
        base_time + 60_000,
        "evaluation-evidence-2",
    );
    let mut mismatched_request = evaluation_resolution_request(
        "acme",
        "resolve-mismatched-evidence",
        &plan.plan_version_id,
        chrono::Utc::now().timestamp_millis(),
    );
    mismatched_request
        .resolution
        .as_mut()
        .unwrap()
        .evidence_object_ids = vec![mismatched_id];
    let mismatched = svc
        .resolve_evaluation_plan(Request::new(mismatched_request))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        mismatched.status,
        evaluation_manifest_domain::RESOLUTION_UNKNOWN
    );
    assert_eq!(mismatched.findings[0].code, "evidence_subject_mismatch");
}

#[tokio::test]
async fn evaluation_resolution_rejects_future_evaluation_time() {
    let svc = memory_service();
    let mut request = evaluation_resolution_request(
        "acme",
        "resolve-future",
        "evaluation-plan:future",
        chrono::Utc::now().timestamp_millis() + 60_000,
    );
    request.resolution.as_mut().unwrap().subject_content_digest =
        format!("sha256:{}", "c".repeat(64));
    let error = svc
        .resolve_evaluation_plan(Request::new(request))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        error.message(),
        "evaluation_time_ms cannot be in the future"
    );
}

#[tokio::test]
async fn evaluation_resolution_binds_requirement_provenance_evidence() {
    use crate::sekai::evidence::EvidenceClassification;

    let svc = memory_service();
    let base_time = chrono::Utc::now().timestamp_millis();
    let evidence_id = project_evaluation_evidence(
        &svc,
        "document:42",
        EvidenceClassification::Internal,
        base_time + 60_000,
        "requirement-evidence-1",
    );
    let requirement_id = install_requirement_with_evidence(
        &svc,
        "acme",
        "schema-provenance",
        vec![evidence_id.clone()],
    );
    let invariant_id = install_invariant_with_contract(
        &svc,
        "acme",
        "document-schema",
        vec![],
        vec![],
        vec![],
        vec![requirement_id.clone()],
    );
    let definition = svc
        .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .definition
        .unwrap();
    let plan = svc
        .put_evaluation_plan(Request::new(evaluation_plan_request(
            "acme",
            &definition.definition_id,
            &invariant_id,
            "1.0.0",
        )))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();

    let resolved = svc
        .resolve_evaluation_plan(Request::new(evaluation_resolution_request(
            "acme",
            "resolve-requirement-evidence",
            &plan.plan_version_id,
            chrono::Utc::now().timestamp_millis(),
        )))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        resolved.status,
        evaluation_manifest_domain::RESOLUTION_RESOLVED
    );
    let manifest = resolved.manifest.unwrap();
    assert_eq!(manifest.evidence.len(), 1);
    assert_eq!(manifest.evidence[0].evidence_object_id, evidence_id);
    assert_eq!(manifest.requirements.len(), 1);
    assert_eq!(
        manifest.requirements[0].requirement_version_id,
        requirement_id
    );
    assert_eq!(
        manifest.requirements[0].provenance_evidence_object_ids,
        vec![evidence_id]
    );
}

#[tokio::test]
async fn evaluation_resolution_detects_hidden_applicable_waivers() {
    let svc = memory_service();
    let invariant_id = install_invariant(&svc, "acme");
    let definition = svc
        .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .definition
        .unwrap();
    let plan = svc
        .put_evaluation_plan(Request::new(evaluation_plan_request(
            "acme",
            &definition.definition_id,
            &invariant_id,
            "1.0.0",
        )))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    let waiver = governed_fact_domain::put_waiver(
        &svc.db,
        governed_fact_domain::GovernedWaiverInput {
            contract_version: governed_fact_domain::PROFILE_CONTRACT_VERSION.into(),
            namespace: "acme".into(),
            waiver_id: "root-only-exception".into(),
            version: "1.0.0".into(),
            invariant_version_ids: vec![invariant_id],
            applicability: governed_fact_domain::FactApplicability {
                subject_profiles: vec!["document/v1".into()],
                subject_refs: vec![],
            },
            reason: "Visible only to a different principal.".into(),
            evidence_refs: vec![],
            source_ref: "decision:root-only-waiver".into(),
            valid_from_ms: 3,
            expires_at_ms: 20,
            supersedes_object_id: String::new(),
            access_marking: String::new(),
        },
        "root",
        3,
    )
    .unwrap();
    svc.db
        .create_grant(&Grant {
            id: "root-only-manifest-waiver".into(),
            object_id: waiver.object_id,
            principal: "root".into(),
            role: Role::Viewer,
            created: 3,
        })
        .unwrap();
    svc.db
        .create_object(&Object {
            id: "evaluation-resolution-namespace-acme".into(),
            kind: "namespace".into(),
            name: "Acme".into(),
            namespace: String::new(),
            external_id: "namespace:acme".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
    svc.db
        .create_grant(&Grant {
            id: "alice-evaluation-resolution-acme".into(),
            object_id: "evaluation-resolution-namespace-acme".into(),
            principal: "alice".into(),
            role: Role::Admin,
            created: 1,
        })
        .unwrap();

    let mut request = Request::new(evaluation_resolution_request(
        "acme",
        "resolve-hidden-waiver",
        &plan.plan_version_id,
        10,
    ));
    request
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());
    let outcome = svc
        .resolve_evaluation_plan(request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        outcome.status,
        evaluation_manifest_domain::RESOLUTION_UNKNOWN
    );
    assert!(outcome.manifest.is_none());
    assert_eq!(outcome.findings[0].code, "invariant_resolution_incomplete");
}

fn governed_subject_request(
    request_id: &str,
    subject_profile: &str,
    evaluation_profile: &str,
    observed_at_ms: i64,
) -> Request<EvaluateGovernedSubjectRequest> {
    let digest = format!("sha256:{}", "a".repeat(64));
    let kinds = if subject_profile == subject::SOFTWARE_RELEASE_PROFILE {
        ["source_tree", "manifest", "artifact", "build_definition"].as_slice()
    } else {
        ["policy_document", "policy_schema"].as_slice()
    };
    let mut request = Request::new(EvaluateGovernedSubjectRequest {
        subject: Some(GovernedSubjectEnvelope {
            version: subject::ENVELOPE_VERSION.into(),
            namespace: "team-a".into(),
            request_id: request_id.into(),
            subject_profile: subject_profile.into(),
            subject_identity: "subject-1".into(),
            content_digest: digest.clone(),
            references: kinds
                .iter()
                .map(|kind| GovernedSubjectReference {
                    kind: (*kind).into(),
                    reference: format!("{kind}-1"),
                    content_digest: digest.clone(),
                    observed_at_ms,
                })
                .collect(),
            evaluation_profile: evaluation_profile.into(),
        }),
    });
    request
        .metadata_mut()
        .insert("x-principal", "root".parse().unwrap());
    request
}

#[tokio::test]
async fn governed_subject_profiles_share_receipt_and_idempotency_contract() {
    let svc = memory_service();
    let now = chrono::Utc::now().timestamp_millis();
    for (index, profile) in [
        subject::SOFTWARE_RELEASE_PROFILE,
        subject::POLICY_BUNDLE_PROFILE,
    ]
    .into_iter()
    .enumerate()
    {
        let request_id = format!("subject-request-{index}");
        let first = svc
            .evaluate_governed_subject(governed_subject_request(
                &request_id,
                profile,
                subject::ALLOW_PROFILE,
                now,
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        let mut replay_request =
            governed_subject_request(&request_id, profile, subject::ALLOW_PROFILE, now - 1);
        replay_request
            .get_mut()
            .subject
            .as_mut()
            .unwrap()
            .references
            .reverse();
        let replay = svc
            .evaluate_governed_subject(replay_request)
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(first.decision, "allow");
        assert_eq!(first.operation_id, replay.operation_id);
        assert_eq!(first.receipt_digest, replay.receipt_digest);
        assert!(
            replay
                .references
                .iter()
                .all(|reference| reference.observed_at_ms == now)
        );
        let receipt = svc
            .db
            .get_operation_receipt(&first.operation_id)
            .unwrap()
            .unwrap();
        assert!(receipt.completeness().complete);
        let mut reconcile = Request::new(GetOperationReceiptRequest {
            operation_id: String::new(),
            request_id: request_id.clone(),
            caller_scope: subject::caller_scope("team-a", "root"),
            attempt: 0,
        });
        reconcile
            .metadata_mut()
            .insert("x-principal", "root".parse().unwrap());
        let reconciled = svc
            .get_operation_receipt(reconcile)
            .await
            .unwrap()
            .into_inner();
        assert!(reconciled.complete);
        assert_eq!(
            first.receipt_digest,
            format!(
                "sha256:{:x}",
                sha2::Sha256::digest(reconciled.receipt_json.as_bytes())
            )
        );
        let serialized = serde_json::to_string(&receipt).unwrap();
        for forbidden in [
            "subject_payload",
            "repository_path",
            "prompt",
            "credential",
            "raw_tool_output",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }
}

#[tokio::test]
async fn governed_subject_rejects_changed_bindings_and_unauthorized_callers() {
    let svc = memory_service();
    let now = chrono::Utc::now().timestamp_millis();
    svc.evaluate_governed_subject(governed_subject_request(
        "binding-conflict",
        subject::POLICY_BUNDLE_PROFILE,
        subject::ALLOW_PROFILE,
        now,
    ))
    .await
    .unwrap();
    let conflict = svc
        .evaluate_governed_subject(governed_subject_request(
            "binding-conflict",
            subject::POLICY_BUNDLE_PROFILE,
            subject::DENY_PROFILE,
            now,
        ))
        .await
        .unwrap_err();
    assert_eq!(conflict.code(), tonic::Code::AlreadyExists);

    let mut unauthorized = governed_subject_request(
        "unauthorized",
        subject::POLICY_BUNDLE_PROFILE,
        subject::ALLOW_PROFILE,
        now,
    );
    unauthorized
        .metadata_mut()
        .insert("x-principal", "intruder".parse().unwrap());
    let denied = svc
        .evaluate_governed_subject(unauthorized)
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn governed_subject_returns_fixed_failures_without_diagnostics() {
    let svc = memory_service();
    let now = chrono::Utc::now().timestamp_millis();
    for (index, profile, expected_decision, expected_code) in [
        (0, subject::DENY_PROFILE, "deny", ""),
        (
            1,
            subject::UNAVAILABLE_PROFILE,
            "unavailable",
            "evaluation_unavailable",
        ),
        (2, subject::TIMEOUT_PROFILE, "unknown", "evaluation_timeout"),
    ] {
        let result = svc
            .evaluate_governed_subject(governed_subject_request(
                &format!("fixed-outcome-{index}"),
                subject::POLICY_BUNDLE_PROFILE,
                profile,
                now,
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(result.decision, expected_decision);
        assert_eq!(result.failure_code, expected_code);
        assert!(!result.failure_message.contains('/'));
    }
    let stale = svc
        .evaluate_governed_subject(governed_subject_request(
            "stale-outcome",
            subject::POLICY_BUNDLE_PROFILE,
            subject::ALLOW_PROFILE,
            now - subject::MAX_EVIDENCE_AGE_MS - 1,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert_eq!(stale.decision, "unknown");
    assert_eq!(stale.failure_code, "stale_evidence");
    assert!(!stale.fresh);
}

fn governed_subject_provenance_request(
    export_id: &str,
    result: &GovernedSubjectResult,
) -> Request<ExportGovernedSubjectProvenanceRequest> {
    let mut request = Request::new(ExportGovernedSubjectProvenanceRequest {
        export_id: export_id.into(),
        operation_id: result.operation_id.clone(),
        expected_subject_identity: "subject-1".into(),
        expected_subject_content_digest: format!("sha256:{}", "a".repeat(64)),
        expected_manifest_digest: format!("sha256:{}", "a".repeat(64)),
        expected_artifact_digest: format!("sha256:{}", "a".repeat(64)),
        expected_receipt_digest: result.receipt_digest.clone(),
    });
    request
        .metadata_mut()
        .insert("x-principal", "root".parse().unwrap());
    request
}

#[tokio::test]
async fn governed_subject_provenance_is_tenkai_compatible_and_replay_safe() {
    let svc = memory_service();
    let now = chrono::Utc::now().timestamp_millis();
    let result = svc
        .evaluate_governed_subject(governed_subject_request(
            "provenance-release",
            subject::SOFTWARE_RELEASE_PROFILE,
            subject::ALLOW_PROFILE,
            now,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();

    let first = svc
        .export_governed_subject_provenance(governed_subject_provenance_request(
            "publish-1",
            &result,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!first.replayed);
    let envelope = first.envelope.clone().unwrap();
    assert_eq!(envelope.profile, subject_provenance::PROFILE);
    assert_eq!(envelope.issuer, subject_provenance::ISSUER);
    assert_eq!(envelope.decision, "allow");
    assert_eq!(envelope.receipt_schema, subject::RECEIPT_SCHEMA_VERSION);
    assert_eq!(envelope.receipt_digest, result.receipt_digest);
    assert_eq!(envelope.governed_references.len(), 1);
    assert_eq!(envelope.governed_references[0].kind, "operation");
    assert_eq!(
        envelope.content_digest,
        subject_provenance::release_content_digest(
            &format!("sha256:{}", "a".repeat(64)),
            &format!("sha256:{}", "a".repeat(64))
        )
        .unwrap()
    );

    let replay = svc
        .export_governed_subject_provenance(governed_subject_provenance_request(
            "publish-1",
            &result,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(replay.replayed);
    assert_eq!(replay.envelope, first.envelope);
    assert_eq!(replay.envelope_digest, first.envelope_digest);

    let root = first.trust_root.unwrap();
    assert_eq!(root.version, subject_provenance::TRUST_ROOT_VERSION);
    assert_eq!(root.identity, subject_provenance::ISSUER);
    assert_eq!(root.key_id, envelope.issuer_key_id);
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(root.public_key)
        .unwrap();
    let domain_envelope = subject_provenance::ProvenanceEnvelope {
        profile: envelope.profile,
        issuer: envelope.issuer,
        issuer_key_id: envelope.issuer_key_id,
        subject: envelope.subject,
        content_digest: envelope.content_digest,
        decision: envelope.decision,
        receipt_schema: envelope.receipt_schema,
        receipt_digest: envelope.receipt_digest,
        governed_references: envelope
            .governed_references
            .into_iter()
            .map(|reference| subject_provenance::GovernedReference {
                kind: reference.kind,
                id: reference.id,
                digest: reference.digest,
            })
            .collect(),
        observed_at_unix_ms: envelope.observed_at_unix_ms,
        expires_at_unix_ms: envelope.expires_at_unix_ms,
        signature: envelope.signature,
    };
    domain_envelope
        .verify(
            public_key.as_slice().try_into().unwrap(),
            chrono::Utc::now().timestamp_millis(),
        )
        .unwrap();

    svc.db
        .ensure_team_namespace("team-a", "alice", Role::Editor, "root")
        .unwrap();
    let mut delegated = governed_subject_provenance_request("publish-delegated", &result);
    delegated
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());
    assert!(
        svc.export_governed_subject_provenance(delegated)
            .await
            .unwrap()
            .into_inner()
            .envelope
            .is_some()
    );
}

#[tokio::test]
async fn governed_subject_provenance_fails_closed_and_preserves_rotated_roots() {
    let svc = memory_service();
    let now = chrono::Utc::now().timestamp_millis();
    let result = svc
        .evaluate_governed_subject(governed_subject_request(
            "provenance-failures",
            subject::SOFTWARE_RELEASE_PROFILE,
            subject::ALLOW_PROFILE,
            now,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    let first = svc
        .export_governed_subject_provenance(governed_subject_provenance_request(
            "rotation-old",
            &result,
        ))
        .await
        .unwrap()
        .into_inner()
        .envelope
        .unwrap();

    let mut conflict = governed_subject_provenance_request("rotation-old", &result);
    conflict.get_mut().expected_artifact_digest = format!("sha256:{}", "b".repeat(64));
    assert_eq!(
        svc.export_governed_subject_provenance(conflict)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::AlreadyExists
    );
    for (index, export_id) in [
        "mismatch-subject",
        "mismatch-subject-content",
        "mismatch-receipt",
        "mismatch-content",
    ]
    .into_iter()
    .enumerate()
    {
        let mut request = governed_subject_provenance_request(export_id, &result);
        match index {
            0 => request.get_mut().expected_subject_identity = "other-subject".into(),
            1 => {
                request.get_mut().expected_subject_content_digest =
                    format!("sha256:{}", "b".repeat(64))
            }
            2 => request.get_mut().expected_receipt_digest = format!("sha256:{}", "b".repeat(64)),
            3 => request.get_mut().expected_manifest_digest = format!("sha256:{}", "b".repeat(64)),
            _ => unreachable!("fixed mismatch cases"),
        }
        assert_eq!(
            svc.export_governed_subject_provenance(request)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
    }

    let mut rotated_config = config(":memory:");
    rotated_config.governed_subject_provenance_signing_key = Some("0a".repeat(32));
    let rotated = ChiseiServiceImpl::new(svc.db.clone(), rotated_config);
    let second = rotated
        .export_governed_subject_provenance(governed_subject_provenance_request(
            "rotation-new",
            &result,
        ))
        .await
        .unwrap()
        .into_inner()
        .envelope
        .unwrap();
    assert_ne!(first.issuer_key_id, second.issuer_key_id);
    let interrupted_replay = rotated
        .export_governed_subject_provenance(governed_subject_provenance_request(
            "rotation-old",
            &result,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(interrupted_replay.replayed);
    assert_eq!(
        interrupted_replay.envelope.unwrap().issuer_key_id,
        first.issuer_key_id
    );

    let old_root = interrupted_replay.trust_root.unwrap();
    assert_eq!(old_root.key_id, first.issuer_key_id);

    let mut short_lived_config = config(":memory:");
    short_lived_config.governed_subject_provenance_ttl_ms = 1;
    let short_lived = ChiseiServiceImpl::new(svc.db.clone(), short_lived_config);
    short_lived
        .export_governed_subject_provenance(governed_subject_provenance_request(
            "short-lived",
            &result,
        ))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(
        short_lived
            .export_governed_subject_provenance(governed_subject_provenance_request(
                "short-lived",
                &result,
            ))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );

    let mut expired_config = config(":memory:");
    expired_config.governed_subject_provenance_key_expires_at_ms = now;
    let expired = ChiseiServiceImpl::new(svc.db.clone(), expired_config);
    assert_eq!(
        expired
            .export_governed_subject_provenance(governed_subject_provenance_request(
                "expired-key",
                &result,
            ))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );

    let unauthenticated =
        Request::new(governed_subject_provenance_request("unauthenticated", &result).into_inner());
    assert_eq!(
        rotated
            .export_governed_subject_provenance(unauthenticated)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
}

fn external_action_request(
    actor: &str,
    idempotency_key: &str,
) -> Request<AuthorizeExternalActionRequest> {
    let mut request = Request::new(AuthorizeExternalActionRequest {
        request: Some(ExternalActionRequest {
            version: external::REQUEST_VERSION.into(),
            operation_id: "op-ext-1".into(),
            parent_operation_id: String::new(),
            attempt_id: "attempt-1".into(),
            request_id: "request-1".into(),
            actor: actor.into(),
            namespace: "team-a".into(),
            requesting_harness: "harness-a".into(),
            intended_executor: "executor-a".into(),
            action_type: "repository.write/v1".into(),
            parameter_schema: "repository.write.params/v1".into(),
            canonical_arguments_digest: "sha256:arguments".into(),
            policy_summary: HashMap::from([("repository".into(), "example/repo".into())]),
            target_selectors: vec!["project:team-a/repo:example/repo".into()],
            immutable_preconditions: HashMap::from([("head".into(), "abc123".into())]),
            risk_class: "write".into(),
            expected_effects: vec!["git.commit".into()],
            requested_invocation_count: 1,
            deadline_ms: 4_102_444_800_000,
            estimated_cost_micros: 0,
            estimated_volume: 1,
            affected_resource_count: 1,
            rollback_capability: "revert_commit".into(),
            required_host_capabilities: vec!["git.ref-precondition/v1".into()],
            idempotency_key: idempotency_key.into(),
            policy_project: "team-a".into(),
        }),
        offline: false,
    });
    request
        .metadata_mut()
        .insert("x-principal", actor.parse().unwrap());
    request
}

#[tokio::test]
async fn external_action_authorization_allows_and_replays_idempotently() {
    let svc = memory_service();
    svc.db
        .upsert_action_policy(&crate::sekai::action_policy::ActionPolicy::allow_all(
            "agent:local",
        ))
        .unwrap();
    let first = svc
        .authorize_external_action(external_action_request("local", "idem-allow"))
        .await
        .unwrap()
        .into_inner();
    let replay = svc
        .authorize_external_action(external_action_request("local", "idem-allow"))
        .await
        .unwrap()
        .into_inner();
    let first_decision = first.decision.unwrap();
    let replay_decision = replay.decision.unwrap();
    assert_eq!(first_decision.decision, "permit");
    assert_eq!(
        replay_decision.authorization_id,
        first_decision.authorization_id
    );
    assert_eq!(
        replay.permit.unwrap().permit_id,
        first.permit.unwrap().permit_id
    );
    assert!(first_decision.assurance.unwrap().authorization_only);
}

#[tokio::test]
async fn external_action_authorization_denies_by_policy_and_expiry() {
    let svc = memory_service();
    let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("agent:local");
    policy.action_overrides.insert(
        "external_action/repository.write/v1".into(),
        ActionDecision::Deny,
    );
    svc.db.upsert_action_policy(&policy).unwrap();
    let denied = svc
        .authorize_external_action(external_action_request("local", "idem-deny"))
        .await
        .unwrap()
        .into_inner()
        .decision
        .unwrap();
    assert_eq!(denied.decision, "deny");

    svc.db
        .upsert_action_policy(&crate::sekai::action_policy::ActionPolicy::allow_all(
            "agent:local",
        ))
        .unwrap();
    let mut expired = external_action_request("local", "idem-expired");
    expired.get_mut().request.as_mut().unwrap().deadline_ms = 1;
    let expired = svc
        .authorize_external_action(expired)
        .await
        .unwrap()
        .into_inner()
        .decision
        .unwrap();
    assert_eq!(expired.decision, "deny");
    assert!(expired.reason.contains("expired"));
}

#[tokio::test]
async fn external_action_authorization_rejects_namespace_and_idempotency_abuse() {
    let svc = memory_service();
    let unauthorized = svc
        .authorize_external_action(external_action_request("agent-x", "idem-unauthorized"))
        .await
        .unwrap_err();
    assert_eq!(unauthorized.code(), tonic::Code::PermissionDenied);

    svc.authorize_external_action(external_action_request("local", "idem-conflict"))
        .await
        .unwrap();
    let mut conflict = external_action_request("local", "idem-conflict");
    conflict
        .get_mut()
        .request
        .as_mut()
        .unwrap()
        .target_selectors = vec!["project:team-a/repo:other/repo".into()];
    let conflict = svc.authorize_external_action(conflict).await.unwrap_err();
    assert_eq!(conflict.code(), tonic::Code::AlreadyExists);
}

#[tokio::test]
async fn external_action_authorization_denies_when_action_policy_is_missing() {
    let svc = memory_service();
    let denied = svc
        .authorize_external_action(external_action_request("local", "idem-missing-policy"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(denied.decision.unwrap().decision, "deny");
    assert!(denied.permit.is_none());
}

#[tokio::test]
async fn external_action_permit_replay_re_evaluates_current_policy() {
    let svc = memory_service();
    svc.db
        .upsert_action_policy(&crate::sekai::action_policy::ActionPolicy::allow_all(
            "agent:local",
        ))
        .unwrap();
    let first = svc
        .authorize_external_action(external_action_request("local", "idem-replay-policy"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.decision.unwrap().decision, "permit");
    assert!(first.permit.is_some());

    let mut deny = crate::sekai::action_policy::ActionPolicy::allow_all("agent:local");
    deny.default_decision = ActionDecision::Deny;
    svc.db.upsert_action_policy(&deny).unwrap();
    let replay = svc
        .authorize_external_action(external_action_request("local", "idem-replay-policy"))
        .await
        .unwrap_err();
    assert_eq!(replay.code(), tonic::Code::PermissionDenied);
}

fn effective_summary_request(
    namespace: &str,
    principal: &str,
) -> Request<GetEffectivePolicySummaryRequest> {
    let mut request = Request::new(GetEffectivePolicySummaryRequest {
        namespace: namespace.into(),
        provider: String::new(),
    });
    request
        .metadata_mut()
        .insert("x-principal", principal.parse().unwrap());
    request
}

fn available_models_request(
    namespace: &str,
    provider: &str,
    principal: Option<&str>,
) -> Request<GetEffectivePolicySummaryRequest> {
    let mut request = Request::new(GetEffectivePolicySummaryRequest {
        namespace: namespace.into(),
        provider: provider.into(),
    });
    if let Some(principal) = principal {
        request
            .metadata_mut()
            .insert("x-principal", principal.parse().unwrap());
    }
    request
}

#[tokio::test]
async fn available_models_are_authenticated_namespace_scoped_and_filterable() {
    let svc = memory_service();
    svc.db
        .ensure_team_namespace("acme", "alice", Role::Viewer, "local")
        .unwrap();

    let missing_auth = svc
        .get_effective_policy_summary(available_models_request("acme", "", None))
        .await
        .unwrap_err();
    assert_eq!(missing_auth.code(), tonic::Code::Unauthenticated);
    let denied = svc
        .get_effective_policy_summary(available_models_request("acme", "", Some("mallory")))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    let response = svc
        .get_effective_policy_summary(available_models_request("acme", "native", Some("alice")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.namespace, "acme");
    assert_eq!(response.models.len(), 1);
    assert_eq!(response.models[0].provider, "native");
    assert_eq!(response.models[0].canonical_model, "native/native-default");
    assert!(response.models[0].capabilities.is_some());
    assert!(response.models[0].pricing.is_some());
}

#[tokio::test]
async fn effective_policy_summary_is_authorized_bounded_and_live() {
    use crate::sekai::action::RiskClass;
    use crate::sekai::action_policy::{ActionDecision, ActionPolicy};

    let svc = memory_service();
    svc.db
        .ensure_team_namespace("acme", "alice", Role::Viewer, "local")
        .unwrap();
    svc.policy.set_namespace_policy(
        "acme",
        Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: "internal".into(),
        },
    );
    svc.db
        .budget_set_limit("global", METRIC_REQUESTS, 100, "daily")
        .unwrap();
    svc.db
        .budget_set_limit("project:acme", METRIC_TOKENS, 1_000, "weekly")
        .unwrap();
    svc.db
        .budget_adjust_chain("project:acme", METRIC_TOKENS, 37, 1)
        .unwrap();
    let mut action_policy = ActionPolicy::allow_all("project:acme");
    action_policy
        .action_overrides
        .insert("shell.exec".into(), ActionDecision::RequireApproval);
    action_policy
        .risk_overrides
        .insert(RiskClass::Destructive, ActionDecision::Deny);
    svc.db.upsert_action_policy(&action_policy).unwrap();
    let denied = svc
        .get_effective_policy_summary(effective_summary_request("acme", "mallory"))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    let first = svc
        .get_effective_policy_summary(effective_summary_request("acme", "alice"))
        .await
        .unwrap()
        .into_inner();
    let routing = first.routing.unwrap();
    assert_eq!(routing.runtime, "openai");
    assert_eq!(routing.model, "gpt-5.5");
    assert_eq!(routing.policy_scope, "acme");
    assert_eq!(routing.policy_version.len(), 64);
    let budgets = first.budgets.unwrap();
    assert_eq!(budgets.limits.len(), 2);
    assert!(budgets.limits.iter().all(|limit| limit.max_amount != 37));
    let actions = first.actions.unwrap();
    assert_eq!(actions.allow_rule_count, 0);
    assert_eq!(actions.deny_rule_count, 1);
    assert_eq!(actions.require_approval_rule_count, 1);
    assert_eq!(actions.default_decision, "allow");
    svc.policy.set_namespace_policy(
        "acme",
        Policy {
            allowed_runtimes: vec!["anthropic".into()],
            allowed_models: vec!["claude-sonnet-4-20250514".into()],
            default_runtime: "anthropic".into(),
            default_model: "claude-sonnet-4-20250514".into(),
            data_class: "internal".into(),
        },
    );
    svc.db
        .budget_set_limit("project:acme", METRIC_TOKENS, 2_000, "weekly")
        .unwrap();
    let changed = svc
        .get_effective_policy_summary(effective_summary_request("acme", "alice"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        changed
            .budgets
            .unwrap()
            .limits
            .into_iter()
            .find(|limit| limit.metric == METRIC_TOKENS)
            .unwrap()
            .max_amount,
        2_000
    );
    assert_eq!(changed.routing.unwrap().runtime, "anthropic");
}

#[tokio::test]
async fn effective_policy_summary_reports_unconfigured_sections() {
    let svc = memory_service();
    svc.db
        .ensure_team_namespace("empty", "alice", Role::Viewer, "local")
        .unwrap();
    let summary = svc
        .get_effective_policy_summary(effective_summary_request("empty", "alice"))
        .await
        .unwrap()
        .into_inner();
    for (configured, status) in [
        (summary.routing.unwrap().configured, "routing"),
        (summary.budgets.unwrap().configured, "budgets"),
        (summary.actions.unwrap().configured, "actions"),
    ] {
        assert!(!configured, "{status} unexpectedly configured");
    }
}

fn file_service(path: &str) -> ChiseiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path).unwrap())));
    ChiseiServiceImpl::new(db, config(path))
}

fn resolve_policy_request(
    namespace: &str,
    preferred_runtime: &str,
    preferred_model: &str,
) -> ResolvePolicyRequest {
    ResolvePolicyRequest {
        namespace: namespace.into(),
        preferred_runtime: preferred_runtime.into(),
        preferred_model: preferred_model.into(),
        subject: String::new(),
        project: String::new(),
        agent: String::new(),
        key_id: String::new(),
        task_class: String::new(),
        user_id: String::new(),
        expected_calls: 1,
        budget_route_bias: String::new(),
        route_override: String::new(),
        capability_requirements_json: Vec::new(),
    }
}

fn create_suite(svc: &ChiseiServiceImpl, namespace: &str) {
    svc.eval
        .put_suite(crate::chisei::eval::Suite {
            id: "suite-1".into(),
            name: "suite".into(),
            description: String::new(),
            cases: std::iter::once(crate::chisei::eval::Case {
                id: "case-1".into(),
                name: "case".into(),
                namespace: namespace.into(),
                spec: "spec".into(),
                assertions: vec![],
            })
            .chain(
                (1..=MIN_EVIDENCE_CONTEXT_EVAL_CASES).map(|case| crate::chisei::eval::Case {
                    id: format!("evidence-case-{case}"),
                    name: format!("evidence case {case}"),
                    namespace: namespace.into(),
                    spec: "compare decision quality with and without evidence".into(),
                    assertions: vec![],
                }),
            )
            .collect(),
        })
        .unwrap();
}

fn seed_eval_run(
    svc: &ChiseiServiceImpl,
    run: crate::chisei::eval::Run,
    changed_file: impl AsRef<str>,
    diff_hash: impl AsRef<str>,
) {
    let changed_file = changed_file.as_ref();
    let diff_hash = diff_hash.as_ref();
    let suite_id = run.suite_id.clone();
    let run_id = run.id.clone();
    svc.eval
        .put_run(crate::chisei::eval::Run {
            id: run.id,
            suite_id: run.suite_id,
            config_ref: run.config_ref,
            results: run
                .results
                .into_iter()
                .map(|result| crate::chisei::eval::CaseResult {
                    case_id: result.case_id,
                    passed: result.passed,
                    status: result.status,
                    result: result.result,
                    score: result.score,
                    reason: result.reason,
                    elapsed: result.elapsed,
                })
                .collect(),
            timestamp: run.timestamp,
        })
        .unwrap();
    if !changed_file.is_empty() {
        svc.eval
            .track_iteration(&suite_id, &run_id, changed_file, diff_hash)
            .unwrap();
    }
}

fn eval_run(id: &str, suite_id: &str, score: i32, timestamp: i64) -> crate::chisei::eval::Run {
    crate::chisei::eval::Run {
        id: id.into(),
        suite_id: suite_id.into(),
        config_ref: "native-default".into(),
        results: vec![crate::chisei::eval::CaseResult {
            case_id: "case-1".into(),
            passed: score >= 80,
            status: if score >= 80 { "done" } else { "failed" }.into(),
            result: "result".into(),
            score,
            reason: String::new(),
            elapsed: 10,
        }],
        timestamp,
    }
}

fn evidence_eval_run(
    id: &str,
    suite_id: &str,
    source_type: &str,
    evidence_type: &str,
    with_evidence: bool,
    score: i32,
    timestamp: i64,
) -> crate::chisei::eval::Run {
    crate::chisei::eval::Run {
        id: id.into(),
        suite_id: suite_id.into(),
        config_ref: evidence_context_config_ref(source_type, evidence_type, with_evidence),
        results: (1..=MIN_EVIDENCE_CONTEXT_EVAL_CASES)
            .map(|case| crate::chisei::eval::CaseResult {
                case_id: format!("evidence-case-{case}"),
                passed: score >= 80,
                status: if score >= 80 { "done" } else { "failed" }.into(),
                result: "result".into(),
                score,
                reason: String::new(),
                elapsed: 10,
            })
            .collect(),
        timestamp,
    }
}

fn run_test_gateway_pipeline(
    svc: &ChiseiServiceImpl,
    request_id: &str,
    namespace: &str,
    spec: &str,
    task_class: &str,
) -> GatewayPipelineDecision {
    svc.gateway_pipeline_decision(GatewayPipelineInput {
        actor: "local",
        delegated_principal: None,
        request_id,
        namespace,
        spec,
        model: "native-default",
        runtime: "native",
        task_class,
    })
    .unwrap()
}

#[tokio::test]
async fn gunshi_scorecards_require_namespace_membership() {
    let svc = memory_service();
    svc.db
        .ensure_team_namespace(
            "acme",
            "alice",
            crate::sekai::security::Role::Viewer,
            "local",
        )
        .unwrap();
    let mut denied = Request::new(GetGunshiAllocationStatusRequest {
        namespace: "acme".into(),
    });
    denied
        .metadata_mut()
        .insert("x-principal", "bob".parse().unwrap());
    assert_eq!(
        svc.get_gunshi_allocation_status(denied)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );

    let mut allowed = Request::new(GetGunshiAllocationStatusRequest {
        namespace: "acme".into(),
    });
    allowed
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());
    let scorecard: crate::chisei::gunshi::AdvisoryScorecard = serde_json::from_str(
        &svc.get_gunshi_allocation_status(allowed)
            .await
            .unwrap()
            .into_inner()
            .scorecard_json,
    )
    .unwrap();
    assert_eq!(scorecard.comparisons, 0);
    assert!(require_namespace_write_access(&svc.db, "alice", "acme").is_err());
    svc.db
        .ensure_team_namespace(
            "acme",
            "alice",
            crate::sekai::security::Role::Editor,
            "local",
        )
        .unwrap();
    require_namespace_write_access(&svc.db, "alice", "acme").unwrap();
}

#[tokio::test]
async fn configuration_mutations_require_control_plane_administration() {
    let svc = memory_service();
    let mut budget = Request::new(SetBudgetLimitRequest {
        subject: "project:acme".into(),
        max_tokens: 1_000,
        period_type: "week".into(),
        ..Default::default()
    });
    budget
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());
    assert_eq!(
        svc.set_budget_limit(budget).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );

    let mut policy = Request::new(SetNamespacePolicyRequest {
        namespace: "acme".into(),
        ..Default::default()
    });
    policy
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());
    assert_eq!(
        svc.set_namespace_policy(policy).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
}

#[test]
fn team_execution_uses_authenticated_namespace_and_budget_scope() {
    let svc = memory_service();
    svc.db
        .create_object(&Object {
            id: "existing-namespace-acme".into(),
            kind: "namespace".into(),
            name: "Acme".into(),
            namespace: String::new(),
            external_id: "namespace:acme".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
    svc.db
        .create_grant(&crate::sekai::security::Grant {
            id: "alice-acme".into(),
            object_id: "existing-namespace-acme".into(),
            principal: "alice".into(),
            role: crate::sekai::security::Role::Viewer,
            created: 1,
        })
        .unwrap();

    require_namespace_access(&svc.db, "alice", "acme").unwrap();
    assert_eq!(
        require_namespace_access(&svc.db, "alice", " acme ")
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        require_namespace_access(&svc.db, "mallory", "acme")
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    require_execution_namespace_access(&svc.db, &svc.config, "chisei-gateway", "unmanaged")
        .unwrap();
    assert_eq!(
        require_execution_namespace_access(&svc.db, &svc.config, "alice", "unmanaged")
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        execution_budget_scope("acme", "alice", "forged"),
        "project:acme/agent:alice"
    );
    assert_eq!(execution_budget_scope("acme", "local", "forged"), "forged");
    assert_eq!(execution_budget_scope("acme", "root", ""), "default");
    assert_eq!(
        strongest_pressure(
            crate::chisei::budget::PressureLevel::None,
            crate::chisei::budget::PressureLevel::Critical,
        ),
        crate::chisei::budget::PressureLevel::Critical
    );
    svc.budget
        .set_limit(
            "project:acme",
            100,
            crate::chisei::budget::PeriodType::Weekly,
        )
        .unwrap();
    svc.budget.record("project:acme/agent:alice", 95);
    assert_eq!(
        svc.budget.scope_pressure("project:acme/agent:alice"),
        crate::chisei::budget::PressureLevel::Critical
    );
}

#[tokio::test]
async fn team_policy_resolution_requires_namespace_membership() {
    let svc = memory_service();
    svc.db
        .ensure_team_namespace(
            "acme",
            "alice",
            crate::sekai::security::Role::Viewer,
            "local",
        )
        .unwrap();
    let mut request = Request::new(ResolvePolicyRequest {
        namespace: "beta".into(),
        ..Default::default()
    });
    request
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());
    assert_eq!(
        svc.resolve_policy(request).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );

    let mut unmanaged = Request::new(ResolvePolicyRequest {
        namespace: "acme".into(),
        ..Default::default()
    });
    unmanaged
        .metadata_mut()
        .insert("x-principal", "unmanaged-principal".parse().unwrap());
    assert_eq!(
        svc.resolve_policy(unmanaged).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
}

#[tokio::test]
async fn team_principals_cannot_mutate_usage_accounting() {
    let svc = memory_service();
    let mut request = Request::new(RecordUsageRequest {
        subject: "project:acme".into(),
        tokens_used: -10,
        idempotency_key: "forged-reset".into(),
        ..Default::default()
    });
    request
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());
    assert_eq!(
        svc.record_usage(request).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );

    let mut sample = Request::new(RecordUsageRequest {
        sample_observation: Some(SampleObservation {
            request_id: "forged".into(),
            namespace: "other-team".into(),
            spec: "forged".into(),
            output_content: "forged".into(),
            ..Default::default()
        }),
        ..Default::default()
    });
    sample
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());
    assert_eq!(
        svc.record_usage(sample).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
}

#[tokio::test]
async fn cached_plan_execution_rechecks_namespace_membership() {
    let svc = memory_service();
    svc.db
        .create_object(&Object {
            id: "namespace-revocation".into(),
            kind: "namespace".into(),
            name: "Revocation".into(),
            namespace: String::new(),
            external_id: "namespace:revocation".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
    svc.db
        .create_grant(&crate::sekai::security::Grant {
            id: "revocation-alice".into(),
            object_id: "namespace-revocation".into(),
            principal: "alice".into(),
            role: crate::sekai::security::Role::Viewer,
            created: 1,
        })
        .unwrap();
    let mut planning = Request::new(PlanExecutionRequest {
        input: Some(ExecutionInput {
            request_id: "revoked-plan".into(),
            namespace: "revocation".into(),
            spec: "summarize".into(),
            preferred_model: "native-default".into(),
            preferred_runtime: "kiro".into(),
            user_id: "forged".into(),
            max_tokens: 16,
            ..Default::default()
        }),
        gunshi_allocation: None,
    });
    planning
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());
    let plan = svc
        .plan_execution(planning)
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    svc.db.delete_grant("revocation-alice").unwrap();

    let mut execution = Request::new(ExecutePlanRequest { plan: Some(plan) });
    execution
        .metadata_mut()
        .insert("x-principal", "alice".parse().unwrap());
    assert_eq!(
        svc.execute_plan(execution).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
}

fn project_test_evidence(svc: &ChiseiServiceImpl) -> String {
    project_test_evidence_from_source(
        svc,
        "verification_system",
        "eval-primary",
        "producer:eval",
        "check-1",
        "eval-delivery-1",
    )
}

fn project_test_evidence_from_source(
    svc: &ChiseiServiceImpl,
    source_type: &str,
    source_instance: &str,
    producer_identity: &str,
    source_record_id: &str,
    idempotency_key: &str,
) -> String {
    use crate::sekai::evidence::{
        EVIDENCE_ENVELOPE_VERSION, EvidenceClassification, EvidenceEnvelope, EvidenceIntent,
        EvidenceSignal, EvidenceTarget, SchemaCompatibility,
    };
    use crate::sekai::evidence_store::{
        EvidenceProducerCapability, EvidenceSchemaDefinition, canonical_content_digest,
    };

    svc.db
        .upsert_evidence_producer(
            &EvidenceProducerCapability {
                producer_identity: producer_identity.into(),
                config_version: 1,
                source_types: vec![source_type.into()],
                source_instances: vec![source_instance.into()],
                namespaces: vec!["acme".into()],
                evidence_types: vec!["verification.result".into()],
                target_kinds: vec!["ticker".into()],
                classification_ceiling: EvidenceClassification::Public,
                allowed_intents: vec![EvidenceIntent::Upsert],
                allow_operation_attachment: false,
                replay_window_ms: 60_000,
                max_clock_skew_ms: 1_000,
                max_payload_bytes: 1_024,
                max_relationships: 4,
                rate_limit_per_minute: 20,
                max_retained_submissions: 100_000,
                revoked: false,
            },
            1,
        )
        .unwrap();
    svc.db
        .register_evidence_schema(
            &EvidenceSchemaDefinition {
                schema_id: "verification.result".into(),
                schema_version: "1.0.0".into(),
                evidence_type: "verification.result".into(),
                compatible_versions: vec![],
            },
            1,
        )
        .unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let content = serde_json::json!({"result": "passed"});
    let envelope = EvidenceEnvelope {
        contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
        source_type: source_type.into(),
        source_instance: source_instance.into(),
        source_record_id: source_record_id.into(),
        source_version: "attempt-1".into(),
        source_sequence: 1,
        target: EvidenceTarget {
            namespace: "acme".into(),
            object_external_id: "ticker:AAPL".into(),
            object_kind: "ticker".into(),
        },
        evidence_type: "verification.result".into(),
        signal: EvidenceSignal::Verification,
        schema_id: "verification.result".into(),
        schema_version: "1.0.0".into(),
        schema_compatibility: SchemaCompatibility::Exact,
        observed_at_ms: now - 1,
        collected_at_ms: now,
        expires_at_ms: Some(now + 60_000),
        content_digest: canonical_content_digest(&content).unwrap(),
        content,
        relationships: vec![],
        producer_identity: producer_identity.into(),
        confidence_bps: 9_500,
        classification: EvidenceClassification::Public,
        provenance: BTreeMap::new(),
        idempotency_key: idempotency_key.into(),
        intent: EvidenceIntent::Upsert,
        causality: None,
    };
    crate::sekai::evidence_admission_lifecycle::EvidenceAdmissionLifecycle::new(&svc.db)
        .admit(&envelope, producer_identity, now)
        .unwrap()
        .submission
        .id
}

#[tokio::test]
async fn internal_gateway_pipeline_audits_and_applies_the_context_expansion_gate() {
    let svc = memory_service();
    svc.db
        .create_object(&Object {
            id: "ticker-aapl".into(),
            kind: "ticker".into(),
            name: "AAPL".into(),
            namespace: "acme".into(),
            external_id: "ticker:AAPL".into(),
            properties: HashMap::from([
                ("score".into(), "0.82".into()),
                (
                    crate::chisei::egress::EXTERNAL_PROPERTIES_KEY.into(),
                    "score".into(),
                ),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    svc.db
        .create_object(&Object {
            id: "analysis-aapl".into(),
            kind: "analysis".into(),
            name: "AAPL analysis".into(),
            namespace: "acme".into(),
            external_id: "analysis:AAPL".into(),
            properties: HashMap::from([
                ("verdict".into(), "validate the filing date".into()),
                (
                    crate::chisei::egress::EXTERNAL_PROPERTIES_KEY.into(),
                    "verdict".into(),
                ),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    svc.db
        .create_link(&crate::domain::Link {
            id: "analysis-touches-aapl".into(),
            from_id: "analysis-aapl".into(),
            to_id: "ticker-aapl".into(),
            relation: crate::domain::REL_TOUCHES.into(),
            created: 1,
        })
        .unwrap();
    let evidence_submission_id = project_test_evidence(&svc);

    let denied = run_test_gateway_pipeline(&svc, "before-eval", "acme", "inspect ticker:AAPL", "");
    assert!(denied.run.prepared_spec.contains("score: 0.82"));
    assert!(
        !denied
            .run
            .prepared_spec
            .contains("validate the filing date")
    );
    assert!(denied.run.evidence_references.is_empty());

    create_suite(&svc, "acme");
    let profile = pipeline_context_expansion_profile_key("acme");
    for (id, score, timestamp) in [("context-base", 90, 1), ("context-pass", 95, 2)] {
        seed_eval_run(
            &svc,
            eval_run(id, "suite-1", score, timestamp),
            &profile,
            format!("hash-{id}"),
        );
    }
    let allowed = run_test_gateway_pipeline(&svc, "after-eval", "acme", "inspect ticker:AAPL", "");
    assert!(
        allowed
            .run
            .prepared_spec
            .contains("validate the filing date")
    );
    assert!(allowed.run.evidence_references.is_empty());
    assert!(!allowed.run.prepared_spec.contains("result=passed"));

    let class_profile =
        evidence_context_profile_key("acme", "verification_system", "verification.result");
    for (id, with_evidence, score, timestamp) in [
        ("evidence-base", false, 90, 3),
        ("evidence-pass", true, 95, 4),
    ] {
        seed_eval_run(
            &svc,
            evidence_eval_run(
                id,
                "suite-1",
                "verification_system",
                "verification.result",
                with_evidence,
                score,
                timestamp,
            ),
            &class_profile,
            format!("hash-{id}"),
        );
    }
    let class_gate =
        svc.evidence_context_gate("acme", "verification_system", "verification.result", true);
    assert!(class_gate.effective_allowed);
    assert_eq!(class_gate.gate.verdict, "pass");
    assert_eq!(class_gate.gate.profile_key, class_profile);

    let invalid_profile =
        evidence_context_profile_key("acme", "verification_system", "operations.health_snapshot");
    for (id, score, timestamp) in [("invalid-base", 90, 5), ("invalid-pass", 95, 6)] {
        seed_eval_run(
            &svc,
            eval_run(id, "suite-1", score, timestamp),
            &invalid_profile,
            format!("hash-{id}"),
        );
    }
    let invalid_gate = svc.evidence_context_gate(
        "acme",
        "verification_system",
        "operations.health_snapshot",
        true,
    );
    assert!(!invalid_gate.effective_allowed);
    assert_eq!(invalid_gate.gate.verdict, "invalid_comparison");

    let evidence_allowed = run_test_gateway_pipeline(
        &svc,
        "after-evidence-eval",
        "acme",
        "inspect ticker:AAPL",
        "",
    );
    assert!(evidence_allowed.run.prepared_spec.contains("result=passed"));
    assert_eq!(evidence_allowed.run.evidence_references.len(), 1);
    assert_eq!(
        evidence_allowed.run.evidence_references[0].submission_id,
        evidence_submission_id
    );

    let decisions = svc
        .db
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            action: Some("chisei.context_expansion".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 3);
    assert!(decisions.iter().any(|decision| {
        decision.evidence["request_id"] == "before-eval"
            && decision.evidence["verdict"] == "missing"
            && decision.evidence["allowed"] == "false"
    }));
    let evidence_decisions = svc
        .db
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            action: Some("chisei.evidence_context_admission".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(evidence_decisions.len(), 3);
    assert!(evidence_decisions.iter().any(|decision| {
        decision.evidence["request_id"] == "after-eval"
            && decision.evidence["verdict"] == "missing"
            && decision.evidence["allowed"] == "false"
            && decision.evidence["used_evidence_count"] == "0"
    }));
    assert!(evidence_decisions.iter().any(|decision| {
        decision.evidence["request_id"] == "after-evidence-eval"
            && decision.evidence["verdict"] == "pass"
            && decision.evidence["allowed"] == "true"
            && decision.evidence["used_evidence_count"] == "1"
    }));
    assert!(decisions.iter().any(|decision| {
        decision.evidence["request_id"] == "after-eval"
            && decision.evidence["verdict"] == "pass"
            && decision.evidence["allowed"] == "true"
            && decision.evidence["expanded_context_items"] != "0"
    }));
}

#[tokio::test]
async fn evidence_context_gate_rejects_duplicate_case_results() {
    let svc = memory_service();
    create_suite(&svc, "acme");
    let evidence_type = "verification.result";
    let profile = evidence_context_profile_key("acme", "verification_system", evidence_type);
    let baseline = evidence_eval_run(
        "duplicate-base",
        "suite-1",
        "verification_system",
        evidence_type,
        false,
        90,
        1,
    );
    let mut candidate = evidence_eval_run(
        "duplicate-pass",
        "suite-1",
        "verification_system",
        evidence_type,
        true,
        95,
        2,
    );
    candidate.results.push(candidate.results[0].clone());
    for run in [baseline, candidate] {
        let id = run.id.clone();
        seed_eval_run(&svc, run, &profile, format!("hash-{id}"));
    }

    let gate = svc.evidence_context_gate("acme", "verification_system", evidence_type, true);
    assert!(!gate.effective_allowed);
    assert_eq!(gate.gate.verdict, "invalid_comparison");
    assert!(gate.gate.reason.contains("duplicate"));
}

#[test]
fn evidence_context_keys_do_not_alias_delimited_source_classes() {
    assert_ne!(
        evidence_context_profile_key("acme", "native:harness", "verification.result"),
        evidence_context_profile_key("acme", "native", "harness:verification.result")
    );
    assert_ne!(
        evidence_context_config_ref("native:harness", "verification.result", true),
        evidence_context_config_ref("native", "harness:verification.result", true)
    );
    assert_ne!(
        evidence_context_profile_key("x", "a:evidence:1:b", "c"),
        evidence_context_profile_key("x:evidence:14:a", "b", "c")
    );
}

#[tokio::test]
async fn native_harness_evidence_requires_its_own_baseline_comparison() {
    let svc = memory_service();
    svc.db
        .create_object(&Object {
            id: "ticker-aapl".into(),
            kind: "ticker".into(),
            name: "AAPL".into(),
            namespace: "acme".into(),
            external_id: "ticker:AAPL".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
    let verification_id = project_test_evidence(&svc);
    let native_id = project_test_evidence_from_source(
        &svc,
        "native_harness",
        "bugyo-tauri",
        "producer:bugyo",
        "bugyo-check-1",
        "bugyo-delivery-1",
    );
    create_suite(&svc, "acme");

    let context_profile = pipeline_context_expansion_profile_key("acme");
    for (id, score, timestamp) in [("context-base", 90, 1), ("context-pass", 95, 2)] {
        seed_eval_run(
            &svc,
            eval_run(id, "suite-1", score, timestamp),
            &context_profile,
            format!("hash-{id}"),
        );
    }

    let verification_profile =
        evidence_context_profile_key("acme", "verification_system", "verification.result");
    for (id, with_evidence, score, timestamp) in [
        ("verification-base", false, 90, 3),
        ("verification-pass", true, 95, 4),
    ] {
        seed_eval_run(
            &svc,
            evidence_eval_run(
                id,
                "suite-1",
                "verification_system",
                "verification.result",
                with_evidence,
                score,
                timestamp,
            ),
            &verification_profile,
            format!("hash-{id}"),
        );
    }

    let before_native_comparison = run_test_gateway_pipeline(
        &svc,
        "before-native-comparison",
        "acme",
        "inspect ticker:AAPL",
        "analysis",
    );
    assert!(
        before_native_comparison
            .run
            .evidence_references
            .iter()
            .any(|reference| reference.submission_id == verification_id)
    );
    assert!(
        !before_native_comparison
            .run
            .evidence_references
            .iter()
            .any(|reference| reference.submission_id == native_id)
    );
    assert!(before_native_comparison.run.memory_references.is_empty());
    assert!(svc.portfolio.points("acme", "analysis").unwrap().is_empty());

    let native_profile =
        evidence_context_profile_key("acme", "native_harness", "verification.result");
    for (id, with_evidence, score, timestamp) in
        [("native-base", false, 90, 5), ("native-pass", true, 95, 6)]
    {
        seed_eval_run(
            &svc,
            evidence_eval_run(
                id,
                "suite-1",
                "native_harness",
                "verification.result",
                with_evidence,
                score,
                timestamp,
            ),
            &native_profile,
            format!("hash-{id}"),
        );
    }
    let after_native_comparison = run_test_gateway_pipeline(
        &svc,
        "after-native-comparison",
        "acme",
        "inspect ticker:AAPL",
        "analysis",
    );
    assert!(
        after_native_comparison
            .run
            .evidence_references
            .iter()
            .any(|reference| reference.submission_id == native_id)
    );
    assert!(after_native_comparison.run.memory_references.is_empty());
    assert!(svc.portfolio.points("acme", "analysis").unwrap().is_empty());
}

#[tokio::test]
async fn record_usage_is_idempotent_for_replayed_keys() {
    let svc = memory_service();
    let request = RecordUsageRequest {
        user_id: "agent:codex-app".into(),
        tokens_used: 8,
        subject: String::new(),
        project: "sekai-chisei".into(),
        agent: "codex-app".into(),
        key_id: "codex-app".into(),
        work_unit: "wu-idempotent".into(),
        metric: String::new(),
        idempotency_key: "request-1:tokens".into(),
        operation_receipt_json: String::new(),
        sample_observation: None,
    };

    for _ in 0..2 {
        let response = svc
            .record_usage(Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.usage.unwrap().tokens_used, 8);
    }

    let response = svc
        .record_usage(Request::new(RecordUsageRequest {
            idempotency_key: "request-2:tokens".into(),
            ..request
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.usage.unwrap().tokens_used, 16);

    let mismatch = svc
        .record_usage(Request::new(RecordUsageRequest {
            user_id: "agent:other".into(),
            tokens_used: 1,
            idempotency_key: "request-1:tokens".into(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(mismatch.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn trusted_usage_accounting_persists_the_canonical_gateway_receipt() {
    let svc = memory_service();
    let operation_id = "gateway-receipt-1";
    let events = vec![
        receipt_event(
            operation_id,
            "intent",
            None,
            1,
            ReceiptEventKind::IntentRecorded,
            "agent:caller",
            BTreeMap::new(),
        ),
        receipt_event(
            operation_id,
            "policy",
            Some("intent"),
            2,
            ReceiptEventKind::PolicyDecided,
            "chisei-gateway",
            BTreeMap::new(),
        ),
        receipt_event(
            operation_id,
            "route",
            Some("policy"),
            3,
            ReceiptEventKind::RouteSelected,
            "chisei-gateway",
            BTreeMap::new(),
        ),
        receipt_event(
            operation_id,
            "budget",
            Some("route"),
            4,
            ReceiptEventKind::BudgetDecided,
            "chisei-gateway",
            BTreeMap::new(),
        ),
        receipt_event(
            operation_id,
            "outcome",
            Some("budget"),
            5,
            ReceiptEventKind::OutcomeRecorded,
            "chisei-gateway",
            BTreeMap::from([("status".into(), "completed".into())]),
        ),
    ];
    let receipt = OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: operation_id.into(),
        parent_operation_id: None,
        namespace: "acme".into(),
        operation_class: "gateway.request".into(),
        initiating_actor: "agent:caller".into(),
        schema_version: EXECUTION_SCHEMA_VERSION.into(),
        policy_version: "policy-v1".into(),
        started_at_ms: 1,
        completed_at_ms: Some(5),
        events,
        uncovered_surfaces: Vec::new(),
        reporter_grants: Vec::new(),
        ontology_digest: None,
        artifact: None,
    };
    assert!(receipt.completeness().complete);
    let usage = RecordUsageRequest {
        user_id: "agent:caller".into(),
        tokens_used: 0,
        project: "acme".into(),
        agent: "gateway".into(),
        work_unit: operation_id.into(),
        idempotency_key: "gateway-receipt-1:accounting".into(),
        operation_receipt_json: serde_json::to_string(&receipt).unwrap(),
        ..Default::default()
    };

    svc.record_usage(Request::new(usage.clone())).await.unwrap();
    assert_eq!(
        svc.db.get_operation_receipt(operation_id).unwrap(),
        Some(receipt)
    );

    let mut untrusted = Request::new(RecordUsageRequest {
        work_unit: "gateway-receipt-2".into(),
        idempotency_key: "gateway-receipt-2:accounting".into(),
        ..usage
    });
    untrusted
        .metadata_mut()
        .insert("x-principal", "agent:intruder".parse().unwrap());
    assert_eq!(
        svc.record_usage(untrusted).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
}

#[tokio::test]
async fn set_namespace_policy_applies_to_resolve_policy() {
    let svc = memory_service();
    svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
        namespace: "sekai-chisei".into(),
        allowed_runtimes: vec!["native".into()],
        allowed_models: vec!["native-default".into()],
        default_runtime: "native".into(),
        default_model: "native-default".into(),
        data_class: String::new(),
        context_admission_policy_json: String::new(),
    }))
    .await
    .unwrap();

    let resolved = svc
        .resolve_policy(Request::new(resolve_policy_request(
            "sekai-chisei",
            "openai",
            "gpt-5.5",
        )))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();

    assert_eq!(resolved.runtime, "native");
    assert_eq!(resolved.model, "native-default");
    assert_eq!(resolved.policy_scope, "sekai-chisei");
    assert_eq!(resolved.policy_version.len(), 64);
}

#[tokio::test]
async fn set_namespace_policy_normalizes_legacy_openai_family_defaults() {
    let svc = memory_service();
    let resolution = svc
        .set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["native-default".into()],
            default_runtime: "openai".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
            context_admission_policy_json: String::new(),
        }))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();

    assert_eq!(resolution.runtime, "native");
    assert_eq!(resolution.model, "native-default");
    assert_eq!(
        svc.policy
            .effective_policy_for_scopes(&["sekai-chisei".into()])
            .unwrap()
            .1
            .default_runtime,
        "native"
    );

    let error = svc
        .set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "opaque-hosted".into(),
            allowed_runtimes: vec!["kiro".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: "kiro".into(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
            context_admission_policy_json: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(
        svc.policy
            .effective_policy_for_scopes(&["opaque-hosted".into()])
            .is_none()
    );
}

#[tokio::test]
async fn resolve_policy_prefers_agent_context_over_project_policy() {
    let svc = memory_service();
    svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
        namespace: "sekai-chisei".into(),
        allowed_runtimes: vec!["native".into()],
        allowed_models: vec!["native-mini".into()],
        default_runtime: "native".into(),
        default_model: "native-mini".into(),
        data_class: String::new(),
        context_admission_policy_json: String::new(),
    }))
    .await
    .unwrap();
    svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
        namespace: "agent:codex-app".into(),
        allowed_runtimes: vec!["native".into()],
        allowed_models: vec!["native-default".into()],
        default_runtime: "native".into(),
        default_model: "native-default".into(),
        data_class: String::new(),
        context_admission_policy_json: String::new(),
    }))
    .await
    .unwrap();

    let mut request = resolve_policy_request("sekai-chisei", "native", "native-mini");
    request.project = "sekai-chisei".into();
    request.agent = "codex-app".into();
    let resolved = svc
        .resolve_policy(Request::new(request))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();

    assert_eq!(resolved.runtime, "native");
    assert_eq!(resolved.model, "native-default");
}

#[tokio::test]
async fn resolve_policy_biases_to_default_model_when_namespace_regressed() {
    let svc = memory_service();
    svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
        namespace: "sekai-chisei".into(),
        allowed_runtimes: vec!["native".into()],
        allowed_models: vec!["native-default".into(), "native-cheap".into()],
        default_runtime: "native".into(),
        default_model: "native-default".into(),
        data_class: String::new(),
        context_admission_policy_json: String::new(),
    }))
    .await
    .unwrap();
    create_suite(&svc, "sekai-chisei");
    seed_eval_run(
        &svc,
        eval_run("run-1", "suite-1", 92, 100),
        "sekai-chisei",
        "hash-a",
    );
    seed_eval_run(
        &svc,
        eval_run("run-2", "suite-1", 60, 200),
        "sekai-chisei",
        "hash-b",
    );

    let resolved = svc
        .resolve_policy(Request::new(resolve_policy_request(
            "sekai-chisei",
            "native",
            "native-cheap",
        )))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();

    assert_eq!(resolved.runtime, "native");
    assert_eq!(resolved.model, "native-default");
    assert!(resolved.eval_regressed);
    assert!(resolved.eval_regression_reason.contains("sekai-chisei"));
}

#[tokio::test]
async fn resolve_policy_reverts_bulk_class_to_capable_when_namespace_regressed() {
    let svc = memory_service();
    svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
        namespace: "sekai-chisei".into(),
        allowed_runtimes: vec!["native".into()],
        allowed_models: vec!["native-default".into(), "native-cheap".into()],
        default_runtime: "native".into(),
        default_model: "native-default".into(),
        data_class: String::new(),
        context_admission_policy_json: String::new(),
    }))
    .await
    .unwrap();
    create_suite(&svc, "sekai-chisei");
    // Two runs with a score drop mark the namespace as regressed.
    seed_eval_run(
        &svc,
        eval_run("run-1", "suite-1", 92, 100),
        "sekai-chisei",
        "hash-a",
    );
    seed_eval_run(
        &svc,
        eval_run("run-2", "suite-1", 60, 200),
        "sekai-chisei",
        "hash-b",
    );

    // A bulk task class would normally route cheap, but the active
    // regression forces it back to the capable default tier with no bias.
    let mut background = resolve_policy_request("sekai-chisei", "native", "native-cheap");
    background.task_class = "background".into();
    let resolved = svc
        .resolve_policy(Request::new(background))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    assert_eq!(resolved.model, "native-default");
    assert_eq!(resolved.route_bias, "");
    assert!(resolved.eval_regressed);
}

#[tokio::test]
async fn portfolio_route_is_audited_and_eval_regression_reverts_it() {
    let svc = memory_service();
    svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
        namespace: "sekai-chisei".into(),
        allowed_runtimes: vec!["native".into()],
        allowed_models: vec!["native-default".into(), "native-cheap".into()],
        default_runtime: "native".into(),
        default_model: "native-default".into(),
        data_class: String::new(),
        context_admission_policy_json: String::new(),
    }))
    .await
    .unwrap();
    for (model, quality, cost) in [("native-cheap", 85.0, 10), ("native-default", 95.0, 30)] {
        svc.portfolio
            .record(&crate::chisei::portfolio::Observation {
                namespace: "sekai-chisei".into(),
                task_class: "primary".into(),
                model: model.into(),
                prompt_variant: String::new(),
                quality_score: quality,
                cost_usd_micros: cost,
                sample_count: 5,
                updated_at: 1,
            })
            .unwrap();
    }
    svc.portfolio
        .set_objective(&crate::chisei::portfolio::Objective {
            namespace: "sekai-chisei".into(),
            mode: crate::chisei::portfolio::ObjectiveMode::MinimizeCost,
            budget_usd_micros: 100,
            quality_bar: 80.0,
            min_samples: 3,
            updated_at: 1,
        })
        .unwrap();

    let routed = svc
        .resolve_policy(Request::new(resolve_policy_request(
            "sekai-chisei",
            "native",
            "native-default",
        )))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    assert_eq!(routed.model, "native-cheap");
    assert_eq!(routed.route_bias, "portfolio");

    create_suite(&svc, "sekai-chisei");
    for (id, score, timestamp) in [("run-1", 95, 100), ("run-2", 60, 200)] {
        seed_eval_run(
            &svc,
            eval_run(id, "suite-1", score, timestamp),
            "sekai-chisei",
            id,
        );
    }
    let reverted = svc
        .resolve_policy(Request::new(resolve_policy_request(
            "sekai-chisei",
            "native",
            "native-default",
        )))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();
    assert_eq!(reverted.model, "native-default");
    assert_eq!(reverted.route_bias, "");
    assert!(reverted.eval_regressed);

    let decisions = svc
        .db
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            action: Some("chisei.portfolio_route_shift".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(decisions.len(), 2);
    assert!(
        decisions
            .iter()
            .any(|decision| decision.outcome == "shifted")
    );
    assert!(
        decisions
            .iter()
            .any(|decision| decision.outcome == "reverted")
    );
}

#[tokio::test]
async fn namespace_policy_reloads_from_sekai_object_store() {
    let path = std::env::temp_dir()
        .join(format!("sekai-policy-{}.db", uuid::Uuid::new_v4()))
        .to_string_lossy()
        .to_string();
    let svc = file_service(&path);
    let context_policy_json = serde_json::json!({
        "contract_version": crate::chisei::policy::CONTEXT_ADMISSION_POLICY_VERSION,
        "default_action": "include",
        "unknown_action": "qualify",
        "rules": []
    })
    .to_string();
    svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
        namespace: "sekai-chisei".into(),
        allowed_runtimes: vec!["openai".into()],
        allowed_models: vec!["native-default".into()],
        default_runtime: "openai".into(),
        default_model: "native-default".into(),
        data_class: String::new(),
        context_admission_policy_json: context_policy_json,
    }))
    .await
    .unwrap();
    drop(svc);

    let reloaded = file_service(&path);
    let resolved = reloaded
        .resolve_policy(Request::new(resolve_policy_request(
            "sekai-chisei",
            "openai",
            "gpt-5.5",
        )))
        .await
        .unwrap()
        .into_inner()
        .resolution
        .unwrap();

    assert_eq!(resolved.runtime, "native");
    assert_eq!(resolved.model, "native-default");
    let context_policy = reloaded
        .policy
        .context_admission_policy("sekai-chisei")
        .unwrap()
        .unwrap();
    assert_eq!(
        context_policy.unknown_action,
        ContextAdmissionAction::Qualify
    );
    let _ = fs::remove_file(path);
}

#[tokio::test]
async fn json_null_context_admission_is_not_restored_by_legacy_namespace_policy() {
    let path = std::env::temp_dir()
        .join(format!("sekai-policy-null-{}.db", uuid::Uuid::new_v4()))
        .to_string_lossy()
        .to_string();
    let include_json = serde_json::json!({
        "contract_version": crate::chisei::policy::CONTEXT_ADMISSION_POLICY_VERSION,
        "default_action": "include",
        "unknown_action": "hold_out",
        "rules": []
    })
    .to_string();
    {
        let mut cfg = config(&path);
        cfg.gateway_provided_providers = vec!["openai".into()];
        let svc = ChiseiServiceImpl::new(
            Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
                SekaiDb::new(&path).unwrap(),
            ))),
            cfg,
        );
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "team-a".into(),
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: "internal".into(),
            context_admission_policy_json: include_json.clone(),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&crate::domain::Object {
                id: "legacy-ns-policy-team-a".into(),
                kind: "namespace_policy".into(),
                name: "team-a".into(),
                namespace: "team-a".into(),
                external_id: "namespace_policy:team-a".into(),
                properties: std::collections::HashMap::from([
                    ("allowed_runtimes".into(), "openai".into()),
                    ("allowed_models".into(), "gpt-5.5".into()),
                    ("default_runtime".into(), "openai".into()),
                    ("default_model".into(), "gpt-5.5".into()),
                    ("data_class".into(), "internal".into()),
                    ("context_admission_policy_json".into(), include_json),
                ]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "team-a".into(),
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: "internal".into(),
            context_admission_policy_json: "null".into(),
        }))
        .await
        .unwrap();
        assert!(
            svc.policy
                .context_admission_policy("team-a")
                .unwrap()
                .is_none()
        );
    }

    let mut cfg = config(&path);
    cfg.gateway_provided_providers = vec!["openai".into()];
    let svc = ChiseiServiceImpl::new(
        Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(&path).unwrap(),
        ))),
        cfg,
    );
    assert!(
        svc.policy
            .context_admission_policy("team-a")
            .unwrap()
            .is_none(),
        "legacy namespace_policy must not restore a JSON-null context-admission clear"
    );
    let denied = svc
        .decide_gateway_execution(decide_request("op-json-null-reload", "summarize team-a"))
        .await
        .unwrap()
        .into_inner();
    assert!(!denied.admitted, "{denied:?}");
    assert_eq!(denied.deny_reason, "policy_denied");
    assert_eq!(
        denied.context_admission_reasons,
        vec!["context_admission:missing"]
    );
    let _ = fs::remove_file(path);
}

#[tokio::test]
async fn internal_eval_run_tracking_is_visible_to_gateway_reads() {
    let svc = memory_service();
    create_suite(&svc, "context-a");

    seed_eval_run(
        &svc,
        eval_run("run-1", "suite-1", 90, 100),
        "skills/context-a.md",
        "hash-a",
    );
    seed_eval_run(
        &svc,
        eval_run("run-2", "suite-1", 70, 200),
        "skills/context-a.md",
        "hash-b",
    );

    let latest = svc
        .eval
        .latest_iteration_for_file("skills/context-a.md")
        .unwrap();
    assert_eq!(latest.baseline_run_id, "run-1");
    assert_eq!(latest.candidate_run_id, "run-2");
    assert!(latest.regressed);

    assert_eq!(svc.eval.list_iterations("suite-1").len(), 2);
}

#[tokio::test]
async fn restored_read_contracts_return_bounded_projections() {
    let svc = memory_service();
    svc.db
        .put_sample_observation(&crate::chisei::scoring::SampleObservation {
            request_id: "observation-1".into(),
            namespace: "context-a".into(),
            spec: "private spec".into(),
            resolved_model: "native-default".into(),
            output_content: "private output".into(),
            sample_reason: "threshold".into(),
            input_tokens: 1,
            output_tokens: 2,
            stop_reason: "stop".into(),
            timestamp: 100,
            scored: false,
            task_class: "primary".into(),
            cost_usd_micros: 3,
        })
        .unwrap();

    let mut observation_request = Request::new(GetSampleObservationRequest {
        request_id: "observation-1".into(),
        namespace: "context-a".into(),
    });
    observation_request
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let observation = svc
        .get_sample_observation(observation_request)
        .await
        .unwrap()
        .into_inner()
        .observation
        .unwrap();
    assert_eq!(observation.request_id, "observation-1");
    assert_eq!(observation.namespace, "context-a");
    assert_eq!(observation.state, "recorded");
    assert_eq!(observation.observed_at, 100);
    assert!(observation.observation_digest.starts_with("sha256:"));

    svc.eval
        .put_suite(crate::chisei::eval::Suite {
            id: "suite-read".into(),
            name: "suite".into(),
            description: "readback".into(),
            cases: vec![crate::chisei::eval::Case {
                id: "case-1".into(),
                name: "case".into(),
                namespace: "context-a".into(),
                spec: "spec".into(),
                assertions: vec![],
            }],
        })
        .unwrap();
    let suite = svc.eval.get_suite("suite-read").unwrap();
    let suite_digest = evaluation_gate_suite_digest(&suite);
    let config_ref = evaluation_gate_config_ref("release", "artifact", &suite_digest);
    svc.eval
        .put_run(crate::chisei::eval::Run {
            id: "run-read".into(),
            suite_id: "suite-read".into(),
            config_ref,
            results: vec![crate::chisei::eval::CaseResult {
                case_id: "case-1".into(),
                passed: true,
                status: "passed".into(),
                result: "ok".into(),
                score: 100,
                reason: String::new(),
                elapsed: 1,
            }],
            timestamp: 101,
        })
        .unwrap();

    let mut gate_request = Request::new(GetEvaluationGateEvidenceRequest {
        suite_id: "suite-read".into(),
        release_digest: "release".into(),
        artifact_digest: "artifact".into(),
        max_timestamp_ms: 101,
    });
    gate_request
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let evidence = svc
        .get_evaluation_gate_evidence(gate_request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(evidence.status, EVALUATION_GATE_STATUS_FOUND);
    let evidence = evidence.evidence.unwrap();
    assert_eq!(evidence.suite_id, "suite-read");
    assert_eq!(evidence.run_id, "run-read");
    assert_eq!(evidence.expected_case_ids, vec!["case-1"]);
    assert_eq!(evidence.results.len(), 1);
    assert!(evidence.results[0].passed);
}

#[tokio::test]
async fn evaluation_gate_evidence_selects_latest_bound_run_and_redacts_details() {
    let svc = memory_service();
    let suite = crate::chisei::eval::Suite {
        id: "gate-suite".into(),
        name: "release gate".into(),
        description: "private suite description".into(),
        cases: vec![
            crate::chisei::eval::Case {
                id: "case-a".into(),
                name: "private case".into(),
                namespace: "private".into(),
                spec: "private spec".into(),
                assertions: vec![crate::chisei::eval::Assertion {
                    assert_type: "contains".into(),
                    value: "private assertion".into(),
                }],
            },
            crate::chisei::eval::Case {
                id: "case-b".into(),
                name: "case b".into(),
                namespace: "private".into(),
                spec: "private spec b".into(),
                assertions: vec![],
            },
        ],
    };
    svc.eval.put_suite(suite.clone()).unwrap();
    let suite_digest = evaluation_gate_suite_digest(&suite);
    let config_ref = evaluation_gate_config_ref("release", "artifact", &suite_digest);
    for run in [
        crate::chisei::eval::Run {
            id: "current-old".into(),
            suite_id: suite.id.clone(),
            config_ref: config_ref.clone(),
            results: vec![crate::chisei::eval::CaseResult {
                case_id: "case-a".into(),
                passed: true,
                status: "passed".into(),
                result: "old raw result".into(),
                score: 99,
                reason: "old private reason".into(),
                elapsed: 10,
            }],
            timestamp: 100,
        },
        crate::chisei::eval::Run {
            id: "current-new".into(),
            suite_id: suite.id.clone(),
            config_ref: config_ref.clone(),
            results: vec![
                crate::chisei::eval::CaseResult {
                    case_id: "case-a".into(),
                    passed: true,
                    status: "passed".into(),
                    result: "private raw result".into(),
                    score: 100,
                    reason: "private reason".into(),
                    elapsed: 11,
                },
                crate::chisei::eval::CaseResult {
                    case_id: "case-b".into(),
                    passed: false,
                    status: "failed".into(),
                    result: "private failure".into(),
                    score: 12,
                    reason: "private failure reason".into(),
                    elapsed: 12,
                },
            ],
            timestamp: 200,
        },
        crate::chisei::eval::Run {
            id: "wrong-config".into(),
            suite_id: suite.id.clone(),
            config_ref: "tenkai:wrong".into(),
            results: vec![],
            timestamp: 300,
        },
    ] {
        svc.eval.put_run(run).unwrap();
    }

    let mut request = Request::new(GetEvaluationGateEvidenceRequest {
        suite_id: suite.id.clone(),
        release_digest: "release".into(),
        artifact_digest: "artifact".into(),
        max_timestamp_ms: 250,
    });
    request
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let response = svc
        .get_evaluation_gate_evidence(request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.status, EVALUATION_GATE_STATUS_FOUND);
    let evidence = response.evidence.unwrap();
    assert_eq!(evidence.run_id, "current-new");
    assert_eq!(evidence.run_timestamp, 200);
    assert_eq!(evidence.expected_case_ids, vec!["case-a", "case-b"]);
    assert_eq!(
        evidence
            .results
            .iter()
            .map(|result| (result.case_id.as_str(), result.passed))
            .collect::<Vec<_>>(),
        vec![("case-a", true), ("case-b", false)]
    );
}

#[tokio::test]
async fn lookup_first_promotion_gate_runs_offline_and_records_audit() {
    let svc = memory_service();
    lookup_first::seed_s1_fixture_graph(&svc.db).unwrap();
    svc.db
        .ensure_team_namespace("acme", "alice", Role::Viewer, "local")
        .unwrap();

    let mut missing_source = Request::new(RunLookupFirstPromotionGateRequest {
        contract_version: lookup_first::LOOKUP_FIRST_GATE_CONTRACT_VERSION.into(),
        namespace: "acme".into(),
        suite_json: include_str!("../../tests/fixtures/lookup_first/promotion-gate-v1.json").into(),
    });
    missing_source
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    assert_eq!(
        svc.run_lookup_first_promotion_gate(missing_source)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );

    let mut request = Request::new(RunLookupFirstPromotionGateRequest {
        contract_version: lookup_first::LOOKUP_FIRST_GATE_CONTRACT_VERSION.into(),
        namespace: "acme".into(),
        suite_json: include_str!("../../tests/fixtures/lookup_first/promotion-gate-v1.json").into(),
    });
    request
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    request
        .metadata_mut()
        .insert(AUTH_SOURCE_HEADER, "local".parse().unwrap());

    let report = svc
        .run_lookup_first_promotion_gate(request)
        .await
        .unwrap()
        .into_inner()
        .report
        .unwrap();
    assert_eq!(report.verdict, "allow");
    assert_eq!(report.passed, 2);
    assert_eq!(report.failed, 0);
    assert!(!report.audit_decision_id.is_empty());
    let decision = svc
        .db
        .get_decision(&report.audit_decision_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        decision.action,
        lookup_first::LOOKUP_FIRST_GATE_AUDIT_ACTION
    );
    assert_eq!(decision.actor, "local");
    assert!(!decision.evidence.contains_key("answer_json"));

    let unauthorized_suite = serde_json::json!({
        "contract_version": lookup_first::LOOKUP_FIRST_GATE_CONTRACT_VERSION,
        "suite_id": "unauthorized-case-actor",
        "namespace": "acme",
        "cases": [{
            "id": "inaccessible-actor",
            "capability": crate::sekai::semantic::CAPABILITY_RESOLVE_REF,
            "namespace": "acme",
            "actor": "mallory",
            "input": {"object_id": "does-not-exist"},
            "expected_path": "model_path",
            "expected_refusal": "incomplete"
        }]
    });
    let mut unauthorized = Request::new(RunLookupFirstPromotionGateRequest {
        contract_version: lookup_first::LOOKUP_FIRST_GATE_CONTRACT_VERSION.into(),
        namespace: "acme".into(),
        suite_json: unauthorized_suite.to_string(),
    });
    unauthorized
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    unauthorized
        .metadata_mut()
        .insert(AUTH_SOURCE_HEADER, "local".parse().unwrap());
    assert_eq!(
        svc.run_lookup_first_promotion_gate(unauthorized)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
}

#[tokio::test]
async fn evaluation_gate_evidence_distinguishes_missing_and_stale_or_mismatched() {
    let svc = memory_service();
    let suite = crate::chisei::eval::Suite {
        id: "gate-status-suite".into(),
        name: "gate".into(),
        description: String::new(),
        cases: vec![crate::chisei::eval::Case {
            id: "case".into(),
            name: "case".into(),
            namespace: "namespace".into(),
            spec: "spec".into(),
            assertions: vec![],
        }],
    };
    svc.eval.put_suite(suite.clone()).unwrap();
    svc.eval
        .put_run(crate::chisei::eval::Run {
            id: "stale".into(),
            suite_id: suite.id.clone(),
            config_ref: "tenkai:not-current".into(),
            results: vec![],
            timestamp: 100,
        })
        .unwrap();

    let request = |suite_id: &str, release_digest: &str| {
        let mut request = Request::new(GetEvaluationGateEvidenceRequest {
            suite_id: suite_id.into(),
            release_digest: release_digest.into(),
            artifact_digest: "artifact".into(),
            max_timestamp_ms: 200,
        });
        request
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        request
    };
    assert_eq!(
        svc.get_evaluation_gate_evidence(request("missing", "release"))
            .await
            .unwrap()
            .into_inner()
            .status,
        EVALUATION_GATE_STATUS_SUITE_NOT_FOUND
    );
    assert_eq!(
        svc.get_evaluation_gate_evidence(request(&suite.id, "release"))
            .await
            .unwrap()
            .into_inner()
            .status,
        EVALUATION_GATE_STATUS_NO_MATCHING_RUN
    );
}

#[tokio::test]
async fn evaluation_gate_evidence_rejects_malformed_selected_results() {
    let svc = memory_service();
    let suite = crate::chisei::eval::Suite {
        id: "gate-integrity-suite".into(),
        name: "gate".into(),
        description: String::new(),
        cases: vec![crate::chisei::eval::Case {
            id: "expected".into(),
            name: "expected".into(),
            namespace: "namespace".into(),
            spec: "spec".into(),
            assertions: vec![],
        }],
    };
    svc.eval.put_suite(suite.clone()).unwrap();
    let suite_digest = evaluation_gate_suite_digest(&suite);
    let config_ref = evaluation_gate_config_ref("release", "artifact", &suite_digest);
    svc.eval
        .put_run(crate::chisei::eval::Run {
            id: "malformed".into(),
            suite_id: suite.id.clone(),
            config_ref,
            results: vec![
                crate::chisei::eval::CaseResult {
                    case_id: "expected".into(),
                    passed: true,
                    status: "passed".into(),
                    result: String::new(),
                    score: 1,
                    reason: String::new(),
                    elapsed: 1,
                },
                crate::chisei::eval::CaseResult {
                    case_id: "unexpected".into(),
                    passed: true,
                    status: "passed".into(),
                    result: String::new(),
                    score: 1,
                    reason: String::new(),
                    elapsed: 1,
                },
            ],
            timestamp: 100,
        })
        .unwrap();
    let mut request = Request::new(GetEvaluationGateEvidenceRequest {
        suite_id: suite.id,
        release_digest: "release".into(),
        artifact_digest: "artifact".into(),
        max_timestamp_ms: 200,
    });
    request
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let error = svc.get_evaluation_gate_evidence(request).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn evaluation_gate_evidence_rejects_unauthorized_readers() {
    let svc = memory_service();
    let mut request = Request::new(GetEvaluationGateEvidenceRequest {
        suite_id: "suite".into(),
        release_digest: "release".into(),
        artifact_digest: "artifact".into(),
        max_timestamp_ms: 1,
    });
    request
        .metadata_mut()
        .insert("x-principal", "untrusted-agent".parse().unwrap());
    let error = svc.get_evaluation_gate_evidence(request).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn evaluation_gate_evidence_rejects_timestamps_beyond_clock_skew_bound() {
    let svc = memory_service();
    let mut request = Request::new(GetEvaluationGateEvidenceRequest {
        suite_id: "suite".into(),
        release_digest: "release".into(),
        artifact_digest: "artifact".into(),
        max_timestamp_ms: chrono::Utc::now()
            .timestamp_millis()
            .saturating_add(EVALUATION_GATE_MAX_FUTURE_SKEW_MS + 60_000),
    });
    request
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let error = svc.get_evaluation_gate_evidence(request).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(error.message(), "max_timestamp_ms is too far in the future");
}

#[tokio::test]
async fn evaluation_gate_evidence_accepts_bound_within_clock_skew_window() {
    let svc = memory_service();
    let mut request = Request::new(GetEvaluationGateEvidenceRequest {
        suite_id: "missing-suite".into(),
        release_digest: "release".into(),
        artifact_digest: "artifact".into(),
        max_timestamp_ms: chrono::Utc::now().timestamp_millis().saturating_add(90_000),
    });
    request
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());

    let response = svc
        .get_evaluation_gate_evidence(request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.status, EVALUATION_GATE_STATUS_SUITE_NOT_FOUND);
}

#[tokio::test]
async fn sqlite_reload_restores_iterations_and_regression_gate() {
    let path = format!(
        "{}/sekai-chisei-{}.db",
        std::env::temp_dir().display(),
        uuid::Uuid::new_v4()
    );
    let svc = file_service(&path);
    create_suite(&svc, "context-a");

    seed_eval_run(
        &svc,
        eval_run("run-1", "suite-1", 92, 100),
        "skills/context-a.md",
        "hash-a",
    );
    seed_eval_run(
        &svc,
        eval_run("run-2", "suite-1", 60, 200),
        "skills/context-a.md",
        "hash-b",
    );

    drop(svc);

    let svc = file_service(&path);
    let latest = svc
        .eval
        .latest_iteration_for_file("skills/context-a.md")
        .unwrap();
    assert!(latest.regressed);

    let plan = svc
        .plan_execution(Request::new(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "task-1".into(),
                namespace: "context-a".into(),
                spec: "ship context-a fix".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
                task_class: String::new(),
                ..Default::default()
            }),
            gunshi_allocation: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    assert!(plan.eval_regressed);
    assert!(!plan.executable);
    assert!(plan.eval_regression_reason.contains("context-a"));
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("regressed"))
    );
    let denied_receipt = svc
        .db
        .get_operation_receipt(&plan.plan_id)
        .unwrap()
        .unwrap();
    assert!(denied_receipt.completeness().complete);
    assert!(denied_receipt.events.iter().any(|event| {
        event.kind == ReceiptEventKind::OutcomeRecorded
            && event.attributes.get("status").map(String::as_str) == Some("denied")
    }));

    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn configured_gateway_principal_can_claim_one_dispatch() {
    let mut svc = memory_service();
    svc.config.gateway_receipt_principals = vec!["Gateway-Prod".into()];
    let claim = ClaimGatewayDispatchRequest {
        caller_scope: "gateway:prod".into(),
        request_alias: "attempt-1".into(),
        request_id: "request-1".into(),
        operation_id: "operation-1".into(),
        dispatch_token: "dispatch-1".into(),
    };
    let mut configured = Request::new(claim.clone());
    configured
        .metadata_mut()
        .insert("x-principal", "Gateway-Prod".parse().unwrap());
    configured
        .metadata_mut()
        .insert(AUTH_SOURCE_HEADER, "token".parse().unwrap());
    assert!(
        svc.claim_gateway_dispatch(configured)
            .await
            .unwrap()
            .into_inner()
            .claimed
    );

    let mut replay = Request::new(ClaimGatewayDispatchRequest {
        dispatch_token: "dispatch-2".into(),
        ..claim.clone()
    });
    replay
        .metadata_mut()
        .insert("x-principal", "Gateway-Prod".parse().unwrap());
    replay
        .metadata_mut()
        .insert(AUTH_SOURCE_HEADER, "token".parse().unwrap());
    assert!(
        !svc.claim_gateway_dispatch(replay)
            .await
            .unwrap()
            .into_inner()
            .claimed
    );

    let mut intruder = Request::new(ClaimGatewayDispatchRequest {
        request_alias: "attempt-2".into(),
        request_id: "request-2".into(),
        ..claim
    });
    intruder
        .metadata_mut()
        .insert("x-principal", "agent:intruder".parse().unwrap());
    assert_eq!(
        svc.claim_gateway_dispatch(intruder)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
}

#[tokio::test]
async fn internal_gateway_pipeline_honors_delegated_membership() {
    let mut svc = memory_service();
    svc.config.gateway_receipt_principals = vec!["Gateway-Prod".into()];
    svc.db
        .ensure_team_namespace(
            "acme",
            "alice",
            crate::sekai::security::Role::Viewer,
            "local",
        )
        .unwrap();
    svc.db
        .create_object(&Object {
            id: "delegated-context".into(),
            kind: "asset".into(),
            name: "Delegated context".into(),
            namespace: "acme".into(),
            external_id: "asset:DELEGATED".into(),
            properties: HashMap::from([
                ("verdict".into(), "delegated context value".into()),
                (
                    crate::chisei::egress::EXTERNAL_PROPERTIES_KEY.into(),
                    "verdict".into(),
                ),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    svc.db
        .create_grant(&crate::sekai::security::Grant {
            id: "delegated-context-alice".into(),
            object_id: "delegated-context".into(),
            principal: "alice".into(),
            role: crate::sekai::security::Role::Viewer,
            created: 1,
        })
        .unwrap();
    assert_eq!(
        execution_context_actor(&svc.db, &svc.config, "Gateway-Prod", Some("alice"), "acme",)
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        execution_context_actor(&svc.db, &svc.config, "local", Some("alice"), "acme",).unwrap(),
        "alice"
    );
    assert_eq!(
        execution_context_actor(&svc.db, &svc.config, "root", Some("alice"), "acme",).unwrap(),
        "alice"
    );
    let response = svc
        .gateway_pipeline_decision(GatewayPipelineInput {
            actor: "chisei-gateway",
            delegated_principal: Some("alice"),
            request_id: "gateway-observation",
            namespace: "acme",
            spec: "inspect asset:DELEGATED",
            model: "native-default",
            runtime: "native",
            task_class: "",
        })
        .unwrap();
    assert!(
        response
            .run
            .prepared_spec
            .contains("delegated context value")
    );
}

#[test]
fn planned_receipt_pins_external_evidence_and_memory_provenance() {
    let svc = memory_service();
    let digest = "a".repeat(64);
    let plan = ExecutionPlan {
        plan_id: "plan-with-evidence".into(),
        input: Some(ExecutionInput {
            request_id: "request-with-evidence".into(),
            namespace: "acme".into(),
            spec: "use governed evidence".into(),
            task_type: " verification ".into(),
            ..Default::default()
        }),
        created_at: 100,
        evidence_references: vec![ContextEvidenceReference {
            submission_id: "submission-7".into(),
            source_version: "attempt-2".into(),
            content_digest: digest.clone(),
            disclosed_fields: vec![
                "content.result".into(),
                "signal".into(),
                "epistemic_descriptor.contract_version".into(),
                "epistemic_descriptor.origin_class".into(),
                "epistemic_descriptor.evidence_status".into(),
                "epistemic_descriptor.lifecycle_status".into(),
                "epistemic_descriptor.source_rows_truncated".into(),
                "epistemic_descriptor.observed_at_ms".into(),
                "epistemic_descriptor.source_refs".into(),
                "epistemic_descriptor.source_digests".into(),
                "epistemic_descriptor.source_row_count".into(),
            ],
            descriptor: Some(EpistemicDescriptor {
                contract_version: EPISTEMIC_DESCRIPTOR_VERSION.into(),
                origin_class: "asserted".into(),
                evidence_status: "unknown".into(),
                lifecycle_status: "current".into(),
                producer_confidence_bps: None,
                confidence_basis: String::new(),
                observed_at_ms: Some(100),
                derivation_ref: String::new(),
                source_refs: vec!["submission-7".into()],
                source_digests: vec![digest.clone()],
                source_row_count: Some(1),
                source_rows_truncated: false,
                supporting_evidence_count: None,
                contradicting_evidence_count: None,
            }),
            ..Default::default()
        }],
        memory_references: vec![MemoryContextReference {
            memory_id: "memory-7".into(),
            memory_version: 3,
            classification: "internal".into(),
            confidence_bps: 9_000,
            applicability: "verification".into(),
            evidence_operation_ids: vec!["operation-7".into()],
            content_digest: "b".repeat(64),
            descriptor: None,
        }],
        ..Default::default()
    };

    svc.record_planned_operation(&plan, "agent:test").unwrap();
    let receipt = svc
        .db
        .get_operation_receipt(&plan.plan_id)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.operation_class, "verification");
    let context_event = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::ContextGoverned)
        .expect("context receipt event");
    assert_eq!(
        context_event
            .attributes
            .get("epistemic_descriptor_version")
            .map(String::as_str),
        Some(EPISTEMIC_DESCRIPTOR_VERSION)
    );
    assert_eq!(
        context_event
            .attributes
            .get("epistemic_descriptor_count")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        context_event
            .attributes
            .get("epistemic_descriptor_source_rows")
            .map(String::as_str),
        Some("1")
    );
    let evidence = context_event
        .references
        .iter()
        .find(|reference| reference.kind == "external_evidence")
        .expect("pinned external evidence reference");
    assert_eq!(evidence.reference, "evidence:submission-7@attempt-2");
    assert_eq!(evidence.content_hash.as_deref(), Some(digest.as_str()));
    assert_eq!(
        evidence.disclosed_fields,
        vec![
            "content.result".to_string(),
            "signal".to_string(),
            "epistemic_descriptor.contract_version".to_string(),
            "epistemic_descriptor.origin_class".to_string(),
            "epistemic_descriptor.evidence_status".to_string(),
            "epistemic_descriptor.lifecycle_status".to_string(),
            "epistemic_descriptor.source_rows_truncated".to_string(),
            "epistemic_descriptor.observed_at_ms".to_string(),
            "epistemic_descriptor.source_refs".to_string(),
            "epistemic_descriptor.source_digests".to_string(),
            "epistemic_descriptor.source_row_count".to_string(),
        ]
    );
    let memory = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::ContextGoverned)
        .and_then(|event| {
            event
                .references
                .iter()
                .find(|reference| reference.kind == "kioku_memory")
        })
        .expect("pinned memory reference");
    assert_eq!(memory.reference, "memory:memory-7@3");
    assert_eq!(
        memory.content_hash.as_deref(),
        Some("b".repeat(64).as_str())
    );
    assert_eq!(memory.disclosed_fields, ["claim"]);
    assert!(
        svc.db
            .list_kioku_lifecycle_events("memory-7", 3)
            .unwrap()
            .is_empty(),
        "planning must not record a treatment assignment"
    );
}

#[test]
fn execution_memory_injection_revalidates_cached_versions() {
    let svc = memory_service();
    let error = svc
        .record_execution_memory_injections(
            "request-stale-memory",
            "agent:test",
            &[MemoryContextReference {
                memory_id: "purged-memory".into(),
                memory_version: 4,
                classification: "internal".into(),
                confidence_bps: 9_000,
                applicability: "verification".into(),
                evidence_operation_ids: vec![],
                content_digest: "c".repeat(64),
                descriptor: None,
            }],
        )
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(
        svc.db
            .list_kioku_lifecycle_events("purged-memory", 4)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn missing_execution_memory_holdout_does_not_block_execution() {
    let svc = memory_service();
    svc.invalidate_ineligible_execution_memory_holdouts(
        "operation-1",
        "agent:test",
        &[MemoryHoldoutReference {
            memory_id: "purged-memory".into(),
            memory_version: 4,
            classification: "internal".into(),
            content_digest: "c".repeat(64),
        }],
    )
    .unwrap();
}

#[test]
fn cached_memory_must_remain_active_unexpired_and_retained() {
    use crate::chisei::kioku::MemoryLifecycleState;

    assert!(memory_lifecycle_allows_execution(
        MemoryLifecycleState::Active,
        Some(201),
        Some(201),
        200,
    ));
    assert!(!memory_lifecycle_allows_execution(
        MemoryLifecycleState::Active,
        Some(200),
        Some(201),
        200,
    ));
    assert!(!memory_lifecycle_allows_execution(
        MemoryLifecycleState::Active,
        Some(201),
        Some(200),
        200,
    ));
    assert!(!memory_lifecycle_allows_execution(
        MemoryLifecycleState::Rejected,
        None,
        None,
        200,
    ));
}

#[tokio::test]
async fn execute_plan_rechecks_regression_gate() {
    let svc = memory_service();
    create_suite(&svc, "context-a");

    seed_eval_run(
        &svc,
        eval_run("run-1", "suite-1", 92, 100),
        "skills/context-a.md",
        "hash-a",
    );
    seed_eval_run(
        &svc,
        eval_run("run-2", "suite-1", 60, 200),
        "skills/context-a.md",
        "hash-b",
    );

    let mut plan = svc
        .plan_execution(Request::new(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "task-1".into(),
                namespace: "context-a".into(),
                spec: "ship context-a fix".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
                task_class: String::new(),
                ..Default::default()
            }),
            gunshi_allocation: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    assert!(plan.eval_regressed);
    assert!(!plan.executable);

    plan.executable = true;
    if let Some(input) = plan.input.as_mut() {
        input.namespace = "context-b".into();
    }
    let err = svc
        .execute_plan(Request::new(ExecutePlanRequest { plan: Some(plan) }))
        .await
        .expect_err("forged executable flag should be rejected");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("not executable"));
}

#[tokio::test]
async fn eval_regressed_context_is_force_sampled_and_audited() {
    let svc = memory_service();
    create_suite(&svc, "context-a");

    // Two runs whose drop trips the regression signal for context-a.
    seed_eval_run(
        &svc,
        eval_run("run-1", "suite-1", 92, 100),
        "skills/context-a.md",
        "hash-a",
    );
    seed_eval_run(
        &svc,
        eval_run("run-2", "suite-1", 60, 200),
        "skills/context-a.md",
        "hash-b",
    );

    let plan = svc
        .plan_execution(Request::new(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "task-sample".into(),
                namespace: "context-a".into(),
                spec: "ship context-a fix".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
                task_class: String::new(),
                ..Default::default()
            }),
            gunshi_allocation: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();

    // Base rate is 0.0 in the test config, so sampling here is purely the
    // eval-driven adaptive trigger.
    assert!(plan.sampled);
    assert_eq!(plan.sample_reason, "eval_regressed");
    assert_eq!(plan.sample_rate, 1.0);

    // A matching audit decision was recorded.
    let decisions = svc
        .db
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            action: Some("sample".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(
        decisions
            .iter()
            .any(|d| d.target_id == "task-sample" && d.reason == "eval_regressed"),
        "expected a sampling audit decision for task-sample"
    );
}

#[tokio::test]
async fn plan_execution_exposes_and_audits_egress_decisions() {
    let svc = memory_service();
    svc.db
        .create_object(&Object {
            id: "asset-secret".into(),
            kind: "asset".into(),
            name: "SecretCo".into(),
            namespace: "".into(),
            external_id: "asset:SECRET".into(),
            properties: std::collections::HashMap::from([
                ("verdict".into(), "approved".into()),
                ("score".into(), "99".into()),
                (
                    crate::chisei::egress::EXTERNAL_PROPERTIES_KEY.into(),
                    "verdict".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();

    let plan = svc
        .plan_execution(Request::new(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "task-egress".into(),
                namespace: "asset:SECRET".into(),
                spec: "analyze the referenced asset".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
                task_class: String::new(),
                ..Default::default()
            }),
            gunshi_allocation: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();

    assert!(plan.egress_decisions.iter().any(|decision| {
        decision.provider == "native"
            && decision.external
            && decision.included.contains(&"object#1.verdict".into())
            && decision.redacted.contains(&"object#1.score".into())
            && decision.redacted.contains(&"object#1.identity".into())
    }));
    assert!(plan.enriched_spec.contains("prior_verdict: approved"));
    assert!(!plan.enriched_spec.contains("score: 99"));
    assert!(!plan.enriched_spec.contains("SecretCo"));
    let egress_text = format!("{:?}", plan.egress_decisions);
    assert!(!egress_text.contains("asset:SECRET"));

    let decisions = svc
        .db
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            actor: Some("chisei.egress".into()),
            action: Some("prepare_context".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(decisions.iter().any(|d| {
        d.target_id == "task-egress"
            && d.evidence.get("provider") == Some(&"native".to_string())
            && d.evidence.get("redacted_count") == Some(&"2".to_string())
    }));
}

#[test]
fn egress_audit_serializes_epistemic_descriptor_fields() {
    let svc = memory_service();
    svc.record_egress_audit(
        "prepare_context",
        "task-descriptor-egress",
        "native",
        "native-default",
        &[EgressDecision {
            provider: "native".into(),
            external: false,
            included: vec![
                "object#1.epistemic_descriptor.contract_version".into(),
                "object#1.epistemic_descriptor.source_digests".into(),
            ],
            redacted: vec![],
            reasons: vec![],
        }],
    );

    let decision = svc
        .db
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            actor: Some("chisei.egress".into()),
            action: Some("prepare_context".into()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|decision| decision.target_id == "task-descriptor-egress")
        .expect("descriptor egress audit should be recorded");
    let included: Vec<String> = serde_json::from_str(
        decision
            .evidence
            .get("included_fields")
            .expect("included fields evidence"),
    )
    .expect("included fields should remain JSON-serializable");
    assert_eq!(
        included,
        vec![
            "object#1.epistemic_descriptor.contract_version",
            "object#1.epistemic_descriptor.source_digests",
        ]
    );
}

#[test]
fn namespace_policy_reloads_data_class_from_sekai_object_store() {
    let path = format!(
        "{}/sekai-chisei-policy-{}.db",
        std::env::temp_dir().display(),
        uuid::Uuid::new_v4()
    );
    {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(&path).unwrap()));
        db.create_object(&Object {
            id: "policy-alpha".into(),
            kind: "policy".into(),
            name: "alpha".into(),
            namespace: String::new(),
            external_id: "policy:alpha".into(),
            properties: std::collections::HashMap::from([
                (
                    "allowed_models".into(),
                    "native-default,ollama/capable".into(),
                ),
                ("default_runtime".into(), "kiro".into()),
                ("default_model".into(), "native-default".into()),
                ("data_class".into(), "sensitive".into()),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    }

    let svc = file_service(&path);
    let policy = svc
        .policy
        .effective_policy("alpha")
        .expect("policy should load from object store");
    assert_eq!(policy.data_class, "sensitive");
    assert_eq!(
        policy.allowed_models,
        vec!["native-default", "ollama/capable"]
    );

    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn set_namespace_policy_persists_data_class() {
    let path = format!(
        "{}/sekai-chisei-policy-rpc-{}.db",
        std::env::temp_dir().display(),
        uuid::Uuid::new_v4()
    );
    let svc = file_service(&path);
    let response = svc
        .set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "alpha".into(),
            allowed_runtimes: vec!["native".into()],
            allowed_models: vec!["native-default".into()],
            default_runtime: "native".into(),
            default_model: "native-default".into(),
            data_class: "sensitive".into(),
            context_admission_policy_json: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.resolution.unwrap().data_class, "sensitive");
    drop(svc);

    let reloaded = file_service(&path);
    let policy = reloaded
        .policy
        .effective_policy("alpha")
        .expect("policy should reload");
    assert_eq!(policy.data_class, "sensitive");
    assert_eq!(policy.default_model, "native-default");

    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn sensitive_private_rejects_unsafe_provider() {
    let svc = memory_service();
    svc.policy.set_namespace_policy(
        "alpha",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec![],
            allowed_models: vec![],
            default_runtime: "anthropic".into(),
            default_model: "anthropic/claude-sonnet-4".into(),
            data_class: "sensitive".into(),
        },
    );

    let err = svc
        .plan_execution(Request::new(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "task-sensitive-private".into(),
                namespace: "alpha".into(),
                spec: "analyze private holdings".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
                task_class: String::new(),
                ..Default::default()
            }),
            gunshi_allocation: None,
        }))
        .await
        .expect_err("unsafe provider should be rejected for sensitive private work");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("not safe"));
}

#[tokio::test]
async fn resolve_policy_denies_sensitive_private_unsafe_provider() {
    let svc = memory_service();
    svc.policy.set_namespace_policy(
        "alpha",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec![],
            allowed_models: vec![],
            default_runtime: "kiro".into(),
            default_model: "native-default".into(),
            data_class: "sensitive".into(),
        },
    );

    let err = svc
        .resolve_policy(Request::new(ResolvePolicyRequest {
            namespace: "alpha".into(),
            preferred_runtime: "anthropic".into(),
            preferred_model: "anthropic/claude-sonnet-4".into(),
            subject: String::new(),
            project: String::new(),
            agent: String::new(),
            key_id: String::new(),
            task_class: String::new(),
            user_id: String::new(),
            expected_calls: 1,
            budget_route_bias: String::new(),
            route_override: String::new(),
            capability_requirements_json: Vec::new(),
        }))
        .await
        .expect_err("sensitive private preflight should deny unsafe provider");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn sensitive_template_only_skips_context_enrichment() {
    let svc = memory_service();
    svc.policy.set_namespace_policy(
        "alpha",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec![],
            allowed_models: vec![],
            default_runtime: "kiro".into(),
            default_model: "native-default".into(),
            data_class: "sensitive".into(),
        },
    );
    svc.db
        .create_object(&Object {
            id: "asset-secret".into(),
            kind: "asset".into(),
            name: "SecretCo".into(),
            namespace: "alpha".into(),
            external_id: "asset:SECRET".into(),
            properties: std::collections::HashMap::from([("verdict".into(), "approved".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();

    let plan = svc
        .plan_execution(Request::new(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "task-template".into(),
                namespace: "alpha".into(),
                spec: "write a generic evaluation rubric".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
                task_class: "template_only".into(),
                ..Default::default()
            }),
            gunshi_allocation: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();

    assert_eq!(plan.task_class, "template_only");
    assert!(plan.executable);
    assert!(
        plan.steps
            .iter()
            .any(|step| { step.step == "object_context_enrich" && step.action == "skipped" })
    );
    assert!(!plan.enriched_spec.contains("SecretCo"));
    assert!(!plan.enriched_spec.contains("approved"));
}

#[tokio::test]
async fn template_only_plan_blocks_known_entity_leak() {
    let svc = memory_service();
    svc.policy.set_namespace_policy(
        "alpha",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec![],
            allowed_models: vec![],
            default_runtime: "kiro".into(),
            default_model: "native-default".into(),
            data_class: "sensitive".into(),
        },
    );
    svc.db
        .create_object(&Object {
            id: "asset-secret".into(),
            kind: "asset".into(),
            name: "SecretCo".into(),
            namespace: "alpha".into(),
            external_id: "asset:SECRET".into(),
            properties: std::collections::HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
    svc.db
        .create_object(&Object {
            id: "leak-rule-secretco".into(),
            kind: "leak_rule".into(),
            name: "company-name".into(),
            namespace: "alpha".into(),
            external_id: "leak_rule:secretco".into(),
            properties: std::collections::HashMap::from([
                ("pattern".into(), "SecretCo".into()),
                ("label".into(), "company_name".into()),
                ("action".into(), "block".into()),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();

    let plan = svc
        .plan_execution(Request::new(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "task-leak".into(),
                namespace: "alpha".into(),
                spec: "write a generic rubric for SecretCo".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
                task_class: "template_only".into(),
                ..Default::default()
            }),
            gunshi_allocation: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();

    assert!(!plan.executable);
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("leak checker blocked"))
    );
    assert!(plan.egress_decisions.iter().any(|decision| {
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("known_entity:SecretCo"))
    }));
    assert!(plan.egress_decisions.iter().any(|decision| {
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("company_name"))
    }));
    let decisions = svc
        .db
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            actor: Some("chisei.privacy".into()),
            action: Some("leak_check".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(decisions.iter().any(|decision| {
        decision.target_id == "task-leak"
            && decision.outcome == "leak_blocked"
            && decision
                .evidence
                .get("labels")
                .is_some_and(|labels| labels.contains("company_name"))
    }));
}

#[tokio::test]
async fn execute_plan_rejects_after_policy_flips_sensitive() {
    let svc = memory_service();
    let plan = svc
        .plan_execution(Request::new(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "task-stale-policy".into(),
                namespace: "alpha".into(),
                spec: "do ordinary work".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
                task_class: String::new(),
                ..Default::default()
            }),
            gunshi_allocation: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    assert!(plan.executable);

    svc.policy.set_namespace_policy(
        "alpha",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec![],
            allowed_models: vec![],
            default_runtime: "kiro".into(),
            default_model: "native-default".into(),
            data_class: "sensitive".into(),
        },
    );

    let err = svc
        .execute_plan(Request::new(ExecutePlanRequest {
            plan: Some(plan.clone()),
        }))
        .await
        .expect_err("stale external plan should be blocked after policy flip");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("privacy gate"));

    let receipt = svc
        .db
        .get_operation_receipt(&plan.plan_id)
        .unwrap()
        .expect("rejected execution receipt");
    assert!(receipt.completeness().complete);
    assert!(receipt.events.iter().any(|event| {
        event.kind == ReceiptEventKind::OutcomeRecorded
            && event.attributes.get("status").map(String::as_str) == Some("denied")
            && event
                .attributes
                .get("completion_reason")
                .map(String::as_str)
                == Some("provider_became_unsafe")
    }));
}

#[tokio::test]
async fn execute_plan_stream_rejects_after_policy_flips_sensitive() {
    let svc = memory_service();
    let plan = svc
        .plan_execution(Request::new(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "task-stale-stream-policy".into(),
                namespace: "alpha".into(),
                spec: "do ordinary streamed work".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                user_id: "user-1".into(),
                max_tokens: 512,
                ..Default::default()
            }),
            gunshi_allocation: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    assert!(plan.executable);

    svc.policy.set_namespace_policy(
        "alpha",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec![],
            allowed_models: vec![],
            default_runtime: "kiro".into(),
            default_model: "native-default".into(),
            data_class: "sensitive".into(),
        },
    );

    let error = match svc
        .execute_plan_stream(Request::new(ExecutePlanRequest {
            plan: Some(plan.clone()),
        }))
        .await
    {
        Ok(_) => panic!("stale streamed external plan bypassed the privacy gate"),
        Err(error) => error,
    };
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("privacy gate"));

    let receipt = svc
        .db
        .get_operation_receipt(&plan.plan_id)
        .unwrap()
        .expect("rejected streamed execution receipt");
    assert!(receipt.completeness().complete);
    assert!(receipt.events.iter().any(|event| {
        event.kind == ReceiptEventKind::OutcomeRecorded
            && event.attributes.get("status").map(String::as_str) == Some("denied")
            && event
                .attributes
                .get("completion_reason")
                .map(String::as_str)
                == Some("provider_became_unsafe")
    }));
}

#[tokio::test]
async fn execute_plan_rejects_external_plan_without_egress_decisions() {
    let svc = memory_service();
    let plan = ExecutionPlan {
        plan_id: "plan-forged-egress".into(),
        input: Some(ExecutionInput {
            request_id: "task-forged-egress".into(),
            namespace: "ns".into(),
            spec: "do work".into(),
            preferred_model: "native-default".into(),
            preferred_runtime: "kiro".into(),
            task_type: String::new(),
            priority: 0,
            user_id: "user-1".into(),
            estimated_tokens: 0,
            messages: vec![],
            tools: vec![],
            system: String::new(),
            max_tokens: 512,
            task_class: String::new(),
            ..Default::default()
        }),
        resolved_runtime: "kiro".into(),
        resolved_model: "native-default".into(),
        enriched_spec: "do work".into(),
        prepared_system: String::new(),
        prepared_messages: vec![ChatMessage {
            role: "user".into(),
            content: "do work".into(),
            tool_call_id: String::new(),
            tool_calls: vec![],
        }],
        tools: vec![],
        budget: Some(BudgetVerdict {
            allowed: true,
            usage: None,
            reason: String::new(),
        }),
        steps: vec![],
        review_policy: None,
        risk_score: 0.0,
        low_success_namespace: false,
        executable: true,
        warnings: vec![],
        max_tokens: 512,
        created_at: chrono::Utc::now().timestamp_millis(),
        affinity_namespaces: vec![],
        eval_regressed: false,
        eval_regression_reason: String::new(),
        sampled: false,
        sample_rate: 0.0,
        sample_reason: String::new(),
        egress_decisions: vec![],
        task_class: String::new(),
        evidence_references: vec![],
        memory_references: vec![],
        planning_actor: "local".into(),
        context_admission_policy_version: String::new(),
        context_admission_descriptor_version: String::new(),
        context_admission_decision: String::new(),
        context_admission_reasons: Vec::new(),
        context_admission_source_digests: Vec::new(),
        context_admission_requires_review: false,
        context_admission_requires_verification: false,
        memory_holdouts: vec![],
        context_bytes: 0,
        context_tokens: 0,
        context_projection_latency_ms: 0,
        context_truncated: false,
        ..Default::default()
    };
    svc.cache_plan(plan.clone());

    let err = svc
        .execute_plan(Request::new(ExecutePlanRequest { plan: Some(plan) }))
        .await
        .expect_err("external plan without egress decisions should be rejected");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("missing egress decisions"));
}

#[tokio::test]
async fn cached_plans_remain_bound_to_the_planning_principal() {
    let svc = memory_service();
    let plan = ExecutionPlan {
        plan_id: "actor-bound-plan".into(),
        planning_actor: "agent:planner".into(),
        context_admission_policy_version: String::new(),
        context_admission_descriptor_version: String::new(),
        context_admission_decision: String::new(),
        context_admission_reasons: Vec::new(),
        context_admission_source_digests: Vec::new(),
        context_admission_requires_review: false,
        context_admission_requires_verification: false,
        memory_holdouts: vec![],
        context_bytes: 0,
        context_tokens: 0,
        context_projection_latency_ms: 0,
        context_truncated: false,
        executable: true,
        created_at: chrono::Utc::now().timestamp_millis(),
        ..Default::default()
    };
    svc.cache_plan(plan.clone());
    let mut request = Request::new(ExecutePlanRequest { plan: Some(plan) });
    request
        .metadata_mut()
        .insert("x-principal", "agent:intruder".parse().unwrap());

    let error = svc.execute_plan(request).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert!(
        svc.planned_executions
            .lock()
            .unwrap()
            .contains_key("actor-bound-plan")
    );
}

#[tokio::test]
async fn execute_plan_stream_rejects_external_plan_without_egress_decisions() {
    let svc = memory_service();
    let plan = ExecutionPlan {
        plan_id: "stream-external-plan".into(),
        input: Some(ExecutionInput {
            request_id: "stream-external-plan".into(),
            namespace: "sekai-chisei".into(),
            spec: "do work".into(),
            preferred_model: "gpt-5.5".into(),
            preferred_runtime: "openai".into(),
            task_type: String::new(),
            priority: 0,
            user_id: "user-1".into(),
            task_class: String::new(),
            estimated_tokens: 0,
            messages: vec![],
            tools: vec![],
            system: String::new(),
            max_tokens: 512,
            ..Default::default()
        }),
        resolved_runtime: "openai".into(),
        resolved_model: "gpt-5.5".into(),
        enriched_spec: "do work".into(),
        prepared_system: String::new(),
        prepared_messages: vec![ChatMessage {
            role: "user".into(),
            content: "do work".into(),
            tool_call_id: String::new(),
            tool_calls: vec![],
        }],
        tools: vec![],
        budget: Some(BudgetVerdict {
            allowed: true,
            usage: None,
            reason: String::new(),
        }),
        steps: vec![],
        review_policy: None,
        risk_score: 0.0,
        low_success_namespace: false,
        executable: true,
        warnings: vec![],
        max_tokens: 512,
        created_at: chrono::Utc::now().timestamp_millis(),
        affinity_namespaces: vec![],
        eval_regressed: false,
        eval_regression_reason: String::new(),
        sampled: false,
        sample_rate: 0.0,
        sample_reason: String::new(),
        egress_decisions: vec![],
        task_class: String::new(),
        evidence_references: vec![],
        memory_references: vec![],
        planning_actor: "local".into(),
        context_admission_policy_version: String::new(),
        context_admission_descriptor_version: String::new(),
        context_admission_decision: String::new(),
        context_admission_reasons: Vec::new(),
        context_admission_source_digests: Vec::new(),
        context_admission_requires_review: false,
        context_admission_requires_verification: false,
        memory_holdouts: vec![],
        context_bytes: 0,
        context_tokens: 0,
        context_projection_latency_ms: 0,
        context_truncated: false,
        ..Default::default()
    };
    svc.cache_plan(plan.clone());

    let result = svc
        .execute_plan_stream(Request::new(ExecutePlanRequest { plan: Some(plan) }))
        .await;
    let err = result
        .err()
        .expect("external stream plan without egress decisions should be rejected");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("missing egress decisions"));
}

#[tokio::test]
async fn sqlite_reload_backfills_legacy_iteration_context_gates() {
    let path = format!(
        "{}/sekai-chisei-legacy-{}.db",
        std::env::temp_dir().display(),
        uuid::Uuid::new_v4()
    );
    let svc = file_service(&path);
    create_suite(&svc, "context-a");

    seed_eval_run(
        &svc,
        eval_run("run-1", "suite-1", 92, 100),
        "skills/context-a.md",
        "hash-a",
    );
    seed_eval_run(
        &svc,
        eval_run("run-2", "suite-1", 60, 200),
        "skills/context-a.md",
        "hash-b",
    );

    svc.db
        .conn()
        .execute("UPDATE chisei_eval_iterations SET namespace = ''", [])
        .unwrap();
    drop(svc);

    let svc = file_service(&path);
    let plan = svc
        .plan_execution(Request::new(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "task-1".into(),
                namespace: "context-a".into(),
                spec: "ship context-a fix".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
                task_class: String::new(),
                ..Default::default()
            }),
            gunshi_allocation: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .plan
        .unwrap();
    assert!(plan.eval_regressed);
    assert!(plan.eval_regression_reason.contains("context-a"));

    let _ = fs::remove_file(&path);
}

#[test]
fn cache_plan_keeps_newest_inserted_plan() {
    let svc = memory_service();
    let now = chrono::Utc::now().timestamp_millis();
    for i in 0..MAX_CACHED_EXECUTION_PLANS {
        svc.cache_plan(ExecutionPlan {
            plan_id: format!("plan-{i:03}"),
            input: None,
            resolved_runtime: String::new(),
            resolved_model: String::new(),
            enriched_spec: String::new(),
            prepared_system: String::new(),
            prepared_messages: vec![],
            tools: vec![],
            budget: None,
            steps: vec![],
            review_policy: None,
            risk_score: 0.0,
            low_success_namespace: false,
            executable: true,
            warnings: vec![],
            max_tokens: 0,
            created_at: now,
            affinity_namespaces: vec![],
            eval_regressed: false,
            eval_regression_reason: String::new(),
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            egress_decisions: vec![],
            task_class: String::new(),
            evidence_references: vec![],
            memory_references: vec![],
            planning_actor: String::new(),
            context_admission_policy_version: String::new(),
            context_admission_descriptor_version: String::new(),
            context_admission_decision: String::new(),
            context_admission_reasons: Vec::new(),
            context_admission_source_digests: Vec::new(),
            context_admission_requires_review: false,
            context_admission_requires_verification: false,
            memory_holdouts: vec![],
            context_bytes: 0,
            context_tokens: 0,
            context_projection_latency_ms: 0,
            context_truncated: false,
            ..Default::default()
        });
    }
    let newest = ExecutionPlan {
        plan_id: "plan-new".into(),
        input: None,
        resolved_runtime: String::new(),
        resolved_model: String::new(),
        enriched_spec: String::new(),
        prepared_system: String::new(),
        prepared_messages: vec![],
        tools: vec![],
        budget: None,
        steps: vec![],
        review_policy: None,
        risk_score: 0.0,
        low_success_namespace: false,
        executable: true,
        warnings: vec![],
        max_tokens: 0,
        created_at: now,
        affinity_namespaces: vec![],
        eval_regressed: false,
        eval_regression_reason: String::new(),
        sampled: false,
        sample_rate: 0.0,
        sample_reason: String::new(),
        egress_decisions: vec![],
        task_class: String::new(),
        evidence_references: vec![],
        memory_references: vec![],
        planning_actor: String::new(),
        context_admission_policy_version: String::new(),
        context_admission_descriptor_version: String::new(),
        context_admission_decision: String::new(),
        context_admission_reasons: Vec::new(),
        context_admission_source_digests: Vec::new(),
        context_admission_requires_review: false,
        context_admission_requires_verification: false,
        memory_holdouts: vec![],
        context_bytes: 0,
        context_tokens: 0,
        context_projection_latency_ms: 0,
        context_truncated: false,
        ..Default::default()
    };
    svc.cache_plan(newest.clone());

    let plans = svc
        .planned_executions
        .lock()
        .expect("planned executions poisoned");
    assert_eq!(plans.len(), MAX_CACHED_EXECUTION_PLANS);
    assert!(plans.contains_key(&newest.plan_id));
}

#[test]
fn cache_plan_prunes_expired_entries() {
    let svc = memory_service();
    let expired = ExecutionPlan {
        plan_id: "plan-old".into(),
        input: None,
        resolved_runtime: String::new(),
        resolved_model: String::new(),
        enriched_spec: String::new(),
        prepared_system: String::new(),
        prepared_messages: vec![],
        tools: vec![],
        budget: None,
        steps: vec![],
        review_policy: None,
        risk_score: 0.0,
        low_success_namespace: false,
        executable: true,
        warnings: vec![],
        max_tokens: 0,
        created_at: chrono::Utc::now().timestamp_millis() - MAX_CACHED_EXECUTION_PLAN_AGE_MS - 1,
        affinity_namespaces: vec![],
        eval_regressed: false,
        eval_regression_reason: String::new(),
        sampled: false,
        sample_rate: 0.0,
        sample_reason: String::new(),
        egress_decisions: vec![],
        task_class: String::new(),
        evidence_references: vec![],
        memory_references: vec![],
        planning_actor: String::new(),
        context_admission_policy_version: String::new(),
        context_admission_descriptor_version: String::new(),
        context_admission_decision: String::new(),
        context_admission_reasons: Vec::new(),
        context_admission_source_digests: Vec::new(),
        context_admission_requires_review: false,
        context_admission_requires_verification: false,
        memory_holdouts: vec![],
        context_bytes: 0,
        context_tokens: 0,
        context_projection_latency_ms: 0,
        context_truncated: false,
        ..Default::default()
    };
    let fresh = ExecutionPlan {
        plan_id: "plan-fresh".into(),
        created_at: chrono::Utc::now().timestamp_millis(),
        ..expired.clone()
    };
    svc.cache_plan(expired);
    svc.cache_plan(fresh.clone());

    let plans = svc
        .planned_executions
        .lock()
        .expect("planned executions poisoned");
    assert!(!plans.contains_key("plan-old"));
    assert!(plans.contains_key(&fresh.plan_id));
}

#[test]
fn cache_plan_keeps_inserted_plan_when_timestamps_tie() {
    let svc = memory_service();
    let now = chrono::Utc::now().timestamp_millis();
    for i in 0..MAX_CACHED_EXECUTION_PLANS {
        svc.cache_plan(ExecutionPlan {
            plan_id: format!("plan-z{i:03}"),
            input: None,
            resolved_runtime: String::new(),
            resolved_model: String::new(),
            enriched_spec: String::new(),
            prepared_system: String::new(),
            prepared_messages: vec![],
            tools: vec![],
            budget: None,
            steps: vec![],
            review_policy: None,
            risk_score: 0.0,
            low_success_namespace: false,
            executable: true,
            warnings: vec![],
            max_tokens: 0,
            created_at: now,
            affinity_namespaces: vec![],
            eval_regressed: false,
            eval_regression_reason: String::new(),
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            egress_decisions: vec![],
            task_class: String::new(),
            evidence_references: vec![],
            memory_references: vec![],
            planning_actor: String::new(),
            context_admission_policy_version: String::new(),
            context_admission_descriptor_version: String::new(),
            context_admission_decision: String::new(),
            context_admission_reasons: Vec::new(),
            context_admission_source_digests: Vec::new(),
            context_admission_requires_review: false,
            context_admission_requires_verification: false,
            memory_holdouts: vec![],
            context_bytes: 0,
            context_tokens: 0,
            context_projection_latency_ms: 0,
            context_truncated: false,
            ..Default::default()
        });
    }
    let inserted = ExecutionPlan {
        plan_id: "plan-a".into(),
        input: None,
        resolved_runtime: String::new(),
        resolved_model: String::new(),
        enriched_spec: String::new(),
        prepared_system: String::new(),
        prepared_messages: vec![],
        tools: vec![],
        budget: None,
        steps: vec![],
        review_policy: None,
        risk_score: 0.0,
        low_success_namespace: false,
        executable: true,
        warnings: vec![],
        max_tokens: 0,
        created_at: now,
        affinity_namespaces: vec![],
        eval_regressed: false,
        eval_regression_reason: String::new(),
        sampled: false,
        sample_rate: 0.0,
        sample_reason: String::new(),
        egress_decisions: vec![],
        task_class: String::new(),
        evidence_references: vec![],
        memory_references: vec![],
        planning_actor: String::new(),
        context_admission_policy_version: String::new(),
        context_admission_descriptor_version: String::new(),
        context_admission_decision: String::new(),
        context_admission_reasons: Vec::new(),
        context_admission_source_digests: Vec::new(),
        context_admission_requires_review: false,
        context_admission_requires_verification: false,
        memory_holdouts: vec![],
        context_bytes: 0,
        context_tokens: 0,
        context_projection_latency_ms: 0,
        context_truncated: false,
        ..Default::default()
    };
    svc.cache_plan(inserted.clone());

    let plans = svc
        .planned_executions
        .lock()
        .expect("planned executions poisoned");
    assert_eq!(plans.len(), MAX_CACHED_EXECUTION_PLANS);
    assert!(plans.contains_key(&inserted.plan_id));
}

#[tokio::test]
async fn decide_gateway_execution_admits_and_denies_closed() {
    use crate::chisei::gateway_decide::GATEWAY_DECIDE_CONTRACT_VERSION;

    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let mut cfg = config(":memory:");
    cfg.gateway_provided_providers = vec!["openai".into()];
    let svc = ChiseiServiceImpl::new(db, cfg);
    svc.policy.set_namespace_policy(
        "team-a",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into(), "gpt-5.5-mini".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: "internal".into(),
        },
    );
    svc.policy
        .set_context_admission_policy(
            "team-a",
            crate::chisei::policy::ContextAdmissionPolicy::allow_by_default(),
        )
        .unwrap();

    let mut admit = Request::new(DecideGatewayExecutionRequest {
        contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
        namespace: "team-a".into(),
        requested_model: "gpt-5.5".into(),
        operation_class: "chat".into(),
        estimated_cost_usd_micros: 0,
        correlation_operation_id: "op-decide-1".into(),
        correlation_attempt: 1,
        estimated_tokens: 10,
        task_class: "interactive".into(),
        preferred_runtime: "openai".into(),
        project: "team-a".into(),
        agent: "local".into(),
        key_id: String::new(),
        work_unit: String::new(),
        local_free_available: false,
        user_id: "local".into(),
        route_override: String::new(),
        capability_requirements_json: Vec::new(),
        expected_calls: 1,
        pipeline_spec: "summarize team-a".into(),
    });
    admit
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let admitted = svc
        .decide_gateway_execution(admit)
        .await
        .unwrap()
        .into_inner();
    assert!(admitted.admitted, "{admitted:?}");
    assert_eq!(admitted.resolved_model, "gpt-5.5");
    assert_eq!(admitted.resolved_runtime, "openai");
    assert_eq!(admitted.policy_scope, "team-a");
    assert_eq!(admitted.data_class, "unclassified");
    assert_eq!(
        admitted.fallback_models,
        vec!["openai/gpt-5.5", "openai/gpt-5.5-mini"]
    );
    assert!(!admitted.eval_regressed);
    assert!(admitted.deny_reason.is_empty());
    assert!(!admitted.budget_grant_id.is_empty());
    assert!(admitted.sampling_evaluated);
    assert!(!admitted.prepared_spec.is_empty());
    assert_eq!(admitted.context_admission_decision, "include");

    svc.policy
        .set_context_admission_policy(
            "team-a",
            crate::chisei::policy::ContextAdmissionPolicy {
                contract_version: crate::chisei::policy::CONTEXT_ADMISSION_POLICY_VERSION.into(),
                default_action: ContextAdmissionAction::Include,
                unknown_action: ContextAdmissionAction::HoldOut,
                rules: vec![crate::chisei::policy::ContextAdmissionRule {
                    action: ContextAdmissionAction::RequireReview,
                    origin_classes: vec![],
                    evidence_statuses: vec![],
                    lifecycle_statuses: vec![],
                    applicability: None,
                    confidence_basis: None,
                    min_confidence_bps: None,
                    max_confidence_bps: None,
                    operation_risk: Some(crate::chisei::policy::OperationRisk::High),
                }],
            },
        )
        .unwrap();
    let mut context_denied = Request::new(DecideGatewayExecutionRequest {
        contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
        namespace: "team-a".into(),
        requested_model: "gpt-5.5".into(),
        operation_class: "write".into(),
        estimated_cost_usd_micros: 0,
        correlation_operation_id: "op-decide-context-review".into(),
        correlation_attempt: 1,
        estimated_tokens: 10,
        task_class: "interactive".into(),
        preferred_runtime: "openai".into(),
        project: "team-a".into(),
        agent: "local".into(),
        key_id: String::new(),
        work_unit: String::new(),
        local_free_available: false,
        user_id: "local".into(),
        route_override: String::new(),
        capability_requirements_json: Vec::new(),
        expected_calls: 1,
        pipeline_spec: String::new(),
    });
    context_denied
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let context_denied = svc
        .decide_gateway_execution(context_denied)
        .await
        .unwrap()
        .into_inner();
    assert!(!context_denied.admitted);
    assert_eq!(context_denied.context_admission_decision, "require_review");
    assert_eq!(
        context_denied.context_admission_reasons,
        vec!["context_admission:require_review"]
    );
    assert_eq!(
        context_denied.deny_message,
        "context admission policy requires review or verification"
    );
    svc.policy
        .set_context_admission_policy(
            "team-a",
            crate::chisei::policy::ContextAdmissionPolicy::allow_by_default(),
        )
        .unwrap();

    svc.budget
        .set_limit_with_metric(
            "project:team-a",
            crate::db::chisei_budget::METRIC_REQUESTS,
            1,
            crate::chisei::budget::PeriodType::Daily,
        )
        .unwrap();
    let mut request_budget_denied = Request::new(DecideGatewayExecutionRequest {
        contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
        namespace: "team-a".into(),
        requested_model: "gpt-5.5".into(),
        operation_class: "chat".into(),
        estimated_cost_usd_micros: 0,
        correlation_operation_id: "op-decide-request-budget".into(),
        correlation_attempt: 1,
        estimated_tokens: 10,
        task_class: "interactive".into(),
        preferred_runtime: "openai".into(),
        project: "team-a".into(),
        agent: "local".into(),
        key_id: String::new(),
        work_unit: String::new(),
        local_free_available: true,
        user_id: "local".into(),
        route_override: String::new(),
        capability_requirements_json: Vec::new(),
        expected_calls: 2,
        pipeline_spec: String::new(),
    });
    request_budget_denied
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let request_budget_denied = svc
        .decide_gateway_execution(request_budget_denied)
        .await
        .unwrap()
        .into_inner();
    assert!(!request_budget_denied.admitted);
    assert_eq!(request_budget_denied.deny_reason, "budget_denied");
    assert_eq!(request_budget_denied.budget_scope, "project:team-a");

    // Non-bootstrap principal without a grant fails closed (unauthorized).
    let mut denied = Request::new(DecideGatewayExecutionRequest {
        contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
        namespace: "team-a".into(),
        requested_model: "gpt-5.5".into(),
        operation_class: "chat".into(),
        estimated_cost_usd_micros: 0,
        correlation_operation_id: "op-decide-2".into(),
        correlation_attempt: 1,
        estimated_tokens: 10,
        task_class: "interactive".into(),
        preferred_runtime: "openai".into(),
        project: "team-a".into(),
        agent: "mallory".into(),
        key_id: String::new(),
        work_unit: String::new(),
        local_free_available: false,
        user_id: "mallory".into(),
        route_override: String::new(),
        capability_requirements_json: Vec::new(),
        expected_calls: 1,
        pipeline_spec: String::new(),
    });
    denied
        .metadata_mut()
        .insert("x-principal", "mallory".parse().unwrap());
    let denied = svc
        .decide_gateway_execution(denied)
        .await
        .unwrap()
        .into_inner();
    assert!(!denied.admitted, "{denied:?}");
    assert_eq!(denied.deny_reason, "unauthorized");
}

fn openai_team_a_service() -> ChiseiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let mut cfg = config(":memory:");
    cfg.gateway_provided_providers = vec!["openai".into()];
    let svc = ChiseiServiceImpl::new(db, cfg);
    svc.policy.set_namespace_policy(
        "team-a",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: "internal".into(),
        },
    );
    svc
}

fn decide_request(
    correlation: &str,
    pipeline_spec: &str,
) -> Request<DecideGatewayExecutionRequest> {
    use crate::chisei::gateway_decide::GATEWAY_DECIDE_CONTRACT_VERSION;
    let mut request = Request::new(DecideGatewayExecutionRequest {
        contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
        namespace: "team-a".into(),
        requested_model: "gpt-5.5".into(),
        operation_class: "chat".into(),
        estimated_cost_usd_micros: 0,
        correlation_operation_id: correlation.into(),
        correlation_attempt: 1,
        estimated_tokens: 10,
        task_class: "interactive".into(),
        preferred_runtime: "openai".into(),
        project: "team-a".into(),
        agent: "local".into(),
        key_id: String::new(),
        work_unit: String::new(),
        local_free_available: false,
        user_id: "local".into(),
        route_override: String::new(),
        capability_requirements_json: Vec::new(),
        expected_calls: 1,
        pipeline_spec: pipeline_spec.into(),
    });
    request
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    request
}

#[tokio::test]
async fn decide_gateway_execution_denies_missing_context_admission_policy() {
    let svc = openai_team_a_service();
    let denied = svc
        .decide_gateway_execution(decide_request("op-missing-context-policy", ""))
        .await
        .unwrap()
        .into_inner();
    assert!(!denied.admitted, "{denied:?}");
    assert_eq!(denied.deny_reason, "policy_denied");
    assert_eq!(denied.deny_message, "context admission policy is required");
    assert_ne!(denied.context_admission_decision, "include");
    assert_eq!(
        denied.context_admission_reasons,
        vec!["context_admission:missing"]
    );
}

#[tokio::test]
async fn decide_gateway_execution_denies_corrupt_context_admission_policy() {
    let svc = openai_team_a_service();
    svc.policy
        .set_context_admission_error("team-a", "corrupt context admission policy");
    let denied = svc
        .decide_gateway_execution(decide_request("op-corrupt-context-policy", ""))
        .await
        .unwrap()
        .into_inner();
    assert!(!denied.admitted, "{denied:?}");
    assert_eq!(denied.deny_reason, "policy_denied");
    assert_eq!(denied.deny_message, "context admission policy unavailable");
    assert_ne!(denied.context_admission_decision, "include");
    assert_eq!(
        denied.context_admission_reasons,
        vec!["context_admission:unavailable"]
    );
}

#[tokio::test]
async fn decide_gateway_execution_denies_when_fallback_action_blocks_provider() {
    let svc = openai_team_a_service();
    svc.policy
        .set_context_admission_policy(
            "team-a",
            crate::chisei::policy::ContextAdmissionPolicy {
                contract_version: crate::chisei::policy::CONTEXT_ADMISSION_POLICY_VERSION.into(),
                default_action: ContextAdmissionAction::RequireReview,
                unknown_action: ContextAdmissionAction::HoldOut,
                rules: vec![],
            },
        )
        .unwrap();
    let denied = svc
        .decide_gateway_execution(decide_request("op-fallback-blocks", ""))
        .await
        .unwrap()
        .into_inner();
    assert!(!denied.admitted, "{denied:?}");
    assert_eq!(denied.deny_reason, "policy_denied");
    assert_eq!(denied.context_admission_decision, "require_review");
    assert_eq!(
        denied.context_admission_reasons,
        vec!["context_admission:require_review"]
    );
}

#[tokio::test]
async fn decide_gateway_execution_denies_pipeline_error_after_admit() {
    let mut svc = openai_team_a_service();
    svc.policy
        .set_context_admission_policy(
            "team-a",
            crate::chisei::policy::ContextAdmissionPolicy::allow_by_default(),
        )
        .unwrap();
    svc.pipeline = pipe::Pipeline::new(vec![]);
    let denied = svc
        .decide_gateway_execution(decide_request("op-pipeline-error", "summarize team-a"))
        .await
        .unwrap()
        .into_inner();
    assert!(!denied.admitted, "{denied:?}");
    assert_eq!(denied.deny_reason, "policy_denied");
    assert!(
        denied
            .deny_message
            .contains("gateway pipeline decision unavailable"),
        "{denied:?}"
    );
    assert!(!denied.sampling_evaluated);
    assert!(denied.prepared_spec.is_empty());
    assert!(denied.resolved_model.is_empty());
}

#[tokio::test]
async fn decide_rejects_mixed_capability_catalogs_as_unsupported() {
    use crate::chisei::gateway_decide::GATEWAY_DECIDE_CONTRACT_VERSION;
    use crate::provider_profile::{
        CAPABILITY_MATRIX_VERSION, CapabilityMatrix, CapabilityRequirements,
        NATIVE_CAPABILITY_CATALOG_CONTRACT,
    };

    let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let mut cfg = config(":memory:");
    cfg.gateway_provided_providers = vec!["openai".into()];
    let svc = ChiseiServiceImpl::new(db, cfg);
    svc.policy.set_namespace_policy(
        "team-a",
        crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: "internal".into(),
        },
    );
    svc.policy
        .set_context_admission_policy(
            "team-a",
            crate::chisei::policy::ContextAdmissionPolicy::allow_by_default(),
        )
        .unwrap();

    let decide = |capability_requirements_json: Vec<u8>, correlation: &str| {
        let mut request = Request::new(DecideGatewayExecutionRequest {
            contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
            namespace: "team-a".into(),
            requested_model: "gpt-5.5".into(),
            operation_class: "chat".into(),
            estimated_cost_usd_micros: 0,
            correlation_operation_id: correlation.into(),
            correlation_attempt: 1,
            estimated_tokens: 10,
            task_class: "interactive".into(),
            preferred_runtime: "openai".into(),
            project: "team-a".into(),
            agent: "local".into(),
            key_id: String::new(),
            work_unit: String::new(),
            local_free_available: false,
            user_id: "local".into(),
            route_override: String::new(),
            capability_requirements_json,
            expected_calls: 1,
            pipeline_spec: String::new(),
        });
        request
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        request
    };

    let native = serde_json::json!({
        "capabilities": [{
            "name": "sekai.semantic.expand_relations",
            "product_tier": "core"
        }],
        "contract_version": NATIVE_CAPABILITY_CATALOG_CONTRACT,
        "catalog_version": "sha256:deadbeef",
        "cache_scope": "authorization_context"
    });
    let native_denied = svc
        .decide_gateway_execution(decide(
            serde_json::to_vec(&native).unwrap(),
            "op-mix-native",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!native_denied.admitted, "{native_denied:?}");
    assert_eq!(native_denied.deny_reason, "capability_unsupported");
    assert!(
        native_denied
            .deny_message
            .contains("DiscoverCapabilities contract 1.0"),
        "{native_denied:?}"
    );

    let matrix_denied = svc
        .decide_gateway_execution(decide(
            serde_json::to_vec(&CapabilityMatrix::built_in()).unwrap(),
            "op-mix-matrix",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!matrix_denied.admitted, "{matrix_denied:?}");
    assert_eq!(matrix_denied.deny_reason, "capability_unsupported");
    assert!(
        matrix_denied
            .deny_message
            .contains(CAPABILITY_MATRIX_VERSION),
        "{matrix_denied:?}"
    );

    let admitted = svc
        .decide_gateway_execution(decide(
            serde_json::to_vec(&CapabilityRequirements {
                responses: true,
                ..CapabilityRequirements::default()
            })
            .unwrap(),
            "op-mix-requirements",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(admitted.admitted, "{admitted:?}");
    assert!(admitted.deny_reason.is_empty());
}

#[tokio::test]
async fn decide_gateway_execution_requires_authenticated_principal() {
    use crate::chisei::gateway_decide::GATEWAY_DECIDE_CONTRACT_VERSION;

    let svc = memory_service();
    let request = Request::new(DecideGatewayExecutionRequest {
        contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
        namespace: "team-a".into(),
        requested_model: "gpt-5.5".into(),
        operation_class: "chat".into(),
        estimated_cost_usd_micros: 0,
        correlation_operation_id: "op-decide-missing-principal".into(),
        correlation_attempt: 1,
        estimated_tokens: 10,
        task_class: "interactive".into(),
        preferred_runtime: "openai".into(),
        project: "team-a".into(),
        agent: "mallory".into(),
        key_id: String::new(),
        work_unit: String::new(),
        local_free_available: false,
        user_id: "mallory".into(),
        route_override: String::new(),
        capability_requirements_json: Vec::new(),
        expected_calls: 1,
        pipeline_spec: String::new(),
    });
    let err = svc.decide_gateway_execution(request).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn execute_plan_lookup_first_hit_skips_provider_with_zero_tokens() {
    use crate::chisei::lookup_first;
    use crate::sekai::semantic;

    let svc = memory_service();
    lookup_first::seed_s1_fixture_graph(&svc.db).expect("seed lookup fixtures");

    let plan = ExecutionPlan {
        plan_id: "lookup-hit-plan".into(),
        input: Some(ExecutionInput {
            request_id: "lookup-hit-req".into(),
            namespace: "acme".into(),
            spec: r#"{"external_id":"widget:lookup-root"}"#.into(),
            preferred_model: "llama3.2".into(),
            preferred_runtime: "ollama".into(),
            task_type: semantic::CAPABILITY_RESOLVE_REF.into(),
            priority: 0,
            user_id: "alice".into(),
            estimated_tokens: 0,
            messages: vec![],
            tools: vec![],
            system: String::new(),
            max_tokens: 256,
            task_class: String::new(),
            ..Default::default()
        }),
        resolved_runtime: "ollama".into(),
        resolved_model: "llama3.2".into(),
        enriched_spec: r#"{"external_id":"widget:lookup-root"}"#.into(),
        prepared_system: String::new(),
        prepared_messages: vec![ChatMessage {
            role: "user".into(),
            content: r#"{"external_id":"widget:lookup-root"}"#.into(),
            tool_call_id: String::new(),
            tool_calls: vec![],
        }],
        tools: vec![],
        budget: Some(BudgetVerdict {
            allowed: true,
            usage: None,
            reason: String::new(),
        }),
        steps: vec![],
        review_policy: None,
        risk_score: 0.0,
        low_success_namespace: false,
        executable: true,
        warnings: vec![],
        max_tokens: 256,
        created_at: chrono::Utc::now().timestamp_millis(),
        affinity_namespaces: vec![],
        eval_regressed: false,
        eval_regression_reason: String::new(),
        sampled: false,
        sample_rate: 0.0,
        sample_reason: String::new(),
        egress_decisions: vec![],
        task_class: String::new(),
        evidence_references: vec![],
        memory_references: vec![],
        planning_actor: "local".into(),
        context_admission_policy_version: String::new(),
        context_admission_descriptor_version: String::new(),
        context_admission_decision: String::new(),
        context_admission_reasons: Vec::new(),
        context_admission_source_digests: Vec::new(),
        context_admission_requires_review: false,
        context_admission_requires_verification: false,
        memory_holdouts: vec![],
        context_bytes: 0,
        context_tokens: 0,
        context_projection_latency_ms: 0,
        context_truncated: false,
        ..Default::default()
    };
    svc.record_planned_operation(&plan, "local").unwrap();
    svc.cache_plan(plan.clone());

    let mut request = Request::new(ExecutePlanRequest {
        plan: Some(plan.clone()),
    });
    request
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());

    let response = svc
        .execute_plan(request)
        .await
        .expect("lookup hit should execute without provider")
        .into_inner()
        .response
        .expect("response body");
    assert_eq!(response.provider, lookup_first::LOOKUP_PROVIDER);
    assert_eq!(response.stop_reason, lookup_first::LOOKUP_HIT_STOP_REASON);
    assert_eq!(response.input_tokens, 0);
    assert_eq!(response.output_tokens, 0);
    assert_eq!(response.cache_read_input_tokens, 0);
    assert_eq!(response.cache_creation_input_tokens, 0);
    let body: serde_json::Value = serde_json::from_str(&response.content).unwrap();
    assert_eq!(body["resolved"], true);
    assert_eq!(body["object"]["id"], "lookup-root");

    let receipt = svc
        .db
        .get_operation_receipt("lookup-hit-plan")
        .unwrap()
        .unwrap();
    let outcome = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        .expect("outcome");
    assert_eq!(
        outcome
            .attributes
            .get(lookup_first::ANSWER_PATH_ATTR)
            .map(String::as_str),
        Some(lookup_first::ANSWER_PATH_LOOKUP_HIT)
    );
    assert_eq!(
        outcome
            .attributes
            .get("provider_tokens")
            .map(String::as_str),
        Some("0")
    );
    assert!(
        !receipt
            .events
            .iter()
            .any(|event| event.kind == ReceiptEventKind::ModelCalled),
        "lookup hit must not record a model call"
    );

    create_suite(&svc, "acme");
    seed_eval_run(
        &svc,
        eval_run("lookup-regression-baseline", "suite-1", 95, 100),
        "acme",
        "lookup-regression-baseline",
    );
    seed_eval_run(
        &svc,
        eval_run("lookup-regression-candidate", "suite-1", 50, 200),
        "acme",
        "lookup-regression-candidate",
    );
    assert!(
        svc.eval
            .namespace_regression_signal("acme")
            .expect("regression signal")
            .regressed
    );

    let mut regressed_plan = plan.clone();
    regressed_plan.plan_id = "lookup-regressed-plan".into();
    regressed_plan
        .input
        .as_mut()
        .expect("plan input")
        .request_id = "lookup-regressed-req".into();
    svc.record_planned_operation(&regressed_plan, "local")
        .unwrap();
    svc.cache_plan(regressed_plan.clone());

    let mut regressed_request = Request::new(ExecutePlanRequest {
        plan: Some(regressed_plan),
    });
    regressed_request
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    let error = svc.execute_plan(regressed_request).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(
        error
            .message()
            .contains("latest eval iteration regressed for namespace acme")
    );
}

#[tokio::test]
async fn execute_plan_lookup_first_incomplete_records_refusal_before_model_path() {
    use crate::chisei::lookup_first;
    use crate::sekai::semantic;

    // Only evaluate the decision path here — full model execute needs a live
    // provider. The fail-closed refusal is unit-tested below via evaluate.
    let db = RuntimeDb::memory();
    lookup_first::seed_s1_fixture_graph(&db).unwrap();
    let input = ExecutionInput {
        request_id: "incomplete".into(),
        namespace: "acme".into(),
        spec: r#"{"object_id":"does-not-exist"}"#.into(),
        task_type: semantic::CAPABILITY_RESOLVE_REF.into(),
        ..Default::default()
    };
    match evaluate_execute_lookup_first(&db, &input, "alice") {
        ExecuteLookupFirst::ModelPath {
            lookup_refusal: Some(reason),
        } => assert_eq!(reason, "incomplete"),
        other => panic!("expected incomplete model path, got {other:?}"),
    }

    let cross = ExecutionInput {
        request_id: "cross".into(),
        namespace: "acme".into(),
        spec: r#"{"object_id":"other-ns-object"}"#.into(),
        task_type: semantic::CAPABILITY_RESOLVE_REF.into(),
        ..Default::default()
    };
    match evaluate_execute_lookup_first(&db, &cross, "alice") {
        ExecuteLookupFirst::ModelPath {
            lookup_refusal: Some(reason),
        } => assert_eq!(reason, "cross_namespace"),
        other => panic!("expected cross_namespace model path, got {other:?}"),
    }
}

#[test]
fn execute_lookup_first_s2_hits_have_zero_provider_fields() {
    use crate::chisei::lookup_first;
    use crate::sekai::semantic;

    let db = RuntimeDb::memory();
    lookup_first::seed_s1_fixture_graph(&db).expect("seed lookup fixtures");
    for (capability, spec) in [
        (
            semantic::CAPABILITY_EXPAND_RELATIONS,
            r#"{"root":{"object_id":"lookup-root"},"direction":"outgoing","max_depth":1}"#,
        ),
        (
            semantic::CAPABILITY_RETRIEVE_CONTEXT,
            r#"{"roots":[{"object_id":"lookup-root"}],"direction":"outgoing","max_depth":1}"#,
        ),
        (
            semantic::CAPABILITY_EXPLAIN_DERIVATION,
            r#"{"from":{"object_id":"lookup-root"},"to":{"object_id":"lookup-child"},"direction":"outgoing","max_depth":1}"#,
        ),
    ] {
        let input = ExecutionInput {
            namespace: "acme".into(),
            spec: spec.into(),
            task_type: capability.into(),
            ..Default::default()
        };
        match evaluate_execute_lookup_first(&db, &input, "alice") {
            ExecuteLookupFirst::Hit { response, .. } => {
                assert_eq!(response.provider, lookup_first::LOOKUP_PROVIDER);
                assert_eq!(response.input_tokens, 0);
                assert_eq!(response.output_tokens, 0);
                assert_eq!(response.cache_read_input_tokens, 0);
                assert_eq!(response.cache_creation_input_tokens, 0);
                assert!(!response.content.is_empty());
            }
            other => panic!("expected {capability} lookup hit, got {other:?}"),
        }
    }
}
