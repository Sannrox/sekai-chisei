use super::*;

pub(super) fn learning_id(namespace: &str, request_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"chisei.scoring.record_learning.v1");
    for value in [namespace, request_id] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    let encoded = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("learning:chisei.scoring:{encoded}")
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    let mut normalized = String::new();
    let mut chars: usize = 0;
    let mut pending_space = false;
    for character in value.chars() {
        if character.is_whitespace() || character.is_control() {
            pending_space = !normalized.is_empty();
            continue;
        }
        if pending_space {
            if chars.saturating_add(1) >= max_chars {
                break;
            }
            normalized.push(' ');
            chars += 1;
        }
        pending_space = false;
        if chars >= max_chars {
            break;
        }
        normalized.push(character);
        chars += 1;
    }
    normalized
}

pub(super) fn source_request_id(request_id: &str) -> String {
    let trimmed = request_id.trim();
    if trimmed.chars().count() <= 256 && !trimmed.chars().any(char::is_control) {
        return trimmed.to_string();
    }
    let mut digest = Sha256::new();
    digest.update(b"chisei.scoring.source_request.v1");
    digest.update((request_id.len() as u64).to_be_bytes());
    digest.update(request_id.as_bytes());
    let encoded = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{encoded}")
}

pub(super) async fn admit(
    service: &SekaiServiceImpl,
    request: &KnowledgeWriteRequest,
) -> Result<KnowledgeWriteOutcome, String> {
    let namespace = request.namespace.trim();
    if namespace.is_empty() {
        return Err("knowledge write requires an observation namespace".into());
    }
    if request.request_id.trim().is_empty() {
        return Err("knowledge write requires a source request id".into());
    }

    let target = match service
        .db
        .find_by_external_id(&format!("namespace:{namespace}"))?
    {
        Some(target) if target.kind == "namespace" => target,
        Some(target) => {
            return Err(format!(
                "namespace external id resolved to unexpected kind: {}",
                target.kind
            ));
        }
        None => service
            .db
            .find_by_external_id(&format!("policy:{namespace}"))?
            .or(service
                .db
                .find_by_external_id(&format!("project:{namespace}"))?)
            .ok_or_else(|| format!("no governed target found for namespace: {namespace}"))?,
    };
    if !service.security.can_write(&target.id, &["chisei.scoring"]) {
        return Err("knowledge write target access denied".into());
    }

    let learning_id = learning_id(namespace, &request.request_id);
    let passed = if request.passed { "true" } else { "false" };
    let mut reasoning = bounded_text(&request.reasoning, 2_000);
    if reasoning.is_empty() {
        reasoning = format!(
            "The scoring judge recorded a {} outcome with score {}.",
            if request.passed { "passing" } else { "failing" },
            request.score.clamp(0, 100)
        );
    }
    let task_class = bounded_text(&request.task_class, 128);
    let model = bounded_text(&request.model, 256);
    let task_class = if task_class.is_empty() {
        "unclassified".to_string()
    } else {
        task_class
    };
    let model = if model.is_empty() {
        "unknown".to_string()
    } else {
        model
    };
    let title = format!(
        "Scored {task_class} task outcome: {}",
        if request.passed {
            "passed"
        } else {
            "needs correction"
        }
    );
    let prevention = if request.passed {
        format!("Preserve this evaluated behavior: {reasoning}")
    } else {
        format!("Before repeating this task, address: {reasoning}")
    };
    let params = HashMap::from([
        ("id".into(), learning_id.clone()),
        ("target_id".into(), target.id.clone()),
        ("title".into(), title),
        ("prevention".into(), prevention),
        ("reasoning".into(), reasoning),
        (
            "source_request_id".into(),
            source_request_id(&request.request_id),
        ),
        ("score".into(), request.score.clamp(0, 100).to_string()),
        ("passed".into(), passed.into()),
        ("task_class".into(), task_class),
        ("model".into(), model),
        ("producer".into(), "chisei.scoring".into()),
        ("status".into(), "candidate".into()),
    ]);
    let resolved_policy =
        service
            .db
            .resolve_action_policy("chisei.scoring", namespace, namespace)?;
    let decision = resolved_policy
        .as_ref()
        .map(|policy| {
            policy.decide(
                crate::sekai::learning::RECORD_LEARNING_ACTION,
                RiskClass::Write,
            )
        })
        .unwrap_or(ActionDecision::Allow);
    if decision != ActionDecision::Allow {
        service.db.record_decision(&audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: now_millis(),
            actor: "chisei.scoring".into(),
            action: crate::sekai::learning::RECORD_LEARNING_ACTION.into(),
            reason: "action_policy_denied".into(),
            evidence: HashMap::from([
                (
                    "policy_scope".into(),
                    resolved_policy
                        .as_ref()
                        .map(|policy| policy.scope.clone())
                        .unwrap_or_default(),
                ),
                ("decision".into(), decision.as_str().into()),
            ]),
            target_id: target.id.clone(),
            outcome: "policy_denied".into(),
        })?;
        return Ok(KnowledgeWriteOutcome::PolicyDenied);
    }
    let schema = service
        .schema_definitions
        .refresh_snapshot()
        .map_err(|error| format!("learning schema unavailable: {error:?}"))?;
    crate::sekai::learning::record_learning(&service.db, &schema, &params, "chisei.scoring")?;
    // Refresh the process ACL cache before any post-commit audit work so a
    // durable private Learning object cannot remain world-readable on cache miss
    // if later bookkeeping fails.
    let grants = service.db.list_grants(&learning_id)?;
    if grants.is_empty() {
        return Err("record_learning completed without a learning ACL".into());
    }
    for grant in &grants {
        service.security.add_grant(grant);
    }
    service.db.record_decision(&audit::Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: now_millis(),
        actor: "chisei.scoring".into(),
        action: crate::sekai::learning::RECORD_LEARNING_ACTION.into(),
        reason: "action_policy_allowed".into(),
        evidence: params
            .keys()
            .filter(|key| key.as_str() != "id" && key.as_str() != "target_id")
            .map(|key| (key.clone(), REDACTED_VALUE.into()))
            .chain(std::iter::once(("decision".into(), "allow".into())))
            .collect(),
        target_id: target.id,
        outcome: "executed".into(),
    })?;
    Ok(KnowledgeWriteOutcome::Accepted)
}
