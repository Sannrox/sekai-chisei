use crate::config::Config;
use crate::domain::Object;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub const ENTITY_SCAN_OPT_OUT_KEY: &str = "chisei.egress.entity_scan";
/// Bound on objects fetched for entity literals. Palantir analog: Object Search pageSize.
pub const ENTITY_SCAN_LIMIT: i32 = 500;
pub const ENTITY_LITERAL_LIMIT: usize = 500;
pub const SCAN_TRUNCATED_LABEL: &str = "scan_truncated";
const MIN_ENTITY_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClass {
    Unclassified,
    Open,
    Sensitive,
}

impl DataClass {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "open" => Self::Open,
            "sensitive" => Self::Sensitive,
            _ => Self::Unclassified,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unclassified => "unclassified",
            Self::Open => "open",
            Self::Sensitive => "sensitive",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskClass {
    Private,
    TemplateOnly,
}

impl TaskClass {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "template_only" | "template-only" => Self::TemplateOnly,
            _ => Self::Private,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::TemplateOnly => "template_only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakAction {
    Block,
    Redact,
}

impl LeakAction {
    pub fn parse(value: &str) -> Self {
        if value.eq_ignore_ascii_case("redact") {
            Self::Redact
        } else {
            Self::Block
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Redact => "redact",
        }
    }
}

#[derive(Clone)]
pub struct LeakRule {
    pub id: String,
    pub label: String,
    pub pattern: Regex,
    pub action: LeakAction,
}

struct CachedPrivacyScan {
    leak_fingerprint: String,
    entity_fingerprint: String,
    rules: Arc<Vec<LeakRule>>,
    entities: Option<Arc<Vec<String>>>,
    truncated: bool,
}

/// Compiled leak rules and entity literals reused while both object sets are unchanged.
/// Palantir analog: function-backed actions reuse one ontology snapshot per run;
/// the next invocation searches the current object set.
pub struct PrivacyScan {
    pub rules: Arc<Vec<LeakRule>>,
    pub entities: Arc<Vec<String>>,
    pub truncated: bool,
}

#[derive(Default)]
pub struct PrivacyScanCache {
    entries: Mutex<HashMap<String, CachedPrivacyScan>>,
}

impl PrivacyScanCache {
    pub fn load<E>(
        &self,
        namespace: &str,
        need_entities: bool,
        leak_objects: impl FnOnce() -> Result<Vec<Object>, E>,
        entity_objects: impl FnOnce() -> Result<Vec<Object>, E>,
    ) -> Result<PrivacyScan, E> {
        let leaks = leak_objects()?;
        let leak_fp = leak_fingerprint(&leaks);
        let entity_objs = if need_entities {
            Some(entity_objects()?)
        } else {
            None
        };
        let entity_fp = entity_objs
            .as_deref()
            .map(entity_fingerprint)
            .unwrap_or_default();
        {
            let guard = self
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cached) = guard.get(namespace)
                && cached.leak_fingerprint == leak_fp
            {
                if !need_entities {
                    return Ok(PrivacyScan {
                        rules: cached.rules.clone(),
                        entities: Arc::new(Vec::new()),
                        truncated: false,
                    });
                }
                if cached.entity_fingerprint == entity_fp
                    && let Some(entities) = cached.entities.clone()
                {
                    return Ok(PrivacyScan {
                        rules: cached.rules.clone(),
                        entities,
                        truncated: cached.truncated,
                    });
                }
            }
        }
        let rules = Arc::new(compile_leak_rules(&leaks));
        let (entities, truncated) = match entity_objs {
            Some(objects) => {
                // Palantir analog: Object Search pageSize is a maximum;
                // more results exist only when a further page is non-empty.
                let listed_overflow = objects.len() > ENTITY_SCAN_LIMIT as usize;
                let scanned = if listed_overflow {
                    &objects[..ENTITY_SCAN_LIMIT as usize]
                } else {
                    objects.as_slice()
                };
                let (literals, literal_truncated) = entity_scan_literals(scanned);
                (
                    Some(Arc::new(literals)),
                    listed_overflow || literal_truncated,
                )
            }
            None => (None, false),
        };
        let returned_entities = entities.clone().unwrap_or_else(|| Arc::new(Vec::new()));
        let mut guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.insert(
            namespace.to_string(),
            CachedPrivacyScan {
                leak_fingerprint: leak_fp,
                entity_fingerprint: entity_fp,
                rules: rules.clone(),
                entities,
                truncated,
            },
        );
        Ok(PrivacyScan {
            rules,
            entities: returned_entities,
            truncated,
        })
    }
}

fn leak_fingerprint(objects: &[Object]) -> String {
    let mut parts: Vec<String> = objects
        .iter()
        .map(|object| {
            format!(
                "{}|{}|{}|{}",
                object.namespace,
                object.id,
                object
                    .properties
                    .get("pattern")
                    .map(String::as_str)
                    .unwrap_or(""),
                object
                    .properties
                    .get("action")
                    .map(String::as_str)
                    .unwrap_or("block"),
            )
        })
        .collect();
    parts.sort();
    parts.join("\n")
}

fn entity_fingerprint(objects: &[Object]) -> String {
    let mut parts: Vec<String> = objects
        .iter()
        .map(|object| {
            format!(
                "{}|{}|{}|{}|{}|{}",
                object.namespace,
                object.id,
                object.name,
                object.external_id,
                object
                    .properties
                    .get(ENTITY_SCAN_OPT_OUT_KEY)
                    .map(String::as_str)
                    .unwrap_or(""),
                object.updated,
            )
        })
        .collect();
    parts.sort();
    parts.join("\n")
}

pub fn compile_leak_rules(objects: &[Object]) -> Vec<LeakRule> {
    let mut rules = Vec::new();
    for obj in objects {
        let Some(pattern) = obj.properties.get("pattern") else {
            continue;
        };
        let Ok(pattern) = Regex::new(pattern) else {
            continue;
        };
        rules.push(LeakRule {
            id: obj.id.clone(),
            label: obj
                .properties
                .get("label")
                .cloned()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| obj.name.clone()),
            pattern,
            action: LeakAction::parse(
                obj.properties
                    .get("action")
                    .map(String::as_str)
                    .unwrap_or("block"),
            ),
        });
    }
    rules
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakFinding {
    pub rule_label: String,
    pub action: LeakAction,
    pub match_count: usize,
}

pub fn safe_providers(config: &Config) -> HashSet<String> {
    let mut providers = HashSet::from(["ollama".to_string()]);
    providers.extend(
        config
            .safe_egress_providers
            .iter()
            .map(|provider| provider.to_ascii_lowercase()),
    );
    providers
}

pub fn provider_safe_to_send(provider: &str, safe: &HashSet<String>) -> bool {
    safe.contains(&provider.to_ascii_lowercase())
}

pub fn external_allowed(data_class: DataClass, task_class: TaskClass) -> bool {
    !matches!(
        (data_class, task_class),
        (DataClass::Sensitive, TaskClass::Private)
    )
}

pub fn gate_reason(data_class: DataClass, task_class: TaskClass, provider: &str) -> String {
    format!(
        "data_class={} task_class={} provider={} privacy gate",
        data_class.as_str(),
        task_class.as_str(),
        provider
    )
}

pub fn entity_scan_literals(objects: &[Object]) -> (Vec<String>, bool) {
    let mut seen = HashSet::new();
    let mut literals = Vec::new();
    let mut truncated = false;
    for obj in objects {
        if obj
            .properties
            .get(ENTITY_SCAN_OPT_OUT_KEY)
            .is_some_and(|value| value.eq_ignore_ascii_case("false"))
        {
            continue;
        }
        for value in [&obj.name, &obj.external_id] {
            let trimmed = value.trim();
            if trimmed.chars().count() < MIN_ENTITY_LEN {
                continue;
            }
            let key = trimmed.to_ascii_lowercase();
            if seen.insert(key) {
                if literals.len() >= ENTITY_LITERAL_LIMIT {
                    truncated = true;
                    break;
                }
                literals.push(trimmed.to_string());
            }
        }
        if truncated {
            break;
        }
    }
    (literals, truncated)
}

pub fn check_payload(
    payload: &str,
    rules: &[LeakRule],
    entities: &[String],
    truncated: bool,
) -> Vec<LeakFinding> {
    let mut findings = Vec::new();
    if truncated {
        findings.push(LeakFinding {
            rule_label: SCAN_TRUNCATED_LABEL.into(),
            action: LeakAction::Block,
            match_count: 0,
        });
    }
    for rule in rules {
        let count = rule.pattern.find_iter(payload).count();
        if count > 0 {
            findings.push(LeakFinding {
                rule_label: rule.label.clone(),
                action: rule.action,
                match_count: count,
            });
        }
    }
    for entity in entities {
        let pattern = format!(r"(?i)\b{}\b", regex::escape(entity));
        if let Ok(regex) = Regex::new(&pattern) {
            let count = regex.find_iter(payload).count();
            if count > 0 {
                findings.push(LeakFinding {
                    rule_label: format!("known_entity:{entity}"),
                    action: LeakAction::Block,
                    match_count: count,
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn gate_matrix_blocks_sensitive_private_only() {
        assert!(!external_allowed(DataClass::Sensitive, TaskClass::Private));
        assert!(external_allowed(
            DataClass::Sensitive,
            TaskClass::TemplateOnly
        ));
        assert!(external_allowed(DataClass::Open, TaskClass::Private));
        assert!(external_allowed(
            DataClass::Unclassified,
            TaskClass::Private
        ));
    }

    #[test]
    fn safe_providers_always_include_ollama() {
        let config = Config {
            grpc_port: 50051,
            sekai_bind: None,
            ops_port: None,
            ops_bind: "127.0.0.1".into(),
            http_port: None,
            http_bind: "127.0.0.1".into(),
            db_path: ":memory:".into(),
            sekai_socket: None,
            anthropic_api_key: None,
            openai_api_key: None,
            ollama_url: "http://localhost:11434".into(),
            native_llm_url: None,
            sample_rate: 0.05,
            sample_risk_threshold: 0.7,
            scoring_enabled: false,
            scoring_interval_secs: 60,
            scoring_model: "judge".into(),
            scoring_batch_size: 16,
            default_data_class: "unclassified".into(),
            safe_egress_providers: vec!["native".into()],
            gateway_provided_providers: vec![],
            routing_endpoint_allowlist: vec![],
            routing_credential_refs: vec![],
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
        };
        let safe = safe_providers(&config);
        assert!(provider_safe_to_send("ollama", &safe));
        assert!(provider_safe_to_send("native", &safe));
        assert!(!provider_safe_to_send("openai", &safe));
    }

    #[test]
    fn leak_checker_reports_labels_and_counts() {
        let rules = vec![LeakRule {
            id: "r1".into(),
            label: "account_id".into(),
            pattern: Regex::new(r"ACCT-[0-9]+").unwrap(),
            action: LeakAction::Block,
        }];
        let findings = check_payload(
            "Review ACCT-123 and SecretCo.",
            &rules,
            &["SecretCo".into()],
            false,
        );
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_label, "account_id");
        assert_eq!(findings[0].match_count, 1);
        assert_eq!(findings[1].rule_label, "known_entity:SecretCo");
    }

    #[test]
    fn truncated_scan_fails_closed_even_when_payload_has_no_match() {
        let findings = check_payload("harmless payload", &[], &[], true);
        assert_eq!(
            findings,
            vec![LeakFinding {
                rule_label: SCAN_TRUNCATED_LABEL.into(),
                action: LeakAction::Block,
                match_count: 0,
            }]
        );
    }

    #[test]
    fn entity_scan_literals_flags_truncation_at_literal_cap() {
        let objects: Vec<Object> = (0..=ENTITY_LITERAL_LIMIT)
            .map(|index| Object {
                id: format!("o{index}"),
                kind: "asset".into(),
                name: format!("Name{index:04}"),
                namespace: "alpha".into(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .collect();
        let (literals, truncated) = entity_scan_literals(&objects);
        assert!(truncated);
        assert_eq!(literals.len(), ENTITY_LITERAL_LIMIT);
        assert_eq!(literals[0], "Name0000");
        assert_eq!(literals.last().map(String::as_str), Some("Name0499"));
    }

    #[test]
    fn entity_scan_skips_short_and_opted_out_entities() {
        let objects = vec![
            Object {
                id: "o1".into(),
                kind: "asset".into(),
                name: "ABC".into(),
                namespace: "alpha".into(),
                external_id: "asset:ABC".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            },
            Object {
                id: "o2".into(),
                kind: "asset".into(),
                name: "SecretCo".into(),
                namespace: "alpha".into(),
                external_id: "asset:SECRET".into(),
                properties: HashMap::from([(ENTITY_SCAN_OPT_OUT_KEY.into(), "false".into())]),
                created: 0,
                updated: 0,
            },
        ];
        assert_eq!(entity_scan_literals(&objects).0, vec!["asset:ABC"]);
    }

    #[test]
    fn privacy_scan_cache_reuses_literals_when_entity_set_unchanged() {
        let cache = PrivacyScanCache::default();
        let leak = Object {
            id: "leak-1".into(),
            kind: "leak_rule".into(),
            name: "company".into(),
            namespace: "alpha".into(),
            external_id: "leak_rule:company".into(),
            properties: HashMap::from([
                ("pattern".into(), "SecretCo".into()),
                ("label".into(), "company_name".into()),
                ("action".into(), "block".into()),
            ]),
            created: 0,
            updated: 0,
        };
        let asset = Object {
            id: "asset-1".into(),
            kind: "asset".into(),
            name: "SecretCo".into(),
            namespace: "alpha".into(),
            external_id: "asset:SECRET".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        };
        let leak_calls = std::cell::Cell::new(0);
        let entity_calls = std::cell::Cell::new(0);
        let load = || {
            cache.load(
                "alpha",
                true,
                || {
                    leak_calls.set(leak_calls.get() + 1);
                    Ok::<_, ()>(vec![leak.clone()])
                },
                || {
                    entity_calls.set(entity_calls.get() + 1);
                    Ok(vec![asset.clone()])
                },
            )
        };
        let first = load().unwrap();
        let second = load().unwrap();
        assert_eq!(leak_calls.get(), 2);
        assert_eq!(entity_calls.get(), 2);
        assert_eq!(first.rules.len(), 1);
        assert_eq!(first.entities.as_slice(), ["SecretCo", "asset:SECRET"]);
        assert_eq!(second.rules[0].id, first.rules[0].id);
        assert_eq!(second.entities.as_slice(), first.entities.as_slice());
        assert!(Arc::ptr_eq(&first.entities, &second.entities));
        assert!(!first.truncated);
    }

    fn fill_scan_objects(count: usize) -> Vec<Object> {
        (0..count)
            .map(|index| Object {
                id: format!("fill-{index:04}"),
                kind: "asset".into(),
                name: "x".into(),
                namespace: "alpha".into(),
                external_id: format!("{index:03}"),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .collect()
    }

    #[test]
    fn privacy_scan_cache_does_not_truncate_an_exact_full_set() {
        let cache = PrivacyScanCache::default();
        let scan = cache
            .load(
                "alpha",
                true,
                || Ok::<_, ()>(Vec::new()),
                || Ok(fill_scan_objects(ENTITY_SCAN_LIMIT as usize)),
            )
            .unwrap();
        assert!(!scan.truncated);
        assert!(scan.entities.is_empty());
    }

    #[test]
    fn privacy_scan_cache_marks_truncated_when_a_further_page_exists() {
        let cache = PrivacyScanCache::default();
        let scan = cache
            .load(
                "alpha",
                true,
                || Ok::<_, ()>(Vec::new()),
                || Ok(fill_scan_objects(ENTITY_SCAN_LIMIT as usize + 1)),
            )
            .unwrap();
        assert!(scan.truncated);
        assert!(scan.entities.is_empty());
    }

    #[test]
    fn privacy_scan_cache_includes_entity_created_after_first_scan() {
        let cache = PrivacyScanCache::default();
        let first_entities = vec![Object {
            id: "asset-1".into(),
            kind: "asset".into(),
            name: "SecretCo".into(),
            namespace: "alpha".into(),
            external_id: "asset:SECRET".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        }];
        let mut second_entities = first_entities.clone();
        second_entities.push(Object {
            id: "asset-2".into(),
            kind: "asset".into(),
            name: "UniqueSecretCorp".into(),
            namespace: "alpha".into(),
            external_id: "asset:LATE".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        });
        let entities = std::cell::RefCell::new(first_entities);
        let first = cache
            .load(
                "alpha",
                true,
                || Ok::<_, ()>(Vec::new()),
                || Ok(entities.borrow().clone()),
            )
            .unwrap();
        assert_eq!(first.entities.as_slice(), ["SecretCo", "asset:SECRET"]);
        *entities.borrow_mut() = second_entities;
        let second = cache
            .load(
                "alpha",
                true,
                || Ok::<_, ()>(Vec::new()),
                || Ok(entities.borrow().clone()),
            )
            .unwrap();
        assert!(
            second
                .entities
                .iter()
                .any(|literal| literal == "UniqueSecretCorp"),
            "entity created after the first scan must be in the next snapshot: {:?}",
            second.entities
        );
        let findings = check_payload(
            "mention UniqueSecretCorp in the brief",
            &[],
            &second.entities,
            second.truncated,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_label == "known_entity:UniqueSecretCorp"),
            "new entity name must block on the next scan: {findings:?}"
        );
    }

    #[test]
    fn privacy_scan_cache_reloads_entities_when_leak_rules_change() {
        let cache = PrivacyScanCache::default();
        let mut leak = Object {
            id: "leak-1".into(),
            kind: "leak_rule".into(),
            name: "company".into(),
            namespace: "alpha".into(),
            external_id: "leak_rule:company".into(),
            properties: HashMap::from([("pattern".into(), "SecretCo".into())]),
            created: 0,
            updated: 0,
        };
        let asset = Object {
            id: "asset-1".into(),
            kind: "asset".into(),
            name: "SecretCo".into(),
            namespace: "alpha".into(),
            external_id: "asset:SECRET".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        };
        let entity_calls = std::cell::Cell::new(0);
        cache
            .load(
                "alpha",
                true,
                || Ok::<_, ()>(vec![leak.clone()]),
                || {
                    entity_calls.set(entity_calls.get() + 1);
                    Ok(vec![asset.clone()])
                },
            )
            .unwrap();
        leak.properties.insert("pattern".into(), "OtherCo".into());
        cache
            .load(
                "alpha",
                true,
                || Ok::<_, ()>(vec![leak.clone()]),
                || {
                    entity_calls.set(entity_calls.get() + 1);
                    Ok(vec![asset.clone()])
                },
            )
            .unwrap();
        assert_eq!(entity_calls.get(), 2);
    }
}
