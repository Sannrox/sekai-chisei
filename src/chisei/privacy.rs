use crate::config::Config;
use crate::domain::Object;
use regex::Regex;
use std::collections::HashSet;

pub const ENTITY_SCAN_OPT_OUT_KEY: &str = "chisei.egress.entity_scan";
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

pub struct LeakRule {
    pub id: String,
    pub label: String,
    pub pattern: Regex,
    pub action: LeakAction,
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

pub fn entity_scan_literals(objects: &[Object]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut literals = Vec::new();
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
                literals.push(trimmed.to_string());
            }
        }
        if literals.len() >= 500 {
            break;
        }
    }
    literals
}

pub fn check_payload(payload: &str, rules: &[LeakRule], entities: &[String]) -> Vec<LeakFinding> {
    let mut findings = Vec::new();
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
            db_path: ":memory:".into(),
            sekai_socket: None,
            anthropic_api_key: None,
            openai_api_key: None,
            ollama_url: "http://localhost:11434".into(),
            native_llm_url: None,
            auth_token: None,
            sample_rate: 0.05,
            sample_risk_threshold: 0.7,
            scoring_enabled: false,
            scoring_interval_secs: 60,
            scoring_model: "judge".into(),
            scoring_batch_size: 16,
            default_data_class: "unclassified".into(),
            safe_egress_providers: vec!["native".into()],
            gateway_provided_providers: vec![],
            gateway_receipt_principals: vec![],
            leak_review_model: None,
            tls_cert: None,
            tls_key: None,
            allow_plaintext: false,
            insecure: false,
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
        );
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_label, "account_id");
        assert_eq!(findings[0].match_count, 1);
        assert_eq!(findings[1].rule_label, "known_entity:SecretCo");
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
        assert_eq!(entity_scan_literals(&objects), vec!["asset:ABC"]);
    }
}
