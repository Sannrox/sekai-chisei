//! Trust scores on objects (#1456).
//!
//! A namespace's versioned `sekai.trust-scoring-rule/v1` turns plain signals
//! into one 0..=100 score per object with the reasons that produced it:
//! source health, age against expected freshness, manual verification, and
//! corroborating or contradicting links. The rule is a transparent points
//! table, not a model. Rules are stored as one reserved governance object per
//! namespace, so every change is in the audited object change log.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{Object, is_valid_property_key};
use crate::sekai::source_health::{CLASS_BLOCKED, CLASS_DELAYED, CLASS_UNAVAILABLE};

pub const TRUST_SCORING_RULE_CONTRACT: &str = "sekai.trust-scoring-rule/v1";
pub const TRUST_SCORING_RULE_KIND: &str = "trust_scoring_rule";
pub const MAX_TRUST_SCORE: u8 = 100;

const PENALIZED_SOURCE_CLASSES: &[&str] = &[CLASS_DELAYED, CLASS_BLOCKED, CLASS_UNAVAILABLE];

/// Points table for one namespace. Zero or empty fields switch a factor off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustScoringRule {
    pub contract_version: String,
    pub namespace: String,
    /// Score before any factor.
    pub base: u8,
    /// Points subtracted when the object's source is in this health class
    /// (`delayed`, `blocked`, `unavailable`).
    #[serde(default)]
    pub source_penalties: BTreeMap<String, u8>,
    /// An object not updated for longer than this is stale.
    #[serde(default)]
    pub expected_freshness_ms: i64,
    #[serde(default)]
    pub stale_penalty: u8,
    /// A non-empty value of this property marks the object verified.
    #[serde(default)]
    pub verification_property: String,
    #[serde(default)]
    pub verified_bonus: u8,
    /// Points per visible object linked to this one with the relation.
    #[serde(default)]
    pub agreement_relation: String,
    #[serde(default)]
    pub agreement_bonus: u8,
    #[serde(default)]
    pub conflict_relation: String,
    #[serde(default)]
    pub conflict_penalty: u8,
}

impl TrustScoringRule {
    pub fn parse(json: &str) -> Result<Self, String> {
        let rule: Self = serde_json::from_str(json)
            .map_err(|error| format!("invalid trust scoring rule: {error}"))?;
        rule.validate()?;
        Ok(rule)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != TRUST_SCORING_RULE_CONTRACT {
            return Err("unsupported trust scoring rule contract".into());
        }
        if self.namespace.trim().is_empty() || self.namespace.trim() != self.namespace {
            return Err("trust scoring rule namespace is required".into());
        }
        if self.base > MAX_TRUST_SCORE {
            return Err("trust scoring rule base must be at most 100".into());
        }
        if let Some(class) = self
            .source_penalties
            .keys()
            .find(|class| !PENALIZED_SOURCE_CLASSES.contains(&class.as_str()))
        {
            return Err(format!("unknown source health class {class:?}"));
        }
        if self.expected_freshness_ms < 0 {
            return Err("expected_freshness_ms must not be negative".into());
        }
        if !self.verification_property.is_empty()
            && !is_valid_property_key(&self.verification_property)
        {
            return Err("verification_property is not a valid property key".into());
        }
        for relation in [&self.agreement_relation, &self.conflict_relation] {
            if relation.trim() != relation.as_str() {
                return Err("relations must not carry surrounding whitespace".into());
            }
        }
        if !self.agreement_relation.is_empty() && self.agreement_relation == self.conflict_relation
        {
            return Err("agreement and conflict relations must differ".into());
        }
        Ok(())
    }

    /// Canonical JSON: struct field order and sorted maps.
    pub fn canonical_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|error| error.to_string())
    }

    pub fn revision_digest(&self) -> Result<String, String> {
        let mut hasher = Sha256::new();
        hasher.update(b"sekai.trust-scoring-rule/v1\0");
        hasher.update(self.canonical_json()?.as_bytes());
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }
}

/// What is known about one object when it is scored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustInputs {
    /// Health class of the source that syncs the object; `None` when no
    /// source owns it.
    pub source_class: Option<String>,
    pub age_ms: i64,
    pub verified: bool,
    pub agreements: u32,
    pub conflicts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustReason {
    pub factor: String,
    pub delta: i32,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustScore {
    pub score: u8,
    /// Every factor that moved the score, base first.
    pub reasons: Vec<TrustReason>,
}

/// Score one object. Pure: the same rule and inputs give the same score.
pub fn score(rule: &TrustScoringRule, inputs: &TrustInputs) -> TrustScore {
    let mut reasons = vec![TrustReason {
        factor: "base".into(),
        delta: i32::from(rule.base),
        detail: "namespace base score".into(),
    }];
    let mut push = |factor: &str, delta: i32, detail: String| {
        if delta != 0 {
            reasons.push(TrustReason {
                factor: factor.into(),
                delta,
                detail,
            });
        }
    };
    if let Some(class) = &inputs.source_class
        && let Some(penalty) = rule.source_penalties.get(class)
    {
        push("source", -i32::from(*penalty), format!("source is {class}"));
    }
    if rule.expected_freshness_ms > 0 && inputs.age_ms > rule.expected_freshness_ms {
        push(
            "freshness",
            -i32::from(rule.stale_penalty),
            format!(
                "not updated for {} ms, expected within {} ms",
                inputs.age_ms, rule.expected_freshness_ms
            ),
        );
    }
    if inputs.verified {
        push(
            "verification",
            i32::from(rule.verified_bonus),
            format!("{} is set", rule.verification_property),
        );
    }
    push(
        "agreement",
        i32::from(rule.agreement_bonus).saturating_mul(inputs.agreements as i32),
        format!(
            "{} visible {} link(s)",
            inputs.agreements, rule.agreement_relation
        ),
    );
    push(
        "conflict",
        -i32::from(rule.conflict_penalty).saturating_mul(inputs.conflicts as i32),
        format!(
            "{} visible {} link(s)",
            inputs.conflicts, rule.conflict_relation
        ),
    );
    let total: i32 = reasons.iter().map(|reason| reason.delta).sum();
    TrustScore {
        score: total.clamp(0, i32::from(MAX_TRUST_SCORE)) as u8,
        reasons,
    }
}

/// Whether `object` carries the rule's verification property.
pub fn is_verified(rule: &TrustScoringRule, object: &Object) -> bool {
    !rule.verification_property.is_empty()
        && object
            .properties
            .get(&rule.verification_property)
            .is_some_and(|value| !value.trim().is_empty())
}

/// A stored rule revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTrustScoringRule {
    pub rule: TrustScoringRule,
    pub revision_digest: String,
    pub version: u64,
    pub updated_by: String,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRuleError {
    Invalid(String),
    /// The caller's expected revision is not the stored one.
    RevisionMismatch,
    Storage(String),
}

fn rule_object_id(namespace: &str) -> String {
    format!("{TRUST_SCORING_RULE_KIND}:{namespace}")
}

fn stored_from_object(object: &Object) -> Result<StoredTrustScoringRule, String> {
    let property = |key: &str| {
        object
            .properties
            .get(key)
            .cloned()
            .ok_or_else(|| format!("stored trust scoring rule is missing {key}"))
    };
    let rule = TrustScoringRule::parse(&property("rule_json")?)?;
    let revision_digest = property("revision_digest")?;
    if rule.revision_digest()? != revision_digest {
        return Err("stored trust scoring rule digest is stale".into());
    }
    Ok(StoredTrustScoringRule {
        rule,
        revision_digest,
        version: property("version")?
            .parse()
            .map_err(|_| "stored trust scoring rule version is invalid".to_string())?,
        updated_by: property("updated_by")?,
        updated_at_ms: object.updated,
    })
}

/// The namespace's current rule, if any.
pub fn get_rule(db: &RuntimeDb, namespace: &str) -> Result<Option<StoredTrustScoringRule>, String> {
    db.get_object(&rule_object_id(namespace))?
        .filter(|object| object.kind == TRUST_SCORING_RULE_KIND)
        .map(|object| stored_from_object(&object))
        .transpose()
}

/// Store a new rule revision when `expected_revision_digest` names the
/// current one (empty for the first rule). Storing the current revision
/// again is a no-op, so a retried request succeeds. The write goes through
/// the audited object path and fails if another writer got there first.
pub fn put_rule(
    db: &RuntimeDb,
    rule: &TrustScoringRule,
    expected_revision_digest: &str,
    actor: &str,
    now_ms: i64,
) -> Result<StoredTrustScoringRule, TrustRuleError> {
    rule.validate().map_err(TrustRuleError::Invalid)?;
    let digest = rule.revision_digest().map_err(TrustRuleError::Storage)?;
    let id = rule_object_id(&rule.namespace);
    let existing = db.get_object(&id).map_err(TrustRuleError::Storage)?;
    let current = existing
        .as_ref()
        .map(stored_from_object)
        .transpose()
        .map_err(TrustRuleError::Storage)?;
    if let Some(current) = &current
        && current.revision_digest == digest
    {
        return Ok(current.clone());
    }
    let current_digest = current
        .as_ref()
        .map(|current| current.revision_digest.as_str())
        .unwrap_or_default();
    if current_digest != expected_revision_digest {
        return Err(TrustRuleError::RevisionMismatch);
    }
    let version = current.as_ref().map_or(1, |current| current.version + 1);
    let object = Object {
        id: id.clone(),
        kind: TRUST_SCORING_RULE_KIND.into(),
        name: rule.namespace.clone(),
        namespace: String::new(),
        external_id: id,
        properties: [
            (
                "rule_json",
                rule.canonical_json().map_err(TrustRuleError::Storage)?,
            ),
            ("revision_digest", digest),
            ("version", version.to_string()),
            ("updated_by", actor.to_string()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect(),
        created: existing.as_ref().map_or(now_ms, |object| object.created),
        updated: now_ms,
    };
    let written = match &existing {
        None => db.create_object_with_audit(&object, actor),
        Some(existing) => db
            .update_object_with_authorized_snapshot(&object, Some(existing), actor, None)
            .map(|_| ()),
    };
    written.map_err(|error| {
        if error.contains(crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION)
            || error.contains("UNIQUE constraint failed")
            || error.contains("duplicate key value")
        {
            TrustRuleError::RevisionMismatch
        } else {
            TrustRuleError::Storage(error)
        }
    })?;
    stored_from_object(&object).map_err(TrustRuleError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn rule() -> TrustScoringRule {
        TrustScoringRule {
            contract_version: TRUST_SCORING_RULE_CONTRACT.into(),
            namespace: "acme".into(),
            base: 60,
            source_penalties: BTreeMap::from([
                (CLASS_DELAYED.into(), 15),
                (CLASS_BLOCKED.into(), 40),
            ]),
            expected_freshness_ms: 1_000,
            stale_penalty: 20,
            verification_property: "verified_by".into(),
            verified_bonus: 25,
            agreement_relation: "corroborates".into(),
            agreement_bonus: 5,
            conflict_relation: "contradicts".into(),
            conflict_penalty: 10,
        }
    }

    fn factors(score: &TrustScore) -> Vec<(&str, i32)> {
        score
            .reasons
            .iter()
            .map(|reason| (reason.factor.as_str(), reason.delta))
            .collect()
    }

    #[test]
    fn a_stale_object_from_a_failing_source_scores_below_a_fresh_verified_one() {
        let stale = score(
            &rule(),
            &TrustInputs {
                source_class: Some(CLASS_BLOCKED.into()),
                age_ms: 5_000,
                conflicts: 1,
                ..TrustInputs::default()
            },
        );
        let fresh = score(
            &rule(),
            &TrustInputs {
                source_class: Some("healthy".into()),
                age_ms: 10,
                verified: true,
                agreements: 2,
                ..TrustInputs::default()
            },
        );
        assert_eq!(stale.score, 0);
        assert_eq!(
            factors(&stale),
            [
                ("base", 60),
                ("source", -40),
                ("freshness", -20),
                ("conflict", -10)
            ]
        );
        assert_eq!(fresh.score, 95);
        assert_eq!(
            factors(&fresh),
            [("base", 60), ("verification", 25), ("agreement", 10)]
        );
        assert!(stale.score < fresh.score);
    }

    #[test]
    fn scores_clamp_and_switched_off_factors_add_no_reason() {
        let generous = TrustScoringRule {
            base: 100,
            ..rule()
        };
        let verified = TrustInputs {
            verified: true,
            ..TrustInputs::default()
        };
        assert_eq!(score(&generous, &verified).score, MAX_TRUST_SCORE);
        let plain = TrustScoringRule {
            source_penalties: BTreeMap::new(),
            expected_freshness_ms: 0,
            ..rule()
        };
        let old_failing = TrustInputs {
            source_class: Some(CLASS_BLOCKED.into()),
            age_ms: i64::MAX,
            ..TrustInputs::default()
        };
        assert_eq!(factors(&score(&plain, &old_failing)), [("base", 60)]);
    }

    #[test]
    fn rules_validate_and_digest_canonically() {
        assert!(rule().validate().is_ok());
        let unknown_class = TrustScoringRule {
            source_penalties: BTreeMap::from([("healthy".into(), 1)]),
            ..rule()
        };
        assert!(unknown_class.validate().is_err());
        assert!(
            TrustScoringRule {
                base: 101,
                ..rule()
            }
            .validate()
            .is_err()
        );
        assert!(TrustScoringRule::parse(r#"{"contract_version":"x"}"#).is_err());
        let json = rule().canonical_json().unwrap();
        assert_eq!(TrustScoringRule::parse(&json).unwrap(), rule());
        assert_ne!(
            rule().revision_digest().unwrap(),
            TrustScoringRule { base: 61, ..rule() }
                .revision_digest()
                .unwrap()
        );
    }

    #[test]
    fn rule_revisions_are_compare_and_set_and_audited() {
        let db = RuntimeDb::Sqlite(Arc::new(
            crate::db::sekai::SekaiDb::new(":memory:").unwrap(),
        ));
        let first = put_rule(&db, &rule(), "", "root", 10).unwrap();
        assert_eq!(first.version, 1);
        // A retry of the same revision is a no-op.
        assert_eq!(put_rule(&db, &rule(), "", "root", 11).unwrap(), first);
        let tighter = TrustScoringRule { base: 50, ..rule() };
        assert_eq!(
            put_rule(&db, &tighter, "", "root", 12),
            Err(TrustRuleError::RevisionMismatch)
        );
        let second = put_rule(&db, &tighter, &first.revision_digest, "root", 13).unwrap();
        assert_eq!(second.version, 2);
        assert_eq!(get_rule(&db, "acme").unwrap(), Some(second));
        let changes = db
            .list_object_changes(&rule_object_id("acme"), 10, 0)
            .unwrap();
        assert!(
            changes
                .iter()
                .any(|change| change.field == "properties.revision_digest"
                    && change.changed_by == "root")
        );
    }
}
