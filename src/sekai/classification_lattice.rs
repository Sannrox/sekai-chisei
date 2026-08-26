//! Namespace-local classification lattice for hierarchical markings.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::sekai::evidence::EvidenceClassification;
use crate::sekai::markings::{
    MarkingCheckResult, MarkingDecision, PrincipalAuthority, is_trusted_service_principal,
};

pub const CLASSIFICATION_LATTICE_VERSION: &str = "sekai.classification-lattice/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationLattice {
    pub contract_version: String,
    pub namespace: String,
    pub tokens: Vec<String>,
    #[serde(default)]
    pub parents: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub incomparable: Vec<(String, String)>,
}

impl ClassificationLattice {
    pub fn default_evidence_lattice(namespace: &str) -> Self {
        Self {
            contract_version: CLASSIFICATION_LATTICE_VERSION.into(),
            namespace: namespace.into(),
            tokens: vec![
                EvidenceClassification::Public.as_str().into(),
                EvidenceClassification::Internal.as_str().into(),
                EvidenceClassification::Confidential.as_str().into(),
                EvidenceClassification::Restricted.as_str().into(),
            ],
            parents: BTreeMap::from([
                (
                    EvidenceClassification::Public.as_str().into(),
                    vec![EvidenceClassification::Internal.as_str().into()],
                ),
                (
                    EvidenceClassification::Internal.as_str().into(),
                    vec![EvidenceClassification::Confidential.as_str().into()],
                ),
                (
                    EvidenceClassification::Confidential.as_str().into(),
                    vec![EvidenceClassification::Restricted.as_str().into()],
                ),
            ]),
            incomparable: Vec::new(),
        }
    }

    pub fn prepare(&self) -> Result<Self, String> {
        if self.contract_version != CLASSIFICATION_LATTICE_VERSION {
            return Err("unsupported classification lattice contract".into());
        }
        validate_token("namespace", &self.namespace)?;
        if self.tokens.is_empty() {
            return Err("classification lattice must name at least one token".into());
        }
        let mut tokens = BTreeSet::new();
        for token in &self.tokens {
            validate_token("token", token)?;
            if !tokens.insert(token.clone()) {
                return Err(format!("duplicate classification token {token}"));
            }
        }
        let mut parents = BTreeMap::new();
        for (child, child_parents) in &self.parents {
            if !tokens.contains(child) {
                return Err(format!("parent edge references unknown token {child}"));
            }
            let mut unique = BTreeSet::new();
            for parent in child_parents {
                validate_token("parent", parent)?;
                if !tokens.contains(parent) {
                    return Err(format!("parent edge references unknown token {parent}"));
                }
                if parent == child {
                    return Err("classification lattice parent edge cannot be reflexive".into());
                }
                unique.insert(parent.clone());
            }
            parents.insert(child.clone(), unique.into_iter().collect());
        }
        let mut incomparable = BTreeSet::new();
        for (left, right) in &self.incomparable {
            validate_token("incomparable", left)?;
            validate_token("incomparable", right)?;
            if !tokens.contains(left) || !tokens.contains(right) {
                return Err("incomparable pair references an unknown token".into());
            }
            if left == right {
                return Err("incomparable pair cannot name the same token twice".into());
            }
            let pair = ordered_pair(left, right);
            incomparable.insert(pair);
        }
        if has_cycle(&tokens, &parents) {
            return Err("classification lattice parent edges must be acyclic".into());
        }
        Ok(Self {
            contract_version: CLASSIFICATION_LATTICE_VERSION.into(),
            namespace: self.namespace.clone(),
            tokens: tokens.into_iter().collect(),
            parents,
            incomparable: incomparable.into_iter().collect(),
        })
    }

    pub fn digest(&self) -> Result<String, String> {
        let prepared = self.prepare()?;
        let mut hasher = Sha256::new();
        hasher.update(b"sekai.classification-lattice/v1\0");
        hasher.update(serde_json::to_vec(&prepared).map_err(|error| error.to_string())?);
        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn contains(&self, token: &str) -> bool {
        self.tokens.iter().any(|value| value == token)
    }

    pub fn dominates(&self, ceiling: &str, marking: &str) -> Result<bool, String> {
        if !self.contains(ceiling) || !self.contains(marking) {
            return Err("unknown classification token".into());
        }
        if self.incomparable_pair(ceiling, marking) {
            return Ok(false);
        }
        Ok(ceiling == marking || ancestors(marking, &self.parents).contains(ceiling))
    }

    pub fn join(&self, left: &str, right: &str) -> Result<Option<String>, String> {
        if !self.contains(left) || !self.contains(right) {
            return Err("unknown classification token".into());
        }
        if self.incomparable_pair(left, right) {
            return Ok(None);
        }
        if self.dominates(left, right)? {
            return Ok(Some(left.into()));
        }
        if self.dominates(right, left)? {
            return Ok(Some(right.into()));
        }
        let left_up = ancestors(left, &self.parents);
        let right_up = ancestors(right, &self.parents);
        let common = left_up.intersection(&right_up).cloned().collect::<Vec<_>>();
        let mut least = common
            .iter()
            .filter(|candidate| {
                !common.iter().any(|other| {
                    other != *candidate
                        && ancestors(other, &self.parents).contains(candidate.as_str())
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        if least.len() == 1 {
            Ok(Some(least.remove(0)))
        } else {
            Ok(None)
        }
    }

    fn incomparable_pair(&self, left: &str, right: &str) -> bool {
        self.incomparable.contains(&ordered_pair(left, right))
    }
}

pub fn evaluate_lattice_access(
    operation_id: &str,
    object_token: Option<&str>,
    authority: &PrincipalAuthority,
    lattice: Option<&ClassificationLattice>,
) -> MarkingCheckResult {
    let decision_id = format!(
        "marking:{operation_id}:{}",
        uuid::Uuid::new_v4().as_simple()
    );
    let Some(lattice) = lattice else {
        return crate::sekai::markings::evaluate_marking_access(
            operation_id,
            object_token.and_then(|token| {
                crate::sekai::markings::parse_optional_classification(token)
                    .ok()
                    .flatten()
            }),
            authority,
        );
    };
    let Some(marking) = object_token
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return MarkingCheckResult {
            decision: MarkingDecision::NotApplicable,
            decision_id,
            object_classification: None,
            principal_ceiling: authority.classification_ceiling_token(),
            detail: "object has no classification marking".into(),
        };
    };
    if is_trusted_service_principal(&authority.principal) {
        return MarkingCheckResult {
            decision: MarkingDecision::Allow,
            decision_id,
            object_classification: Some(marking.into()),
            principal_ceiling: authority.classification_ceiling_token(),
            detail: "trusted service principal".into(),
        };
    }
    // The sealed ceiling token is a global principal-profile identifier.
    // Dominance is evaluated only against this object's namespace lattice;
    // operators who need isolated compartments must not reuse the same custom
    // token name across lattices.
    if !lattice.contains(marking) {
        return MarkingCheckResult {
            decision: MarkingDecision::Deny,
            decision_id,
            object_classification: Some(marking.into()),
            principal_ceiling: authority.classification_ceiling_token(),
            detail: "object marking is unknown to the activated lattice".into(),
        };
    }
    let Some(ceiling) = authority
        .classification_ceiling_token()
        .filter(|value| !value.is_empty())
    else {
        return MarkingCheckResult {
            decision: MarkingDecision::Deny,
            decision_id,
            object_classification: Some(marking.into()),
            principal_ceiling: None,
            detail: "principal has no classification_ceiling for a marked object".into(),
        };
    };
    match lattice.dominates(&ceiling, marking) {
        Ok(true) => MarkingCheckResult {
            decision: MarkingDecision::Allow,
            decision_id,
            object_classification: Some(marking.into()),
            principal_ceiling: Some(ceiling),
            detail: "principal ceiling dominates object marking".into(),
        },
        Ok(false) => MarkingCheckResult {
            decision: MarkingDecision::Deny,
            decision_id,
            object_classification: Some(marking.into()),
            principal_ceiling: Some(ceiling),
            detail: "principal ceiling does not dominate object marking".into(),
        },
        Err(_) => MarkingCheckResult {
            decision: MarkingDecision::Deny,
            decision_id,
            object_classification: Some(marking.into()),
            principal_ceiling: Some(ceiling),
            detail: "principal ceiling is unknown to the activated lattice".into(),
        },
    }
}

pub fn join_marking_tokens(
    lattice: Option<&ClassificationLattice>,
    left: Option<&str>,
    right: Option<&str>,
) -> Result<Option<String>, String> {
    let left = left.map(str::trim).filter(|value| !value.is_empty());
    let right = right.map(str::trim).filter(|value| !value.is_empty());
    match (lattice, left, right) {
        (_, None, None) => Ok(None),
        (_, Some(token), None) | (_, None, Some(token)) => Ok(Some(token.into())),
        (None, Some(left), Some(right)) => {
            let parsed_left = crate::sekai::markings::parse_optional_classification(left)?;
            let parsed_right = crate::sekai::markings::parse_optional_classification(right)?;
            Ok(match (parsed_left, parsed_right) {
                (Some(left), Some(right)) => Some(left.max(right).as_str().into()),
                (Some(token), None) | (None, Some(token)) => Some(token.as_str().into()),
                (None, None) => None,
            })
        }
        (Some(lattice), Some(left), Some(right)) => lattice.join(left, right),
    }
}

/// Path-carried marking identity. Tokens are only meaningful with the lattice
/// that produced them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PathClassification {
    pub namespace: String,
    pub lattice_digest: Option<String>,
    pub token: Option<String>,
}

impl PathClassification {
    pub fn visit_key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.namespace,
            self.lattice_digest.as_deref().unwrap_or(""),
            self.token.as_deref().unwrap_or("")
        )
    }
}

/// Whether a parent path marking may be joined with a child in `child_namespace`.
///
/// Cross-namespace reuse of a lattice token or digest fails closed. Unmarked
/// hops with no lattice on either side stay allowed.
pub fn validate_written_marking_token(
    token: Option<&str>,
    lattice: Option<&ClassificationLattice>,
) -> Result<(), String> {
    let Some(token) = token.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    match lattice {
        Some(lattice) if lattice.contains(token) => Ok(()),
        Some(_) => Err("object marking is unknown to the activated lattice".into()),
        None => crate::sekai::markings::parse_optional_classification(token).map(|_| ()),
    }
}

pub fn path_marking_compatible(
    parent: Option<&PathClassification>,
    child_namespace: &str,
    child_digest: Option<&str>,
    child_token: Option<&str>,
) -> bool {
    let Some(parent) = parent else {
        return true;
    };
    if parent.namespace != child_namespace {
        return parent.token.is_none()
            && child_token.is_none()
            && parent.lattice_digest.is_none()
            && child_digest.is_none();
    }
    parent.lattice_digest.as_deref() == child_digest
}

fn ancestors(token: &str, parents: &BTreeMap<String, Vec<String>>) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([token.to_string()]);
    while let Some(current) = queue.pop_front() {
        for parent in parents.get(&current).into_iter().flatten() {
            if seen.insert(parent.clone()) {
                queue.push_back(parent.clone());
            }
        }
    }
    seen
}

fn has_cycle(tokens: &BTreeSet<String>, parents: &BTreeMap<String, Vec<String>>) -> bool {
    fn visit(
        node: &str,
        parents: &BTreeMap<String, Vec<String>>,
        visiting: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
    ) -> bool {
        if done.contains(node) {
            return false;
        }
        if !visiting.insert(node.to_string()) {
            return true;
        }
        for parent in parents.get(node).into_iter().flatten() {
            if visit(parent, parents, visiting, done) {
                return true;
            }
        }
        visiting.remove(node);
        done.insert(node.to_string());
        false
    }
    let mut visiting = BTreeSet::new();
    let mut done = BTreeSet::new();
    tokens
        .iter()
        .any(|token| visit(token, parents, &mut visiting, &mut done))
}

fn ordered_pair(left: &str, right: &str) -> (String, String) {
    if left <= right {
        (left.into(), right.into())
    } else {
        (right.into(), left.into())
    }
}

fn validate_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-.:/".contains(character))
    {
        return Err(format!("invalid classification lattice {label}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lattice() -> ClassificationLattice {
        ClassificationLattice {
            contract_version: CLASSIFICATION_LATTICE_VERSION.into(),
            namespace: "ops".into(),
            tokens: vec![
                "public".into(),
                "internal".into(),
                "confidential".into(),
                "secret".into(),
                "health".into(),
            ],
            parents: BTreeMap::from([
                ("public".into(), vec!["internal".into()]),
                ("internal".into(), vec!["confidential".into()]),
                ("confidential".into(), vec!["secret".into()]),
                ("health".into(), vec!["secret".into()]),
            ]),
            incomparable: vec![("confidential".into(), "health".into())],
        }
        .prepare()
        .unwrap()
    }

    fn authority(token: Option<&str>) -> PrincipalAuthority {
        PrincipalAuthority {
            principal: "alice".into(),
            classification_ceiling: token.and_then(|value| {
                crate::sekai::markings::parse_optional_classification(value)
                    .ok()
                    .flatten()
            }),
            allowed_purposes: BTreeSet::new(),
            classification_token: token.map(str::to_string),
        }
    }

    #[test]
    fn lattice_dominance_join_and_incomparable_fail_closed() {
        let lattice = lattice();
        assert!(lattice.dominates("secret", "internal").unwrap());
        assert!(!lattice.dominates("internal", "secret").unwrap());
        assert!(!lattice.dominates("confidential", "health").unwrap());
        assert_eq!(
            lattice.join("public", "internal").unwrap().as_deref(),
            Some("internal")
        );
        assert_eq!(lattice.join("confidential", "health").unwrap(), None);
        assert_eq!(
            lattice.join("internal", "health").unwrap().as_deref(),
            Some("secret")
        );
        assert!(lattice.prepare().is_ok());
        let mut cyclic = lattice.clone();
        cyclic
            .parents
            .insert("secret".into(), vec!["public".into()]);
        assert!(cyclic.prepare().unwrap_err().contains("acyclic"));
        let mut unknown = lattice.clone();
        unknown.contract_version = "sekai.classification-lattice/v2".into();
        assert_eq!(
            unknown.prepare().unwrap_err(),
            "unsupported classification lattice contract"
        );
    }

    #[test]
    fn activated_lattice_denies_unknown_and_incomparable_markings() {
        let lattice = lattice();
        assert_eq!(
            evaluate_lattice_access("read", None, &authority(Some("secret")), Some(&lattice))
                .decision,
            MarkingDecision::NotApplicable
        );
        assert_eq!(
            evaluate_lattice_access(
                "read",
                Some("unknown"),
                &authority(Some("secret")),
                Some(&lattice)
            )
            .detail,
            "object marking is unknown to the activated lattice"
        );
        assert_eq!(
            evaluate_lattice_access(
                "read",
                Some("health"),
                &authority(Some("confidential")),
                Some(&lattice)
            )
            .decision,
            MarkingDecision::Deny
        );
        assert_eq!(
            evaluate_lattice_access(
                "read",
                Some("health"),
                &authority(Some("secret")),
                Some(&lattice)
            )
            .decision,
            MarkingDecision::Allow
        );
        let trusted = PrincipalAuthority {
            principal: "root".into(),
            classification_ceiling: None,
            allowed_purposes: BTreeSet::new(),
            classification_token: None,
        };
        assert_eq!(
            evaluate_lattice_access("read", Some("health"), &trusted, Some(&lattice)).detail,
            "trusted service principal"
        );
    }

    #[test]
    fn written_markings_accept_activated_lattice_tokens() {
        let lattice = lattice();
        assert!(validate_written_marking_token(Some("health"), Some(&lattice)).is_ok());
        assert!(validate_written_marking_token(Some("unknown"), Some(&lattice)).is_err());
        assert!(validate_written_marking_token(Some("confidential"), None).is_ok());
        assert!(validate_written_marking_token(Some("health"), None).is_err());
        assert!(validate_written_marking_token(None, Some(&lattice)).is_ok());
    }

    #[test]
    fn path_markings_fail_closed_across_namespaces_or_digests() {
        let parent = PathClassification {
            namespace: "ops".into(),
            lattice_digest: Some("digest-a".into()),
            token: Some("health".into()),
        };
        assert!(!path_marking_compatible(
            Some(&parent),
            "other",
            Some("digest-a"),
            Some("internal")
        ));
        assert!(!path_marking_compatible(
            Some(&parent),
            "ops",
            Some("digest-b"),
            Some("internal")
        ));
        assert!(path_marking_compatible(
            Some(&parent),
            "ops",
            Some("digest-a"),
            Some("internal")
        ));
        let unmarked = PathClassification {
            namespace: "ops".into(),
            lattice_digest: None,
            token: None,
        };
        assert!(path_marking_compatible(
            Some(&unmarked),
            "other",
            None,
            None
        ));
    }

    #[test]
    fn default_evidence_lattice_matches_ordinal_ceiling() {
        let lattice = ClassificationLattice::default_evidence_lattice("ops")
            .prepare()
            .unwrap();
        assert!(lattice.dominates("restricted", "public").unwrap());
        assert!(!lattice.dominates("public", "internal").unwrap());
        assert_eq!(
            lattice.join("public", "confidential").unwrap().as_deref(),
            Some("confidential")
        );
    }

    #[test]
    fn unactivated_namespace_keeps_evidence_ceiling() {
        let allow = evaluate_lattice_access(
            "read",
            Some("confidential"),
            &authority(Some("confidential")),
            None,
        );
        assert_eq!(allow.decision, MarkingDecision::Allow);
        let ignore_unknown =
            evaluate_lattice_access("read", Some("health"), &authority(Some("public")), None);
        assert_eq!(ignore_unknown.decision, MarkingDecision::NotApplicable);
    }
}
