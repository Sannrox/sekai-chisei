//! Authorized consumer impact from registered declarations only (#837).
//!
//! Registrations are `sekai.definition-consumer-binding/v1` objects. Impact
//! joins `CompareDefinitionRevisions` to visible declarations. The plane does
//! not infer undeclared dependents, and zero visible hits is not proof of
//! zero impact.

use crate::domain::Object;
use crate::sekai::definition_diff::DefinitionRevisionDiff;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const BINDING_CONTRACT: &str = "sekai.definition-consumer-binding/v1";
pub const BINDING_KIND: &str = "definition_consumer_binding";
pub const COMPLETENESS_COMPLETE: &str = "complete";
pub const COMPLETENESS_PARTIAL: &str = "partial";
pub const COMPLETENESS_STALE: &str = "stale";
pub const COMPLETENESS_UNAVAILABLE: &str = "unavailable";
pub const MAX_VISIBLE_BINDINGS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionConsumerBinding {
    pub contract_version: String,
    pub owner: String,
    pub resource_identity: String,
    pub namespace: String,
    pub member_kind: String,
    pub member_id: String,
    pub property: String,
    pub declaration_digest: String,
    pub source_locator: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerImpactPath {
    pub owner: String,
    pub resource_identity: String,
    pub member_kind: String,
    pub member_id: String,
    pub property: String,
    pub source_locator: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerImpactReport {
    pub completeness: String,
    pub from_revision_digest: String,
    pub to_revision_digest: String,
    pub impacts: Vec<ConsumerImpactPath>,
}

pub fn binding_digest(binding: &DefinitionConsumerBinding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_CONTRACT.as_bytes());
    for part in [
        binding.owner.as_str(),
        binding.resource_identity.as_str(),
        binding.namespace.as_str(),
        binding.member_kind.as_str(),
        binding.member_id.as_str(),
        binding.property.as_str(),
        binding.source_locator.as_str(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub fn binding_from_object(object: &Object) -> Result<DefinitionConsumerBinding, String> {
    if object.kind != BINDING_KIND {
        return Err(COMPLETENESS_UNAVAILABLE.into());
    }
    let required = |key: &str| {
        object
            .properties
            .get(key)
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .ok_or_else(|| format!("{key} is required"))
    };
    let binding = DefinitionConsumerBinding {
        contract_version: required("contract_version")?,
        owner: required("owner")?,
        resource_identity: required("resource_identity")?,
        namespace: object.namespace.clone(),
        member_kind: required("member_kind")?,
        member_id: required("member_id")?,
        property: object
            .properties
            .get("property")
            .cloned()
            .unwrap_or_default(),
        declaration_digest: required("declaration_digest")?,
        source_locator: required("source_locator")?,
    };
    if binding.contract_version != BINDING_CONTRACT {
        return Err(COMPLETENESS_UNAVAILABLE.into());
    }
    Ok(binding)
}

pub fn report_consumer_impact(
    diff: &DefinitionRevisionDiff,
    bindings: &[Object],
) -> ConsumerImpactReport {
    if bindings.len() > MAX_VISIBLE_BINDINGS {
        return ConsumerImpactReport {
            completeness: COMPLETENESS_PARTIAL.into(),
            from_revision_digest: diff.from_revision_digest.clone(),
            to_revision_digest: diff.to_revision_digest.clone(),
            impacts: Vec::new(),
        };
    }
    let affected = affected_references(diff);
    let mut completeness = COMPLETENESS_COMPLETE;
    let mut impacts = Vec::new();
    for object in bindings {
        let Ok(binding) = binding_from_object(object) else {
            completeness = COMPLETENESS_STALE;
            continue;
        };
        if binding.declaration_digest != binding_digest(&binding) {
            completeness = COMPLETENESS_STALE;
            continue;
        }
        if !binding_matches(&binding, &affected) {
            continue;
        }
        impacts.push(ConsumerImpactPath {
            owner: binding.owner,
            resource_identity: binding.resource_identity,
            member_kind: binding.member_kind,
            member_id: binding.member_id,
            property: binding.property,
            source_locator: binding.source_locator,
        });
    }
    impacts.sort_by(|left, right| {
        (
            left.owner.as_str(),
            left.resource_identity.as_str(),
            left.member_id.as_str(),
            left.property.as_str(),
        )
            .cmp(&(
                right.owner.as_str(),
                right.resource_identity.as_str(),
                right.member_id.as_str(),
                right.property.as_str(),
            ))
    });
    ConsumerImpactReport {
        completeness: completeness.into(),
        from_revision_digest: diff.from_revision_digest.clone(),
        to_revision_digest: diff.to_revision_digest.clone(),
        impacts,
    }
}

fn affected_references(diff: &DefinitionRevisionDiff) -> BTreeSet<(String, String, String)> {
    let mut refs = BTreeSet::new();
    for change in &diff.removed {
        refs.insert((
            change.member_kind.clone(),
            change.member_id.clone(),
            String::new(),
        ));
        for property in change
            .removed_properties
            .iter()
            .chain(change.changed_properties.iter())
        {
            refs.insert((
                change.member_kind.clone(),
                change.member_id.clone(),
                property.clone(),
            ));
        }
    }
    for change in &diff.changed {
        for property in change
            .removed_properties
            .iter()
            .chain(change.changed_properties.iter())
        {
            refs.insert((
                change.member_kind.clone(),
                change.member_id.clone(),
                property.clone(),
            ));
        }
    }
    refs
}

fn binding_matches(
    binding: &DefinitionConsumerBinding,
    affected: &BTreeSet<(String, String, String)>,
) -> bool {
    let member = (
        binding.member_kind.clone(),
        binding.member_id.clone(),
        String::new(),
    );
    if affected.contains(&member) {
        return true;
    }
    if binding.property.is_empty() {
        return affected.iter().any(|(kind, id, property)| {
            kind == &binding.member_kind && id == &binding.member_id && !property.is_empty()
        });
    }
    affected.contains(&(
        binding.member_kind.clone(),
        binding.member_id.clone(),
        binding.property.clone(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::definition_diff::DefinitionMemberChange;
    use std::collections::HashMap;

    fn binding_object(
        id: &str,
        owner: &str,
        property: &str,
        locator: &str,
        digest: Option<&str>,
    ) -> Object {
        kind_binding_object(
            id,
            owner,
            "object_type",
            "Customer",
            property,
            locator,
            digest,
        )
    }

    fn kind_binding_object(
        id: &str,
        owner: &str,
        member_kind: &str,
        member_id: &str,
        property: &str,
        locator: &str,
        digest: Option<&str>,
    ) -> Object {
        let mut binding = DefinitionConsumerBinding {
            contract_version: BINDING_CONTRACT.into(),
            owner: owner.into(),
            resource_identity: format!("app:{id}"),
            namespace: "sales".into(),
            member_kind: member_kind.into(),
            member_id: member_id.into(),
            property: property.into(),
            declaration_digest: String::new(),
            source_locator: locator.into(),
        };
        binding.declaration_digest = digest.unwrap_or(&binding_digest(&binding)).into();
        Object {
            id: id.into(),
            kind: BINDING_KIND.into(),
            name: id.into(),
            namespace: "sales".into(),
            external_id: format!("sales:{id}"),
            properties: HashMap::from([
                ("contract_version".into(), binding.contract_version),
                ("owner".into(), binding.owner),
                ("resource_identity".into(), binding.resource_identity),
                ("member_kind".into(), binding.member_kind),
                ("member_id".into(), binding.member_id),
                ("property".into(), binding.property),
                ("declaration_digest".into(), binding.declaration_digest),
                ("source_locator".into(), binding.source_locator),
            ]),
            created: 1,
            updated: 1,
        }
    }

    fn owner_removed() -> DefinitionRevisionDiff {
        DefinitionRevisionDiff {
            from_revision_digest: "sha256:from".into(),
            to_revision_digest: "sha256:to".into(),
            diff_digest: "sha256:diff".into(),
            added: vec![DefinitionMemberChange {
                member_kind: "object_type".into(),
                member_id: "Customer".into(),
                from_member_digest: String::new(),
                to_member_digest: "sha256:add".into(),
                added_properties: vec!["nickname".into()],
                removed_properties: Vec::new(),
                changed_properties: Vec::new(),
            }],
            removed: Vec::new(),
            changed: vec![DefinitionMemberChange {
                member_kind: "object_type".into(),
                member_id: "Customer".into(),
                from_member_digest: "sha256:a".into(),
                to_member_digest: "sha256:b".into(),
                added_properties: vec!["nickname".into()],
                removed_properties: vec!["owner".into()],
                changed_properties: Vec::new(),
            }],
        }
    }

    #[test]
    fn removed_owner_hits_two_registered_consumers() {
        let report = report_consumer_impact(
            &owner_removed(),
            &[
                binding_object("billing", "alice", "owner", "app://billing#owner", None),
                binding_object("crm", "bob", "owner", "app://crm#owner", None),
                binding_object("notes", "cara", "nickname", "app://notes#nickname", None),
            ],
        );
        assert_eq!(report.completeness, COMPLETENESS_COMPLETE);
        assert_eq!(report.impacts.len(), 2);
        assert_eq!(report.impacts[0].resource_identity, "app:billing");
        assert_eq!(report.impacts[1].resource_identity, "app:crm");
        assert!(
            report
                .impacts
                .iter()
                .all(|impact| impact.property == "owner")
        );
    }

    #[test]
    fn stale_digest_does_not_invent_dependents() {
        let report = report_consumer_impact(
            &owner_removed(),
            &[binding_object(
                "billing",
                "alice",
                "owner",
                "app://billing#owner",
                Some("sha256:dead"),
            )],
        );
        assert_eq!(report.completeness, COMPLETENESS_STALE);
        assert!(report.impacts.is_empty());
    }

    #[test]
    fn impact_lists_consumers_across_type_function_transform_and_policy() {
        let diff = DefinitionRevisionDiff {
            from_revision_digest: "sha256:from".into(),
            to_revision_digest: "sha256:to".into(),
            diff_digest: "sha256:diff".into(),
            added: Vec::new(),
            removed: vec![
                DefinitionMemberChange {
                    member_kind: "function".into(),
                    member_id: "CountOpen".into(),
                    from_member_digest: "sha256:fn".into(),
                    to_member_digest: String::new(),
                    added_properties: Vec::new(),
                    removed_properties: Vec::new(),
                    changed_properties: Vec::new(),
                },
                DefinitionMemberChange {
                    member_kind: "transform".into(),
                    member_id: "ProjectTickets".into(),
                    from_member_digest: "sha256:tf".into(),
                    to_member_digest: String::new(),
                    added_properties: Vec::new(),
                    removed_properties: Vec::new(),
                    changed_properties: Vec::new(),
                },
                DefinitionMemberChange {
                    member_kind: "policy".into(),
                    member_id: "TicketPolicy".into(),
                    from_member_digest: "sha256:pol".into(),
                    to_member_digest: String::new(),
                    added_properties: Vec::new(),
                    removed_properties: Vec::new(),
                    changed_properties: Vec::new(),
                },
            ],
            changed: vec![DefinitionMemberChange {
                member_kind: "object_type".into(),
                member_id: "Ticket".into(),
                from_member_digest: "sha256:a".into(),
                to_member_digest: "sha256:b".into(),
                added_properties: Vec::new(),
                removed_properties: vec!["owner".into()],
                changed_properties: Vec::new(),
            }],
        };
        let report = report_consumer_impact(
            &diff,
            &[
                kind_binding_object(
                    "crm",
                    "alice",
                    "object_type",
                    "Ticket",
                    "owner",
                    "app://crm#owner",
                    None,
                ),
                kind_binding_object(
                    "count",
                    "bob",
                    "function",
                    "CountOpen",
                    "",
                    "app://count#fn",
                    None,
                ),
                kind_binding_object(
                    "proj",
                    "cara",
                    "transform",
                    "ProjectTickets",
                    "",
                    "app://proj#tf",
                    None,
                ),
                kind_binding_object(
                    "acl",
                    "drew",
                    "policy",
                    "TicketPolicy",
                    "",
                    "app://acl#policy",
                    None,
                ),
            ],
        );
        assert_eq!(report.completeness, COMPLETENESS_COMPLETE);
        assert_eq!(
            report
                .impacts
                .iter()
                .map(|impact| (impact.member_kind.as_str(), impact.member_id.as_str()))
                .collect::<Vec<_>>(),
            [
                ("object_type", "Ticket"),
                ("function", "CountOpen"),
                ("transform", "ProjectTickets"),
                ("policy", "TicketPolicy"),
            ]
        );
    }
}
