//! `sekaictl ontology find` (#2298): which published object types, link
//! types and properties go by a name.
//!
//! A client-side match over the existing definition reads
//! (`GetPublishedDefinitionRevision`, then `GetDefinitionMember`). A name
//! matches a member's id, its `name` or `alternative_names`, a declared
//! property, or a property's `property_alternative_names`. Matching ignores
//! case and treats `_`, `-` and runs of spaces as one separator, so
//! `shipment status`, `Shipment_Status` and `shipment-status` are the same
//! name. Unreviewed text matches too; the output says so.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::ontology_export::{ExportMember, published_members};
use sekai_admin_client::client::connect_sekai;
use sekai_core::sekai::definition_text::{
    ALTERNATIVE_NAMES, PROPERTY_ALTERNATIVE_NAMES, carries_text, unreviewed_paths,
};
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// One member or property that goes by the searched name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NameMatch {
    pub member_kind: String,
    pub member_id: String,
    /// The matching property; `None` when the member itself matched.
    pub property: Option<String>,
    /// The definition field that matched: `id`, `name`, `properties`,
    /// `alternative_names` or `property_alternative_names/<property>`.
    pub field: String,
    /// Whether the matching text is still listed in `unreviewed`.
    pub unreviewed: bool,
}

/// Finds `name` in the namespace's published definitions.
pub async fn find(target: &str, namespace: &str, name: &str) -> Result<Vec<NameMatch>, BoxErr> {
    let mut client = SekaiServiceClient::new(connect_sekai(target).await?);
    let (_, members) = published_members(&mut client, namespace)
        .await?
        .ok_or_else(|| std::io::Error::other("namespace has no published definition revision"))?;
    Ok(match_name(&members, name)?)
}

fn normalize(name: &str) -> String {
    name.split(|c: char| c == '_' || c == '-' || c.is_whitespace())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

fn strings(value: Option<&Value>) -> impl Iterator<Item = &str> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// Matches over object and link types; other member kinds carry no names
/// worth searching.
pub fn match_name(members: &[ExportMember], name: &str) -> Result<Vec<NameMatch>, String> {
    let wanted = normalize(name);
    if wanted.is_empty() {
        return Err("--name must not be empty".into());
    }
    let same = |candidate: &str| normalize(candidate) == wanted;
    let mut found = BTreeSet::new();
    for member in members.iter().filter(|member| carries_text(&member.kind)) {
        let body: Value = serde_json::from_str(&member.definition_json)
            .map_err(|error| format!("{}/{}: {error}", member.kind, member.id))?;
        let unreviewed: BTreeSet<String> = unreviewed_paths(&body).into_iter().collect();
        let mut hit = |property: Option<&str>, field: String| {
            found.insert(NameMatch {
                member_kind: member.kind.clone(),
                member_id: member.id.clone(),
                property: property.map(str::to_string),
                unreviewed: unreviewed.contains(&field),
                field,
            });
        };
        if same(&member.id) {
            hit(None, "id".into());
        }
        if body.get("name").and_then(Value::as_str).is_some_and(same) {
            hit(None, "name".into());
        }
        if strings(body.get(ALTERNATIVE_NAMES)).any(same) {
            hit(None, ALTERNATIVE_NAMES.into());
        }
        for property in strings(body.get("properties")).filter(|property| same(property)) {
            hit(Some(property), "properties".into());
        }
        if let Some(map) = body
            .get(PROPERTY_ALTERNATIVE_NAMES)
            .and_then(Value::as_object)
        {
            for (property, names) in map {
                if strings(Some(names)).any(same) {
                    hit(
                        Some(property),
                        format!("{PROPERTY_ALTERNATIVE_NAMES}/{property}"),
                    );
                }
            }
        }
    }
    Ok(found.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_business_name_finds_the_type_and_property_that_go_by_it() {
        let members = [
            ExportMember {
                kind: "object_type".into(),
                id: "shipment".into(),
                definition_json: serde_json::json!({
                    "name": "shipment",
                    "properties": ["id", "shp_stat_cd"],
                    "alternative_names": ["Parcel"],
                    "property_alternative_names": {"shp_stat_cd": ["Shipment Status"]},
                    "unreviewed": ["property_alternative_names/shp_stat_cd"],
                })
                .to_string(),
            },
            ExportMember {
                kind: "function".into(),
                id: "parcel".into(),
                definition_json: "{}".into(),
            },
        ];
        let status = match_name(&members, "shipment-status").unwrap();
        assert_eq!(
            status,
            [NameMatch {
                member_kind: "object_type".into(),
                member_id: "shipment".into(),
                property: Some("shp_stat_cd".into()),
                field: "property_alternative_names/shp_stat_cd".into(),
                unreviewed: true,
            }]
        );
        let parcel = match_name(&members, "parcel").unwrap();
        assert_eq!(parcel.len(), 1, "{parcel:?}");
        assert_eq!(parcel[0].field, "alternative_names");
        assert!(!parcel[0].unreviewed);
        assert!(match_name(&members, "SHP STAT CD").unwrap()[0].field == "properties");
        assert!(match_name(&members, "invoice").unwrap().is_empty());
    }
}
