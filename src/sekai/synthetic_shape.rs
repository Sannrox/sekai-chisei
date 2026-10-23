//! Shape-driven synthetic domain for local twins (#1735).
//!
//! A local twin is an offline copy of a tenant for developers and agents
//! that carries no real object values. Its data comes from the tenant's
//! *shape*: the object type definitions, and per kind the object count, the
//! share of each marking, and per property a numeric range or nothing. [`shape_of`] extracts a shape from real
//! objects. [`ShapeDomain`] lets the synthetic generator build a twin from
//! one, deterministically from a seed.
//!
//! The extractor keeps no individual value:
//!
//! - No string is kept: a repeated string may still be an identifier. Enum
//!   values come from the definition, and booleans are sampled.
//! - A numeric range comes only from public values of a public property:
//!   at least [`MIN_CONTRIBUTORS`] of them, not all equal, neither end
//!   zero, rounded strictly outward to two significant figures. Timestamps may be numbers or RFC 3339.
//! - An object is public only when it is unmarked or marked `public`; an
//!   unknown marking is protected.
//! - Everything else is opaque, and the twin fills it with placeholders.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::domain::{Link, Object};
use crate::sekai::governed_action_type::GovernedActionType;
use crate::sekai::markings;
use crate::sekai::schema::{ObjectType, PropertyType};
use crate::sekai::synthetic::{
    DomainData, DomainGenerator, DomainGovernance, GeneratedObject, Rng, Spec, role_spaces,
    standard_principals,
};

pub const TWIN_SHAPE_FORMAT: &str = "sekai.twin-shape/v1";
/// Fewest contributing values for a range to be kept.
pub const MIN_CONTRIBUTORS: usize = 5;
/// Most objects a twin generates, whatever the shape says.
pub const MAX_TWIN_OBJECTS: u64 = 50_000;
/// The most links a twin holds.
pub const MAX_TWIN_LINKS: u64 = 200_000;
/// Integer ranges stay where an `f64` is exact, so sampling cannot overflow.
const MAX_EXACT_INTEGER: f64 = 9_007_199_254_740_992.0;

/// What a tenant looks like, without its values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwinShape {
    pub format: String,
    pub object_types: Vec<ObjectType>,
    pub kinds: Vec<KindShape>,
    pub links: Vec<LinkShape>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KindShape {
    pub kind: String,
    pub count: u64,
    /// Objects per marking token; unmarked objects are under `""`.
    pub markings: BTreeMap<String, u64>,
    pub properties: BTreeMap<String, PropertyShape>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "shape", rename_all = "snake_case")]
pub enum PropertyShape {
    Numeric { min: f64, max: f64 },
    Opaque,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkShape {
    pub relation: String,
    pub from_kind: String,
    pub to_kind: String,
    pub count: u64,
}

/// `value` rounded strictly outward to two significant figures, or `None`
/// when it has no usable scale (zero, subnormal, or not finite).
fn round_out(value: f64, up: bool) -> Option<f64> {
    if !value.is_normal() {
        return None;
    }
    let magnitude = 10f64.powi(value.abs().log10().floor() as i32 - 1);
    if !magnitude.is_normal() {
        return None;
    }
    let scaled = value / magnitude;
    // An aligned value moves one step out, so the bound is never the value.
    // Division can land just short of an integer, so the result is checked.
    let first = if up {
        scaled.floor() + 1.0
    } else {
        scaled.ceil() - 1.0
    };
    (0..3)
        .map(|extra| (first + if up { extra } else { -extra } as f64) * magnitude)
        .find(|bound| bound.is_finite() && if up { *bound > value } else { *bound < value })
}

/// Whether the generator can sample `min..=max` for `prop_type`: finite,
/// ordered, with a finite span, and for an integer non-negative (the schema
/// takes only digits), holding an integer, and within exact `f64` range.
fn sampleable(prop_type: &PropertyType, min: f64, max: f64) -> bool {
    min.is_finite()
        && max.is_finite()
        && min <= max
        && (max - min).is_finite()
        && (*prop_type != PropertyType::Int
            || (min >= 0.0 && max <= MAX_EXACT_INTEGER && min.ceil() <= max.floor()))
}

/// Unmarked, or explicitly public. Any other token, including one this
/// build does not know, is protected.
fn is_public(object: &Object) -> bool {
    markings::object_marking_token(object)
        .map(str::trim)
        .is_none_or(|token| token.is_empty() || token.eq_ignore_ascii_case("public"))
}

/// A numeric reading of `value` for `prop_type`: a number, or for a
/// timestamp also an RFC 3339 time, in milliseconds.
fn numeric(prop_type: &PropertyType, value: &str) -> Option<f64> {
    if let Ok(number) = value.trim().parse::<f64>() {
        return number.is_finite().then_some(number);
    }
    (*prop_type == PropertyType::Timestamp)
        .then(|| chrono::DateTime::parse_from_rfc3339(value.trim()).ok())
        .flatten()
        .map(|time| time.timestamp_millis() as f64)
}

/// The shape of `objects` and `links` under `object_types`. Built-in kinds,
/// and objects of a kind without a definition, are left out: the twin's
/// target already has the built-ins, and the generator registers only
/// tenant definitions.
pub fn shape_of(object_types: &[ObjectType], objects: &[Object], links: &[Link]) -> TwinShape {
    let object_types: Vec<ObjectType> = object_types
        .iter()
        .filter(|object_type| !object_type.is_builtin)
        .cloned()
        .collect();
    let mut kinds = Vec::new();
    for object_type in &object_types {
        let of_kind: Vec<&Object> = objects
            .iter()
            .filter(|object| object.kind == object_type.kind)
            .collect();
        let mut marking_counts = BTreeMap::new();
        for object in &of_kind {
            let token = markings::object_marking_token(object).unwrap_or_default();
            *marking_counts.entry(token.to_string()).or_insert(0u64) += 1;
        }
        let mut properties = BTreeMap::new();
        // The marking is carried by the marking counts, not as a property.
        for property in object_type
            .properties
            .iter()
            .filter(|property| property.name != markings::OBJECT_CLASSIFICATION_PROPERTY)
        {
            let public_property = property.classification.trim().is_empty()
                || property.classification.eq_ignore_ascii_case("public");
            let shape = match property.prop_type {
                // Ranges, like categories, come only from public values,
                // and only when they span something: a constant would be
                // the value itself.
                PropertyType::Int | PropertyType::Float | PropertyType::Timestamp
                    if public_property =>
                {
                    let values: Vec<f64> = of_kind
                        .iter()
                        .filter(|object| is_public(object))
                        .filter_map(|object| {
                            numeric(&property.prop_type, object.properties.get(&property.name)?)
                        })
                        .collect();
                    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
                    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
                    // Zero has no scale to round by, so a range ending at
                    // zero has no bounds.
                    let bounds = round_out(min, false).zip(round_out(max, true));
                    if let Some((low, high)) = bounds
                        && values.len() >= MIN_CONTRIBUTORS
                        && min < max
                        && low < high
                        && sampleable(&property.prop_type, low, high)
                    {
                        PropertyShape::Numeric {
                            min: low,
                            max: high,
                        }
                    } else {
                        PropertyShape::Opaque
                    }
                }
                _ => PropertyShape::Opaque,
            };
            properties.insert(property.name.clone(), shape);
        }
        kinds.push(KindShape {
            kind: object_type.kind.clone(),
            count: of_kind.len() as u64,
            markings: marking_counts,
            properties,
        });
    }
    // Links only between shaped kinds: the twin has no other objects.
    let kind_of: HashMap<&str, &str> = objects
        .iter()
        .filter(|object| kinds.iter().any(|kind| kind.kind == object.kind))
        .map(|object| (object.id.as_str(), object.kind.as_str()))
        .collect();
    let mut link_counts: BTreeMap<(String, String, String), u64> = BTreeMap::new();
    for link in links {
        if let (Some(from), Some(to)) = (
            kind_of.get(link.from_id.as_str()),
            kind_of.get(link.to_id.as_str()),
        ) {
            *link_counts
                .entry((link.relation.clone(), from.to_string(), to.to_string()))
                .or_insert(0) += 1;
        }
    }
    TwinShape {
        format: TWIN_SHAPE_FORMAT.into(),
        object_types,
        kinds,
        links: link_counts
            .into_iter()
            .map(|((relation, from_kind, to_kind), count)| LinkShape {
                relation,
                from_kind,
                to_kind,
                count,
            })
            .collect(),
    }
}

/// A synthetic domain that builds a tenant of `shape`.
pub struct ShapeDomain {
    shape: TwinShape,
}

impl ShapeDomain {
    pub fn new(shape: TwinShape) -> Result<Self, String> {
        if shape.format != TWIN_SHAPE_FORMAT {
            return Err(format!("twin shape format must be {TWIN_SHAPE_FORMAT}"));
        }
        let total = shape
            .kinds
            .iter()
            .try_fold(0u64, |total, kind| total.checked_add(kind.count))
            .unwrap_or(u64::MAX);
        if total > MAX_TWIN_OBJECTS {
            return Err(format!(
                "a twin holds at most {MAX_TWIN_OBJECTS} objects; the shape has {total}"
            ));
        }
        let links = shape
            .links
            .iter()
            .try_fold(0u64, |total, link| total.checked_add(link.count))
            .unwrap_or(u64::MAX);
        if links > MAX_TWIN_LINKS {
            return Err(format!(
                "a twin holds at most {MAX_TWIN_LINKS} links; the shape has {links}"
            ));
        }
        for link in shape.links.iter().filter(|link| link.count > 0) {
            for end in [&link.from_kind, &link.to_kind] {
                if !shape
                    .kinds
                    .iter()
                    .any(|kind| kind.kind == *end && kind.count > 0)
                {
                    return Err(format!(
                        "relation {} links kind {end}, which has no objects",
                        link.relation
                    ));
                }
            }
        }
        // The generator registers the definitions in a fresh schema, which
        // knows only the built-in interfaces.
        let interfaces: Vec<String> = crate::sekai::schema::builtin_interfaces()
            .into_iter()
            .map(|interface| interface.name)
            .collect();
        for object_type in &shape.object_types {
            if let Some(custom) = object_type
                .implements
                .iter()
                .find(|name| !interfaces.contains(name))
            {
                return Err(format!(
                    "kind {} implements tenant interface {custom}, which a twin cannot carry",
                    object_type.kind
                ));
            }
        }
        for kind in &shape.kinds {
            let definition = shape
                .object_types
                .iter()
                .find(|object_type| object_type.kind == kind.kind);
            for (name, property) in &kind.properties {
                let prop_type = definition
                    .and_then(|object_type| {
                        object_type.properties.iter().find(|def| def.name == *name)
                    })
                    .map(|def| &def.prop_type);
                if let PropertyShape::Numeric { min, max } = property
                    && !prop_type.is_some_and(|prop_type| sampleable(prop_type, *min, *max))
                {
                    return Err(format!(
                        "kind {} property {name} has an invalid range",
                        kind.kind
                    ));
                }
            }
            // The twin enforces only the standard classifications; a tenant
            // lattice token would read as unmarked there.
            if let Some(token) = kind
                .markings
                .keys()
                .find(|token| markings::parse_optional_classification(token).is_err())
            {
                return Err(format!(
                    "kind {} has marking {token}, which a twin cannot enforce",
                    kind.kind
                ));
            }
            // Markings are assigned one per object, so they cannot outnumber
            // the objects.
            let marked = kind
                .markings
                .values()
                .try_fold(0u64, |total, count| total.checked_add(*count));
            if marked.is_none_or(|marked| marked > kind.count) {
                return Err(format!(
                    "kind {} has more marking counts than objects",
                    kind.kind
                ));
            }
            let Some(object_type) = shape
                .object_types
                .iter()
                .find(|object_type| object_type.kind == kind.kind)
            else {
                return Err(format!("kind {} has no definition in the shape", kind.kind));
            };
            if let Some(property) = object_type.properties.iter().find(|property| {
                property.required
                    && matches!(
                        property.prop_type,
                        PropertyType::Link | PropertyType::Computed | PropertyType::Struct
                    )
            }) {
                return Err(format!(
                    "kind {} requires {}, which a twin cannot generate",
                    kind.kind, property.name
                ));
            }
        }
        Ok(Self { shape })
    }
}

/// A value for `property` under its shape.
fn value(
    property: &crate::sekai::schema::PropertyDef,
    shape: Option<&PropertyShape>,
    kind: &str,
    index: usize,
    rng: &mut Rng,
) -> Option<String> {
    match (&property.prop_type, shape) {
        (PropertyType::Enum, _) if !property.enum_values.is_empty() => {
            Some(property.enum_values[rng.below(property.enum_values.len())].clone())
        }
        (PropertyType::Int, Some(PropertyShape::Numeric { min, max })) => {
            let (low, high) = (min.ceil() as i64, max.floor() as i64);
            let span = (high - low) as u64 + 1;
            Some((low + (rng.next_u64() % span) as i64).to_string())
        }
        (
            PropertyType::Float | PropertyType::Timestamp,
            Some(PropertyShape::Numeric { min, max }),
        ) => {
            let unit = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
            let value = min + (max - min) * unit;
            Some(if property.prop_type == PropertyType::Timestamp {
                (value as i64).to_string()
            } else {
                value.to_string()
            })
        }
        (PropertyType::Int | PropertyType::Timestamp, _) => Some("0".into()),
        (PropertyType::Float, _) => Some("0".into()),
        (PropertyType::Bool, _) => Some((rng.below(2) == 1).to_string()),
        (PropertyType::String, _) => Some(format!("{kind}-{}-{index}", property.name)),
        _ => None,
    }
}

impl DomainGenerator for ShapeDomain {
    fn name(&self) -> &'static str {
        "twin"
    }

    fn object_types(&self) -> Vec<ObjectType> {
        self.shape.object_types.clone()
    }

    fn build(&self, _spec: &Spec, rng: &mut Rng) -> DomainData {
        let mut objects = Vec::new();
        let mut by_kind: HashMap<&str, Vec<usize>> = HashMap::new();
        for kind in &self.shape.kinds {
            let object_type = self
                .shape
                .object_types
                .iter()
                .find(|object_type| object_type.kind == kind.kind)
                .expect("ShapeDomain::new checked every kind has a definition");
            // Markings in the shape's proportions, assigned in order.
            let mut markings: Vec<&String> = Vec::new();
            for (token, count) in &kind.markings {
                markings.extend(std::iter::repeat_n(token, *count as usize));
            }
            for index in 0..kind.count as usize {
                let mut properties = HashMap::new();
                for property in object_type
                    .properties
                    .iter()
                    .filter(|property| property.name != markings::OBJECT_CLASSIFICATION_PROPERTY)
                {
                    if let Some(value) = value(
                        property,
                        kind.properties.get(&property.name),
                        &kind.kind,
                        index,
                        rng,
                    ) {
                        properties.insert(property.name.clone(), value);
                    }
                }
                if let Some(token) = markings.get(index).filter(|token| !token.is_empty()) {
                    properties.insert(
                        markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                        token.to_string(),
                    );
                }
                by_kind.entry(&kind.kind).or_default().push(objects.len());
                objects.push(GeneratedObject {
                    kind: kind.kind.clone(),
                    name: format!("{}-{}", kind.kind, index + 1),
                    properties,
                });
            }
        }
        let mut links = Vec::new();
        for link in &self.shape.links {
            let (Some(from), Some(to)) = (
                by_kind.get(link.from_kind.as_str()),
                by_kind.get(link.to_kind.as_str()),
            ) else {
                continue;
            };
            for _ in 0..link.count {
                links.push((
                    from[rng.below(from.len())],
                    to[rng.below(to.len())],
                    link.relation.clone(),
                ));
            }
        }
        DomainData { objects, links }
    }

    fn action_types(&self, _namespace: &str) -> Vec<GovernedActionType> {
        Vec::new()
    }

    fn governance(&self, spec: &Spec, _data: &DomainData, rng: &mut Rng) -> DomainGovernance {
        let principals = standard_principals(spec, rng);
        let spaces = role_spaces(&principals, "twin-work", "twin-oversight");
        DomainGovernance {
            principals,
            spaces,
            actions: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::schema::PropertyDef;
    use crate::sekai::synthetic::{SizePreset, generate};

    fn property(name: &str, prop_type: PropertyType, classification: &str) -> PropertyDef {
        PropertyDef {
            name: name.into(),
            prop_type,
            required: false,
            description: String::new(),
            enum_values: Vec::new(),
            link_kind: String::new(),
            compute_expr: String::new(),
            classification: classification.into(),
            struct_fields: Vec::new(),
        }
    }

    fn types() -> Vec<ObjectType> {
        vec![ObjectType {
            kind: "ticket".into(),
            description: String::new(),
            properties: vec![
                property("status", PropertyType::String, "public"),
                property("summary", PropertyType::String, "public"),
                property("cost", PropertyType::Int, "public"),
                property("owner_email", PropertyType::String, "sensitive"),
            ],
            is_builtin: false,
            implements: Vec::new(),
        }]
    }

    fn tenant() -> (Vec<Object>, Vec<Link>) {
        let objects: Vec<Object> = (0..12)
            .map(|index| {
                let mut properties: HashMap<String, String> = [
                    ("status", if index % 2 == 0 { "open" } else { "closed" }),
                    ("cost", &*format!("{}", 1234 + index * 37)),
                    ("owner_email", &*format!("person{index}@example.test")),
                ]
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect();
                // Free text: every value distinct.
                properties.insert("summary".into(), format!("printer jam on floor {index}"));
                if index >= 10 {
                    properties.insert(
                        markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                        "confidential".into(),
                    );
                    properties.insert("status".into(), "escalated-secret".into());
                }
                Object {
                    id: format!("t-{index}"),
                    kind: "ticket".into(),
                    name: format!("ticket {index}"),
                    namespace: "acme".into(),
                    external_id: String::new(),
                    properties,
                    created: 1,
                    updated: 1,
                }
            })
            .collect();
        let links = (0..6)
            .map(|index| Link {
                id: format!("l-{index}"),
                from_id: format!("t-{index}"),
                to_id: format!("t-{}", index + 1),
                relation: "blocks".into(),
                created: 1,
            })
            .collect();
        (objects, links)
    }

    #[test]
    fn a_shape_keeps_no_individual_value() {
        let (objects, links) = tenant();
        let shape = shape_of(&types(), &objects, &links);
        let ticket = &shape.kinds[0];
        assert_eq!(ticket.count, 12);
        assert_eq!(ticket.markings.get("confidential"), Some(&2));
        // Strings, even repeated ones, and a confidential property are opaque.
        assert_eq!(ticket.properties["status"], PropertyShape::Opaque);
        assert_eq!(ticket.properties["summary"], PropertyShape::Opaque);
        assert_eq!(ticket.properties["owner_email"], PropertyShape::Opaque);
        // The range, from public objects, is rounded outward: 1234..1567
        // becomes 1200..1600, and an aligned bound moves one step out.
        assert_eq!(round_out(1200.0, false), Some(1100.0));
        assert_eq!(round_out(1600.0, true), Some(1700.0));
        assert!(round_out(0.29, true).unwrap() > 0.29);
        assert!(round_out(0.29, false).unwrap() < 0.29);
        assert_eq!(round_out(5e-324, true), None);
        let (_, mut zeroed_links) = tenant();
        zeroed_links.clear();
        let mut zeroed = tenant().0;
        for (index, object) in zeroed.iter_mut().enumerate() {
            object
                .properties
                .insert("cost".into(), (index * 10).to_string());
        }
        assert_eq!(
            shape_of(&types(), &zeroed, &zeroed_links).kinds[0].properties["cost"],
            PropertyShape::Opaque
        );
        assert_eq!(
            ticket.properties["cost"],
            PropertyShape::Numeric {
                min: 1200.0,
                max: 1600.0
            }
        );
        let serialized = serde_json::to_string(&shape).unwrap();
        for leaked in [
            "printer jam",
            "example.test",
            "escalated-secret",
            "1234",
            "1641",
        ] {
            assert!(!serialized.contains(leaked), "{leaked} leaked");
        }
        assert_eq!(shape.links[0].count, 6);
    }

    #[test]
    fn a_twin_matches_its_shape_and_reproduces_from_the_seed() {
        let (objects, links) = tenant();
        let shape = shape_of(&types(), &objects, &links);
        let spec = Spec {
            namespace: "twin".into(),
            seed: 7,
            preset: SizePreset::Demo,
        };
        let domain = ShapeDomain::new(shape.clone()).unwrap();
        let plan = generate(&domain, &spec).unwrap();
        let again = generate(&ShapeDomain::new(shape).unwrap(), &spec).unwrap();
        // The plan's digest is over its canonical form.
        assert_eq!(plan.digest, again.digest);
        let generated: Vec<&Object> = plan
            .objects
            .iter()
            .filter(|object| object.kind == "ticket")
            .collect();
        assert_eq!(generated.len(), 12);
        assert_eq!(
            generated
                .iter()
                .filter(|object| {
                    object
                        .properties
                        .get(markings::OBJECT_CLASSIFICATION_PROPERTY)
                        == Some(&"confidential".to_string())
                })
                .count(),
            2
        );
        for object in &generated {
            let cost: i64 = object.properties["cost"].parse().unwrap();
            assert!((1200..=1700).contains(&cost), "{cost}");
            assert!(!object.properties["owner_email"].contains("example.test"));
        }
        assert_eq!(plan.links.len(), 6);
    }

    #[test]
    fn protected_and_constant_numbers_and_unknown_markings_stay_opaque() {
        let mut types = types();
        types[0]
            .properties
            .push(property("salary", PropertyType::Int, "sensitive"));
        types[0]
            .properties
            .push(property("level", PropertyType::Int, "public"));
        types[0]
            .properties
            .push(property("opened", PropertyType::Timestamp, "public"));
        let (mut objects, links) = tenant();
        for (index, object) in objects.iter_mut().enumerate() {
            object
                .properties
                .insert("salary".into(), (4200 + index).to_string());
            object.properties.insert("level".into(), "4200".into());
            object.properties.insert(
                "opened".into(),
                format!("2026-10-{:02}T08:00:00Z", 10 + index),
            );
        }
        // An unknown marking token protects the object, so its value does
        // not widen the range.
        for object in objects.iter_mut().take(3) {
            object.properties.insert(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "acme-secret".into(),
            );
            object.properties.insert("cost".into(), "99999".into());
        }
        let shape = shape_of(&types, &objects, &links);
        let ticket = &shape.kinds[0];
        assert_eq!(ticket.properties["salary"], PropertyShape::Opaque);
        assert_eq!(ticket.properties["level"], PropertyShape::Opaque);
        assert!(matches!(
            ticket.properties["opened"],
            PropertyShape::Numeric { .. }
        ));
        assert_eq!(
            ticket.properties["cost"],
            PropertyShape::Numeric {
                min: 1300.0,
                max: 1600.0
            }
        );
    }

    #[test]
    fn built_in_kinds_and_the_marking_property_are_not_shaped() {
        let mut types = types();
        types[0].properties.push(property(
            markings::OBJECT_CLASSIFICATION_PROPERTY,
            PropertyType::String,
            "public",
        ));
        let mut builtin = types[0].clone();
        builtin.kind = "person".into();
        builtin.is_builtin = true;
        types.push(builtin);
        let (mut objects, mut links) = tenant();
        let mut person = objects[0].clone();
        person.id = "p-1".into();
        person.kind = "person".into();
        objects.push(person);
        links.push(Link {
            id: "l-person".into(),
            from_id: "t-0".into(),
            to_id: "p-1".into(),
            relation: "owned_by".into(),
            created: 1,
        });
        let shape = shape_of(&types, &objects, &links);
        assert_eq!(shape.kinds.len(), 1);
        assert!(
            shape
                .object_types
                .iter()
                .all(|object_type| !object_type.is_builtin)
        );
        assert!(shape.links.iter().all(|link| link.relation != "owned_by"));
        assert!(
            !shape.kinds[0]
                .properties
                .contains_key(markings::OBJECT_CLASSIFICATION_PROPERTY)
        );
        // Unmarked objects stay unmarked in the twin.
        let spec = Spec {
            namespace: "twin".into(),
            seed: 7,
            preset: SizePreset::Demo,
        };
        let plan = generate(&ShapeDomain::new(shape).unwrap(), &spec).unwrap();
        let marked = plan
            .objects
            .iter()
            .filter(|object| {
                object
                    .properties
                    .contains_key(markings::OBJECT_CLASSIFICATION_PROPERTY)
            })
            .count();
        assert_eq!(marked, 2);
    }

    #[test]
    fn shapes_are_validated() {
        let (objects, links) = tenant();
        let mut shape = shape_of(&types(), &objects, &links);
        let mut overflowing = shape.clone();
        overflowing.kinds[0].count = u64::MAX;
        overflowing.kinds.push(overflowing.kinds[0].clone());
        overflowing.kinds[1].count = 1;
        assert!(ShapeDomain::new(overflowing).is_err());
        let mut wide = shape.clone();
        wide.kinds[0].properties.insert(
            "cost".into(),
            PropertyShape::Numeric {
                min: i64::MIN as f64,
                max: i64::MAX as f64,
            },
        );
        assert!(ShapeDomain::new(wide).is_err());
        for (min, max) in [(-20.0, -10.0), (0.1, 0.2)] {
            let mut unusable = shape.clone();
            unusable.kinds[0]
                .properties
                .insert("cost".into(), PropertyShape::Numeric { min, max });
            assert!(ShapeDomain::new(unusable).is_err());
        }
        let mut dangling = shape.clone();
        dangling.links[0].to_kind = "ghost".into();
        assert!(ShapeDomain::new(dangling).is_err());
        let mut linked = shape.clone();
        linked.links[0].count = u64::MAX;
        assert!(ShapeDomain::new(linked).is_err());
        let mut custom = shape.clone();
        custom.object_types[0].implements = vec!["TenantThing".into()];
        assert!(ShapeDomain::new(custom).is_err());
        let mut lattice = shape.clone();
        lattice.kinds[0].markings.insert("acme-secret".into(), 1);
        assert!(ShapeDomain::new(lattice).is_err());
        let mut flooded = shape.clone();
        flooded.kinds[0].markings.insert("public".into(), u64::MAX);
        assert!(ShapeDomain::new(flooded).is_err());
        shape.kinds[0].count = MAX_TWIN_OBJECTS + 1;
        assert!(ShapeDomain::new(shape.clone()).is_err());
        shape.format = "other".into();
        assert!(ShapeDomain::new(shape).is_err());
    }
}
