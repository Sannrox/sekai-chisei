//! Deterministic synthetic tenant generator (#1614 and #1615, split from #1450).
//!
//! A generator builds a complete tenant plan from a seed and a size
//! preset: ontology definitions, objects with realistic distributions,
//! links, and the tenant's governance state: object markings, principals
//! with a namespace role and a clearance ceiling, spaces, and a history of
//! proposed Actions. The same seed and preset always produce the same plan
//! and the same digest, so load tests and demos are repeatable. Applying a
//! plan writes only into a namespace that is marked synthetic; a
//! namespace that exists without that marker refuses the write. Action
//! history is admitted through the governed Action path on apply, so its
//! receipts are the real ones.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::domain::{Link, Object};
use crate::sekai::action_instance::STATUS_ADMITTED;
use crate::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionRequest,
};
use crate::sekai::governed_action_type::{EFFECT_KIND_NOTIFY, GovernedActionType};
use crate::sekai::markings;
use crate::sekai::object_security::PrincipalPolicyContext;
use crate::sekai::schema::{
    ObjectType, PropertyDef, PropertyType, SchemaRegistry, validate_object_type_definition,
};
use crate::sekai::security::{Grant, Role};

/// Fixed clock for generated rows, so digests do not depend on wall time.
const BASE_TIME: i64 = 1_700_000_000_000;

/// How large a generated tenant is. The counts are the preset's contract:
/// the load-test preset reaches exactly these object and link counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SizePreset {
    Demo,
    Onboarding,
    LoadTest,
}

impl SizePreset {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Demo => "demo",
            Self::Onboarding => "onboarding",
            Self::LoadTest => "load_test",
        }
    }

    /// Total generated objects (the namespace boundary is not counted).
    pub fn objects(&self) -> usize {
        match self {
            Self::Demo => 48,
            Self::Onboarding => 240,
            Self::LoadTest => 10_000,
        }
    }

    /// Principals per tenant, split across the three namespace roles.
    pub fn principals(&self) -> usize {
        match self {
            Self::Demo => 4,
            Self::Onboarding => 8,
            Self::LoadTest => 12,
        }
    }

    /// Actions proposed and applied to build the tenant's history.
    pub fn actions(&self) -> usize {
        match self {
            Self::Demo => 6,
            Self::Onboarding => 24,
            Self::LoadTest => 200,
        }
    }
}

/// A domain's share of a tenant: its types and how its objects link.
pub trait DomainGenerator {
    /// Stable domain name, recorded on the namespace marker.
    fn name(&self) -> &'static str;
    /// Ontology definitions this domain contributes.
    fn object_types(&self) -> Vec<ObjectType>;
    /// Deterministically build this domain's objects and links. Objects
    /// carry their marking in [`markings::OBJECT_CLASSIFICATION_PROPERTY`].
    fn build(&self, spec: &Spec, rng: &mut Rng) -> DomainData;
    /// Governed Action types this domain's history is proposed through.
    fn action_types(&self, namespace: &str) -> Vec<GovernedActionType>;
    /// Deterministically declare principals, spaces and Action history over
    /// the objects `build` produced.
    fn governance(&self, spec: &Spec, data: &DomainData, rng: &mut Rng) -> DomainGovernance;
}

/// One domain's governance declarations, before ids are stamped.
pub struct DomainGovernance {
    pub principals: Vec<GeneratedPrincipal>,
    pub spaces: Vec<GeneratedSpace>,
    pub actions: Vec<GeneratedAction>,
}

pub struct GeneratedPrincipal {
    /// Local name; the principal id is `<namespace>.<label>`.
    pub label: String,
    pub role: Role,
    /// Classification ceiling token, e.g. `internal`.
    pub clearance: String,
}

pub struct GeneratedSpace {
    pub name: String,
    /// `(index into principals, space role)`.
    pub members: Vec<(usize, String)>,
}

/// One Action to propose against an object the domain built. The
/// generator stamps `object_id`, so history is seeded too.
pub struct GeneratedAction {
    pub type_id: String,
    pub version: String,
    /// Index into the domain's objects; each object is targeted at most once.
    pub target: usize,
    /// Index into principals.
    pub submitter: usize,
    pub parameters: serde_json::Map<String, serde_json::Value>,
}

/// One domain's generated rows, before namespacing and ids are stamped.
pub struct DomainData {
    pub objects: Vec<GeneratedObject>,
    /// `(from index, to index, relation)` into `objects`.
    pub links: Vec<(usize, usize, String)>,
}

pub struct GeneratedObject {
    pub kind: String,
    pub name: String,
    pub properties: HashMap<String, String>,
}

/// What to generate: one domain into one namespace from one seed.
pub struct Spec {
    pub namespace: String,
    pub seed: u64,
    pub preset: SizePreset,
}

/// A small deterministic RNG (SplitMix64), so plans need no clock or OS
/// randomness and reproduce byte-for-byte from the seed.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Value in `0..bound`.
    pub fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound.max(1) as u64) as usize
    }

    pub fn pick<'a>(&mut self, values: &'a [&'a str]) -> &'a str {
        values[self.below(values.len())]
    }

    /// One value, drawn with the given integer weights.
    pub fn weighted<'a>(&mut self, values: &'a [(&'a str, usize)]) -> &'a str {
        let total = values.iter().map(|(_, weight)| weight).sum::<usize>();
        let mut roll = self.below(total);
        for (value, weight) in values {
            if roll < *weight {
                return value;
            }
            roll -= weight;
        }
        values[values.len() - 1].0
    }
}

/// Principals in a fixed role rotation, so every tenant has at least one
/// admin, one editor and one viewer; clearances are seeded.
pub fn standard_principals(spec: &Spec, rng: &mut Rng) -> Vec<GeneratedPrincipal> {
    let roles = [Role::Admin, Role::Editor, Role::Viewer, Role::Viewer];
    let mut per_role: HashMap<&'static str, usize> = HashMap::new();
    (0..spec.preset.principals())
        .map(|index| {
            let role = &roles[index % roles.len()];
            let clearance = if *role == Role::Admin {
                "restricted"
            } else {
                rng.weighted(CLEARANCES)
            };
            let name = match role {
                Role::Admin => "admin",
                Role::Editor => "editor",
                Role::Viewer => "viewer",
            };
            let count = per_role.entry(name).or_default();
            *count += 1;
            GeneratedPrincipal {
                label: format!("{name}-{count}"),
                role: role.clone(),
                clearance: clearance.into(),
            }
        })
        .collect()
}

pub fn principals_with_role(principals: &[GeneratedPrincipal], role: &Role) -> Vec<usize> {
    principals
        .iter()
        .enumerate()
        .filter(|(_, principal)| principal.role == *role)
        .map(|(index, _)| index)
        .collect()
}

/// A working space with every principal, and an oversight space with the
/// admins as approvers and the viewers.
pub fn role_spaces(
    principals: &[GeneratedPrincipal],
    working: &str,
    oversight: &str,
) -> Vec<GeneratedSpace> {
    vec![
        GeneratedSpace {
            name: working.into(),
            members: principals
                .iter()
                .enumerate()
                .map(|(index, principal)| {
                    let role = match principal.role {
                        Role::Admin => "administrator",
                        Role::Editor => "editor",
                        Role::Viewer => "viewer",
                    };
                    (index, role.to_string())
                })
                .collect(),
        },
        GeneratedSpace {
            name: oversight.into(),
            members: principals
                .iter()
                .enumerate()
                .filter(|(_, principal)| principal.role != Role::Editor)
                .map(|(index, principal)| {
                    let role = if principal.role == Role::Admin {
                        "approver"
                    } else {
                        "viewer"
                    };
                    (index, role.to_string())
                })
                .collect(),
        },
    ]
}

/// The built-in domain: a small supply chain.
pub struct SupplyChain;

const REGIONS: &[&str] = &["north", "south", "east", "west", "central"];
const STATUSES: &[&str] = &["planned", "in_transit", "delivered", "delayed"];
const SEVERITIES: &[&str] = &["low", "medium", "high"];
/// Seeded share of each object marking, lowest first.
pub const MARKINGS: &[(&str, usize)] = &[
    ("public", 50),
    ("internal", 30),
    ("confidential", 15),
    ("restricted", 5),
];
/// Clearance ceilings a non-admin principal is drawn from.
const CLEARANCES: &[(&str, usize)] = &[("public", 1), ("internal", 2), ("confidential", 1)];
const INCIDENT_STATES: &[&str] = &["open", "triaged"];
const INCIDENT_TRIAGE: &str = "synthetic.incident.triage";

pub fn property(name: &str, prop_type: PropertyType, required: bool) -> PropertyDef {
    PropertyDef {
        name: name.into(),
        prop_type,
        required,
        description: String::new(),
        enum_values: Vec::new(),
        link_kind: String::new(),
        compute_expr: String::new(),
        classification: "public".into(),
        struct_fields: Vec::new(),
    }
}

/// A property only principals that administer the object may read.
pub fn restricted_property(name: &str, prop_type: PropertyType) -> PropertyDef {
    let mut def = property(name, prop_type, true);
    def.classification = "internal".into();
    def
}

pub fn enum_property(name: &str, values: &[&str]) -> PropertyDef {
    let mut def = property(name, PropertyType::Enum, true);
    def.enum_values = values.iter().map(ToString::to_string).collect();
    def
}

impl DomainGenerator for SupplyChain {
    fn name(&self) -> &'static str {
        "supply_chain"
    }

    fn object_types(&self) -> Vec<ObjectType> {
        let kind = |name: &str, properties: Vec<PropertyDef>| ObjectType {
            kind: name.into(),
            description: format!("Synthetic {name} (supply_chain domain)"),
            properties,
            is_builtin: false,
            implements: Vec::new(),
        };
        vec![
            kind(
                "synthetic_supplier",
                vec![
                    property("code", PropertyType::String, true),
                    enum_property("region", REGIONS),
                    property("since_year", PropertyType::Int, true),
                ],
            ),
            kind(
                "synthetic_part",
                vec![
                    property("sku", PropertyType::String, true),
                    restricted_property("unit_cost", PropertyType::Int),
                    property("critical", PropertyType::Bool, true),
                ],
            ),
            kind(
                "synthetic_warehouse",
                vec![
                    property("code", PropertyType::String, true),
                    enum_property("region", REGIONS),
                    property("capacity", PropertyType::Int, true),
                ],
            ),
            kind(
                "synthetic_shipment",
                vec![
                    property("tracking", PropertyType::String, true),
                    enum_property("status", STATUSES),
                    property("quantity", PropertyType::Int, true),
                ],
            ),
            kind(
                "synthetic_incident",
                vec![
                    property("shipment", PropertyType::String, true),
                    enum_property("severity", SEVERITIES),
                    enum_property("state", INCIDENT_STATES),
                ],
            ),
        ]
    }

    fn action_types(&self, namespace: &str) -> Vec<GovernedActionType> {
        vec![GovernedActionType {
            namespace: namespace.into(),
            type_id: INCIDENT_TRIAGE.into(),
            version: "1".into(),
            description: "Triage one open incident and set its severity".into(),
            parameter_schema_json: serde_json::json!({
                "type": "object",
                "properties": {
                    "object_id": {"type": "string"},
                    "severity": {"type": "string", "enum": SEVERITIES},
                    "state": {"type": "string", "enum": ["triaged"]},
                },
                "required": ["object_id", "severity", "state"],
                "additionalProperties": false,
            })
            .to_string(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            object_kind: "synthetic_incident".into(),
            object_mutation: "update".into(),
            enabled: true,
            created_by: "synthetic".into(),
            ..Default::default()
        }]
    }

    fn governance(&self, spec: &Spec, data: &DomainData, rng: &mut Rng) -> DomainGovernance {
        let principals = standard_principals(spec, rng);
        let editors = principals_with_role(&principals, &Role::Editor);
        let spaces = role_spaces(&principals, "operations", "audit");
        // Each Action triages one open incident, so every incident has at
        // most one history entry.
        let actions = data
            .objects
            .iter()
            .enumerate()
            .filter(|(_, object)| object.kind == "synthetic_incident")
            .map(|(target, _)| {
                let mut parameters = serde_json::Map::new();
                parameters.insert("severity".into(), rng.pick(SEVERITIES).into());
                parameters.insert("state".into(), "triaged".into());
                GeneratedAction {
                    type_id: INCIDENT_TRIAGE.into(),
                    version: "1".into(),
                    target,
                    submitter: editors[rng.below(editors.len())],
                    parameters,
                }
            })
            .collect();
        DomainGovernance {
            principals,
            spaces,
            actions,
        }
    }

    fn build(&self, spec: &Spec, rng: &mut Rng) -> DomainData {
        let total = spec.preset.objects();
        // Shares of the tenant, in type order; the last kind takes the rest.
        let suppliers = (total / 20).max(1);
        let warehouses = (total / 10).max(1);
        let parts = (total * 9 / 20).max(1);
        let incidents = spec.preset.actions();
        let shipments = total - suppliers - warehouses - parts - incidents;
        let mut objects: Vec<GeneratedObject> = Vec::with_capacity(total);
        fn add(
            objects: &mut Vec<GeneratedObject>,
            kind: &str,
            name: String,
            properties: HashMap<String, String>,
        ) {
            objects.push(GeneratedObject {
                kind: kind.into(),
                name,
                properties,
            });
        }
        for index in 0..suppliers {
            add(
                &mut objects,
                "synthetic_supplier",
                format!("Supplier {:04}", index + 1),
                HashMap::from([
                    ("code".into(), format!("SUP-{:04}", index + 1)),
                    ("region".into(), rng.pick(REGIONS).into()),
                    ("since_year".into(), (1990 + rng.below(35)).to_string()),
                ]),
            );
        }
        let part_start = objects.len();
        for index in 0..parts {
            add(
                &mut objects,
                "synthetic_part",
                format!("Part {:04}", index + 1),
                HashMap::from([
                    ("sku".into(), format!("SKU-{:05}", index + 1)),
                    ("unit_cost".into(), (5 + rng.below(500)).to_string()),
                    (
                        "critical".into(),
                        if rng.below(5) == 0 { "true" } else { "false" }.into(),
                    ),
                ]),
            );
        }
        let warehouse_start = objects.len();
        for index in 0..warehouses {
            add(
                &mut objects,
                "synthetic_warehouse",
                format!("Warehouse {:04}", index + 1),
                HashMap::from([
                    ("code".into(), format!("WH-{:03}", index + 1)),
                    ("region".into(), rng.pick(REGIONS).into()),
                    ("capacity".into(), (1_000 + rng.below(50_000)).to_string()),
                ]),
            );
        }
        let shipment_start = objects.len();
        for index in 0..shipments {
            add(
                &mut objects,
                "synthetic_shipment",
                format!("Shipment {:04}", index + 1),
                HashMap::from([
                    ("tracking".into(), format!("TRK-{:06}", index + 1)),
                    ("status".into(), rng.pick(STATUSES).into()),
                    ("quantity".into(), (1 + rng.below(200)).to_string()),
                ]),
            );
        }
        let mut concerns = Vec::with_capacity(incidents);
        for index in 0..incidents {
            let shipment = rng.below(shipments);
            concerns.push((objects.len(), shipment_start + shipment, "concerns".into()));
            add(
                &mut objects,
                "synthetic_incident",
                format!("Incident {:04}", index + 1),
                HashMap::from([
                    ("shipment".into(), format!("TRK-{:06}", shipment + 1)),
                    ("severity".into(), "low".into()),
                    ("state".into(), "open".into()),
                ]),
            );
        }
        for object in &mut objects {
            object.properties.insert(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                rng.weighted(MARKINGS).into(),
            );
        }
        let mut links = Vec::new();
        // Every part is supplied by one supplier and stocked in one warehouse.
        for part in 0..parts {
            links.push((
                part_start + part,
                rng.below(suppliers),
                "supplied_by".into(),
            ));
            links.push((
                part_start + part,
                warehouse_start + rng.below(warehouses),
                "stocked_in".into(),
            ));
        }
        // Every shipment moves one part between two warehouses.
        for shipment in 0..shipments {
            links.push((
                shipment_start + shipment,
                part_start + rng.below(parts),
                "carries".into(),
            ));
            links.push((
                shipment_start + shipment,
                warehouse_start + rng.below(warehouses),
                "ships_to".into(),
            ));
        }
        // Every incident concerns one shipment.
        links.extend(concerns);
        DomainData { objects, links }
    }
}

/// A complete, deterministic tenant plan.
#[derive(Debug, Clone, Serialize)]
pub struct SyntheticPlan {
    pub namespace: String,
    pub domain: String,
    pub seed: u64,
    pub preset: SizePreset,
    pub types: Vec<ObjectType>,
    pub objects: Vec<Object>,
    pub links: Vec<Link>,
    pub principals: Vec<SyntheticPrincipal>,
    /// Sealed principal profiles carrying each principal's clearance.
    pub profiles: Vec<Object>,
    pub spaces: Vec<SyntheticSpace>,
    pub grants: Vec<SyntheticGrant>,
    pub action_types: Vec<GovernedActionType>,
    /// Proposed in order on apply; each updates one plan object.
    pub actions: Vec<SyntheticAction>,
    /// SHA-256 of the canonical plan JSON (everything above).
    pub digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyntheticPrincipal {
    pub id: String,
    /// Namespace role: `viewer`, `editor` or `admin`.
    pub role: String,
    pub clearance: String,
}

/// A permission scope over the tenant. The core stores no spaces (an
/// enterprise extension supplies them), so the plan declares them for the
/// extension or test fake that serves the tenant.
#[derive(Debug, Clone, Serialize)]
pub struct SyntheticSpace {
    pub name: String,
    pub members: Vec<SpaceMember>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpaceMember {
    pub principal: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyntheticGrant {
    pub id: String,
    pub object_id: String,
    pub principal: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyntheticAction {
    pub type_id: String,
    pub version: String,
    pub submitter: String,
    pub idempotency_key: String,
    /// Becomes the operation id, and so the receipt id.
    pub request_id: String,
    /// The plan object the Action updates.
    pub object_id: String,
    pub parameters_json: String,
}

/// Build a plan without touching a store.
pub fn generate(domain: &dyn DomainGenerator, spec: &Spec) -> Result<SyntheticPlan, String> {
    if spec.namespace.trim().is_empty() {
        return Err("namespace required".into());
    }
    // The namespace is part of every generated id, and Action object ids
    // may not contain whitespace.
    if spec.namespace.trim().chars().any(char::is_whitespace) {
        return Err("namespace must not contain whitespace".into());
    }
    let types = domain.object_types();
    let registry = SchemaRegistry::new();
    for object_type in &types {
        validate_object_type_definition(object_type, None, &registry)?;
    }
    let mut rng = Rng::new(spec.seed);
    let data = domain.build(spec, &mut rng);
    let governance = domain.governance(spec, &data, &mut rng);
    let namespace = spec.namespace.trim();
    let seed = spec.seed;
    let objects: Vec<Object> = data
        .objects
        .into_iter()
        .enumerate()
        .map(|(index, generated)| Object {
            id: format!("syn:{namespace}:{seed}:{:06}", index + 1),
            kind: generated.kind,
            name: generated.name,
            namespace: namespace.into(),
            external_id: format!("synthetic:{seed}:{:06}", index + 1),
            properties: generated.properties,
            created: BASE_TIME + index as i64,
            updated: BASE_TIME + index as i64,
        })
        .collect();
    // Generated definitions and markings pass the same checks as real ones.
    let mut checks = SchemaRegistry::new();
    for object_type in &types {
        checks.register(object_type.clone());
    }
    for object in &objects {
        checks.validate(object)?;
        markings::object_classification(object)?;
    }
    for (from, to, _) in &data.links {
        if *from >= objects.len() || *to >= objects.len() {
            return Err(format!(
                "domain {:?} produced a link outside its {} objects",
                domain.name(),
                objects.len()
            ));
        }
    }
    let links: Vec<Link> = data
        .links
        .into_iter()
        .enumerate()
        .map(|(index, (from, to, relation))| Link {
            id: format!("syn:{namespace}:{seed}:link:{:06}", index + 1),
            from_id: objects[from].id.clone(),
            to_id: objects[to].id.clone(),
            relation,
            created: BASE_TIME + index as i64,
        })
        .collect();

    let mut principals = Vec::with_capacity(governance.principals.len());
    let mut profiles = Vec::with_capacity(governance.principals.len());
    for generated in &governance.principals {
        markings::parse_classification(&generated.clearance)?;
        let id = format!("{namespace}.{}", generated.label);
        let external_id = markings::principal_profile_external_id(&id);
        profiles.push(Object {
            id: format!("syn:{namespace}:{seed}:profile:{}", generated.label),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: id.clone(),
            namespace: namespace.into(),
            external_id,
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    generated.clearance.clone(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: BASE_TIME,
            updated: BASE_TIME,
        });
        principals.push(SyntheticPrincipal {
            id,
            role: generated.role.as_str().into(),
            clearance: generated.clearance.clone(),
        });
    }
    let principal_at = |index: usize| -> Result<&SyntheticPrincipal, String> {
        principals.get(index).ok_or_else(|| {
            format!(
                "domain {:?} referenced principal {index} of {}",
                domain.name(),
                principals.len()
            )
        })
    };
    let mut spaces = Vec::with_capacity(governance.spaces.len());
    for space in &governance.spaces {
        let mut members = Vec::with_capacity(space.members.len());
        for (index, role) in &space.members {
            members.push(SpaceMember {
                principal: principal_at(*index)?.id.clone(),
                role: role.clone(),
            });
        }
        spaces.push(SyntheticSpace {
            name: space.name.clone(),
            members,
        });
    }

    let action_types = domain.action_types(namespace);
    let mut actions = Vec::with_capacity(governance.actions.len());
    let mut targeted = std::collections::HashSet::new();
    for (index, generated) in governance.actions.into_iter().enumerate() {
        let type_def = action_types
            .iter()
            .find(|type_def| {
                type_def.type_id == generated.type_id && type_def.version == generated.version
            })
            .ok_or_else(|| {
                format!(
                    "domain {:?} proposed undeclared action type {:?}",
                    domain.name(),
                    generated.type_id
                )
            })?;
        let target = objects.get(generated.target).ok_or_else(|| {
            format!(
                "domain {:?} targeted object {} of {}",
                domain.name(),
                generated.target,
                objects.len()
            )
        })?;
        if target.kind != type_def.object_kind || !targeted.insert(generated.target) {
            return Err(format!(
                "domain {:?} action {index} must target one {} object not targeted before",
                domain.name(),
                type_def.object_kind
            ));
        }
        let object_id = target.id.clone();
        let mut parameters = generated.parameters;
        parameters.insert("object_id".into(), object_id.clone().into());
        let parameters_json = serde_json::Value::Object(parameters).to_string();
        crate::sekai::parameter_schema::validate_parameters(
            &type_def.parameter_schema_json,
            &parameters_json,
        )?;
        actions.push(SyntheticAction {
            type_id: generated.type_id,
            version: generated.version,
            submitter: principal_at(generated.submitter)?.id.clone(),
            idempotency_key: format!("synthetic-{seed}-action-{:06}", index + 1),
            request_id: format!("syn:{namespace}:{seed}:operation:{:06}", index + 1),
            object_id,
            parameters_json,
        });
    }

    // Every principal holds its role on the namespace and on every object
    // the tenant owns; a profile counts only under an admin grant.
    let boundary_id = format!("namespace:{namespace}");
    let mut grants = Vec::new();
    let tenant_objects = std::iter::once(boundary_id.as_str())
        .chain(objects.iter().map(|object| object.id.as_str()));
    for object_id in tenant_objects {
        for principal in &principals {
            grants.push((
                object_id.to_string(),
                principal.id.clone(),
                principal.role.clone(),
            ));
        }
    }
    for profile in &profiles {
        grants.push((
            profile.id.clone(),
            "root".into(),
            Role::Admin.as_str().into(),
        ));
    }
    let grants = grants
        .into_iter()
        .enumerate()
        .map(|(index, (object_id, principal, role))| SyntheticGrant {
            id: format!("syn:{namespace}:{seed}:grant:{:07}", index + 1),
            object_id,
            principal,
            role,
        })
        .collect();

    let mut plan = SyntheticPlan {
        namespace: namespace.into(),
        domain: domain.name().into(),
        seed,
        preset: spec.preset,
        types,
        objects,
        links,
        principals,
        profiles,
        spaces,
        grants,
        action_types,
        actions,
        digest: String::new(),
    };
    plan.digest = plan_digest(&plan)?;
    Ok(plan)
}

/// The canonical digest of a plan's contents, recomputed on apply so a
/// caller-edited plan cannot reuse another plan's marker.
fn plan_digest(plan: &SyntheticPlan) -> Result<String, String> {
    let mut canonical = serde_json::to_value(plan).map_err(|error| error.to_string())?;
    if let Some(fields) = canonical.as_object_mut() {
        fields.remove("digest");
    }
    let canonical = serde_json::to_string(&canonical).map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(canonical.as_bytes())))
}

/// The namespace boundary object for a synthetic tenant, carrying the
/// marker the generator refuses to write without.
pub fn synthetic_boundary(plan: &SyntheticPlan) -> Object {
    let external_id = format!("namespace:{}", plan.namespace);
    Object {
        id: external_id.clone(),
        kind: "namespace".into(),
        name: plan.namespace.clone(),
        namespace: plan.namespace.clone(),
        external_id,
        properties: HashMap::from([
            ("synthetic".into(), "true".into()),
            ("synthetic_domain".into(), plan.domain.clone()),
            ("synthetic_seed".into(), plan.seed.to_string()),
            ("synthetic_preset".into(), plan.preset.name().into()),
            ("synthetic_digest".into(), plan.digest.clone()),
        ]),
        created: BASE_TIME,
        updated: BASE_TIME,
    }
}

/// Claim the plan's namespace atomically: boundary lookup, emptiness
/// check, marker creation and the boundary's grants run in one immediate
/// transaction, so a concurrent writer cannot slip real data in between.
fn claim_boundary(
    db: &SekaiDb,
    plan: &SyntheticPlan,
    grants: &[&SyntheticGrant],
) -> Result<(), String> {
    use rusqlite::params;
    let boundary = synthetic_boundary(plan);
    let mut conn = db.conn();
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let external_id = format!("namespace:{}", plan.namespace);
    let mut statement = tx
        .prepare(
            "SELECT id, namespace, properties FROM sekai_objects \
             WHERE external_id = ?1 AND kind = 'namespace'",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(params![external_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(statement);
    if rows.len() > 1 {
        return Err(format!(
            "namespace {:?} identity is held by {} boundaries; refusing to write",
            plan.namespace,
            rows.len()
        ));
    }
    if let Some((id, namespace, properties)) = rows.into_iter().next() {
        // Grants go on `boundary.id`, so only the canonical boundary row
        // may stand for the namespace.
        if id != boundary.id || namespace != plan.namespace {
            return Err(format!(
                "namespace {:?} boundary is not the canonical {:?}; refusing to write",
                plan.namespace, boundary.id
            ));
        }
        let properties: serde_json::Value = serde_json::from_str(&properties).unwrap_or_default();
        if properties
            .get("synthetic")
            .and_then(serde_json::Value::as_str)
            != Some("true")
        {
            return Err(format!(
                "namespace {:?} exists and is not synthetic; refusing to write",
                plan.namespace
            ));
        }
        // A synthetic namespace belongs to one plan: a different seed,
        // domain, preset or digest would mix two datasets under one marker.
        let expected = synthetic_boundary(plan);
        for (key, value) in &expected.properties {
            if key != "synthetic"
                && properties.get(key).and_then(serde_json::Value::as_str) != Some(value.as_str())
            {
                return Err(format!(
                    "namespace {:?} already holds a different synthetic plan ({key}); refusing to write",
                    plan.namespace
                ));
            }
        }
        ensure_grants(&tx, grants)?;
        return tx.commit().map_err(|error| error.to_string());
    }
    // No boundary does not prove the namespace is empty; objects can
    // carry a namespace string without one.
    let occupied: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM sekai_objects WHERE namespace = ?1",
            params![plan.namespace],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if occupied > 0 {
        return Err(format!(
            "namespace {:?} already has objects and no synthetic marker; refusing to write",
            plan.namespace
        ));
    }
    // Object ids are never reused once they have audit history.
    let history: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM sekai_object_changes WHERE object_id = ?1",
            params![boundary.id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if history > 0 {
        return Err(format!(
            "namespace boundary {:?} has audit history; refusing to reuse its identity",
            boundary.id
        ));
    }
    let properties =
        serde_json::to_string(&boundary.properties).map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_objects (id, kind, name, namespace, external_id, properties, created, updated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            boundary.id,
            boundary.kind,
            boundary.name,
            boundary.namespace,
            boundary.external_id,
            properties,
            boundary.created,
            boundary.updated
        ],
    )
    .map_err(|error| error.to_string())?;
    ensure_grants(&tx, grants)?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(())
}

/// Apply a plan to a store. The target namespace must be new or already
/// marked synthetic; anything else fails closed before any write.
/// Application is restartable: rows that already match the plan are
/// skipped, rows that conflict with it fail the apply, and Actions replay
/// by idempotency key instead of proposing twice. An admission a crash
/// interrupted before its receipt was written is the governed path's to
/// recover; until it does, apply reports it instead of proposing again.
pub fn apply(db: &RuntimeDb, plan: &SyntheticPlan) -> Result<(), String> {
    if plan_digest(plan)? != plan.digest {
        return Err("plan digest does not match its contents; refusing to write".into());
    }
    let sqlite = db
        .as_sqlite()
        .ok_or("synthetic tenants apply to the SQLite store only")?;
    // A caller-built plan cannot smuggle rows out of the guarded
    // namespace, or links and grants onto objects the plan does not own.
    let boundary_id = format!("namespace:{}", plan.namespace);
    let mut owned: std::collections::HashSet<&str> = plan
        .objects
        .iter()
        .chain(&plan.profiles)
        .map(|object| object.id.as_str())
        .collect();
    for object in plan.objects.iter().chain(&plan.profiles) {
        if object.namespace != plan.namespace {
            return Err(format!(
                "plan object {:?} is outside namespace {:?}",
                object.id, plan.namespace
            ));
        }
    }
    for link in &plan.links {
        if !owned.contains(link.from_id.as_str()) || !owned.contains(link.to_id.as_str()) {
            return Err(format!(
                "plan link {:?} references an object outside the plan",
                link.id
            ));
        }
    }
    // Each Action updates one distinct plan object; its expected state
    // after the Action is what a replay must find.
    let mut after_actions: HashMap<&str, Object> = HashMap::new();
    for action in &plan.actions {
        let target = plan
            .objects
            .iter()
            .find(|object| object.id == action.object_id)
            .ok_or_else(|| {
                format!(
                    "plan action {:?} targets an object outside the plan",
                    action.request_id
                )
            })?;
        if after_actions
            .insert(&action.object_id, after_action(target, action)?)
            .is_some()
        {
            return Err(format!(
                "plan action {:?} targets an object another action updates",
                action.request_id
            ));
        }
    }
    owned.insert(boundary_id.as_str());
    for grant in &plan.grants {
        if !owned.contains(grant.object_id.as_str()) {
            return Err(format!(
                "plan grant {:?} targets an object outside the plan",
                grant.id
            ));
        }
    }
    for type_def in &plan.action_types {
        if type_def.namespace != plan.namespace {
            return Err(format!(
                "plan action type {:?} is outside namespace {:?}",
                type_def.type_id, plan.namespace
            ));
        }
    }
    let grants = grants_by_object(plan);
    let grants_on = |object_id: &str| grants.get(object_id).map_or(&[][..], Vec::as_slice);
    claim_boundary(sqlite, plan, grants_on(&boundary_id))?;
    for object_type in &plan.types {
        // Atomic insert-if-absent, then verify: a conflicting definition
        // registered concurrently is a failure, never an overwrite.
        sqlite.insert_object_type_if_absent(object_type)?;
        match sqlite.get_object_type(&object_type.kind)? {
            Some(existing)
                if serde_json::to_value(&existing).ok()
                    != serde_json::to_value(object_type).ok() =>
            {
                return Err(format!(
                    "object type {:?} already exists with a different definition",
                    object_type.kind
                ));
            }
            _ => {}
        }
    }
    // Each object is written with its grants in one transaction, so no
    // generated object is ever visible without its ACL.
    for object in plan.objects.iter().chain(&plan.profiles) {
        let after = after_actions.get(object.id.as_str());
        write_with_grants(sqlite, object, after, grants_on(&object.id))?;
    }
    for link in &plan.links {
        if sqlite.get_link(&link.id)?.is_none() {
            sqlite.create_link(link)?;
        }
        match sqlite.get_link(&link.id)? {
            Some(existing)
                if existing.from_id == link.from_id
                    && existing.to_id == link.to_id
                    && existing.relation == link.relation
                    && existing.created == link.created => {}
            _ => {
                return Err(format!("link {:?} already exists and differs", link.id));
            }
        }
    }
    for type_def in &plan.action_types {
        // Registration is idempotent; a different body under the same
        // version is refused as immutable.
        db.put_governed_action_type(type_def.clone(), "synthetic", BASE_TIME)?;
    }
    // History goes through the same admission as a real submission:
    // parameter schema, policy, freeze checks, object write, receipt.
    let admission = ActionInstanceAdmission::new(db, None);
    for (index, action) in plan.actions.iter().enumerate() {
        let outcome = admission
            .admit(
                ActionInstanceAdmissionRequest {
                    namespace: plan.namespace.clone(),
                    type_id: action.type_id.clone(),
                    version: action.version.clone(),
                    parameters_json: action.parameters_json.clone(),
                    idempotency_key: action.idempotency_key.clone(),
                    evidence_submission_ids: Vec::new(),
                    request_id: action.request_id.clone(),
                    ontology_digest: String::new(),
                    autonomous_envelope_id: String::new(),
                    policy_context: PrincipalPolicyContext::default(),
                    delegating_actor: None,
                    budget_already_reserved: false,
                    resource_tenant: String::new(),
                    binding_markings: Vec::new(),
                    source_object_id: String::new(),
                    marking_gate: Default::default(),
                    expected_object_revision: String::new(),
                    offline: None,
                },
                &action.submitter,
                BASE_TIME + index as i64,
            )
            .map_err(|error| format!("action {:?} refused: {error:?}", action.request_id))?;
        if outcome.instance.status != STATUS_ADMITTED {
            return Err(format!(
                "action {:?} was not admitted (status {:?})",
                action.request_id, outcome.instance.status
            ));
        }
        let updated = sqlite.get_object(&action.object_id)?;
        if !updated
            .as_ref()
            .is_some_and(|object| same_state(object, &after_actions[action.object_id.as_str()]))
        {
            return Err(format!(
                "action {:?} object {:?} differs from the plan",
                action.request_id, action.object_id
            ));
        }
    }
    Ok(())
}

/// `object` as `action` leaves it: the governed update merges the
/// properties it derives from the parameters, and a `name` parameter
/// renames.
impl SyntheticPlan {
    /// The plan's objects as they stand once [`apply`] has run every
    /// declared action, derived the way the governed mutation path derives
    /// them, without touching a store.
    pub fn final_objects(&self) -> Result<Vec<Object>, String> {
        let mut objects = self.objects.clone();
        for action in &self.actions {
            let target = objects
                .iter_mut()
                .find(|object| object.id == action.object_id)
                .ok_or_else(|| {
                    format!(
                        "plan action {:?} targets an object outside the plan",
                        action.request_id
                    )
                })?;
            *target = after_action(target, action)?;
        }
        Ok(objects)
    }
}

fn after_action(object: &Object, action: &SyntheticAction) -> Result<Object, String> {
    let parameters = serde_json::from_str::<serde_json::Value>(&action.parameters_json)
        .map_err(|error| error.to_string())?;
    // Admission mutates the object the parameters name; it must be the
    // plan's declared target.
    if parameters
        .get("object_id")
        .and_then(serde_json::Value::as_str)
        != Some(object.id.as_str())
    {
        return Err(format!(
            "plan action {:?} parameters name another object than its target",
            action.request_id
        ));
    }
    // The properties exactly as the governed mutation path derives them.
    let properties = crate::sekai::action_object_mutation::object_properties(&parameters)
        .map_err(|error| format!("action {:?}: {error:?}", action.request_id))?;
    let mut after = object.clone();
    after.properties.extend(properties);
    // As the mutation path: a present `name` renames, and an empty or
    // non-string one falls back to the object id.
    if let Some(name) = parameters.get("name") {
        after.name = name
            .as_str()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or(&object.id)
            .into();
    }
    Ok(after)
}

/// Equal persisted state, apart from the write time an Action stamps.
fn same_state(stored: &Object, expected: &Object) -> bool {
    let mut expected = expected.clone();
    expected.updated = stored.updated;
    stored.persisted_state_matches(&expected)
}

fn grants_by_object(plan: &SyntheticPlan) -> HashMap<&str, Vec<&SyntheticGrant>> {
    let mut by_object: HashMap<&str, Vec<&SyntheticGrant>> = HashMap::new();
    for grant in &plan.grants {
        by_object
            .entry(grant.object_id.as_str())
            .or_default()
            .push(grant);
    }
    by_object
}

/// Insert one object with its grants, or verify both when the object is
/// already there (as planned, or as its Action left it), in one immediate
/// transaction. A concurrent writer that
/// lands a conflicting row under the same id fails the apply.
fn write_with_grants(
    db: &SekaiDb,
    object: &Object,
    after_action: Option<&Object>,
    grants: &[&SyntheticGrant],
) -> Result<(), String> {
    let mut conn = db.conn();
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    match stored_object(&tx, &object.id)? {
        None => crate::db::sekai::insert_object(&tx, object)?,
        Some(existing)
            if existing.persisted_state_matches(object)
                || after_action.is_some_and(|after| same_state(&existing, after)) => {}
        Some(_) => return Err(format!("object {:?} already exists and differs", object.id)),
    }
    ensure_grants(&tx, grants)?;
    tx.commit().map_err(|error| error.to_string())
}

fn stored_object(conn: &rusqlite::Connection, id: &str) -> Result<Option<Object>, String> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT id, kind, name, namespace, external_id, properties, created, updated \
         FROM sekai_objects WHERE id = ?1",
        [id],
        crate::db::sekai::row_to_object,
    )
    .optional()
    .map_err(|error| error.to_string())
}

/// Insert one object's missing grants on `conn`. Grants upsert on
/// `(object, principal)`, so an existing grant with another role is a
/// conflict, not an overwrite.
fn ensure_grants(conn: &rusqlite::Connection, grants: &[&SyntheticGrant]) -> Result<(), String> {
    let Some(first) = grants.first() else {
        return Ok(());
    };
    // A plan grant is open-ended: no purpose, end date or exception. A
    // stored grant with other terms is a conflict too.
    let existing: HashMap<String, String> = conn
        .prepare(
            "SELECT principal, CASE WHEN purpose = '' AND not_after_ms = 0 \
                AND exception_reason = '' THEN role ELSE role || ' (with terms)' END \
             FROM sekai_grants WHERE object_id = ?1",
        )
        .and_then(|mut statement| {
            statement
                .query_map([&first.object_id], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect()
        })
        .map_err(|error| error.to_string())?;
    for wanted in grants {
        let role = Role::parse(&wanted.role)
            .ok_or_else(|| format!("plan grant {:?} has role {:?}", wanted.id, wanted.role))?;
        match existing.get(&wanted.principal) {
            Some(stored) if *stored == wanted.role => {}
            Some(_) => {
                return Err(format!(
                    "grant for {:?} on {:?} already exists with another role or terms",
                    wanted.principal, wanted.object_id
                ));
            }
            None => crate::sekai::security::insert_grant(
                conn,
                &Grant {
                    id: wanted.id.clone(),
                    object_id: wanted.object_id.clone(),
                    principal: wanted.principal.clone(),
                    role,
                    created: BASE_TIME,
                    ..Default::default()
                },
            )?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(preset: SizePreset) -> Spec {
        Spec {
            namespace: "synthetic-demo".into(),
            seed: 42,
            preset,
        }
    }

    #[test]
    fn the_same_seed_and_preset_produce_identical_plans() {
        let first = generate(&SupplyChain, &spec(SizePreset::Demo)).unwrap();
        let second = generate(&SupplyChain, &spec(SizePreset::Demo)).unwrap();
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.objects.len(), SizePreset::Demo.objects());
        let other = generate(
            &SupplyChain,
            &Spec {
                seed: 7,
                ..spec(SizePreset::Demo)
            },
        )
        .unwrap();
        assert_ne!(first.digest, other.digest);
    }

    #[test]
    fn the_load_test_preset_reaches_its_stated_counts() {
        let plan = generate(&SupplyChain, &spec(SizePreset::LoadTest)).unwrap();
        assert_eq!(plan.objects.len(), 10_000);
        // Two links per part and per shipment.
        assert!(plan.links.len() > plan.objects.len());
        assert!(
            plan.objects
                .iter()
                .all(|object| object.namespace == "synthetic-demo")
        );
    }

    #[test]
    fn apply_marks_the_namespace_and_writes_the_plan() {
        let db = RuntimeDb::memory();
        let plan = generate(&SupplyChain, &spec(SizePreset::Demo)).unwrap();
        apply(&db, &plan).unwrap();
        let boundary = db
            .find_namespace_boundary("synthetic-demo")
            .unwrap()
            .unwrap();
        assert_eq!(
            boundary.properties.get("synthetic").map(String::as_str),
            Some("true")
        );
        let first = db.get_object(&plan.objects[0].id).unwrap().unwrap();
        assert_eq!(first.name, plan.objects[0].name);
        assert!(db.get_object_type("synthetic_part").unwrap().is_some());
        // Reapplying the same plan is a no-op, not a uniqueness failure.
        apply(&db, &plan).unwrap();
    }

    #[test]
    fn final_objects_are_what_apply_leaves() {
        let db = RuntimeDb::memory();
        let plan = generate(&SupplyChain, &spec(SizePreset::Demo)).unwrap();
        apply(&db, &plan).unwrap();
        let finals = plan.final_objects().unwrap();
        assert!(!plan.actions.is_empty());
        for action in &plan.actions {
            let stored = db.get_object(&action.object_id).unwrap().unwrap();
            let derived = finals
                .iter()
                .find(|object| object.id == action.object_id)
                .unwrap();
            assert_eq!(stored.properties, derived.properties, "{}", stored.id);
            assert_eq!(stored.name, derived.name);
        }
    }

    #[test]
    fn apply_refuses_a_namespace_that_is_not_synthetic() {
        let db = RuntimeDb::memory();
        db.create_object(&Object {
            id: "namespace:real-tenant".into(),
            kind: "namespace".into(),
            name: "real-tenant".into(),
            namespace: "real-tenant".into(),
            external_id: "namespace:real-tenant".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        let plan = generate(
            &SupplyChain,
            &Spec {
                namespace: "real-tenant".into(),
                ..spec(SizePreset::Demo)
            },
        )
        .unwrap();
        let error = apply(&db, &plan).unwrap_err();
        assert!(error.contains("not synthetic"), "{error}");
        assert!(db.get_object(&plan.objects[0].id).unwrap().is_none());
    }

    /// Markings, roles and history as one comparable record: everything
    /// the seed decides, read back from the store.
    fn governance_state(db: &RuntimeDb, plan: &SyntheticPlan) -> Vec<String> {
        let mut state: Vec<String> = plan
            .objects
            .iter()
            .map(|object| {
                let stored = db.get_object(&object.id).unwrap().unwrap();
                format!(
                    "{} marked {:?}",
                    stored.id,
                    markings::object_marking_token(&stored)
                )
            })
            .collect();
        for principal in &plan.principals {
            let roles = db
                .list_namespace_roles_for_principal(&principal.id)
                .unwrap()
                .into_iter()
                .map(|(namespace, role)| format!("{namespace}={}", role.as_str()))
                .collect::<Vec<_>>();
            state.push(format!(
                "{} {roles:?} {}",
                principal.id, principal.clearance
            ));
        }
        let mut instances = db
            .list_action_instances(&plan.namespace, None, None, 1_000)
            .unwrap();
        instances.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
        for instance in instances {
            state.push(format!(
                "{} {} {} {}",
                instance.operation_id,
                instance.principal,
                instance.status,
                instance.parameters_json
            ));
        }
        for action in &plan.actions {
            let created = db.get_object(&action.object_id).unwrap().unwrap();
            let mut properties: Vec<_> = created.properties.into_iter().collect();
            properties.sort();
            state.push(format!("{} {properties:?}", created.id));
        }
        state
    }

    #[test]
    fn the_same_seed_gives_identical_markings_roles_and_history() {
        let plan = generate(&SupplyChain, &spec(SizePreset::Demo)).unwrap();
        let first = RuntimeDb::memory();
        let second = RuntimeDb::memory();
        apply(&first, &plan).unwrap();
        apply(
            &second,
            &generate(&SupplyChain, &spec(SizePreset::Demo)).unwrap(),
        )
        .unwrap();
        let state = governance_state(&first, &plan);
        assert_eq!(state, governance_state(&second, &plan));
        assert_eq!(
            first
                .list_action_instances("synthetic-demo", None, None, 100)
                .unwrap()
                .len(),
            SizePreset::Demo.actions()
        );
        // The seeded distributions are real distributions, not one value.
        let marked: std::collections::HashSet<_> = plan
            .objects
            .iter()
            .filter_map(markings::object_marking_token)
            .collect();
        assert!(marked.len() > 1, "{marked:?}");
        let roles: std::collections::HashSet<_> = plan
            .principals
            .iter()
            .map(|principal| &principal.role)
            .collect();
        assert_eq!(roles.len(), 3);

        // Reapplying replays the history by idempotency key.
        apply(&first, &plan).unwrap();
        assert_eq!(governance_state(&first, &plan), state);
    }

    #[test]
    fn generated_history_carries_verifiable_receipts() {
        use crate::db::receipt_chain::install_test_signer;
        use crate::sekai::receipt_chain::{SigningKeySet, verify_bundle};
        let keys = SigningKeySet::from_seed_hex(
            "0000000000000000000000000000000000000000000000000000000000000015",
            1,
        )
        .unwrap();
        let _guard = install_test_signer(keys.clone());
        let db = RuntimeDb::memory();
        let plan = generate(&SupplyChain, &spec(SizePreset::Demo)).unwrap();
        apply(&db, &plan).unwrap();
        for action in &plan.actions {
            let receipt = db.get_operation_receipt(&action.request_id).unwrap();
            assert!(receipt.is_some(), "{} has no receipt", action.request_id);
        }
        let bundle = db.export_receipt_chain("synthetic-demo").unwrap();
        assert_eq!(bundle.entries.len(), plan.actions.len());
        verify_bundle(&bundle, &[keys.current_public_key_hex().as_str()])
            .expect("generated history verifies");
    }

    #[test]
    fn an_action_target_held_elsewhere_gets_no_synthetic_grant() {
        let db = RuntimeDb::memory();
        let plan = generate(&SupplyChain, &spec(SizePreset::Demo)).unwrap();
        let target = &plan.actions[0].object_id;
        db.create_object(&Object {
            id: target.clone(),
            kind: "record".into(),
            name: "real".into(),
            namespace: "real-tenant".into(),
            external_id: "real-record".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        assert!(apply(&db, &plan).is_err());
        assert!(db.list_grants(target).unwrap().is_empty());
    }

    #[test]
    fn reapply_refuses_a_changed_action_object() {
        let db = RuntimeDb::memory();
        let plan = generate(&SupplyChain, &spec(SizePreset::Demo)).unwrap();
        apply(&db, &plan).unwrap();
        let mut incident = db.get_object(&plan.actions[0].object_id).unwrap().unwrap();
        incident.name = "Edited".into();
        db.as_sqlite()
            .unwrap()
            .conn()
            .execute(
                "UPDATE sekai_objects SET name = ?1 WHERE id = ?2",
                rusqlite::params![incident.name, incident.id],
            )
            .unwrap();
        let error = apply(&db, &plan).unwrap_err();
        assert!(error.contains("differs"), "{error}");
    }

    #[test]
    fn a_namespace_with_whitespace_is_refused_before_any_write() {
        let error = generate(
            &SupplyChain,
            &Spec {
                namespace: "synthetic demo".into(),
                ..spec(SizePreset::Demo)
            },
        )
        .unwrap_err();
        assert!(error.contains("whitespace"), "{error}");
    }
}
