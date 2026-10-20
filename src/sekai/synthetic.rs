//! Deterministic synthetic tenant generator (#1614, split from #1450).
//!
//! A generator builds a complete tenant plan from a seed and a size
//! preset: ontology definitions, objects with realistic distributions,
//! and links. The same seed and preset always produce the same plan and
//! the same digest, so load tests and demos are repeatable. Applying a
//! plan writes only into a namespace that is marked synthetic; a
//! namespace that exists without that marker refuses the write.

use std::collections::HashMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::db::sekai::SekaiDb;
use crate::domain::{Link, Object};
use crate::sekai::schema::{
    ObjectType, PropertyDef, PropertyType, SchemaRegistry, validate_object_type_definition,
};

/// Fixed clock for generated rows, so digests do not depend on wall time.
const BASE_TIME: i64 = 1_700_000_000_000;

/// How large a generated tenant is. The counts are the preset's contract:
/// the load-test preset reaches exactly these object and link counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
}

/// A domain's share of a tenant: its types and how its objects link.
pub trait DomainGenerator {
    /// Stable domain name, recorded on the namespace marker.
    fn name(&self) -> &'static str;
    /// Ontology definitions this domain contributes.
    fn object_types(&self) -> Vec<ObjectType>;
    /// Deterministically build this domain's objects and links.
    fn build(&self, spec: &Spec, rng: &mut Rng) -> DomainData;
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
}

/// The built-in domain: a small supply chain.
pub struct SupplyChain;

const REGIONS: &[&str] = &["north", "south", "east", "west", "central"];
const STATUSES: &[&str] = &["planned", "in_transit", "delivered", "delayed"];

fn property(name: &str, prop_type: PropertyType, required: bool) -> PropertyDef {
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

fn enum_property(name: &str, values: &[&str]) -> PropertyDef {
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
                    property("unit_cost", PropertyType::Int, true),
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
        ]
    }

    fn build(&self, spec: &Spec, rng: &mut Rng) -> DomainData {
        let total = spec.preset.objects();
        // Shares of the tenant, in type order; the last kind takes the rest.
        let suppliers = (total / 20).max(1);
        let warehouses = (total / 10).max(1);
        let parts = (total * 9 / 20).max(1);
        let shipments = total - suppliers - warehouses - parts;
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
    /// SHA-256 of the canonical plan JSON (types, objects, links).
    pub digest: String,
}

/// Build a plan without touching a store.
pub fn generate(domain: &dyn DomainGenerator, spec: &Spec) -> Result<SyntheticPlan, String> {
    if spec.namespace.trim().is_empty() {
        return Err("namespace required".into());
    }
    let types = domain.object_types();
    let registry = SchemaRegistry::new();
    for object_type in &types {
        validate_object_type_definition(object_type, None, &registry)?;
    }
    let mut rng = Rng::new(spec.seed);
    let data = domain.build(spec, &mut rng);
    let namespace = spec.namespace.trim();
    let objects: Vec<Object> = data
        .objects
        .into_iter()
        .enumerate()
        .map(|(index, generated)| Object {
            id: format!("syn:{}:{}:{:06}", namespace, spec.seed, index + 1),
            kind: generated.kind,
            name: generated.name,
            namespace: namespace.into(),
            external_id: format!("synthetic:{}:{:06}", spec.seed, index + 1),
            properties: generated.properties,
            created: BASE_TIME + index as i64,
            updated: BASE_TIME + index as i64,
        })
        .collect();
    // Generated definitions pass the same schema checks as real ones.
    let mut checks = SchemaRegistry::new();
    for object_type in &types {
        checks.register(object_type.clone());
    }
    for object in &objects {
        checks.validate(object)?;
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
            id: format!("syn:{}:{}:link:{:06}", namespace, spec.seed, index + 1),
            from_id: objects[from].id.clone(),
            to_id: objects[to].id.clone(),
            relation,
            created: BASE_TIME + index as i64,
        })
        .collect();
    let digest = plan_digest(
        namespace,
        domain.name(),
        spec.seed,
        spec.preset,
        &types,
        &objects,
        &links,
    )?;
    Ok(SyntheticPlan {
        namespace: namespace.into(),
        domain: domain.name().into(),
        seed: spec.seed,
        preset: spec.preset,
        types,
        objects,
        links,
        digest,
    })
}

/// The canonical digest of a plan's contents, recomputed on apply so a
/// caller-edited plan cannot reuse another plan's marker.
fn plan_digest(
    namespace: &str,
    domain: &str,
    seed: u64,
    preset: SizePreset,
    types: &[ObjectType],
    objects: &[Object],
    links: &[Link],
) -> Result<String, String> {
    let canonical = serde_json::to_string(&serde_json::json!({
        "namespace": namespace,
        "domain": domain,
        "seed": seed,
        "preset": preset.name(),
        "types": types,
        "objects": objects,
        "links": links,
    }))
    .map_err(|error| error.to_string())?;
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
/// check and marker creation run in one immediate transaction, so a
/// concurrent writer cannot slip real data in between.
fn claim_boundary(db: &SekaiDb, plan: &SyntheticPlan) -> Result<(), String> {
    use rusqlite::params;
    let boundary = synthetic_boundary(plan);
    let mut conn = db.conn();
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let external_id = format!("namespace:{}", plan.namespace);
    let mut statement = tx
        .prepare(
            "SELECT properties FROM sekai_objects WHERE external_id = ?1 AND kind = 'namespace'",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(params![external_id], |row| row.get::<_, String>(0))
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
    if let Some(properties) = rows.into_iter().next() {
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
        return Ok(());
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
    tx.commit().map_err(|error| error.to_string())?;
    Ok(())
}

/// Apply a plan to a store. The target namespace must be new or already
/// marked synthetic; anything else fails closed before any write.
/// Application is restartable: rows that already match the plan are
/// skipped, rows that conflict with it fail the apply.
pub fn apply(db: &SekaiDb, plan: &SyntheticPlan) -> Result<(), String> {
    let recomputed = plan_digest(
        &plan.namespace,
        &plan.domain,
        plan.seed,
        plan.preset,
        &plan.types,
        &plan.objects,
        &plan.links,
    )?;
    if recomputed != plan.digest {
        return Err("plan digest does not match its contents; refusing to write".into());
    }
    // A caller-built plan cannot smuggle rows out of the guarded
    // namespace, or links into objects the plan does not own.
    let owned: std::collections::HashSet<&str> = plan
        .objects
        .iter()
        .map(|object| object.id.as_str())
        .collect();
    for object in &plan.objects {
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
    claim_boundary(db, plan)?;
    for object_type in &plan.types {
        // Atomic insert-if-absent, then verify: a conflicting definition
        // registered concurrently is a failure, never an overwrite.
        db.insert_object_type_if_absent(object_type)?;
        match db.get_object_type(&object_type.kind)? {
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
    // Inserts are verified by reading back: a concurrent writer that
    // lands a conflicting row under the same id is a failure, even when
    // the underlying insert treats an existing id as success.
    for object in &plan.objects {
        if db.get_object(&object.id)?.is_none() {
            db.create_object(object)?;
        }
        match db.get_object(&object.id)? {
            Some(existing) if existing.persisted_state_matches(object) => {}
            _ => {
                return Err(format!("object {:?} already exists and differs", object.id));
            }
        }
    }
    for link in &plan.links {
        if db.get_link(&link.id)?.is_none() {
            db.create_link(link)?;
        }
        match db.get_link(&link.id)? {
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
        let db = SekaiDb::new(":memory:").unwrap();
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
    fn apply_refuses_a_namespace_that_is_not_synthetic() {
        let db = SekaiDb::new(":memory:").unwrap();
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
}
