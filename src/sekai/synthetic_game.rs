//! The game reference workload as a synthetic tenant domain (#1616).
//!
//! [`GameWorkload`] builds a tenant from the pinned `hoshi-ontology/v1`
//! package (`examples/hoshi-ontology/`): players own planets, fleets are
//! stationed at planets, and players ally. It runs through the same
//! [`generate`](super::synthetic::generate) and [`apply`](super::synthetic::apply)
//! as every domain, so it shares the presets, determinism, markings,
//! principals and governed Action history. Game logic stays out of the core:
//! the history is governed Actions that give fleets standing orders; a fleet
//! stays at the planet its `stationed-at` link names.

use std::collections::HashMap;

use crate::sekai::governed_action_type::{EFFECT_KIND_NOTIFY, GovernedActionType};
use crate::sekai::markings;
use crate::sekai::schema::{ObjectType, PropertyType};
use crate::sekai::security::Role;
use crate::sekai::synthetic::{
    DomainData, DomainGenerator, DomainGovernance, GeneratedAction, GeneratedObject, MARKINGS, Rng,
    Spec, enum_property, principals_with_role, property, restricted_property, role_spaces,
    standard_principals,
};

/// The pinned package the classes and relations come from.
const PACKAGE: &str = include_str!("../../examples/hoshi-ontology/hoshi-v1.json");
const STANCES: &[&str] = &["parked", "patrol", "transit"];
const DISPOSITIONS: &[&str] = &["friendly", "neutral", "hostile"];
const FLEET_ORDER: &str = "game.fleet.order";

pub struct GameWorkload;

/// The package's description of `class`, or a fallback naming the package.
fn class_description(class: &str) -> String {
    serde_json::from_str::<serde_json::Value>(PACKAGE)
        .ok()
        .and_then(|package| {
            package["classes"].as_array().and_then(|classes| {
                classes
                    .iter()
                    .find(|entry| entry["name"] == class)
                    .and_then(|entry| entry["description"].as_str().map(str::to_string))
            })
        })
        .unwrap_or_else(|| format!("{class} (hoshi-ontology/v1)"))
}

fn coordinates(index: usize) -> String {
    format!(
        "{}:{}:{}",
        index / 225 + 1,
        index / 15 % 15 + 1,
        index % 15 + 1
    )
}

impl DomainGenerator for GameWorkload {
    fn name(&self) -> &'static str {
        "game_reference"
    }

    fn object_types(&self) -> Vec<ObjectType> {
        let kind = |class: &str, kind: &str, properties| ObjectType {
            kind: kind.into(),
            description: class_description(class),
            properties,
            is_builtin: false,
            implements: Vec::new(),
        };
        vec![
            kind(
                "Player",
                "game_player",
                vec![property("handle", PropertyType::String, true)],
            ),
            kind(
                "Planet",
                "game_planet",
                vec![
                    property("coordinates", PropertyType::String, true),
                    property("owner", PropertyType::String, true),
                    // Economic detail only the planet's administrators read.
                    restricted_property("resources", PropertyType::Int),
                ],
            ),
            kind(
                "Fleet",
                "game_fleet",
                vec![
                    property("planet", PropertyType::String, true),
                    property("ships", PropertyType::Int, true),
                    enum_property("stance", STANCES),
                    // Standing orders, for example `move:1:2:3`.
                    property("orders", PropertyType::String, false),
                ],
            ),
            kind(
                "Faction",
                "game_faction",
                vec![enum_property("disposition", DISPOSITIONS)],
            ),
        ]
    }

    fn action_types(&self, namespace: &str) -> Vec<GovernedActionType> {
        vec![GovernedActionType {
            namespace: namespace.into(),
            type_id: FLEET_ORDER.into(),
            version: "1".into(),
            description: "Give a fleet standing orders".into(),
            parameter_schema_json: serde_json::json!({
                "type": "object",
                "properties": {
                    "object_id": {"type": "string"},
                    "orders": {"type": "string"},
                },
                "required": ["object_id", "orders"],
                "additionalProperties": false,
            })
            .to_string(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            object_kind: "game_fleet".into(),
            object_mutation: "update".into(),
            enabled: true,
            created_by: "synthetic".into(),
            ..Default::default()
        }]
    }

    fn build(&self, spec: &Spec, rng: &mut Rng) -> DomainData {
        let total = spec.preset.objects();
        // Shares of the tenant; fleets take the rest.
        let players = (total / 20).max(2);
        let factions = (total / 40).max(1);
        let planets = (total * 9 / 20).max(1);
        let fleets = total - players - factions - planets;
        let mut objects: Vec<GeneratedObject> = Vec::with_capacity(total);
        let mut push = |kind: &str, name: String, properties: HashMap<String, String>| {
            objects.push(GeneratedObject {
                kind: kind.into(),
                name,
                properties,
            });
        };
        for index in 0..players {
            push(
                "game_player",
                format!("Player {:04}", index + 1),
                HashMap::from([("handle".into(), format!("player-{:04}", index + 1))]),
            );
        }
        for index in 0..factions {
            push(
                "game_faction",
                format!("Faction {:04}", index + 1),
                HashMap::from([("disposition".into(), rng.pick(DISPOSITIONS).into())]),
            );
        }
        let planet_start = players + factions;
        let mut links = Vec::new();
        for index in 0..planets {
            let owner = rng.below(players);
            links.push((owner, planet_start + index, "owns".to_string()));
            push(
                "game_planet",
                format!("Planet {}", coordinates(index)),
                HashMap::from([
                    ("coordinates".into(), coordinates(index)),
                    ("owner".into(), format!("player-{:04}", owner + 1)),
                    ("resources".into(), (rng.below(10_000)).to_string()),
                ]),
            );
        }
        let fleet_start = planet_start + planets;
        for index in 0..fleets {
            let planet = rng.below(planets);
            links.push((
                fleet_start + index,
                planet_start + planet,
                "stationed-at".into(),
            ));
            push(
                "game_fleet",
                format!("Fleet {:04}", index + 1),
                HashMap::from([
                    ("planet".into(), coordinates(planet)),
                    ("ships".into(), (1 + rng.below(500)).to_string()),
                    ("stance".into(), rng.pick(&STANCES[..2]).into()),
                ]),
            );
        }
        // Neighbouring players ally.
        for index in (0..players.saturating_sub(1)).step_by(2) {
            links.push((index, index + 1, "allied-with".into()));
        }
        for object in &mut objects {
            object.properties.insert(
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                rng.weighted(MARKINGS).into(),
            );
        }
        DomainData { objects, links }
    }

    fn governance(&self, spec: &Spec, data: &DomainData, rng: &mut Rng) -> DomainGovernance {
        let principals = standard_principals(spec, rng);
        let editors = principals_with_role(&principals, &Role::Editor);
        let spaces = role_spaces(&principals, "command", "intelligence");
        let planets: Vec<&str> = data
            .objects
            .iter()
            .filter(|object| object.kind == "game_planet")
            .map(|object| object.properties["coordinates"].as_str())
            .collect();
        // Each Action orders one distinct fleet to move to a planet.
        let actions = data
            .objects
            .iter()
            .enumerate()
            .filter(|(_, object)| object.kind == "game_fleet")
            .take(spec.preset.actions())
            .map(|(target, _)| {
                let mut parameters = serde_json::Map::new();
                parameters.insert(
                    "orders".into(),
                    format!("move:{}", planets[rng.below(planets.len())]).into(),
                );
                GeneratedAction {
                    type_id: FLEET_ORDER.into(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::runtime_db::RuntimeDb;
    use crate::sekai::synthetic::{SizePreset, apply, generate};

    fn spec(seed: u64) -> Spec {
        Spec {
            namespace: "game-demo".into(),
            seed,
            preset: SizePreset::Demo,
        }
    }

    #[test]
    fn the_package_defines_every_class_and_relation_the_domain_uses() {
        const CLASSES: &[&str] = &["Player", "Planet", "Fleet", "Faction"];
        const RELATIONS: &[&str] = &["owns", "stationed-at", "allied-with"];
        let package: serde_json::Value = serde_json::from_str(PACKAGE).unwrap();
        let named = |list: &str, name: &str| {
            package[list]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["name"] == name)
        };
        for class in CLASSES {
            assert!(named("classes", class), "{class}");
        }
        for relation in RELATIONS {
            assert!(named("relations", relation), "{relation}");
        }
        let types = GameWorkload.object_types();
        assert_eq!(types[0].description, class_description("Player"));
        assert!(!types[0].description.contains("hoshi-ontology/v1"));
    }

    #[test]
    fn the_same_seed_gives_the_same_tenant_and_it_applies_through_the_governed_path() {
        let first = generate(&GameWorkload, &spec(7)).unwrap();
        assert_eq!(
            first.digest,
            generate(&GameWorkload, &spec(7)).unwrap().digest
        );
        assert_ne!(
            first.digest,
            generate(&GameWorkload, &spec(8)).unwrap().digest
        );
        assert_eq!(first.objects.len(), SizePreset::Demo.objects());
        assert_eq!(first.domain, "game_reference");

        let db = RuntimeDb::memory();
        apply(&db, &first).unwrap();
        // History moved fleets through admitted governed Actions.
        let instances = db
            .list_action_instances("game-demo", Some(FLEET_ORDER), None, 100)
            .unwrap();
        assert_eq!(instances.len(), SizePreset::Demo.actions());
        assert!(
            instances
                .iter()
                .all(|instance| instance.status == "admitted")
        );
        let ordered = db.get_object(&first.actions[0].object_id).unwrap().unwrap();
        assert!(ordered.properties["orders"].starts_with("move:"));
        // Orders leave the fleet where its stationed-at link says it is.
        let station = first
            .links
            .iter()
            .find(|link| link.from_id == ordered.id && link.relation == "stationed-at")
            .unwrap();
        let planet = first
            .objects
            .iter()
            .find(|object| object.id == station.to_id)
            .unwrap();
        assert_eq!(
            ordered.properties["planet"],
            planet.properties["coordinates"]
        );
        // Reapplying replays rather than duplicating.
        apply(&db, &first).unwrap();
        assert_eq!(
            db.list_action_instances("game-demo", Some(FLEET_ORDER), None, 100)
                .unwrap()
                .len(),
            SizePreset::Demo.actions()
        );
    }
}
