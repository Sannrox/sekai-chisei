//! Catalog entry lineage from typed core bindings (#1685).
//!
//! Traversal uses bindings and the existing transform graph. Unbound entries
//! have no lineage. A node whose target the caller cannot discover is a
//! redacted placeholder: kind only.

use std::collections::{HashSet, VecDeque};

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::catalog::{
    BindingKind, CATALOG_ENTRY_KIND, CatalogBinding, CatalogError, binding_from_entry,
};
use crate::sekai::governed_transform::GovernedTransform;

pub const DEFAULT_LINEAGE_DEPTH: usize = 8;
pub const MAX_LINEAGE_DEPTH: usize = 8;
pub const DEFAULT_LINEAGE_PAGE: usize = 32;
pub const MAX_LINEAGE_PAGE: usize = 32;

#[derive(Debug, Clone)]
pub struct LineageNode {
    pub entry: Option<Object>,
    pub redacted: bool,
    pub entry_kind: String,
}

#[derive(Debug, Clone)]
pub struct LineagePage {
    pub has_binding: bool,
    pub upstream: Vec<LineageNode>,
    pub downstream: Vec<LineageNode>,
    pub next_page_token: String,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CoreRef {
    kind: BindingKind,
    id: String,
}

pub fn parse_depth(depth: i32) -> Result<usize, CatalogError> {
    if depth < 0 || depth as usize > MAX_LINEAGE_DEPTH {
        return Err(CatalogError::Invalid(format!(
            "lineage depth must be between 0 and {MAX_LINEAGE_DEPTH}"
        )));
    }
    Ok(if depth == 0 {
        DEFAULT_LINEAGE_DEPTH
    } else {
        depth as usize
    })
}

pub fn parse_page(page_size: i32, page_token: &str) -> Result<(usize, usize), CatalogError> {
    if page_size < 0 || page_size as usize > MAX_LINEAGE_PAGE {
        return Err(CatalogError::Invalid(format!(
            "lineage page_size must be between 0 and {MAX_LINEAGE_PAGE}"
        )));
    }
    let page_size = if page_size == 0 {
        DEFAULT_LINEAGE_PAGE
    } else {
        page_size as usize
    };
    if page_token.is_empty() {
        return Ok((page_size, 0));
    }
    let offset = page_token
        .parse::<usize>()
        .map_err(|_| CatalogError::Invalid("lineage page_token is not an offset".into()))?;
    Ok((page_size, offset))
}

/// Walk upstream and downstream from `start`. `readable` is the catalog
/// entry; `discoverable` is the bound core artifact.
pub fn walk_lineage(
    db: &RuntimeDb,
    start: &Object,
    depth: usize,
    page_size: usize,
    offset: usize,
    readable: impl Fn(&Object) -> bool,
    discoverable: impl Fn(&CatalogBinding) -> bool,
) -> Result<LineagePage, CatalogError> {
    let Some(start_binding) = binding_from_entry(start) else {
        return Ok(LineagePage {
            has_binding: false,
            upstream: Vec::new(),
            downstream: Vec::new(),
            next_page_token: String::new(),
        });
    };
    let entries = list_catalog_entries(db, &start.namespace)?;
    let transforms = db
        .list_governed_transforms(&start.namespace)
        .map_err(CatalogError::Storage)?;
    let datasets = db.list_datasets().map_err(CatalogError::Storage)?;
    let mut type_links = Vec::new();
    for dataset in &datasets {
        for (namespace, kind) in db
            .dataset_bindings(&dataset.id)
            .map_err(CatalogError::Storage)?
        {
            if namespace == start.namespace {
                type_links.push((dataset.id.clone(), kind));
            }
        }
    }
    let mut source_datasets = Vec::new();
    for entry in &entries {
        let Some(binding) = binding_from_entry(entry) else {
            continue;
        };
        if binding.kind != BindingKind::Source {
            continue;
        }
        let Some(lineage) = db
            .get_source_identity_lineage(&start.namespace, &binding.target_id)
            .map_err(CatalogError::Storage)?
        else {
            continue;
        };
        source_datasets.push((binding.target_id, lineage.dataset_id));
    }
    let start_core = CoreRef {
        kind: start_binding.kind,
        id: start_binding.target_id.clone(),
    };
    let upstream = collect_direction(
        &start_core,
        Direction::Upstream,
        depth,
        &entries,
        &transforms,
        &type_links,
        &source_datasets,
        &readable,
        &discoverable,
    );
    let downstream = collect_direction(
        &start_core,
        Direction::Downstream,
        depth,
        &entries,
        &transforms,
        &type_links,
        &source_datasets,
        &readable,
        &discoverable,
    );
    let more = upstream.len().saturating_sub(offset) > page_size
        || downstream.len().saturating_sub(offset) > page_size;
    Ok(LineagePage {
        has_binding: true,
        upstream: page(&upstream, offset, page_size),
        downstream: page(&downstream, offset, page_size),
        next_page_token: if more {
            (offset + page_size).to_string()
        } else {
            String::new()
        },
    })
}

#[derive(Clone, Copy)]
enum Direction {
    Upstream,
    Downstream,
}

fn collect_direction(
    start: &CoreRef,
    direction: Direction,
    depth: usize,
    entries: &[Object],
    transforms: &[GovernedTransform],
    type_links: &[(String, String)],
    source_datasets: &[(String, String)],
    readable: &impl Fn(&Object) -> bool,
    discoverable: &impl Fn(&CatalogBinding) -> bool,
) -> Vec<LineageNode> {
    let mut nodes = Vec::new();
    let mut seen_cores = HashSet::from([start.clone()]);
    let mut seen_entries = HashSet::from([entries
        .iter()
        .find(|entry| {
            binding_from_entry(entry)
                .map(|binding| binding.kind == start.kind && binding.target_id == start.id)
                .unwrap_or(false)
        })
        .map(|entry| entry.id.clone())
        .unwrap_or_default()]);
    let mut queue = VecDeque::from([(start.clone(), 0usize)]);
    while let Some((core, hops)) = queue.pop_front() {
        if hops >= depth {
            continue;
        }
        for neighbor in neighbors(&core, direction, transforms, type_links, source_datasets) {
            if !seen_cores.insert(neighbor.clone()) {
                continue;
            }
            queue.push_back((neighbor.clone(), hops + 1));
            for entry in entries_for(&neighbor, entries) {
                if !seen_entries.insert(entry.id.clone()) {
                    continue;
                }
                let binding = binding_from_entry(entry);
                let hidden = binding
                    .as_ref()
                    .map(|binding| !discoverable(binding))
                    .unwrap_or(true)
                    || !readable(entry);
                nodes.push(if hidden {
                    LineageNode {
                        entry: None,
                        redacted: true,
                        entry_kind: neighbor.kind.entry_kind().as_str().into(),
                    }
                } else {
                    LineageNode {
                        entry: Some(entry.clone()),
                        redacted: false,
                        entry_kind: neighbor.kind.entry_kind().as_str().into(),
                    }
                });
            }
        }
    }
    nodes
}

fn neighbors(
    core: &CoreRef,
    direction: Direction,
    transforms: &[GovernedTransform],
    type_links: &[(String, String)],
    source_datasets: &[(String, String)],
) -> Vec<CoreRef> {
    let mut out = Vec::new();
    match (core.kind, direction) {
        (BindingKind::Dataset, Direction::Upstream) => {
            for transform in transforms {
                if transform.output_dataset_id == core.id {
                    out.push(CoreRef {
                        kind: BindingKind::Transform,
                        id: transform.transform_id.clone(),
                    });
                }
            }
            for (source_id, dataset_id) in source_datasets {
                if dataset_id == &core.id {
                    out.push(CoreRef {
                        kind: BindingKind::Source,
                        id: source_id.clone(),
                    });
                }
            }
        }
        (BindingKind::Dataset, Direction::Downstream) => {
            for transform in transforms {
                if transform.consumes_dataset(&core.id) {
                    out.push(CoreRef {
                        kind: BindingKind::Transform,
                        id: transform.transform_id.clone(),
                    });
                }
            }
            for (dataset_id, object_type_id) in type_links {
                if dataset_id == &core.id {
                    out.push(CoreRef {
                        kind: BindingKind::ObjectType,
                        id: object_type_id.clone(),
                    });
                }
            }
        }
        (BindingKind::Transform, Direction::Upstream) => {
            if let Some(transform) = transforms.iter().find(|t| t.transform_id == core.id) {
                for (_, dataset_id) in transform.input_bindings() {
                    if !dataset_id.is_empty() {
                        out.push(CoreRef {
                            kind: BindingKind::Dataset,
                            id: dataset_id,
                        });
                    }
                }
            }
        }
        (BindingKind::Transform, Direction::Downstream) => {
            if let Some(transform) = transforms.iter().find(|t| t.transform_id == core.id) {
                if !transform.output_dataset_id.is_empty() {
                    out.push(CoreRef {
                        kind: BindingKind::Dataset,
                        id: transform.output_dataset_id.clone(),
                    });
                }
            }
        }
        (BindingKind::ObjectType, Direction::Upstream) => {
            for (dataset_id, object_type_id) in type_links {
                if object_type_id == &core.id {
                    out.push(CoreRef {
                        kind: BindingKind::Dataset,
                        id: dataset_id.clone(),
                    });
                }
            }
        }
        (BindingKind::ObjectType, Direction::Downstream) => {}
        (BindingKind::Source, Direction::Upstream) => {}
        (BindingKind::Source, Direction::Downstream) => {
            for (source_id, dataset_id) in source_datasets {
                if source_id == &core.id {
                    out.push(CoreRef {
                        kind: BindingKind::Dataset,
                        id: dataset_id.clone(),
                    });
                }
            }
        }
    }
    out
}

fn entries_for<'a>(core: &CoreRef, entries: &'a [Object]) -> Vec<&'a Object> {
    entries
        .iter()
        .filter(|entry| {
            binding_from_entry(entry)
                .map(|binding| binding.kind == core.kind && binding.target_id == core.id)
                .unwrap_or(false)
        })
        .collect()
}

fn list_catalog_entries(db: &RuntimeDb, namespace: &str) -> Result<Vec<Object>, CatalogError> {
    let mut listed = Vec::new();
    loop {
        let page = db
            .list_objects(&crate::domain::ListFilter {
                kind: Some(CATALOG_ENTRY_KIND.into()),
                namespace: Some(namespace.into()),
                limit: crate::domain::MAX_LIST_LIMIT,
                offset: listed.len() as i32,
                ..crate::domain::ListFilter::default()
            })
            .map_err(CatalogError::Storage)?;
        let full = page.len() == crate::domain::MAX_LIST_LIMIT as usize;
        listed.extend(page);
        if !full {
            break;
        }
    }
    Ok(listed)
}

fn page(nodes: &[LineageNode], offset: usize, page_size: usize) -> Vec<LineageNode> {
    nodes.iter().skip(offset).take(page_size).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::catalog::{CatalogRegistration, EntryKind, register};
    use crate::sekai::dataset::Dataset;
    use crate::sekai::governed_transform::{CONTRACT_VERSION, TransformStep};
    use std::sync::Arc;

    fn db() -> RuntimeDb {
        RuntimeDb::Sqlite(Arc::new(
            crate::db::sekai::SekaiDb::new(":memory:").unwrap(),
        ))
    }

    fn dataset(id: &str, object_id: &str) -> Dataset {
        Dataset {
            id: id.into(),
            name: id.into(),
            columns: Vec::new(),
            object_id: object_id.into(),
            created: 1,
            partition_keys: Vec::new(),
        }
    }

    fn transform(namespace: &str, id: &str, input: &str, output: &str) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            transform_id: id.into(),
            input_dataset_id: input.into(),
            output_dataset_id: output.into(),
            steps: vec![TransformStep {
                kind: "filter".into(),
                column: "keep".into(),
                op: "eq".into(),
                value: "yes".into(),
                columns: Vec::new(),
            }],
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    }

    fn entry(kind: EntryKind, source_id: &str, binding: CatalogBinding) -> CatalogRegistration {
        CatalogRegistration {
            namespace: "acme".into(),
            entry_kind: kind,
            source_system: "test".into(),
            source_id: source_id.into(),
            display_name: source_id.into(),
            description: String::new(),
            owners: vec!["alice".into()],
            steward: String::new(),
            tags: Vec::new(),
            marking: String::new(),
            schema_summary: String::new(),
            freshness_ms: 0,
            deprecated: false,
            source_generation: 0,
            binding: Some(binding),
        }
    }

    #[test]
    fn unbound_entry_has_no_lineage() {
        let db = db();
        let registered = register(
            &db,
            CatalogRegistration {
                binding: None,
                ..entry(
                    EntryKind::Dataset,
                    "free",
                    CatalogBinding {
                        kind: BindingKind::Dataset,
                        target_id: "missing".into(),
                        source_type_descriptor_id: String::new(),
                    },
                )
            },
            "svc",
            1,
            None,
            |_, _| Ok(()),
        )
        .unwrap();
        let page = walk_lineage(&db, &registered.entry, 8, 32, 0, |_| true, |_| true).unwrap();
        assert!(!page.has_binding);
        assert!(page.upstream.is_empty());
        assert!(page.downstream.is_empty());
    }

    #[test]
    fn fixture_chain_source_transform_dataset_object_type() {
        let db = db();
        let descriptor =
            crate::sekai::source_type_descriptor::ProposedSourceTypeDescriptor::prepare(
                "warehouse",
                "Order",
                "v1",
            )
            .unwrap();
        crate::sekai::source_type_descriptor::register_source_type_descriptor(
            &db,
            "svc",
            "acme",
            &descriptor,
            1,
        )
        .unwrap();
        let source_id =
            crate::sekai::source_type_descriptor::registered_source_id(&descriptor, "shop", "tbl1")
                .unwrap();
        let mut batch = crate::sekai::object_sync::SourceBatch {
            contract_version: crate::sekai::object_sync::SOURCE_BATCH_VERSION.into(),
            namespace: "acme".into(),
            producer_identity: "connector/warehouse".into(),
            source: descriptor.source.clone(),
            source_instance: "shop".into(),
            family: crate::sekai::object_sync::FAMILY_OBJECT_SYNC.into(),
            adapter_id: crate::sekai::object_sync::ADAPTER_REGISTERED_OBJECT_SYNC.into(),
            adapter_version: crate::sekai::object_sync::ADAPTER_REGISTERED_OBJECT_SYNC_VERSION
                .into(),
            type_digest: descriptor.digest.clone(),
            current_cursor: String::new(),
            proposed_next_cursor: "cursor:1".into(),
            idempotency_key: "order-1".into(),
            batch_digest: String::new(),
            collected_at_ms: 20,
            records: vec![crate::sekai::object_sync::SourceRecord {
                source: descriptor.source.clone(),
                source_instance: "shop".into(),
                external_id: "tbl1".into(),
                source_version: "v1".into(),
                type_name: descriptor.record_kind.clone(),
                display_name: "orders".into(),
                payload_digest: format!("sha256:{}", "a".repeat(64)),
                properties: Default::default(),
                deleted: false,
                observed_at_ms: 10,
                source_sequence: None,
            }],
            delivery: None,
        };
        batch.batch_digest = batch.canonical_digest().unwrap();
        db.apply_source_batch(&batch, "connector/warehouse", 10)
            .unwrap();
        let raw_id = db
            .get_source_identity_lineage("acme", &source_id)
            .unwrap()
            .expect("receipt lineage")
            .dataset_id;
        db.create_dataset(&dataset(&raw_id, "acl-object")).unwrap();
        db.create_dataset(&dataset("orders", "")).unwrap();
        db.put_governed_transform(&transform("acme", "pipe", &raw_id, "orders"), 1)
            .unwrap();
        db.register_object_type_datasource(
            &crate::sekai::object_type_index::ObjectTypeDatasource {
                contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
                namespace: "acme".into(),
                kind: "Ticket".into(),
                definition_digest: "sha256:ticket".into(),
                dataset_id: "orders".into(),
                key_column: "id".into(),
                property_mapping: Default::default(),
                hidden_column: String::new(),
                edits_only: false,
            }
            .prepare()
            .unwrap(),
            1,
        )
        .unwrap();
        let source = register(
            &db,
            entry(
                EntryKind::Source,
                "src",
                CatalogBinding {
                    kind: BindingKind::Source,
                    target_id: source_id,
                    source_type_descriptor_id: descriptor.digest.clone(),
                },
            ),
            "svc",
            1,
            None,
            |_, _| Ok(()),
        )
        .unwrap()
        .entry;
        let pipeline = register(
            &db,
            entry(
                EntryKind::Pipeline,
                "pipe",
                CatalogBinding {
                    kind: BindingKind::Transform,
                    target_id: "pipe".into(),
                    source_type_descriptor_id: String::new(),
                },
            ),
            "svc",
            1,
            None,
            |_, _| Ok(()),
        )
        .unwrap()
        .entry;
        let dataset_entry = register(
            &db,
            entry(
                EntryKind::Dataset,
                "orders",
                CatalogBinding {
                    kind: BindingKind::Dataset,
                    target_id: "orders".into(),
                    source_type_descriptor_id: String::new(),
                },
            ),
            "svc",
            1,
            None,
            |_, _| Ok(()),
        )
        .unwrap()
        .entry;
        let parent = crate::sekai::definition_branch::DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            definition_json: r#"{"name":"Ticket"}"#.into(),
            member_digest: String::new(),
        }
        .prepare("acme")
        .unwrap();
        let revision = crate::sekai::definition_branch::prepare_revision(
            "acme",
            "",
            [crate::sekai::definition_branch::DefinitionRevisionMember {
                member_kind: parent.member_kind.clone(),
                member_id: parent.member_id.clone(),
                member_digest: parent.member_digest.clone(),
            }],
            true,
            "root",
            1,
        )
        .unwrap();
        db.seed_published_definition_revision(&revision, &[parent])
            .unwrap();
        crate::sekai::catalog::sync_ontology_entries(&db, "acme", "root", 2).unwrap();

        let from_source = walk_lineage(&db, &source, 8, 32, 0, |_| true, |_| true).unwrap();
        assert!(from_source.has_binding);
        assert!(from_source.upstream.is_empty());
        let down_kinds: Vec<_> = from_source
            .downstream
            .iter()
            .map(|node| node.entry_kind.as_str())
            .collect();
        assert!(down_kinds.contains(&"pipeline"), "{down_kinds:?}");
        assert!(down_kinds.contains(&"dataset"), "{down_kinds:?}");
        assert!(down_kinds.contains(&"object_type"), "{down_kinds:?}");

        let from_dataset = walk_lineage(&db, &dataset_entry, 8, 32, 0, |_| true, |_| true).unwrap();
        let up_kinds: Vec<_> = from_dataset
            .upstream
            .iter()
            .map(|node| node.entry_kind.as_str())
            .collect();
        assert!(up_kinds.contains(&"pipeline"), "{up_kinds:?}");
        assert!(up_kinds.contains(&"source"), "{up_kinds:?}");
        assert_eq!(from_dataset.downstream[0].entry_kind, "object_type");

        let hidden = walk_lineage(
            &db,
            &pipeline,
            8,
            32,
            0,
            |_| true,
            |binding| binding.kind != BindingKind::Dataset,
        )
        .unwrap();
        assert!(
            hidden
                .downstream
                .iter()
                .any(|node| node.redacted && node.entry_kind == "dataset")
        );
        assert!(hidden.downstream.iter().all(|node| {
            if node.redacted {
                node.entry.is_none()
            } else {
                true
            }
        }));
    }

    #[test]
    fn depth_and_page_limits_are_enforced() {
        assert!(parse_depth(9).is_err());
        assert!(parse_page(33, "").is_err());
        assert_eq!(parse_depth(0).unwrap(), 8);
        assert_eq!(parse_page(0, "4").unwrap(), (32, 4));
    }
}
