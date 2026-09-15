//! Dual-write / dual-read adapter for the kura object log.
//! Default remains the SQL object-type index. Nothing is deleted.

use crate::grpc::sekai_service::SekaiServiceImpl;
use crate::sekai::object_type_index::ObjectTypeIndexMember;
use kura::{
    Aggregate, BatchIngest, EvaluateRequest, Hop, LocalCompute, ObjectRecord, ObjectSet,
    PropertyAcl, Store,
};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectStoreMode {
    Sql,
    Kura,
    Dual,
}

impl ObjectStoreMode {
    pub fn from_env() -> Self {
        match std::env::var("SEKAI_OBJECT_STORE")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "kura" => Self::Kura,
            "dual" => Self::Dual,
            _ => Self::Sql,
        }
    }

    pub fn writes_kura(self) -> bool {
        matches!(self, Self::Kura | Self::Dual)
    }

    pub fn reads_kura(self) -> bool {
        matches!(self, Self::Kura | Self::Dual)
    }
}

pub fn log_path(namespace: &str) -> PathBuf {
    let root = std::env::var("KURA_LOG_DIR").unwrap_or_else(|_| "data/kura".into());
    PathBuf::from(root).join(format!("{namespace}.jsonl"))
}

pub fn persist_kind(service: &SekaiServiceImpl, namespace: &str, kind: &str) -> Result<(), String> {
    let members = service.db.list_visible_index_members(
        namespace,
        kind,
        &crate::sekai::dataset::RowQuery::default(),
    )?;
    let path = log_path(namespace);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut store = if path.exists() {
        Store::open(&path)?
    } else {
        Store::create(&path)?
    };
    let records: Vec<ObjectRecord> = members.iter().map(member_to_record).collect();
    store.replace_kind(kind, records)
}

pub fn evaluate_members(
    members: &[ObjectTypeIndexMember],
    root_kind: &str,
    hops: &[crate::sekai::object_set::ObjectSetTraversal],
    sum_kind: &str,
    sum_property: &str,
) -> Result<(usize, i64), String> {
    let dir = std::env::temp_dir().join(format!("kura-eval-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let log = dir.join("eval.jsonl");
    let mut store = Store::create(&log).map_err(|e| e.to_string())?;
    let records: Vec<ObjectRecord> = members.iter().map(member_to_record).collect();
    BatchIngest::run(&mut store, records).map_err(|e| e.to_string())?;
    let oss = ObjectSet::new(LocalCompute);
    let response = oss
        .evaluate(
            &store,
            &EvaluateRequest {
                root_kind: root_kind.into(),
                hops: hops
                    .iter()
                    .map(|hop| Hop {
                        far_kind: hop.far_kind.clone(),
                        join_property: hop.join_property.clone(),
                    })
                    .collect(),
                sum_kind: sum_kind.into(),
                sum_property: sum_property.into(),
                aggregate: Aggregate::CountAndSum,
                acl: PropertyAcl::allow_all(),
            },
        )
        .map_err(|e| format!("{e:?}"))?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok((response.two_hop_count, response.sum_amount))
}

fn member_to_record(member: &ObjectTypeIndexMember) -> ObjectRecord {
    ObjectRecord {
        generation: 1,
        kind: member.kind.clone(),
        key: member.source_key.clone(),
        hidden: member.hidden,
        props: member.properties.clone().into_iter().collect(),
    }
}
