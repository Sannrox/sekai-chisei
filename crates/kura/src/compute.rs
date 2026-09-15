use crate::acl::AclError;
use crate::objectset::{Aggregate, EvaluateRequest, EvaluateResponse};
use crate::store::{ObjectRecord, Store};
use std::collections::{HashMap, HashSet};

fn evaluate_local(store: &Store, request: &EvaluateRequest) -> EvaluateResponse {
    let mut paths: Vec<Vec<&ObjectRecord>> = store
        .visible_of_kind(&request.root_kind)
        .into_iter()
        .map(|record| vec![record])
        .collect();
    for hop in &request.hops {
        let children = store.visible_of_kind(&hop.far_kind);
        let mut by_value: HashMap<&str, Vec<&ObjectRecord>> = HashMap::new();
        for child in &children {
            if let Some(value) = child.props.get(&hop.join_property) {
                by_value.entry(value.as_str()).or_default().push(*child);
            }
        }
        let mut next = Vec::new();
        for path in &paths {
            let parent = path[path.len() - 1];
            if let Some(matched) = by_value.get(parent.key.as_str()) {
                for child in matched {
                    let mut joined = path.clone();
                    joined.push(*child);
                    next.push(joined);
                }
            }
        }
        paths = next;
    }
    let mut roots = HashSet::new();
    let mut sum = 0i64;
    for path in &paths {
        roots.insert(path[0].key.as_str());
        let leaf = path[path.len() - 1];
        if leaf.kind == request.sum_kind {
            if let Some(amount) = leaf
                .props
                .get(&request.sum_property)
                .and_then(|raw| raw.parse::<i64>().ok())
            {
                sum += amount;
            }
        }
    }
    EvaluateResponse {
        two_hop_count: roots.len(),
        sum_amount: sum,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputeError {
    Acl(AclError),
    UnsupportedBackend { name: &'static str },
}

pub trait ComputeBackend {
    fn name(&self) -> &'static str;
    fn evaluate(
        &self,
        store: &Store,
        request: &EvaluateRequest,
    ) -> Result<EvaluateResponse, ComputeError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LocalCompute;

impl ComputeBackend for LocalCompute {
    fn name(&self) -> &'static str {
        "local"
    }

    fn evaluate(
        &self,
        store: &Store,
        request: &EvaluateRequest,
    ) -> Result<EvaluateResponse, ComputeError> {
        match request.aggregate {
            Aggregate::CountAndSum => {
                request
                    .acl
                    .check(&request.sum_kind, &request.sum_property)
                    .map_err(ComputeError::Acl)?;
                Ok(evaluate_local(store, request))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SparkCompute;

impl ComputeBackend for SparkCompute {
    fn name(&self) -> &'static str {
        "spark"
    }

    fn evaluate(
        &self,
        _store: &Store,
        _request: &EvaluateRequest,
    ) -> Result<EvaluateResponse, ComputeError> {
        Err(ComputeError::UnsupportedBackend { name: "spark" })
    }
}
