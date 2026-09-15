use crate::acl::PropertyAcl;
use crate::compute::{ComputeBackend, ComputeError};
use crate::store::Store;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aggregate {
    CountAndSum,
}

#[derive(Clone, Debug)]
pub struct Hop {
    pub far_kind: String,
    pub join_property: String,
}

#[derive(Clone, Debug)]
pub struct EvaluateRequest {
    pub root_kind: String,
    pub hops: Vec<Hop>,
    pub sum_kind: String,
    pub sum_property: String,
    pub aggregate: Aggregate,
    pub acl: PropertyAcl,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluateResponse {
    pub two_hop_count: usize,
    pub sum_amount: i64,
}

pub struct ObjectSet<B> {
    backend: B,
}

impl<B: ComputeBackend> ObjectSet<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn evaluate(
        &self,
        store: &Store,
        request: &EvaluateRequest,
    ) -> Result<EvaluateResponse, ComputeError> {
        self.backend.evaluate(store, request)
    }
}
