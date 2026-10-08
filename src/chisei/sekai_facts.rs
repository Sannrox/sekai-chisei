//! Chisei-owned read port for Sekai facts.
//!
//! Sekai owns objects, links, grants, and schemas. Chisei reads them through
//! this port instead of its own store, so lookup-first and context injection
//! see the same facts whether Sekai shares the physical store, lives in a
//! second store in the same process, or runs as a separate process.
//!
//! - Combined mode reads the Sekai store in process (shared or split layout).
//! - The Chisei plane reads over an authenticated gRPC hop; `chisei-plane`
//!   requires `SEKAI_ENDPOINT` at boot (ADR 0096 rule 4). Sekai enforces its
//!   own authorization on the hop.

use std::fmt;
use std::sync::Arc;

use crate::chisei::object_schema::ObjectType;
use crate::chisei::principal::{MarkingClearance, PrincipalGrant};
use crate::db::store::SekaiStore;
use crate::domain::{Direction, ListFilter, Object};

/// Refusal reason when the attached Sekai cannot serve a read over its hop.
pub const SEKAI_READ_UNSUPPORTED: &str = "sekai_read_unsupported";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SekaiFactError {
    /// The attached Sekai cannot serve this read (for example over a gRPC hop).
    Unsupported(&'static str),
    /// The read reached Sekai and failed.
    Read(String),
}

impl SekaiFactError {
    /// Stable refusal reason for receipts and lookup decisions.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Unsupported(_) => SEKAI_READ_UNSUPPORTED,
            Self::Read(_) => "sekai_read_failed",
        }
    }
}

impl fmt::Display for SekaiFactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(read) => write!(f, "{SEKAI_READ_UNSUPPORTED}: {read}"),
            Self::Read(error) => f.write_str(error),
        }
    }
}

/// Sekai fact reads Chisei depends on.
pub trait SekaiFactReader: Send + Sync {
    fn find_by_external_id(&self, external_id: &str) -> Result<Option<Object>, SekaiFactError>;
    fn find_namespace_boundary(&self, namespace: &str) -> Result<Option<Object>, SekaiFactError>;
    /// Grants on an object, mapped into the Chisei principal context.
    fn list_grants(&self, object_id: &str) -> Result<Vec<PrincipalGrant>, SekaiFactError>;
    /// Classification-marking clearance of `principal` for `object`. Sekai
    /// owns markings and the lattice; Chisei receives only the outcome.
    fn marking_clearance(
        &self,
        operation_id: &str,
        object: &Object,
        principal: &str,
    ) -> Result<MarkingClearance, SekaiFactError>;
    fn get_object_type(&self, kind: &str) -> Result<Option<ObjectType>, SekaiFactError>;
    fn get_object(&self, id: &str) -> Result<Option<Object>, SekaiFactError>;
    fn list_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, SekaiFactError>;
    fn get_linked_objects(
        &self,
        object_id: &str,
        relation: &str,
        direction: &Direction,
    ) -> Result<Vec<Object>, SekaiFactError>;
    /// Graph-engine reads (bounded retrieval, computed properties, ontology
    /// snapshots) need the Sekai store in this process.
    fn in_process_store(&self) -> Result<&SekaiStore, SekaiFactError>;
}

/// Cloneable handle to the Sekai fact reader a Chisei service was built with.
#[derive(Clone)]
pub struct SekaiFacts(Arc<dyn SekaiFactReader>);

impl SekaiFacts {
    pub fn new(reader: Arc<dyn SekaiFactReader>) -> Self {
        Self(reader)
    }

    /// Combined mode: read the Sekai store in this process.
    pub fn in_process(store: SekaiStore) -> Self {
        Self(Arc::new(store))
    }

    pub fn reader(&self) -> &dyn SekaiFactReader {
        self.0.as_ref()
    }
}

impl Default for SekaiFacts {
    fn default() -> Self {
        Self::in_process(SekaiStore::memory())
    }
}

impl fmt::Debug for SekaiFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let attachment = match self.0.in_process_store() {
            Ok(_) => "in_process",
            Err(_) => "remote",
        };
        f.debug_tuple("SekaiFacts").field(&attachment).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_process_reader_reads_the_sekai_store_it_was_given() {
        let sekai = SekaiStore::memory();
        sekai
            .create_object(&Object {
                id: "o1".into(),
                kind: "widget".into(),
                name: "w".into(),
                namespace: "acme".into(),
                external_id: "widget:w".into(),
                properties: Default::default(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        let facts = SekaiFacts::in_process(sekai);
        assert_eq!(
            facts
                .reader()
                .find_by_external_id("widget:w")
                .unwrap()
                .map(|object| object.id),
            Some("o1".to_string())
        );
    }
}
