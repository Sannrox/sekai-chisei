//! Chisei-owned read port for Sekai facts.
//!
//! Sekai owns objects, links, grants, and schemas. Chisei reads them through
//! this port instead of its own store, so lookup-first and context injection
//! see the same facts whether Sekai shares the physical store, lives in a
//! second store in the same process, or runs as a separate process.
//!
//! - Combined mode reads the Sekai store in process (shared or split layout).
//! - The Chisei plane reads over an authenticated gRPC hop when
//!   `SEKAI_ENDPOINT` is set; Sekai enforces its own authorization there.
//! - Without Sekai every read returns [`SekaiFactError::NotAttached`], never
//!   an empty answer.

use std::fmt;
use std::sync::Arc;

use crate::chisei::principal::{MarkingClearance, PrincipalGrant};
use crate::db::store::SekaiStore;
use crate::domain::{Direction, Object};
use crate::sekai::schema::ObjectType;

/// Refusal reason when no Sekai is attached to this Chisei process.
pub const SEKAI_NOT_ATTACHED: &str = "sekai_not_attached";
/// Refusal reason when the attached Sekai cannot serve a read over its hop.
pub const SEKAI_READ_UNSUPPORTED: &str = "sekai_read_unsupported";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SekaiFactError {
    /// No Sekai is configured for this process.
    NotAttached,
    /// The attached Sekai cannot serve this read (for example over a gRPC hop).
    Unsupported(&'static str),
    /// The read reached Sekai and failed.
    Read(String),
}

impl SekaiFactError {
    /// Stable refusal reason for receipts and lookup decisions.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotAttached => SEKAI_NOT_ATTACHED,
            Self::Unsupported(_) => SEKAI_READ_UNSUPPORTED,
            Self::Read(_) => "sekai_read_failed",
        }
    }
}

impl fmt::Display for SekaiFactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAttached => f.write_str(SEKAI_NOT_ATTACHED),
            Self::Unsupported(read) => write!(f, "{SEKAI_READ_UNSUPPORTED}: {read}"),
            Self::Read(error) => f.write_str(error),
        }
    }
}

/// Sekai fact reads Chisei depends on.
pub trait SekaiFactReader: Send + Sync {
    /// False only when no Sekai is configured for this process.
    fn attached(&self) -> bool {
        true
    }
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

/// Reader for a Chisei process with no Sekai attached.
#[derive(Debug, Clone, Copy, Default)]
pub struct SekaiNotAttached;

impl SekaiFactReader for SekaiNotAttached {
    fn attached(&self) -> bool {
        false
    }

    fn find_by_external_id(&self, _: &str) -> Result<Option<Object>, SekaiFactError> {
        Err(SekaiFactError::NotAttached)
    }

    fn find_namespace_boundary(&self, _: &str) -> Result<Option<Object>, SekaiFactError> {
        Err(SekaiFactError::NotAttached)
    }

    fn list_grants(&self, _: &str) -> Result<Vec<PrincipalGrant>, SekaiFactError> {
        Err(SekaiFactError::NotAttached)
    }

    fn marking_clearance(
        &self,
        _: &str,
        _: &Object,
        _: &str,
    ) -> Result<MarkingClearance, SekaiFactError> {
        Err(SekaiFactError::NotAttached)
    }

    fn get_object_type(&self, _: &str) -> Result<Option<ObjectType>, SekaiFactError> {
        Err(SekaiFactError::NotAttached)
    }

    fn get_linked_objects(
        &self,
        _: &str,
        _: &str,
        _: &Direction,
    ) -> Result<Vec<Object>, SekaiFactError> {
        Err(SekaiFactError::NotAttached)
    }

    fn in_process_store(&self) -> Result<&SekaiStore, SekaiFactError> {
        Err(SekaiFactError::NotAttached)
    }
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

    /// No Sekai attached: every read is an explicit refusal.
    pub fn not_attached() -> Self {
        Self(Arc::new(SekaiNotAttached))
    }

    pub fn reader(&self) -> &dyn SekaiFactReader {
        self.0.as_ref()
    }
}

impl Default for SekaiFacts {
    fn default() -> Self {
        Self::not_attached()
    }
}

impl fmt::Debug for SekaiFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let attachment = match self.0.in_process_store() {
            Ok(_) => "in_process",
            Err(_) if !self.0.attached() => SEKAI_NOT_ATTACHED,
            Err(_) => "remote",
        };
        f.debug_tuple("SekaiFacts").field(&attachment).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_attached_reads_refuse_instead_of_missing() {
        let facts = SekaiFacts::not_attached();
        let reader = facts.reader();
        assert_eq!(
            reader.find_by_external_id("widget:x").unwrap_err(),
            SekaiFactError::NotAttached
        );
        assert_eq!(
            reader.list_grants("x").unwrap_err().reason(),
            SEKAI_NOT_ATTACHED
        );
        assert!(reader.in_process_store().is_err());
        assert!(!reader.attached());
        assert_eq!(format!("{facts:?}"), "SekaiFacts(\"sekai_not_attached\")");
    }

    #[test]
    fn not_attached_grant_and_clearance_reads_deny() {
        use crate::chisei::principal::PrincipalContext;
        let reader = SekaiNotAttached;
        let object = Object {
            id: "o1".into(),
            kind: "widget".into(),
            name: "w".into(),
            namespace: "acme".into(),
            external_id: "widget:w".into(),
            properties: Default::default(),
            created: 0,
            updated: 0,
        };
        // No grants can be read, so no context decision can allow: callers
        // treat the refusal as a deny, never as "unrestricted".
        let alice = PrincipalContext::from_credential("alice");
        assert!(
            !reader
                .list_grants("o1")
                .is_ok_and(|grants| alice.may_read(&grants))
        );
        assert_eq!(
            reader
                .marking_clearance("test", &object, "alice")
                .unwrap_err(),
            SekaiFactError::NotAttached
        );
    }

    #[test]
    fn in_process_reader_reads_the_sekai_store_it_was_given() {
        let sekai = SekaiStore::memory();
        sekai
            .runtime()
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
