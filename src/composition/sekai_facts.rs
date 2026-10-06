//! In-process implementation of the Chisei Sekai fact port (ADR 0092 rule 4).
//!
//! Combined mode reads the Sekai store in this process, shared or split.

use crate::chisei::principal::{MarkingClearance, PrincipalGrant};
use crate::chisei::sekai_facts::{SekaiFactError, SekaiFactReader};
use crate::db::store::SekaiStore;
use crate::domain::{Direction, Object};
use crate::sekai::schema::ObjectType;

fn read<T>(result: Result<T, String>) -> Result<T, SekaiFactError> {
    result.map_err(SekaiFactError::Read)
}

impl SekaiFactReader for SekaiStore {
    fn find_by_external_id(&self, external_id: &str) -> Result<Option<Object>, SekaiFactError> {
        read(self.runtime().find_by_external_id(external_id))
    }

    fn find_namespace_boundary(&self, namespace: &str) -> Result<Option<Object>, SekaiFactError> {
        read(self.runtime().find_namespace_boundary(namespace))
    }

    fn list_grants(&self, object_id: &str) -> Result<Vec<PrincipalGrant>, SekaiFactError> {
        read(self.runtime().list_principal_grants(object_id))
    }

    fn marking_clearance(
        &self,
        operation_id: &str,
        object: &Object,
        principal: &str,
    ) -> Result<MarkingClearance, SekaiFactError> {
        read(self.principal_marking_clearance(operation_id, object, principal))
    }

    fn get_object_type(&self, kind: &str) -> Result<Option<ObjectType>, SekaiFactError> {
        read(self.runtime().get_object_type(kind))
    }

    fn get_linked_objects(
        &self,
        object_id: &str,
        relation: &str,
        direction: &Direction,
    ) -> Result<Vec<Object>, SekaiFactError> {
        read(
            self.runtime()
                .get_linked_objects(object_id, relation, direction),
        )
    }

    fn in_process_store(&self) -> Result<&SekaiStore, SekaiFactError> {
        Ok(self)
    }
}
