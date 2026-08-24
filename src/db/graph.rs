//! Backend-neutral contract for the reusable, non-tenant Sekai graph.
//!
//! The contract deliberately stops at graph facts, object ACLs, schema
//! metadata, lineage, and mutation audit. Coordination, evidence, retention,
//! ontology reasoning, and Chisei persistence are separate capabilities.

use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, Link, ListFilter, Object};
use crate::sekai::audit::ObjectChange;
use crate::sekai::lineage::LineageResult;
use crate::sekai::schema::{InterfaceDef, ObjectType};
use crate::sekai::security::Grant;
use rusqlite::{OptionalExtension, params};

pub const POSTGRES_GRAPH_SURFACES: &[&str] = &["sekai.audit", "sekai.authorization", "sekai.graph"];

pub fn postgres_graph_capabilities() -> crate::runtime_backend::BackendCapabilities {
    crate::runtime_backend::BackendCapabilities {
        contract_version: crate::runtime_backend::RUNTIME_BACKEND_CONTRACT_VERSION.into(),
        backend: crate::runtime_backend::BackendIdentity::Postgres,
        reusable_surfaces: POSTGRES_GRAPH_SURFACES
            .iter()
            .map(|surface| (*surface).to_string())
            .collect(),
        migration_version: None,
    }
}

/// Complete persistence boundary used by the reusable core graph.
///
/// Mutations are intentionally actor-bearing: implementations must commit the
/// graph write and its object-change audit rows in one database transaction.
pub trait GraphBackend: Send + Sync {
    fn create_object(&self, object: &Object, actor: &str) -> Result<(), String>;
    fn get_object(&self, id: &str) -> Result<Option<Object>, String>;
    fn update_object(
        &self,
        object: &Object,
        actor: &str,
        expected_updated: i64,
    ) -> Result<Option<Object>, String>;
    fn delete_object(&self, id: &str, actor: &str) -> Result<Option<Object>, String>;
    fn list_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String>;
    fn list_objects_for_principals(
        &self,
        filter: &ListFilter,
        principals: &[&str],
    ) -> Result<(Vec<Object>, i32), String>;

    fn create_link(&self, link: &Link) -> Result<bool, String>;
    fn delete_link(&self, id: &str) -> Result<(), String>;
    fn get_links(
        &self,
        object_id: &str,
        relation: &str,
        direction: &Direction,
    ) -> Result<Vec<Link>, String>;

    fn upsert_object_type(&self, object_type: &ObjectType) -> Result<(), String>;
    fn get_object_type(&self, kind: &str) -> Result<Option<ObjectType>, String>;
    fn list_object_types(&self) -> Result<Vec<ObjectType>, String>;
    fn delete_object_type(&self, kind: &str) -> Result<bool, String>;
    fn upsert_interface(&self, interface: &InterfaceDef) -> Result<(), String>;
    fn list_interfaces(&self) -> Result<Vec<InterfaceDef>, String>;
    fn delete_interface(&self, name: &str) -> Result<bool, String>;

    fn create_grant(&self, grant: &Grant) -> Result<(), String>;
    fn delete_grant(&self, id: &str) -> Result<Option<Grant>, String>;
    fn list_grants(&self, object_id: &str) -> Result<Vec<Grant>, String>;
    fn can_access(&self, object_id: &str, principals: &[&str]) -> Result<bool, String>;
    fn can_write(&self, object_id: &str, principals: &[&str]) -> Result<bool, String>;
    fn can_admin(&self, object_id: &str, principals: &[&str]) -> Result<bool, String>;

    fn list_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String>;
    fn lineage(&self, object_id: &str, max_nodes: usize) -> Result<LineageResult, String>;
}

impl GraphBackend for SekaiDb {
    fn create_object(&self, object: &Object, actor: &str) -> Result<(), String> {
        self.create_object_with_audit(object, actor)
    }
    fn get_object(&self, id: &str) -> Result<Option<Object>, String> {
        self.get_object(id)
    }
    fn update_object(
        &self,
        object: &Object,
        actor: &str,
        expected_updated: i64,
    ) -> Result<Option<Object>, String> {
        sqlite_update_object(self, object, actor, expected_updated)
    }
    fn delete_object(&self, id: &str, actor: &str) -> Result<Option<Object>, String> {
        self.delete_object_with_audit(id, None, actor)
    }
    fn list_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        self.list_objects(filter)
    }
    fn list_objects_for_principals(
        &self,
        filter: &ListFilter,
        principals: &[&str],
    ) -> Result<(Vec<Object>, i32), String> {
        self.list_objects_with_total_for_principals(filter, principals, &[])
    }
    fn create_link(&self, link: &Link) -> Result<bool, String> {
        self.create_link_once(link)
    }
    fn delete_link(&self, id: &str) -> Result<(), String> {
        self.delete_link(id)
    }
    fn get_links(
        &self,
        object_id: &str,
        relation: &str,
        direction: &Direction,
    ) -> Result<Vec<Link>, String> {
        self.get_links(object_id, relation, direction)
    }
    fn upsert_object_type(&self, object_type: &ObjectType) -> Result<(), String> {
        self.upsert_object_type(object_type)
    }
    fn get_object_type(&self, kind: &str) -> Result<Option<ObjectType>, String> {
        self.get_object_type(kind)
    }
    fn list_object_types(&self) -> Result<Vec<ObjectType>, String> {
        self.list_object_types()
    }
    fn delete_object_type(&self, kind: &str) -> Result<bool, String> {
        self.delete_object_type(kind)
    }
    fn upsert_interface(&self, interface: &InterfaceDef) -> Result<(), String> {
        self.upsert_interface(interface)
    }
    fn list_interfaces(&self) -> Result<Vec<InterfaceDef>, String> {
        self.list_interfaces()
    }
    fn delete_interface(&self, name: &str) -> Result<bool, String> {
        self.delete_interface(name)
    }
    fn create_grant(&self, grant: &Grant) -> Result<(), String> {
        self.create_grant(grant)
    }
    fn delete_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        self.delete_grant(id)
    }
    fn list_grants(&self, object_id: &str) -> Result<Vec<Grant>, String> {
        self.list_grants(object_id)
    }
    fn can_access(&self, object_id: &str, principals: &[&str]) -> Result<bool, String> {
        crate::db::graph::sqlite_access(self, object_id, principals, "read")
    }
    fn can_write(&self, object_id: &str, principals: &[&str]) -> Result<bool, String> {
        crate::db::graph::sqlite_access(self, object_id, principals, "write")
    }
    fn can_admin(&self, object_id: &str, principals: &[&str]) -> Result<bool, String> {
        crate::db::graph::sqlite_access(self, object_id, principals, "admin")
    }
    fn list_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String> {
        self.list_object_changes(object_id, limit, offset)
    }
    fn lineage(&self, object_id: &str, max_nodes: usize) -> Result<LineageResult, String> {
        crate::sekai::lineage::get_lineage(self, object_id, max_nodes)
    }
}

fn sqlite_access(
    db: &SekaiDb,
    object_id: &str,
    principals: &[&str],
    action: &str,
) -> Result<bool, String> {
    let Some(object) = db.get_object(object_id)? else {
        return Ok(false);
    };
    let privileged = principals
        .iter()
        .any(|principal| matches!(*principal, "root" | "local"));
    if !privileged
        && let Some(boundary) = db.find_namespace_boundary(&object.namespace)?
        && boundary
            .properties
            .get("team_managed")
            .is_some_and(|managed| managed == "true")
        && !db
            .list_grants(&boundary.id)?
            .iter()
            .any(|grant| principals.contains(&grant.principal.as_str()))
    {
        return Ok(false);
    }
    let grants = db.list_grants(object_id)?;
    if action == "admin" {
        return Ok(grants.iter().any(|grant| {
            principals.contains(&grant.principal.as_str())
                && grant.role == crate::sekai::security::Role::Admin
        }));
    }
    if grants.is_empty() {
        return Ok(true);
    }
    Ok(grants.iter().any(|grant| {
        principals.contains(&grant.principal.as_str())
            && (action == "read"
                || matches!(
                    grant.role,
                    crate::sekai::security::Role::Editor | crate::sekai::security::Role::Admin
                ))
    }))
}

fn sqlite_update_object(
    db: &SekaiDb,
    object: &Object,
    actor: &str,
    expected_updated: i64,
) -> Result<Option<Object>, String> {
    if object.external_id.starts_with("namespace:") && object.kind != "namespace" {
        return Err("namespace:* external IDs are reserved for namespace boundaries".into());
    }
    let mut connection = db.conn();
    let transaction = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    let before = transaction
        .query_row(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated
             FROM sekai_objects WHERE id = ?1",
            params![object.id],
            crate::db::sekai::row_to_object,
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(before) = before else {
        transaction.commit().map_err(|error| error.to_string())?;
        return Ok(None);
    };
    if before.updated != expected_updated || object.updated <= expected_updated {
        return Err("object revision conflict".into());
    }
    if before.namespace != object.namespace {
        return Err("object namespace is immutable".into());
    }
    if before.created != object.created {
        return Err("object created timestamp is immutable".into());
    }
    if before.kind != object.kind {
        crate::sekai::ontology::validate_object_kind_change(
            &transaction,
            &object.id,
            &object.kind,
        )?;
    }
    let properties =
        serde_json::to_string(&object.properties).map_err(|error| error.to_string())?;
    let changed = transaction
        .execute(
            "UPDATE sekai_objects SET
                kind = ?2, name = ?3, namespace = ?4, external_id = ?5,
                properties = ?6, updated = ?7
             WHERE id = ?1 AND updated = ?8",
            params![
                object.id,
                object.kind,
                object.name,
                object.namespace,
                object.external_id,
                properties,
                object.updated,
                expected_updated
            ],
        )
        .map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err("object revision conflict".into());
    }
    let now = chrono::Utc::now().timestamp_millis();
    crate::sekai::audit::insert_object_changes(
        &transaction,
        &crate::sekai::audit::object_diff_changes(actor, Some(&before), Some(object), now),
    )?;
    transaction.commit().map_err(|error| error.to_string())?;
    Ok(Some(before))
}

impl GraphBackend for PostgresDb {
    fn create_object(&self, object: &Object, actor: &str) -> Result<(), String> {
        self.create_object_with_audit(object, actor)
    }
    fn get_object(&self, id: &str) -> Result<Option<Object>, String> {
        self.get_object(id)
    }
    fn update_object(
        &self,
        object: &Object,
        actor: &str,
        expected_updated: i64,
    ) -> Result<Option<Object>, String> {
        self.update_object_with_audit_if_revision(object, actor, expected_updated, None)
    }
    fn delete_object(&self, id: &str, actor: &str) -> Result<Option<Object>, String> {
        self.delete_object_with_audit(id, None, actor)
    }
    fn list_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        self.list_objects(filter)
    }
    fn list_objects_for_principals(
        &self,
        filter: &ListFilter,
        principals: &[&str],
    ) -> Result<(Vec<Object>, i32), String> {
        self.list_objects_with_total_for_principals(filter, principals)
    }
    fn create_link(&self, link: &Link) -> Result<bool, String> {
        self.create_link_once(link)
    }
    fn delete_link(&self, id: &str) -> Result<(), String> {
        self.delete_link(id)
    }
    fn get_links(
        &self,
        object_id: &str,
        relation: &str,
        direction: &Direction,
    ) -> Result<Vec<Link>, String> {
        self.get_links(object_id, relation, direction)
    }
    fn upsert_object_type(&self, object_type: &ObjectType) -> Result<(), String> {
        self.upsert_object_type(object_type)
    }
    fn get_object_type(&self, kind: &str) -> Result<Option<ObjectType>, String> {
        self.get_object_type(kind)
    }
    fn list_object_types(&self) -> Result<Vec<ObjectType>, String> {
        self.list_object_types()
    }
    fn delete_object_type(&self, kind: &str) -> Result<bool, String> {
        self.delete_object_type(kind)
    }
    fn upsert_interface(&self, interface: &InterfaceDef) -> Result<(), String> {
        self.upsert_interface(interface)
    }
    fn list_interfaces(&self) -> Result<Vec<InterfaceDef>, String> {
        self.list_interfaces()
    }
    fn delete_interface(&self, name: &str) -> Result<bool, String> {
        self.delete_interface(name)
    }
    fn create_grant(&self, grant: &Grant) -> Result<(), String> {
        self.create_grant(grant)
    }
    fn delete_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        self.delete_grant(id)
    }
    fn list_grants(&self, object_id: &str) -> Result<Vec<Grant>, String> {
        self.list_grants(object_id)
    }
    fn can_access(&self, object_id: &str, principals: &[&str]) -> Result<bool, String> {
        self.can_access(object_id, principals)
    }
    fn can_write(&self, object_id: &str, principals: &[&str]) -> Result<bool, String> {
        self.can_write(object_id, principals)
    }
    fn can_admin(&self, object_id: &str, principals: &[&str]) -> Result<bool, String> {
        self.can_admin(object_id, principals)
    }
    fn list_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String> {
        self.list_object_changes(object_id, limit, offset)
    }
    fn lineage(&self, object_id: &str, max_nodes: usize) -> Result<LineageResult, String> {
        self.get_lineage(object_id, max_nodes)
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;

    #[test]
    fn postgres_advertises_only_completed_core_graph_surfaces() {
        let fixture: crate::runtime_backend::BackendCapabilities = serde_json::from_str(
            include_str!("../../tests/fixtures/runtime_backend/postgres-graph-v1.json"),
        )
        .unwrap();
        assert_eq!(postgres_graph_capabilities(), fixture);
        assert!(!fixture.reusable_surfaces.iter().any(|surface| {
            surface.starts_with("chisei.")
                || matches!(
                    surface.as_str(),
                    "sekai.coordination" | "sekai.evidence" | "sekai.ontology"
                )
        }));
    }
}
