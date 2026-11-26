//! Dual-backend community-store dispatch for object security.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn put_object_security_policy(
        &self,
        policy: &ObjectSecurityPolicy,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityPolicyRevision, String> {
        match self {
            Self::Sqlite(db) => {
                db.put_object_security_policy(policy, actor, idempotency_key, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_object_security_policy(policy, actor, idempotency_key, now_ms)
            }),
        }
    }

    pub fn get_object_security_policy(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<ObjectSecurityPolicyRevision>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_security_policy(namespace, revision_digest),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_object_security_policy(namespace, revision_digest)
            }),
        }
    }

    pub fn activate_object_security_policies(
        &self,
        namespace: &str,
        policies: &BTreeMap<String, String>,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityActivation, String> {
        match self {
            Self::Sqlite(db) => db.activate_object_security_policies(
                namespace,
                policies,
                actor,
                idempotency_key,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.activate_object_security_policies(
                    namespace,
                    policies,
                    actor,
                    idempotency_key,
                    now_ms,
                )
            }),
        }
    }

    pub fn get_object_security_activation(
        &self,
        namespace: &str,
    ) -> Result<Option<ObjectSecurityActivation>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_security_activation(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_object_security_activation(namespace))
            }
        }
    }

    pub fn has_object_security_activations(&self) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.has_object_security_activations(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.has_object_security_activations())
            }
        }
    }

    pub fn record_policy_decision(
        &self,
        record: &crate::sekai::policy_decision::PolicyDecisionRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_policy_decision(record),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.record_policy_decision(record))
            }
        }
    }

    pub fn query_policy_decisions(
        &self,
        query: &crate::sekai::policy_decision::PolicyDecisionQuery,
    ) -> Result<Vec<crate::sekai::policy_decision::PolicyDecisionRecord>, String> {
        match self {
            Self::Sqlite(db) => db.query_policy_decisions(query),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.query_policy_decisions(query))
            }
        }
    }

    pub fn register_object_type_datasource(
        &self,
        binding: &crate::sekai::object_type_index::ObjectTypeDatasource,
        created_at_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.register_object_type_datasource(binding, created_at_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.register_object_type_datasource(binding, created_at_ms)
            }),
        }
    }

    pub fn get_object_type_datasource(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Option<crate::sekai::object_type_index::ObjectTypeDatasource>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_type_datasource(namespace, kind),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_object_type_datasource(namespace, kind))
            }
        }
    }

    pub fn apply_object_type_index(
        &self,
        namespace: &str,
        kind: &str,
        full_rebuild: bool,
        now_ms: i64,
    ) -> Result<crate::sekai::object_type_index::ReindexReport, String> {
        match self {
            Self::Sqlite(db) => db.apply_object_type_index(namespace, kind, full_rebuild, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.apply_object_type_index(namespace, kind, full_rebuild, now_ms)
            }),
        }
    }

    pub fn put_object_type_index_edit(
        &self,
        edit: &crate::sekai::object_type_index::ObjectTypeIndexEdit,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_object_type_index_edit(edit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_object_type_index_edit(edit))
            }
        }
    }

    pub fn object_log_migration_identities(&self) -> Result<Vec<(String, String, String)>, String> {
        match self {
            Self::Sqlite(db) => db.object_log_migration_identities(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.object_log_migration_identities())
            }
        }
    }

    pub fn object_type_index_status(
        &self,
        namespace: &str,
        kind: &str,
        now_ms: i64,
    ) -> Result<Option<crate::sekai::object_type_index::ObjectTypeIndexStatus>, String> {
        match self {
            Self::Sqlite(db) => db.object_type_index_status(namespace, kind, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.object_type_index_status(namespace, kind, now_ms)
            }),
        }
    }

    pub fn list_visible_index_members(
        &self,
        namespace: &str,
        kind: &str,
        query: &RowQuery,
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>, String> {
        self.list_visible_index_members_projected(namespace, kind, query, None)
    }

    pub fn list_visible_index_members_projected(
        &self,
        namespace: &str,
        kind: &str,
        query: &RowQuery,
        needed: Option<&[String]>,
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_visible_index_members_projected(namespace, kind, query, needed)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_visible_index_members_projected(namespace, kind, query, needed)
            }),
        }
    }

    pub fn list_kind_objects_outside_index(
        &self,
        namespace: &str,
        kind: &str,
        offset: i32,
        limit: i32,
    ) -> Result<Vec<crate::domain::Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_kind_objects_outside_index(namespace, kind, offset, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_kind_objects_outside_index(namespace, kind, offset, limit)
            }),
        }
    }

    pub fn list_index_member_object_ids(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Vec<String>, String> {
        match self {
            Self::Sqlite(db) => db.list_index_member_object_ids(namespace, kind),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_index_member_object_ids(namespace, kind)
            }),
        }
    }

    pub fn count_visible_index_members(&self, namespace: &str, kind: &str) -> Result<i32, String> {
        self.count_visible_index_members_matching(namespace, kind, &[])
    }

    pub fn count_visible_index_members_matching(
        &self,
        namespace: &str,
        kind: &str,
        filters: &[crate::sekai::dataset::RowFilter],
    ) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.count_visible_index_members_matching(namespace, kind, filters),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.count_visible_index_members_matching(namespace, kind, filters)
            }),
        }
    }

    pub fn hop_projection_ready(&self, namespace: &str, kind: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.hop_projection_ready(namespace, kind),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.hop_projection_ready(namespace, kind))
            }
        }
    }

    pub fn hop_projection_kinds_ready(
        &self,
        namespace: &str,
        kinds: &[&str],
        published: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.hop_projection_kinds_ready(namespace, kinds, published),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.hop_projection_kinds_ready(namespace, kinds, published)
            }),
        }
    }

    pub fn set_hop_projection_ready(
        &self,
        namespace: &str,
        kind: &str,
        ready: bool,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_hop_projection_ready(namespace, kind, ready, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_hop_projection_ready(namespace, kind, ready, now_ms)
            }),
        }
    }

    pub fn invalidate_namespace_hop_projection(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.invalidate_namespace_hop_projection(namespace, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.invalidate_namespace_hop_projection(namespace, now_ms)
            }),
        }
    }

    pub fn count_index_join_rows(&self, namespace: &str, kind: &str) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.count_index_join_rows(namespace, kind),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.count_index_join_rows(namespace, kind))
            }
        }
    }

    pub fn list_index_join_children(
        &self,
        namespace: &str,
        kind: &str,
        property: &str,
        values: &[String],
    ) -> Result<Vec<(String, String)>, String> {
        match self {
            Self::Sqlite(db) => db.list_index_join_children(namespace, kind, property, values),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_index_join_children(namespace, kind, property, values)
            }),
        }
    }

    pub fn list_index_join_values(
        &self,
        namespace: &str,
        kind: &str,
        property: &str,
        source_keys: &[String],
    ) -> Result<Vec<(String, String)>, String> {
        match self {
            Self::Sqlite(db) => db.list_index_join_values(namespace, kind, property, source_keys),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_index_join_values(namespace, kind, property, source_keys)
            }),
        }
    }

    pub fn list_index_members_by_keys(
        &self,
        namespace: &str,
        kind: &str,
        keys: &[String],
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>, String> {
        self.list_index_members_by_keys_projected(namespace, kind, keys, None)
    }

    pub fn list_index_members_by_keys_projected(
        &self,
        namespace: &str,
        kind: &str,
        keys: &[String],
        needed: Option<&[String]>,
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_index_members_by_keys_projected(namespace, kind, keys, needed)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_index_members_by_keys_projected(namespace, kind, keys, needed)
            }),
        }
    }

    pub fn list_index_member_idents(
        &self,
        namespace: &str,
        kind: &str,
        keys: &[String],
    ) -> Result<Vec<(String, String)>, String> {
        match self {
            Self::Sqlite(db) => db.list_index_member_idents(namespace, kind, keys),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_index_member_idents(namespace, kind, keys)
            }),
        }
    }

    pub fn put_purpose_authorization(
        &self,
        authorization: &crate::sekai::purpose_authorization::PurposeAuthorization,
    ) -> Result<crate::sekai::purpose_authorization::PurposeAuthorization, String> {
        match self {
            Self::Sqlite(db) => db.put_purpose_authorization(authorization),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_purpose_authorization(authorization))
            }
        }
    }

    pub fn get_purpose_authorization(
        &self,
        authorization_id: &str,
    ) -> Result<Option<crate::sekai::purpose_authorization::PurposeAuthorization>, String> {
        match self {
            Self::Sqlite(db) => db.get_purpose_authorization(authorization_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_purpose_authorization(authorization_id))
            }
        }
    }

    pub fn revoke_purpose_authorization(
        &self,
        authorization_id: &str,
        revoked_at_ms: i64,
    ) -> Result<crate::sekai::purpose_authorization::PurposeAuthorization, String> {
        match self {
            Self::Sqlite(db) => db.revoke_purpose_authorization(authorization_id, revoked_at_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.revoke_purpose_authorization(authorization_id, revoked_at_ms)
            }),
        }
    }

    pub fn find_purpose_authorization(
        &self,
        actor: &str,
        purpose: &str,
        namespace: &str,
        kind: &str,
        activation_digest: &str,
        now_ms: i64,
    ) -> Result<Option<crate::sekai::purpose_authorization::PurposeAuthorization>, String> {
        match self {
            Self::Sqlite(db) => db.find_purpose_authorization(
                actor,
                purpose,
                namespace,
                kind,
                activation_digest,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.find_purpose_authorization(
                    actor,
                    purpose,
                    namespace,
                    kind,
                    activation_digest,
                    now_ms,
                )
            }),
        }
    }

    pub fn put_classification_lattice(
        &self,
        lattice: &crate::sekai::classification_lattice::ClassificationLattice,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::classification_lattice::ClassificationLattice, String> {
        match self {
            Self::Sqlite(db) => db.put_classification_lattice(lattice, actor, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_classification_lattice(lattice, actor, now_ms)
            }),
        }
    }

    pub fn get_classification_lattice(
        &self,
        namespace: &str,
    ) -> Result<Option<crate::sekai::classification_lattice::ClassificationLattice>, String> {
        match self {
            Self::Sqlite(db) => db.get_classification_lattice(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_classification_lattice(namespace))
            }
        }
    }

    pub fn classification_lattice_recorded_at_ms(
        &self,
        namespace: &str,
    ) -> Result<Option<i64>, String> {
        match self {
            Self::Sqlite(db) => db.classification_lattice_recorded_at_ms(namespace),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.classification_lattice_recorded_at_ms(namespace)
            }),
        }
    }

    pub fn object_query_cursor_key(&self) -> Result<[u8; 32], String> {
        match self {
            Self::Sqlite(db) => db.object_query_cursor_key(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.object_query_cursor_key()),
        }
    }

    pub fn active_object_policy(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Option<ObjectSecurityPolicy>, String> {
        source_batch_auth_counters::POLICY_LOOKUPS.with(|c| c.set(c.get() + 1));
        let Some(activation) = self.get_object_security_activation(namespace)? else {
            return Ok(None);
        };
        let Some(digest) = activation.policies.get(kind) else {
            return Err(
                "object_security_denied: activated namespace has no policy for kind".into(),
            );
        };
        let Some(revision) = self.get_object_security_policy(namespace, digest)? else {
            return Err("object_security_denied: active policy revision unavailable".into());
        };
        ObjectSecurityPolicy::from_canonical_input(&revision.canonical_policy_json)
            .map(Some)
            .map_err(|_| "object_security_denied: active policy revision is invalid".into())
    }

    pub fn project_object_property_grants(&self, mut object: Object) -> Result<Object, String> {
        if let Some(policy) = self.active_object_policy(&object.namespace, &object.kind)? {
            policy.project_visible_properties(&mut object);
            policy.project_visible_value_instances(&mut object);
        }
        Ok(object)
    }

    pub fn reject_ungranted_property_query(
        &self,
        namespace: Option<&str>,
        kind: Option<&str>,
        properties: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<(), String> {
        let properties = properties
            .into_iter()
            .map(|property| property.as_ref().to_string())
            .filter(|property| !property.is_empty())
            .collect::<Vec<_>>();
        if properties.is_empty() {
            return Ok(());
        }
        let namespaces = match namespace.filter(|value| !value.is_empty()) {
            Some(namespace) => vec![namespace.to_string()],
            None => self.list_activated_object_security_namespaces()?,
        };
        let kind = kind.filter(|value| !value.is_empty());
        for namespace in namespaces {
            let Some(activation) = self.get_object_security_activation(&namespace)? else {
                continue;
            };
            let kinds = match kind {
                Some(kind) if activation.policies.contains_key(kind) => vec![kind.to_string()],
                Some(_) => continue,
                None => activation.policies.keys().cloned().collect(),
            };
            for kind in kinds {
                let policy = match self.active_object_policy(&namespace, &kind) {
                    Ok(Some(policy)) => policy,
                    Ok(None) => continue,
                    Err(error) => return Err(error),
                };
                for property in &properties {
                    if !policy.allows_property_access(property, PropertyGrantAccess::Read) {
                        return Err("object_security_denied: property filter is not granted".into());
                    }
                }
            }
        }
        Ok(())
    }

    pub fn reject_ungranted_value_instance_query(
        &self,
        namespace: Option<&str>,
        kind: Option<&str>,
        cells: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
    ) -> Result<(), String> {
        let cells = cells
            .into_iter()
            .map(|(property, value)| (property.as_ref().to_string(), value.as_ref().to_string()))
            .filter(|(property, _)| !property.is_empty())
            .collect::<Vec<_>>();
        if cells.is_empty() {
            return Ok(());
        }
        let namespaces = match namespace.filter(|value| !value.is_empty()) {
            Some(namespace) => vec![namespace.to_string()],
            None => self.list_activated_object_security_namespaces()?,
        };
        let kind = kind.filter(|value| !value.is_empty());
        for namespace in namespaces {
            let Some(activation) = self.get_object_security_activation(&namespace)? else {
                continue;
            };
            let kinds = match kind {
                Some(kind) if activation.policies.contains_key(kind) => vec![kind.to_string()],
                Some(_) => continue,
                None => activation.policies.keys().cloned().collect(),
            };
            for kind in kinds {
                let policy = match self.active_object_policy(&namespace, &kind) {
                    Ok(Some(policy)) => policy,
                    Ok(None) => continue,
                    Err(error) => return Err(error),
                };
                for (property, value) in &cells {
                    if !policy.allows_value_instance_query(
                        property,
                        value,
                        crate::sekai::object_security::PropertyGrantAccess::Read,
                    ) {
                        return Err("object_security_denied: property filter is not granted".into());
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn retain_granted_value_instance_matches(
        &self,
        objects: Vec<Object>,
        cells: &[(String, String)],
    ) -> Result<Vec<Object>, String> {
        if cells.is_empty() {
            return Ok(objects);
        }
        // One policy read per distinct (namespace, kind), so every object of
        // a kind in this call is checked against the same policy.
        let mut policies = HashMap::<(String, String), Option<ObjectSecurityPolicy>>::new();
        let mut kept = Vec::with_capacity(objects.len());
        for object in objects {
            let key = (object.namespace.clone(), object.kind.clone());
            let policy = match policies.entry(key) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let (namespace, kind) = entry.key();
                    let policy = self.active_object_policy(namespace, kind)?;
                    entry.insert(policy)
                }
            };
            let Some(policy) = policy.as_ref() else {
                kept.push(object);
                continue;
            };
            if cells.iter().all(|(property, value)| {
                object.properties.get(property).is_some_and(|stored| {
                    stored == value
                        && policy.allows_value_instance_access(
                            &object.id,
                            property,
                            stored,
                            crate::sekai::object_security::PropertyGrantAccess::Read,
                        )
                })
            }) {
                kept.push(object);
            }
        }
        Ok(kept)
    }

    pub(crate) fn value_instance_grants_active(
        &self,
        namespace: Option<&str>,
        kind: Option<&str>,
    ) -> Result<bool, String> {
        let namespaces = match namespace.filter(|value| !value.is_empty()) {
            Some(namespace) => vec![namespace.to_string()],
            None => self.list_activated_object_security_namespaces()?,
        };
        let kind = kind.filter(|value| !value.is_empty());
        for namespace in namespaces {
            let Some(activation) = self.get_object_security_activation(&namespace)? else {
                continue;
            };
            let kinds = match kind {
                Some(kind) if activation.policies.contains_key(kind) => vec![kind.to_string()],
                Some(_) => continue,
                None => activation.policies.keys().cloned().collect(),
            };
            for kind in kinds {
                if self
                    .active_object_policy(&namespace, &kind)?
                    .is_some_and(|policy| policy.value_instance_grants_enforced())
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub(crate) fn reject_value_instance_sort(
        &self,
        namespace: Option<&str>,
        kind: Option<&str>,
    ) -> Result<(), String> {
        // Storage ORDER BY would rank hidden cells. Fail closed while cell
        // grants are enforced rather than sorting an unauthorized projection.
        if self.value_instance_grants_active(namespace, kind)? {
            return Err("object_security_denied: property filter is not granted".into());
        }
        Ok(())
    }

    pub(crate) fn reject_value_instance_filter_ops(
        &self,
        namespace: Option<&str>,
        kind: Option<&str>,
        filters: &[crate::domain::PropertyFilter],
    ) -> Result<(), String> {
        if filters
            .iter()
            .all(|filter| filter.op.is_empty() || filter.op == "eq")
            || !self.value_instance_grants_active(namespace, kind)?
        {
            return Ok(());
        }
        Err("object_security_denied: property filter is not granted".into())
    }

    pub fn list_activated_object_security_namespaces(&self) -> Result<Vec<String>, String> {
        match self {
            Self::Sqlite(db) => db.list_activated_object_security_namespaces(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_activated_object_security_namespaces())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::object_security::{
        OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityOperation, ObjectSecurityPredicate,
        ObjectSecurityRule, PropertyGrant, PropertyGrantAccess, ValueInstanceGrant,
        value_instance_digest,
    };

    fn note(id: &str, kind: &str, body: &str) -> Object {
        Object {
            id: id.into(),
            kind: kind.into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: id.into(),
            properties: HashMap::from([("body".into(), body.into())]),
            created: 1,
            updated: 1,
        }
    }

    /// Matches are filtered against one policy read per distinct kind, not
    /// one per matched object.
    #[test]
    fn value_instance_matches_read_each_kinds_policy_once() {
        let db = RuntimeDb::memory();
        // Activation covers instantiated kinds; only `note` is stored.
        db.create_object_with_audit(&note("note-0", "note", "shared"), "editor")
            .unwrap();
        let grants = (0..5)
            .map(|index| ValueInstanceGrant {
                object_id: format!("note-{index}"),
                property: "body".into(),
                value_digest: value_instance_digest("shared").unwrap(),
                access: PropertyGrantAccess::Read,
            })
            .collect();
        let policy = ObjectSecurityPolicy {
            contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "acme".into(),
            kind: "note".into(),
            rules: vec![ObjectSecurityRule {
                operation: ObjectSecurityOperation::Read,
                predicates: vec![ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: Some(vec![PropertyGrant {
                property: "body".into(),
                access: PropertyGrantAccess::Read,
            }]),
            value_instance_grants: Some(grants),
            required_purpose: None,
        };
        let revision = db
            .put_object_security_policy(&policy, "root", "put", 1)
            .unwrap();
        db.activate_object_security_policies(
            "acme",
            &std::collections::BTreeMap::from([("note".into(), revision.revision_digest)]),
            "root",
            "activate",
            2,
        )
        .unwrap();
        // Six notes, five granted, plus two objects in a namespace with no
        // activated policies.
        let mut objects: Vec<_> = (0..6)
            .map(|index| note(&format!("note-{index}"), "note", "shared"))
            .collect();
        objects.push(Object {
            namespace: "plain".into(),
            ..note("memo-a", "memo", "shared")
        });
        objects.push(Object {
            namespace: "plain".into(),
            ..note("memo-b", "memo", "shared")
        });
        source_batch_auth_counters::POLICY_LOOKUPS.with(|count| count.set(0));
        let kept = db
            .retain_granted_value_instance_matches(objects, &[("body".into(), "shared".into())])
            .unwrap();
        assert_eq!(
            source_batch_auth_counters::POLICY_LOOKUPS.with(std::cell::Cell::get),
            2
        );
        let ids: Vec<_> = kept.iter().map(|object| object.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "note-0", "note-1", "note-2", "note-3", "note-4", "memo-a", "memo-b"
            ]
        );
    }
}
