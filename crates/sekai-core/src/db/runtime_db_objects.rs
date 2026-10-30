//! Dual-backend community-store dispatch for objects.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn get_object(&self, id: &str) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.get_object(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_object(id)),
        }
    }

    pub fn get_object_with_policy_context(
        &self,
        id: &str,
        context: &PrincipalPolicyContext,
    ) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_with_policy_context(id, context),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_object_with_policy_context(id, context))
            }
        }
    }

    pub fn list_objects_by_ids_with_policy_context(
        &self,
        ids: &[String],
        principals: &[&str],
        context: &PrincipalPolicyContext,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => {
                crate::db::graph::GraphBackend::list_objects_by_ids_with_policy_context(
                    db.as_ref(),
                    ids,
                    principals,
                    context,
                )
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                crate::db::graph::GraphBackend::list_objects_by_ids_with_policy_context(
                    db.as_ref(),
                    ids,
                    principals,
                    context,
                )
            }),
        }
    }

    pub fn create_link(&self, l: &Link) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_link(l),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_link(l)),
        }
    }

    pub fn create_link_once(&self, l: &Link) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.create_link_once(l),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_link_once(l)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_link_with_authorized_endpoints(
        &self,
        l: &Link,
        expected_from: &Object,
        expected_to: &Object,
        from_generation: Option<&str>,
        to_generation: Option<&str>,
        fail_if_exists: bool,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.create_link_with_authorized_endpoints(
                l,
                expected_from,
                expected_to,
                from_generation,
                to_generation,
                fail_if_exists,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.create_link_with_authorized_endpoints(
                    l,
                    expected_from,
                    expected_to,
                    from_generation,
                    to_generation,
                    fail_if_exists,
                )
            }),
        }
    }

    pub fn create_object(&self, o: &Object) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_object(o),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_object(o)),
        }
    }

    /// Creates `object` with change rows stamped with `attribution` (#1690).
    pub fn create_object_attributed(
        &self,
        object: &Object,
        actor: &str,
        expected_policy_generation: Option<&str>,
        attribution: &ChangeAttribution,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.create_object_attributed(object, actor, expected_policy_generation, attribution)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.create_object_attributed(object, actor, expected_policy_generation, attribution)
            }),
        }
    }

    /// Updates `object` with change rows stamped with `attribution`; with
    /// `expected`, only if the stored object still matches it.
    pub fn update_object_attributed(
        &self,
        object: &Object,
        expected: Option<&Object>,
        actor: &str,
        expected_policy_generation: Option<&str>,
        attribution: &ChangeAttribution,
    ) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.update_object_attributed(
                object,
                expected,
                actor,
                expected_policy_generation,
                attribution,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.update_object_attributed(
                    object,
                    expected,
                    actor,
                    expected_policy_generation,
                    attribution,
                )
            }),
        }
    }

    /// Deletes with change rows stamped with `attribution`.
    pub fn delete_object_attributed(
        &self,
        id: &str,
        expected: Option<&Object>,
        actor: &str,
        expected_policy_generation: Option<&str>,
        attribution: &ChangeAttribution,
    ) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.delete_object_attributed(
                id,
                expected,
                actor,
                expected_policy_generation,
                attribution,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.delete_object_attributed(
                    id,
                    expected,
                    actor,
                    expected_policy_generation,
                    attribution,
                )
            }),
        }
    }

    pub fn create_object_with_audit(&self, object: &Object, actor: &str) -> Result<(), String> {
        self.create_object_with_authorized_policy(object, actor, None)
    }

    pub fn create_object_with_authorized_policy(
        &self,
        object: &Object,
        actor: &str,
        expected_policy_generation: Option<&str>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.create_object_with_authorized_policy(object, actor, expected_policy_generation)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.create_object_with_authorized_policy(object, actor, expected_policy_generation)
            }),
        }
    }

    pub fn create_governed_object_with_audit(
        &self,
        object: &Object,
        actor: &str,
        history_identity_property: &str,
        history_identity: &str,
        predecessor_property: &str,
        predecessor_id: &str,
        max_objects: usize,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_governed_object_with_audit(
                object,
                actor,
                history_identity_property,
                history_identity,
                predecessor_property,
                predecessor_id,
                max_objects,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.create_governed_object_with_audit(
                    object,
                    actor,
                    history_identity_property,
                    history_identity,
                    predecessor_property,
                    predecessor_id,
                    max_objects,
                )
            }),
        }
    }

    pub fn delete_interface(&self, name: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_interface(name),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.delete_interface(name)),
        }
    }

    pub fn delete_link(&self, id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_link(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.delete_link(id)),
        }
    }

    pub fn delete_link_with_authorized_endpoints(
        &self,
        id: &str,
        expected_from: &Object,
        expected_to: &Object,
        from_generation: Option<&str>,
        to_generation: Option<&str>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_link_with_authorized_endpoints(
                id,
                expected_from,
                expected_to,
                from_generation,
                to_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.delete_link_with_authorized_endpoints(
                    id,
                    expected_from,
                    expected_to,
                    from_generation,
                    to_generation,
                )
            }),
        }
    }

    pub fn delete_object_type(&self, kind: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_object_type(kind),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.delete_object_type(kind)),
        }
    }

    pub fn delete_object_with_audit(
        &self,
        id: &str,
        actor: &str,
    ) -> Result<Option<Object>, String> {
        self.delete_object_with_authorized_snapshot(id, None, actor, None)
    }

    pub fn delete_object_with_authorized_snapshot(
        &self,
        id: &str,
        expected: Option<&Object>,
        actor: &str,
        expected_policy_generation: Option<&str>,
    ) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.delete_object_with_authorized_snapshot(
                id,
                expected,
                actor,
                expected_policy_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.delete_object_with_authorized_snapshot(
                    id,
                    expected,
                    actor,
                    expected_policy_generation,
                )
            }),
        }
    }

    pub fn find_all_by_external_id(&self, external_id: &str) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_all_by_external_id(external_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.find_all_by_external_id(external_id))
            }
        }
    }

    pub fn find_all_by_external_ids_in_namespace(
        &self,
        namespace: &str,
        external_ids: &[String],
    ) -> Result<Vec<Object>, String> {
        #[cfg(any(test, feature = "gateway-test-support"))]
        if !external_ids.is_empty() {
            source_batch_auth_counters::LOOKUP_QUERIES.with(|c| c.set(c.get() + 1));
        }
        match self {
            Self::Sqlite(db) => db.find_all_by_external_ids_in_namespace(namespace, external_ids),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.find_all_by_external_ids_in_namespace(namespace, external_ids)
            }),
        }
    }

    pub fn find_all_by_external_id_with_policy_context(
        &self,
        external_id: &str,
        context: &PrincipalPolicyContext,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => {
                db.find_all_by_external_id_with_policy_context(external_id, context)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.find_all_by_external_id_with_policy_context(external_id, context)
            }),
        }
    }

    pub fn find_by_external_id(&self, external_id: &str) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_by_external_id(external_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.find_by_external_id(external_id))
            }
        }
    }

    pub fn find_by_property(
        &self,
        kind: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_by_property(kind, key, value),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.find_by_property(kind, key, value))
            }
        }
    }

    pub fn find_by_property_with_policy_context(
        &self,
        kind: &str,
        key: &str,
        value: &str,
        context: &PrincipalPolicyContext,
    ) -> Result<Vec<Object>, String> {
        self.reject_ungranted_property_query(None, Some(kind), [key])?;
        self.reject_ungranted_value_instance_query(None, Some(kind), [(key, value)])?;
        let rows = match self {
            Self::Sqlite(db) => db.find_by_property_with_policy_context(kind, key, value, context),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.find_by_property_with_policy_context(kind, key, value, context)
            }),
        }?;
        self.retain_granted_value_instance_matches(rows, &[(key.to_string(), value.to_string())])
    }

    pub fn find_namespace_boundary(&self, namespace: &str) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_namespace_boundary(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.find_namespace_boundary(namespace))
            }
        }
    }

    pub fn get_link(&self, id: &str) -> Result<Option<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_link(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_link(id)),
        }
    }

    pub fn get_linked_objects(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.get_linked_objects(object_id, relation, dir),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_linked_objects(object_id, relation, dir))
            }
        }
    }

    pub fn get_linked_objects_with_policy_context(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
        context: &PrincipalPolicyContext,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => {
                db.get_linked_objects_with_policy_context(object_id, relation, dir, context)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_linked_objects_with_policy_context(object_id, relation, dir, context)
            }),
        }
    }

    pub fn get_links(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
    ) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_links(object_id, relation, dir),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_links(object_id, relation, dir))
            }
        }
    }

    /// At most `limit` links, so a caller can bound the read itself, not only its result.
    pub fn get_links_with_policy_context_limited(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
        context: &PrincipalPolicyContext,
        limit: usize,
    ) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_links_with_policy_context_limited(
                object_id,
                relation,
                dir,
                context,
                Some(limit),
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_links_with_policy_context_limited(
                    object_id,
                    relation,
                    dir,
                    context,
                    Some(limit),
                )
            }),
        }
    }

    pub fn get_links_with_policy_context(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
        context: &PrincipalPolicyContext,
    ) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_links_with_policy_context(object_id, relation, dir, context),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_links_with_policy_context(object_id, relation, dir, context)
            }),
        }
    }

    pub fn guarded_create_object(
        &self,
        object: &Object,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<Object, LeaseError> {
        self.guarded_create_object_with_policy(
            object, namespace, key, token, request_id, actor, now_ms, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn guarded_create_object_with_policy(
        &self,
        object: &Object,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
        expected_policy_generation: Option<&str>,
    ) -> Result<Object, LeaseError> {
        match self {
            Self::Sqlite(db) => db.guarded_create_object_with_policy(
                object,
                namespace,
                key,
                token,
                request_id,
                actor,
                now_ms,
                expected_policy_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.guarded_create_object_with_policy(
                    object,
                    namespace,
                    key,
                    token,
                    request_id,
                    actor,
                    now_ms,
                    expected_policy_generation,
                )
            }),
        }
    }

    pub fn guarded_delete_object(
        &self,
        object_id: &str,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), LeaseError> {
        self.guarded_delete_object_with_policy(
            object_id, expected, namespace, key, token, request_id, actor, now_ms, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn guarded_delete_object_with_policy(
        &self,
        object_id: &str,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
        expected_policy_generation: Option<&str>,
    ) -> Result<(), LeaseError> {
        match self {
            Self::Sqlite(db) => db.guarded_delete_object_with_policy(
                object_id,
                expected,
                namespace,
                key,
                token,
                request_id,
                actor,
                now_ms,
                expected_policy_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.guarded_delete_object_with_policy(
                    object_id,
                    expected,
                    namespace,
                    key,
                    token,
                    request_id,
                    actor,
                    now_ms,
                    expected_policy_generation,
                )
            }),
        }
    }

    pub fn guarded_object_replay(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        operation: &str,
        target_id: &str,
        request_object: &Object,
    ) -> Result<Option<Object>, LeaseError> {
        match self {
            Self::Sqlite(db) => db.guarded_object_replay(
                namespace,
                key,
                token,
                request_id,
                operation,
                target_id,
                request_object,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.guarded_object_replay(
                    namespace,
                    key,
                    token,
                    request_id,
                    operation,
                    target_id,
                    request_object,
                )
            }),
        }
    }

    pub fn guarded_update_object(
        &self,
        object: &Object,
        request_object: &Object,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<Object, LeaseError> {
        self.guarded_update_object_with_policy(
            object,
            request_object,
            expected,
            namespace,
            key,
            token,
            request_id,
            actor,
            now_ms,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn guarded_update_object_with_policy(
        &self,
        object: &Object,
        request_object: &Object,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
        expected_policy_generation: Option<&str>,
    ) -> Result<Object, LeaseError> {
        match self {
            Self::Sqlite(db) => db.guarded_update_object_with_policy(
                object,
                request_object,
                expected,
                namespace,
                key,
                token,
                request_id,
                actor,
                now_ms,
                expected_policy_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.guarded_update_object_with_policy(
                    object,
                    request_object,
                    expected,
                    namespace,
                    key,
                    token,
                    request_id,
                    actor,
                    now_ms,
                    expected_policy_generation,
                )
            }),
        }
    }

    pub fn list_all_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_all_objects(filter),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_all_objects(filter)),
        }
    }

    pub fn list_interfaces(&self) -> Result<Vec<InterfaceDef>, String> {
        match self {
            Self::Sqlite(db) => db.list_interfaces(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_interfaces()),
        }
    }

    pub fn list_links_by_relation(&self, relation: &str) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.list_links_by_relation(relation),
            Self::Postgres(_) => Err(
                "list_links_by_relation is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_object_types_with_errors(
        &self,
    ) -> Result<(Vec<ObjectType>, HashMap<String, String>), String> {
        match self {
            Self::Sqlite(db) => db.list_object_types_with_errors(),
            // PostgreSQL rows are validated on write and a corrupt row fails
            // the read outright, so there are no per-row load errors to report.
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_object_types().map(|types| (types, HashMap::new()))
            }),
        }
    }

    pub fn list_objects_with_total_for_principals(
        &self,
        filter: &ListFilter,
        principals: &[&str],
        excluded_kinds: &[&str],
    ) -> Result<(Vec<Object>, i32), String> {
        match self {
            Self::Sqlite(db) => {
                db.list_objects_with_total_for_principals(filter, principals, excluded_kinds)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_objects_with_total_for_principals(filter, principals, excluded_kinds)
            }),
        }
    }

    pub fn list_objects_with_total_for_policy_context(
        &self,
        filter: &ListFilter,
        principals: &[&str],
        excluded_kinds: &[&str],
        context: &PrincipalPolicyContext,
    ) -> Result<(Vec<Object>, i32), String> {
        let mut queried = filter
            .property_filters
            .iter()
            .map(|property_filter| property_filter.key.clone())
            .collect::<Vec<_>>();
        if let Some(property) = filter.order_by.strip_prefix("property:")
            && !property.is_empty()
        {
            queried.push(property.to_string());
        }
        self.reject_ungranted_property_query(
            filter.namespace.as_deref(),
            filter.kind.as_deref(),
            queried.clone(),
        )?;
        if !filter
            .order_by
            .strip_prefix("property:")
            .unwrap_or("")
            .is_empty()
        {
            self.reject_value_instance_sort(filter.namespace.as_deref(), filter.kind.as_deref())?;
        }
        self.reject_value_instance_filter_ops(
            filter.namespace.as_deref(),
            filter.kind.as_deref(),
            &filter.property_filters,
        )?;
        let cells = filter
            .property_filters
            .iter()
            .map(|property_filter| (property_filter.key.clone(), property_filter.value.clone()))
            .collect::<Vec<_>>();
        self.reject_ungranted_value_instance_query(
            filter.namespace.as_deref(),
            filter.kind.as_deref(),
            cells
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        )?;
        let cell_page = !cells.is_empty()
            && self.value_instance_grants_active(
                filter.namespace.as_deref(),
                filter.kind.as_deref(),
            )?;
        if !cell_page {
            let (rows, total) = match self {
                Self::Sqlite(db) => db.list_objects_with_total_for_policy_context(
                    filter,
                    principals,
                    excluded_kinds,
                    context,
                ),
                Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                    db.list_objects_with_total_for_policy_context(
                        filter,
                        principals,
                        excluded_kinds,
                        context,
                    )
                }),
            }?;
            return self
                .retain_granted_value_instance_matches(rows, &cells)
                .map(|rows| (rows, total));
        }
        // Paginate the authorized relation. Callers such as
        // `list_objects_with_marking` overwrite offset/limit to their scan
        // window (offset starts at 0) and apply the user page after marking
        // and purpose filters. `limit == i32::MAX` means the full authorized
        // set, matching storage `list_all_objects`.
        let offset = usize::try_from(filter.offset.max(0)).unwrap_or(0);
        let limit = if filter.limit == i32::MAX {
            usize::MAX
        } else if filter.limit <= 0 {
            crate::domain::DEFAULT_LIST_LIMIT as usize
        } else {
            filter.limit.min(crate::domain::MAX_LIST_LIMIT) as usize
        };
        let mut authorized = Vec::new();
        let mut total = 0usize;
        let mut storage_offset = 0i32;
        loop {
            let mut storage_filter = filter.clone();
            storage_filter.limit = crate::domain::MAX_LIST_LIMIT;
            storage_filter.offset = storage_offset;
            let (page, _) = match self {
                Self::Sqlite(db) => db.list_objects_with_total_for_policy_context(
                    &storage_filter,
                    principals,
                    excluded_kinds,
                    context,
                ),
                Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                    db.list_objects_with_total_for_policy_context(
                        &storage_filter,
                        principals,
                        excluded_kinds,
                        context,
                    )
                }),
            }?;
            let page_len = page.len();
            for object in self.retain_granted_value_instance_matches(page, &cells)? {
                if total >= offset && authorized.len() < limit {
                    authorized.push(object);
                }
                total = total.saturating_add(1);
            }
            if page_len < crate::domain::MAX_LIST_LIMIT as usize {
                break;
            }
            storage_offset = storage_offset.saturating_add(crate::domain::MAX_LIST_LIMIT);
            if storage_offset >= i32::MAX - crate::domain::MAX_LIST_LIMIT {
                break;
            }
        }
        Ok((authorized, i32::try_from(total).unwrap_or(i32::MAX)))
    }

    pub fn list_objects_with_text_visibility(
        &self,
        filter: &ListFilter,
        principals: &[&str],
        excluded_kinds: &[&str],
        allowed_markings: &[&str],
        trusted: bool,
    ) -> Result<(Vec<Object>, i32), String> {
        match self {
            Self::Sqlite(db) => db.list_objects_with_text_visibility(
                filter,
                principals,
                excluded_kinds,
                allowed_markings,
                trusted,
            ),
            Self::Postgres(_) => Err(
                "authorization-built text visibility is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_objects_with_text_visibility_page(
        &self,
        filter: &ListFilter,
        principals: &[&str],
        excluded_kinds: &[&str],
        allowed_markings: &[&str],
        trusted: bool,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_objects_with_text_visibility_page(
                filter,
                principals,
                excluded_kinds,
                allowed_markings,
                trusted,
            ),
            Self::Postgres(_) => Err(
                "authorization-built text visibility is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_visible_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String> {
        match self {
            Self::Sqlite(db) => db.list_visible_object_changes(object_id, limit, offset),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_visible_object_changes(object_id, limit, offset)
            }),
        }
    }

    pub fn namespace_object_generation(&self, namespace: &str) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.namespace_object_generation(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.namespace_object_generation(namespace))
            }
        }
    }

    pub fn object_change_watermark(&self, namespace: &str) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.object_change_watermark(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.object_change_watermark(namespace))
            }
        }
    }

    pub fn object_change_oldest_seq(&self, namespace: &str) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.object_change_oldest_seq(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.object_change_oldest_seq(namespace))
            }
        }
    }

    pub fn list_committed_object_mutations_after(
        &self,
        namespace: &str,
        after_seq: u64,
        limit: i32,
    ) -> Result<Vec<crate::sekai::object_change_subscription::CommittedObjectMutation>, String>
    {
        let rows = match self {
            Self::Sqlite(db) => {
                db.list_committed_object_mutations_after(namespace, after_seq, limit)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_committed_object_mutations_after(namespace, after_seq, limit)
            }),
        }?;
        Ok(rows
            .into_iter()
            .map(|(change, seq, object_kind, object_namespace)| {
                crate::sekai::object_change_subscription::CommittedObjectMutation {
                    change,
                    seq,
                    object_kind,
                    object_namespace,
                }
            })
            .collect())
    }

    pub fn object_change_kind(&self, object_id: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.object_change_kind(object_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.object_change_kind(object_id))
            }
        }
    }

    pub fn object_change_namespace(&self, object_id: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.object_change_namespace(object_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.object_change_namespace(object_id))
            }
        }
    }

    pub fn update_object(&self, o: &Object) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_object(o),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.update_object(o)),
        }
    }

    pub fn update_object_with_audit(
        &self,
        object: &Object,
        actor: &str,
    ) -> Result<Option<Object>, String> {
        self.update_object_with_authorized_snapshot(object, None, actor, None)
    }

    pub fn update_object_with_authorized_snapshot(
        &self,
        object: &Object,
        expected: Option<&Object>,
        actor: &str,
        expected_policy_generation: Option<&str>,
    ) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.update_object_with_authorized_snapshot(
                object,
                expected,
                actor,
                expected_policy_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                let Some(existing) = db.get_object(&object.id)? else {
                    return Ok(None);
                };
                if let Some(expected) = expected
                    && !existing.persisted_state_matches(expected)
                {
                    return Err(crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION.into());
                }
                db.update_object_with_audit_if_revision(
                    object,
                    actor,
                    existing.updated,
                    expected_policy_generation,
                    expected,
                )
            }),
        }
    }

    pub fn upsert_interface(&self, interface: &InterfaceDef) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_interface(interface),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.upsert_interface(interface))
            }
        }
    }

    pub fn upsert_object_type(&self, object_type: &ObjectType) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_object_type(object_type),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.upsert_object_type(object_type))
            }
        }
    }

    pub fn get_links_limited(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
        limit: usize,
    ) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_links_limited(object_id, relation, dir, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_links_limited(object_id, relation, dir, limit)
            }),
        }
    }

    pub fn get_object_type(&self, kind: &str) -> Result<Option<ObjectType>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_type(kind),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_object_type(kind)),
        }
    }

    pub fn record_object_changes(&self, changes: &[ObjectChange]) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_object_changes(changes),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.record_object_changes(changes))
            }
        }
    }

    pub fn record_object_change(&self, c: &ObjectChange) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_object_change(c),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.record_object_change(c)),
        }
    }

    pub fn list_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String> {
        match self {
            Self::Sqlite(db) => db.list_object_changes(object_id, limit, offset),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_object_changes(object_id, limit, offset)
            }),
        }
    }

    pub fn list_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_objects(filter),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_objects(filter)),
        }
    }

    /// One unfiltered page without `excluded_kinds`; the kinds are internal constants.
    pub fn list_objects_excluding_kinds(
        &self,
        filter: &ListFilter,
        excluded_kinds: &[&str],
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_objects_excluding_kinds(filter, excluded_kinds),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_objects_excluding_kinds(filter, excluded_kinds)
            }),
        }
    }

    pub fn delete_object(&self, id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_object(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.delete_object(id)),
        }
    }

    pub fn abort_unreceipted_object_create(&self, id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.abort_unreceipted_object_create(id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.abort_unreceipted_object_create(id))
            }
        }
    }
}
