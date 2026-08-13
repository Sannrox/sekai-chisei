//! Object mutation admission and persistence ordering behind one private interface.
//!
//! The tonic adapter forwards create, update, and delete requests here. This
//! module owns tenant, namespace, lease, marking, schema including per-kind
//! load before write, replay, persistence, grant, and response-resolution
//! ordering for both direct and guarded object mutations.

use super::*;

pub(super) struct GuardedCreateObjectRequest {
    pub(super) object: Option<Object>,
    pub(super) lease_precondition: Option<LeasePrecondition>,
}

#[derive(Debug)]
pub(super) struct GuardedCreateObjectResponse {
    pub(super) object: Option<Object>,
}

pub(super) struct GuardedUpdateObjectRequest {
    pub(super) object: Option<Object>,
    pub(super) lease_precondition: Option<LeasePrecondition>,
}

#[derive(Debug)]
pub(super) struct GuardedUpdateObjectResponse {
    pub(super) object: Option<Object>,
}

pub(super) struct GuardedDeleteObjectRequest {
    pub(super) id: String,
    pub(super) lease_precondition: Option<LeasePrecondition>,
}

#[derive(Debug)]
pub(super) struct GuardedDeleteObjectResponse {}

impl SekaiServiceImpl {
    pub(super) async fn guarded_create_object(
        &self,
        req: Request<GuardedCreateObjectRequest>,
    ) -> Result<Response<GuardedCreateObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let input = req.into_inner();
        let precondition = input.lease_precondition;
        if precondition.is_some() {
            require_authenticated(&principals)?;
        }
        let object = input
            .object
            .ok_or(Status::invalid_argument("object required"))?;
        if object.id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        if object.kind == "namespace" {
            require_credential_admin(&principals)?;
            return Err(Status::failed_precondition(
                "namespace objects must be managed through EnsureTeamNamespace",
            ));
        }
        if object.id.starts_with("namespace:") || object.external_id.starts_with("namespace:") {
            return Err(Status::invalid_argument(
                "namespace:* identifiers are reserved for namespace boundaries",
            ));
        }
        if object
            .external_id
            .starts_with(markings::PRINCIPAL_PROFILE_EXTERNAL_ID_PREFIX)
            && object.kind != markings::PRINCIPAL_PROFILE_KIND
        {
            return Err(Status::invalid_argument(
                "principal:* external IDs are reserved for principal_profile objects",
            ));
        }
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &object.namespace,
            true,
        )?;
        check_team_namespace(&self.db, &principals, &object.namespace, true)?;
        check_write(&self.security, &object.id, &principals)?;
        if let Some(precondition) = &precondition {
            enforce_namespace_tenant_context(
                &self.db,
                tenant_context.as_ref(),
                &precondition.namespace,
                true,
            )?;
            check_team_namespace(&self.db, &principals, &precondition.namespace, true)?;
            LeaseLifecycle::new(&self.db, &self.security, &self.site_id)
                .validate_guarded_mutation(GuardedMutationPrecondition {
                    key: &precondition.key,
                    lease_namespace: &precondition.namespace,
                    target: GuardedMutationTarget::Create,
                })
                .map_err(map_lease_lifecycle_error)?;
        }
        let domain_object = from_proto_obj(&object);
        if let Some(value) = domain_object
            .properties
            .get(markings::OBJECT_CLASSIFICATION_PROPERTY)
        {
            markings::parse_optional_classification(value).map_err(Status::invalid_argument)?;
        }
        let mutation = precondition.as_ref().map_or_else(
            || ObjectMutation::direct(&self.db),
            |precondition| {
                ObjectMutation::guarded(
                    &self.db,
                    MutationLeasePrecondition {
                        namespace: &precondition.namespace,
                        key: &precondition.key,
                        fencing_token: &precondition.fencing_token,
                        request_id: &precondition.request_id,
                    },
                )
            },
        );
        if let Some(created) = mutation
            .replay("create", &domain_object)
            .map_err(map_mutation_persistence_error)?
        {
            let created =
                self.resolve_computed_for_response(created, &principals, tenant_context.as_ref())?;
            return Ok(Response::new(GuardedCreateObjectResponse {
                object: Some(to_proto_obj(&created)),
            }));
        }
        if is_reserved_governance_kind(&domain_object.kind) {
            return Err(Status::permission_denied(
                "reserved governance kind; use the dedicated action RPCs",
            ));
        }
        let mut domain_object = domain_object;
        if domain_object.kind == markings::PRINCIPAL_PROFILE_KIND {
            require_credential_admin(&principals)?;
            validate_principal_profile_object(&object)?;
            domain_object.properties.insert(
                markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                "true".into(),
            );
        } else {
            self.require_schema_kind_loaded(&domain_object.kind)?;
            let schema = self
                .schema_definitions
                .snapshot()
                .map_err(map_schema_definition_lifecycle_error)?;
            schema
                .validate(&domain_object)
                .map_err(Status::invalid_argument)?;
            ensure_restricted_create_properties_allowed(
                &schema,
                &self.security,
                &principals,
                &domain_object,
            )?;
            drop(schema);
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        let created = mutation
            .create(&domain_object, actor, now_millis())
            .map_err(map_mutation_persistence_error)?;
        if created.kind == markings::PRINCIPAL_PROFILE_KIND {
            let grant = security::Grant {
                id: format!("principal-profile-admin-{}", Uuid::new_v4().simple()),
                object_id: created.id.clone(),
                principal: if actor.is_empty() {
                    "root".into()
                } else {
                    actor.into()
                },
                role: security::Role::Admin,
                created: now_millis(),
            };
            if let Err(error) = self.db.create_grant(&grant) {
                let _ = self.db.delete_object(&created.id);
                return Err(Status::internal(error));
            }
            self.security.add_grant(&grant);
        }
        let created =
            self.resolve_computed_for_response(created, &principals, tenant_context.as_ref())?;
        Ok(Response::new(GuardedCreateObjectResponse {
            object: Some(to_proto_obj(&created)),
        }))
    }

    pub(super) async fn guarded_update_object(
        &self,
        req: Request<GuardedUpdateObjectRequest>,
    ) -> Result<Response<GuardedUpdateObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let input = req.into_inner();
        let precondition = input.lease_precondition;
        if precondition.is_some() {
            require_authenticated(&principals)?;
        }
        let object = input
            .object
            .ok_or(Status::invalid_argument("object required"))?;
        if object.id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        if object.external_id.starts_with("namespace:") && object.kind != "namespace" {
            return Err(Status::invalid_argument(
                "namespace:* external IDs are reserved for namespace boundaries",
            ));
        }
        let existing = self.db.get_object(&object.id).map_err(Status::internal)?;
        if precondition.is_none() && existing.is_none() {
            return Err(Status::not_found("not found"));
        }
        if object.kind == "namespace"
            || existing
                .as_ref()
                .is_some_and(|existing| existing.kind == "namespace")
        {
            require_credential_admin(&principals)?;
        }
        if object.kind == markings::PRINCIPAL_PROFILE_KIND
            || existing
                .as_ref()
                .is_some_and(|existing| existing.kind == markings::PRINCIPAL_PROFILE_KIND)
        {
            require_credential_admin(&principals)?;
            validate_principal_profile_object(&object)?;
        }
        if let Some(existing) = &existing {
            enforce_namespace_tenant_context(
                &self.db,
                tenant_context.as_ref(),
                &existing.namespace,
                true,
            )?;
            check_team_namespace(&self.db, &principals, &existing.namespace, true)?;
        }
        enforce_namespace_tenant_context(
            &self.db,
            tenant_context.as_ref(),
            &object.namespace,
            true,
        )?;
        check_team_namespace(&self.db, &principals, &object.namespace, true)?;
        check_write(&self.security, &object.id, &principals)?;
        if let Some(existing) = &existing {
            enforce_object_marking_access(
                &self.db,
                existing,
                &principals,
                &format!("guarded_update_object:{}", existing.id),
            )?;
        }
        if let Some(precondition) = &precondition {
            enforce_namespace_tenant_context(
                &self.db,
                tenant_context.as_ref(),
                &precondition.namespace,
                true,
            )?;
            check_team_namespace(&self.db, &principals, &precondition.namespace, true)?;
            LeaseLifecycle::new(&self.db, &self.security, &self.site_id)
                .validate_guarded_mutation(GuardedMutationPrecondition {
                    key: &precondition.key,
                    lease_namespace: &precondition.namespace,
                    target: GuardedMutationTarget::Object {
                        id: object.id.as_str(),
                        namespace: Some(object.namespace.as_str()),
                    },
                })
                .map_err(map_lease_lifecycle_error)?;
        }
        let mut domain_object = from_proto_obj(&object);
        if let Some(value) = domain_object
            .properties
            .get(markings::OBJECT_CLASSIFICATION_PROPERTY)
        {
            markings::parse_optional_classification(value).map_err(Status::invalid_argument)?;
        }
        let request_object = domain_object.clone();
        let mutation = precondition.as_ref().map_or_else(
            || ObjectMutation::direct(&self.db),
            |precondition| {
                ObjectMutation::guarded(
                    &self.db,
                    MutationLeasePrecondition {
                        namespace: &precondition.namespace,
                        key: &precondition.key,
                        fencing_token: &precondition.fencing_token,
                        request_id: &precondition.request_id,
                    },
                )
            },
        );
        if let Some(updated) = mutation
            .replay("update", &request_object)
            .map_err(map_mutation_persistence_error)?
        {
            enforce_object_marking_access(
                &self.db,
                &updated,
                &principals,
                &format!("guarded_update_object_replay:{}", updated.id),
            )?;
            let updated =
                self.resolve_computed_for_response(updated, &principals, tenant_context.as_ref())?;
            return Ok(Response::new(GuardedUpdateObjectResponse {
                object: Some(to_proto_obj(&updated)),
            }));
        }
        if is_reserved_governance_kind(&domain_object.kind)
            || existing
                .as_ref()
                .is_some_and(|existing| is_reserved_governance_kind(&existing.kind))
        {
            return Err(Status::permission_denied(
                "reserved governance kind; use the dedicated action RPCs",
            ));
        }
        if domain_object.kind == markings::PRINCIPAL_PROFILE_KIND {
            domain_object.properties.insert(
                markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                "true".into(),
            );
        } else {
            self.require_schema_kind_loaded(&domain_object.kind)?;
            let schema = self
                .schema_definitions
                .snapshot()
                .map_err(map_schema_definition_lifecycle_error)?;
            if existing.is_some() {
                preserve_redacted_restricted_properties(
                    &self.db,
                    &schema,
                    &self.security,
                    &principals,
                    &mut domain_object,
                )?;
            }
            schema
                .validate(&domain_object)
                .map_err(Status::invalid_argument)?;
            drop(schema);
        }
        if let Some(existing) = &existing {
            validate_object_kind_change_access(
                &self.db,
                &self.security,
                &principals,
                existing,
                &domain_object,
            )?;
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        let updated = mutation
            .update(
                &domain_object,
                &request_object,
                existing.as_ref(),
                actor,
                now_millis(),
            )
            .map_err(map_mutation_persistence_error)?;
        let updated =
            self.resolve_computed_for_response(updated, &principals, tenant_context.as_ref())?;
        Ok(Response::new(GuardedUpdateObjectResponse {
            object: Some(to_proto_obj(&updated)),
        }))
    }

    pub(super) async fn guarded_delete_object(
        &self,
        req: Request<GuardedDeleteObjectRequest>,
    ) -> Result<Response<GuardedDeleteObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        let input = req.into_inner();
        let precondition = input.lease_precondition;
        if precondition.is_some() {
            require_authenticated(&principals)?;
        }
        let expected = self.db.get_object(&input.id).map_err(Status::internal)?;
        if precondition.is_none() && expected.is_none() {
            return Ok(Response::new(GuardedDeleteObjectResponse {}));
        }
        check_write(&self.security, &input.id, &principals)?;
        if let Some(precondition) = &precondition {
            enforce_namespace_tenant_context(
                &self.db,
                tenant_context.as_ref(),
                &precondition.namespace,
                true,
            )?;
            check_team_namespace(&self.db, &principals, &precondition.namespace, true)?;
            LeaseLifecycle::new(&self.db, &self.security, &self.site_id)
                .validate_guarded_mutation(GuardedMutationPrecondition {
                    key: &precondition.key,
                    lease_namespace: &precondition.namespace,
                    target: GuardedMutationTarget::Object {
                        id: input.id.as_str(),
                        namespace: expected.as_ref().map(|object| object.namespace.as_str()),
                    },
                })
                .map_err(map_lease_lifecycle_error)?;
        }
        if let Some(existing) = &expected {
            enforce_namespace_tenant_context(
                &self.db,
                tenant_context.as_ref(),
                &existing.namespace,
                true,
            )?;
            check_team_namespace(&self.db, &principals, &existing.namespace, true)?;
            enforce_object_marking_access(
                &self.db,
                existing,
                &principals,
                &format!("guarded_delete_object:{}", existing.id),
            )?;
            if existing.kind == markings::PRINCIPAL_PROFILE_KIND {
                require_credential_admin(&principals)?;
            }
            if existing.kind == "namespace" {
                require_credential_admin(&principals)?;
                if existing
                    .properties
                    .get("team_managed")
                    .is_some_and(|value| value == "true")
                {
                    return Err(Status::failed_precondition(
                        "team-managed namespaces cannot be deleted through the generic object API",
                    ));
                }
            }
            if is_reserved_governance_kind(&existing.kind) {
                return Err(Status::permission_denied(
                    "object cannot be deleted through the guarded object API",
                ));
            }
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        let mutation = precondition.as_ref().map_or_else(
            || ObjectMutation::direct(&self.db),
            |precondition| {
                ObjectMutation::guarded(
                    &self.db,
                    MutationLeasePrecondition {
                        namespace: &precondition.namespace,
                        key: &precondition.key,
                        fencing_token: &precondition.fencing_token,
                        request_id: &precondition.request_id,
                    },
                )
            },
        );
        mutation
            .delete(&input.id, expected.as_ref(), actor, now_millis())
            .map_err(map_mutation_persistence_error)?;
        Ok(Response::new(GuardedDeleteObjectResponse {}))
    }

    pub(super) fn require_schema_kind_loaded(&self, kind: &str) -> Result<(), Status> {
        self.schema_definitions
            .ensure_kind_loaded(kind)
            .map_err(map_schema_definition_lifecycle_error)
    }
}
