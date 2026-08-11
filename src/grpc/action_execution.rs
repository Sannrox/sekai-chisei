//! Admission for legacy governed Action execution.
//!
//! The gRPC adapter authenticates the caller, resolves catalog correlation,
//! and maps protocol responses. This deep module owns the live target,
//! classification, purpose, namespace, schema, and policy admission ordering
//! that every direct Action execution must cross before an effect can run.

use super::{
    ERASED_NAMESPACE, RequestEnterpriseContext, SekaiServiceImpl, action_policy_namespace,
    check_team_namespace, check_write, enforce_namespace_tenant_context,
    enforce_object_marking_access, ensure_action_schema_kinds_allowed, is_managed_team_principal,
    record_marking_or_purpose_decision, resolve_principal_authority,
};
use crate::grpc::pb::sekai::ActionRequest;
use crate::sekai::action_lifecycle::GovernedActionContext;
use crate::sekai::markings;
use std::collections::{HashMap, HashSet};
use std::sync::RwLockReadGuard;
use tonic::Status;

pub(super) struct AdmittedAction<'a> {
    pub target_ids: Vec<String>,
    pub sensitive_params: HashSet<String>,
    pub schema_kinds: Vec<String>,
    pub actor: String,
    pub lifecycle: GovernedActionContext,
    pub actions: RwLockReadGuard<'a, crate::sekai::action::ActionExecutor>,
}

pub(super) struct ActionExecutionAdmission<'a> {
    service: &'a SekaiServiceImpl,
}

impl<'a> ActionExecutionAdmission<'a> {
    pub(super) fn new(service: &'a SekaiServiceImpl) -> Self {
        Self { service }
    }

    pub(super) fn admit(
        &self,
        request: &ActionRequest,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
        work_unit: &str,
        catalog_namespace: Option<&str>,
    ) -> Result<AdmittedAction<'a>, Status> {
        let actions = self
            .service
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?;
        let mask_missing_link = actions.masks_missing_link(&request.action);
        let sensitive_params = actions.sensitive_param_names(&request.action);
        let target_ids = actions
            .target_ids(&self.service.db, &request.action, &request.params)
            .map_err(|error| {
                if mask_missing_link && error == "link not found" {
                    Status::permission_denied("write denied")
                } else {
                    Status::invalid_argument(error)
                }
            })?;

        if let Some(namespace) = catalog_namespace {
            for target_id in &target_ids {
                if let Some(target) = self
                    .service
                    .db
                    .get_object(target_id)
                    .map_err(Status::internal)?
                    && target.namespace != namespace
                {
                    return Err(Status::failed_precondition(
                        "capability namespace does not match action target",
                    ));
                }
            }
            if request
                .params
                .get("namespace")
                .is_some_and(|target_namespace| target_namespace != namespace)
            {
                return Err(Status::failed_precondition(
                    "capability namespace does not match action target",
                ));
            }
        }

        if actions.creates_namespace(&request.action, &request.params) {
            return Err(Status::permission_denied(
                "namespace objects must be managed through EnsureTeamNamespace",
            ));
        }
        for target_id in &target_ids {
            if let Some(target) = self
                .service
                .db
                .get_object(target_id)
                .map_err(Status::internal)?
            {
                if target.kind == markings::PRINCIPAL_PROFILE_KIND {
                    return Err(Status::permission_denied(
                        "principal_profile objects require credential-admin CRUD paths",
                    ));
                }
                enforce_namespace_tenant_context(
                    &self.service.db,
                    tenant_context,
                    &target.namespace,
                    true,
                )?;
                check_team_namespace(&self.service.db, principals, &target.namespace, true)?;
                let _ = enforce_object_marking_access(
                    &self.service.db,
                    &target,
                    principals,
                    &format!("execute_action:{}:{}", request.action, target_id),
                )?;
            }
            check_write(&self.service.security, target_id, principals)?;
        }

        self.validate_classification(request, &actions)?;
        self.check_purpose(request, principals, &target_ids, &actions)?;

        if let Some(namespace) = request.params.get("namespace") {
            enforce_namespace_tenant_context(&self.service.db, tenant_context, namespace, true)?;
            check_team_namespace(&self.service.db, principals, namespace, true)?;
        } else if request.action == "create_object"
            && (tenant_context.is_some()
                || is_managed_team_principal(&self.service.db, principals)?)
        {
            return Err(Status::permission_denied(
                "team object creation requires a canonical namespace",
            ));
        }

        let schema_kinds = actions
            .schema_kinds(&self.service.db, &request.action, &request.params)
            .map_err(Status::invalid_argument)?;
        ensure_action_schema_kinds_allowed(&schema_kinds)?;
        let actor = principals.first().cloned().unwrap_or_default();
        let policy_namespace =
            action_policy_namespace(&self.service.db, &target_ids, &request.params);
        let (op_mutations, op_deletes) = actions.action_op_counts(&request.action, &request.params);
        let lifecycle = GovernedActionContext::resolve(
            &self.service.db,
            &actor,
            &policy_namespace,
            &request.action,
            actions.action_risk_class(&request.action),
            work_unit,
            op_mutations,
            op_deletes,
            ERASED_NAMESPACE,
        )
        .map_err(Status::internal)?;

        Ok(AdmittedAction {
            target_ids,
            sensitive_params,
            schema_kinds,
            actor,
            lifecycle,
            actions,
        })
    }

    fn validate_classification(
        &self,
        request: &ActionRequest,
        actions: &crate::sekai::action::ActionExecutor,
    ) -> Result<(), Status> {
        if request
            .params
            .get("key")
            .is_some_and(|key| key == markings::OBJECT_CLASSIFICATION_PROPERTY)
            && let Some(value) = request.params.get("value")
        {
            markings::parse_optional_classification(value).map_err(Status::invalid_argument)?;
        }
        if let Some(value) = request.params.get(markings::OBJECT_CLASSIFICATION_PROPERTY) {
            markings::parse_optional_classification(value).map_err(Status::invalid_argument)?;
        }
        if let Some(action_type) = actions.get_action_type(&request.action) {
            for operation in &action_type.ops {
                if operation.op == "set_property"
                    && operation.property == markings::OBJECT_CLASSIFICATION_PROPERTY
                {
                    let value = if operation.value_from.is_empty() {
                        request.params.get("value")
                    } else {
                        request.params.get(&operation.value_from)
                    };
                    if let Some(value) = value {
                        markings::parse_optional_classification(value)
                            .map_err(Status::invalid_argument)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn check_purpose(
        &self,
        request: &ActionRequest,
        principals: &[String],
        target_ids: &[String],
        actions: &crate::sekai::action::ActionExecutor,
    ) -> Result<(), Status> {
        let required_purpose = actions
            .get_action_type(&request.action)
            .map(|action_type| action_type.required_purpose.clone())
            .unwrap_or_default();
        if required_purpose.trim().is_empty() {
            return Ok(());
        }
        let authority = resolve_principal_authority(&self.service.db, principals)?;
        let purpose = markings::evaluate_purpose_access(
            &format!("execute_action:{}", request.action),
            &required_purpose,
            &authority,
        );
        let actor = principals.first().cloned().unwrap_or_default();
        let mut evidence = HashMap::from([
            ("required_purpose".into(), purpose.required_purpose.clone()),
            ("detail".into(), purpose.detail.clone()),
        ]);
        if purpose.decision == markings::MarkingDecision::Deny {
            evidence.insert("outcome".into(), "denied".into());
            let _ = record_marking_or_purpose_decision(
                &self.service.db,
                &actor,
                "purpose.execute",
                target_ids.first().map(String::as_str).unwrap_or(""),
                &purpose.decision_id,
                "denied",
                evidence,
            );
            return Err(Status::permission_denied("purpose not allow-listed"));
        }
        if purpose.decision == markings::MarkingDecision::Allow {
            evidence.insert("outcome".into(), "allowed".into());
            record_marking_or_purpose_decision(
                &self.service.db,
                &actor,
                "purpose.execute",
                target_ids.first().map(String::as_str).unwrap_or(""),
                &purpose.decision_id,
                "allowed",
                evidence,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::runtime_db::RuntimeDb;
    use crate::domain;
    use crate::sekai::action_policy::ActionDecision;
    use crate::sekai::security::{Grant, Role};
    use std::sync::Arc;

    fn admitted_service() -> SekaiServiceImpl {
        let service = SekaiServiceImpl::new(Arc::new(RuntimeDb::memory()));
        service
            .db
            .create_object(&domain::Object {
                id: "target-1".into(),
                kind: "object".into(),
                name: "target".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        let grant = Grant {
            id: "grant-1".into(),
            object_id: "target-1".into(),
            principal: "alice".into(),
            role: Role::Editor,
            created: 0,
        };
        service.db.create_grant(&grant).unwrap();
        service.security.add_grant(&grant);
        service
    }

    fn set_property_request(value: &str) -> ActionRequest {
        ActionRequest {
            action: "set_property".into(),
            params: HashMap::from([
                ("id".into(), "target-1".into()),
                ("key".into(), "status".into()),
                ("value".into(), value.into()),
            ]),
            actor: "ignored-protocol-actor".into(),
        }
    }

    #[test]
    fn interface_admits_authorized_target_and_binds_authenticated_actor() {
        let service = admitted_service();
        let admitted = ActionExecutionAdmission::new(&service)
            .admit(
                &set_property_request("ready"),
                &["alice".into()],
                None,
                "work-1",
                None,
            )
            .unwrap();

        assert_eq!(admitted.target_ids, ["target-1"]);
        assert_eq!(admitted.actor, "alice");
        assert_eq!(admitted.lifecycle.decision, ActionDecision::Allow);
        assert_eq!(admitted.lifecycle.work_unit, "work-1");
    }

    #[test]
    fn interface_rejects_ungranted_target_before_policy_resolution() {
        let service = admitted_service();
        let error = match ActionExecutionAdmission::new(&service).admit(
            &set_property_request("ready"),
            &["mallory".into()],
            None,
            "work-1",
            None,
        ) {
            Ok(_) => panic!("ungranted target must be denied"),
            Err(error) => error,
        };

        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }
}
