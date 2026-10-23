//! Experimental ExplainValue RPC (#1452): the chain of writes behind one
//! property value.
//!
//! The caller needs read access to the object's history, as for
//! `ListObjectChanges`, and to the property. Each step joins its change row to
//! the writer's record: the source transaction and the object's record result,
//! the transform run, or the Action instance with its decisions. A step whose
//! record the caller may not read, or that is gone, is reported as hidden
//! rather than dropped, and the chain then reads incomplete.

use super::rpc_actions::authorize_action_instance_visibility;
use super::rpc_data::{authorize_live_object_history, caller_can_read_run_datasets};
use super::*;
use crate::sekai::audit::{
    WRITER_ACTION_INSTANCE, WRITER_SOURCE_TRANSACTION, WRITER_TRANSFORM_RUN,
};
use crate::sekai::value_explanation::{
    ExplainedStep, WriterView, chain_complete, change_field, explain_steps, field_history,
    marking_field,
};
use std::collections::BTreeMap;

const HISTORY_PAGE: i32 = 500;

pub(super) async fn explain_value(
    service: &SekaiServiceImpl,
    req: Request<ExplainValueRequest>,
) -> Result<Response<ExplainValueResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let policy_context = principal_policy_context(&req);
    let input = req.into_inner();
    let property = input.property.trim();
    if property.is_empty() || property.starts_with('_') {
        return Err(Status::invalid_argument("an object property is required"));
    }
    check_object_namespace_access(service.db.runtime(), &principals, &input.object_id, false)?;
    check_read(&service.security, &input.object_id, &principals)?;
    let object = service
        .db
        .runtime()
        .get_object(&input.object_id)
        .map_err(Status::internal)?
        .filter(|object| !is_reserved_governance_kind(&object.kind))
        .ok_or_else(|| Status::not_found("not found"))?;
    authorize_live_object_history(
        service,
        &principals,
        tenant_context.as_ref(),
        &object,
        "explain_value",
    )?;
    let property_policy = service
        .db
        .runtime()
        .active_object_policy(&object.namespace, &object.kind)
        .map_err(|_| Status::unavailable("object authorization unavailable"))?;
    if property_policy.as_ref().is_some_and(|policy| {
        policy.property_grants_enforced()
            && !policy.allows_property_access(
                property,
                crate::sekai::object_security::PropertyGrantAccess::Read,
            )
    }) {
        return Err(Status::permission_denied("ungranted property"));
    }

    let schema = service
        .schema_definitions
        .snapshot()
        .map_err(map_schema_definition_lifecycle_error)?;
    let context = principal_policy_context_from(&principals, tenant_context.as_ref());
    // Values read as ListObjectChanges shows them.
    let redact = |mut change: crate::sekai::audit::ObjectChange| {
        let shown = redact_object_change_values(
            change.clone(),
            &object.id,
            &object.kind,
            &schema,
            &service.security,
            &context,
            property_policy.as_ref(),
        );
        change.old_value = shown.old_value;
        change.new_value = shown.new_value;
        change
    };
    // Guests and shared spaces see filtered history, which cannot explain
    // a value: a hidden write would read as a gap in the chain.
    if visible_collaboration_history_page(
        service.db.runtime(),
        tenant_context.as_ref(),
        Some(&object),
        1,
        0,
    )?
    .is_some()
    {
        return Err(Status::failed_precondition(
            "explaining a value needs the object's full history",
        ));
    }
    // Pages are newest first, so a write landing between pages repeats a
    // row rather than skipping one; ids drop the repeat. The object was read
    // first, so its value stands in for creation only when no later row
    // shows an edit.
    let mut changes = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut offset = 0;
    loop {
        let page = service
            .db
            .runtime()
            .list_visible_object_changes(&object.id, HISTORY_PAGE, offset)
            .map_err(map_runtime_store_error)?;
        let full = page.len() as i32 == HISTORY_PAGE;
        changes.extend(
            page.into_iter()
                .filter(|change| seen.insert(change.id.clone()))
                .map(&redact),
        );
        if !full {
            break;
        }
        offset += HISTORY_PAGE;
    }
    // Authorization saw the object as read above. A write since may have
    // raised its marking over rows read here: refuse rather than return them
    // under the old check.
    let unchanged = service
        .db
        .runtime()
        .get_object(&object.id)
        .map_err(Status::internal)?
        .is_some_and(|now| {
            (
                now.updated,
                &now.kind,
                &now.name,
                &now.namespace,
                &now.properties,
            ) == (
                object.updated,
                &object.kind,
                &object.name,
                &object.namespace,
                &object.properties,
            )
        });
    if !unchanged {
        return Err(Status::aborted(
            "the object changed while it was explained; retry",
        ));
    }
    // The store lists newest first; write order is the reverse.
    changes.reverse();

    let latest = |field: String, value: String| {
        redact(crate::sekai::audit::ObjectChange {
            object_id: object.id.clone(),
            field,
            new_value: value,
            ..Default::default()
        })
        .new_value
    };
    let field = change_field(property);
    let current = if property == "name" {
        object.name.clone()
    } else {
        object.properties.get(property).cloned().unwrap_or_default()
    };
    let history = field_history(
        &changes,
        &field,
        &latest(field.clone(), current),
        input.as_of_ms,
    )
    .ok_or_else(|| Status::not_found("the object did not exist at that time"))?;
    let marking_current = crate::sekai::markings::object_marking_token(&object)
        .unwrap_or_default()
        .to_string();
    let marking = field_history(
        &changes,
        &marking_field(),
        &latest(marking_field(), marking_current),
        input.as_of_ms,
    )
    .unwrap_or_default();

    let mut resolve = |row: &crate::sekai::audit::ObjectChange| {
        writer_view(
            service,
            &principals,
            tenant_context.as_ref(),
            &policy_context,
            &object,
            row,
        )
    };
    let steps = explain_steps(history.steps, &mut resolve)?;
    let marking_steps = explain_steps(marking.steps, &mut resolve)?;
    // A value no row recorded, or whose origin retention purged, cannot be
    // explained in full.
    let complete = history.value.is_some()
        && marking.value.is_some()
        && !history.truncated
        && !marking.truncated
        && chain_complete(&steps)
        && chain_complete(&marking_steps);
    Ok(Response::new(ExplainValueResponse {
        object_id: object.id.clone(),
        property: property.to_string(),
        value: history.value.unwrap_or_default(),
        marking: marking.value.unwrap_or_default(),
        steps: steps.into_iter().map(to_proto_step).collect(),
        marking_steps: marking_steps.into_iter().map(to_proto_step).collect(),
        complete,
    }))
}

/// What the caller may see of the record behind one change row.
fn writer_view(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    policy_context: &crate::sekai::object_security::PrincipalPolicyContext,
    object: &crate::domain::Object,
    row: &crate::sekai::audit::ObjectChange,
) -> Result<WriterView, Status> {
    let db = service.db.runtime();
    let view = match row.writer_kind.as_str() {
        WRITER_SOURCE_TRANSACTION => {
            let record = db
                .get_source_write_record(&row.writer_ref, &object.id)
                .map_err(Status::internal)?;
            // The source's own producer, or a credential admin, reads it.
            record
                .filter(|record| {
                    require_credential_admin(principals).is_ok()
                        || (principals.contains(&record.producer_identity)
                            && authorize_source_sync_namespace(
                                service,
                                principals,
                                tenant_context,
                                &record.namespace,
                                false,
                            )
                            .is_ok())
                })
                .map(|record| {
                    BTreeMap::from([
                        ("binding_id".into(), record.binding_id),
                        ("namespace".into(), record.namespace),
                        ("producer_identity".into(), record.producer_identity),
                        ("status".into(), record.status),
                        ("outcome".into(), record.outcome),
                        ("closed_at_ms".into(), record.closed_at_ms.to_string()),
                        ("source_id".into(), record.source_id),
                        ("source_version".into(), record.source_version),
                        ("record_outcome".into(), record.record_outcome),
                    ])
                })
        }
        WRITER_TRANSFORM_RUN => {
            let checkpoint = row
                .writer_ref
                .rsplit_once('@')
                .map(|(_, checkpoint)| checkpoint.to_string())
                .unwrap_or_default();
            let run = db
                .get_governed_transform_run(&row.receipt_id)
                .map_err(Status::internal)?;
            run.filter(|run| {
                check_team_namespace(db, principals, &run.namespace, false).is_ok()
                    && enforce_namespace_tenant_context(db, tenant_context, &run.namespace, false)
                        .is_ok()
                    && caller_can_read_run_datasets(service, principals, run)
            })
            .map(|run| {
                BTreeMap::from([
                    ("transform_id".into(), run.transform_id),
                    ("definition_digest".into(), run.definition_digest),
                    ("checkpoint".into(), checkpoint),
                    ("trigger_cause".into(), run.trigger_cause),
                    ("markings_in".into(), run.markings_in),
                    ("markings_out".into(), run.markings_out),
                    ("created_at_ms".into(), run.created_at_ms.to_string()),
                ])
            })
        }
        WRITER_ACTION_INSTANCE => {
            let instance = db
                .get_action_instance(&row.writer_ref)
                .map_err(Status::internal)?;
            instance
                .filter(|instance| {
                    authorize_action_instance_read(
                        service,
                        principals,
                        &instance.namespace,
                        tenant_context,
                    )
                    .is_ok()
                        && enforce_namespace_tenant_context(
                            db,
                            tenant_context,
                            &instance.namespace,
                            false,
                        )
                        .is_ok()
                        && authorize_action_instance_visibility(
                            service,
                            principals,
                            tenant_context,
                            policy_context,
                            instance,
                        )
                        .is_ok()
                })
                .map(|instance| {
                    BTreeMap::from([
                        ("type_id".into(), instance.type_id),
                        ("version".into(), instance.version),
                        ("principal".into(), instance.principal),
                        (
                            "delegating_actor".into(),
                            instance.delegating_actor.unwrap_or_default(),
                        ),
                        ("status".into(), instance.status),
                        ("policy_decision".into(), instance.policy_decision),
                        ("decided_by".into(), instance.decided_by),
                        ("approval_decision".into(), instance.approval_decision),
                        ("operation_id".into(), instance.operation_id),
                    ])
                })
        }
        // Direct and unattributed writes have no record beyond the row.
        _ => Some(BTreeMap::new()),
    };
    Ok(view.map_or(WriterView::Hidden, WriterView::Visible))
}

fn to_proto_step(step: ExplainedStep) -> ValueExplanationStep {
    ValueExplanationStep {
        change_id: step.change_id,
        timestamp: step.timestamp,
        field: step.field,
        value: step.value,
        writer_kind: step.writer_kind,
        hidden: step.hidden,
        writer_ref: step.writer_ref,
        receipt_id: step.receipt_id,
        changed_by: step.changed_by,
        details: step.details.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::audit::ChangeAttribution;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, GovernedTransform, TransformStep};
    use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tonic::metadata::MetadataValue;

    fn service_from(db: RuntimeDb) -> SekaiServiceImpl {
        SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
            db,
        )))
    }

    fn as_principal<T>(payload: T, principal: &str) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    fn note(body: &str) -> crate::domain::Object {
        crate::domain::Object {
            id: "n1".into(),
            kind: "note".into(),
            name: "n1".into(),
            namespace: "ops".into(),
            external_id: String::new(),
            properties: HashMap::from([("body".into(), body.into())]),
            created: 1,
            updated: 1,
        }
    }

    fn explain(object_id: &str, property: &str, as_of_ms: i64) -> ExplainValueRequest {
        ExplainValueRequest {
            object_id: object_id.into(),
            property: property.into(),
            as_of_ms,
        }
    }

    #[tokio::test]
    async fn each_write_names_its_writer_and_records_it_cannot_read_are_hidden() {
        let db = RuntimeDb::memory();
        db.create_object_attributed(
            &note("raw"),
            "tester",
            None,
            &ChangeAttribution::source("tx-1"),
        )
        .unwrap();
        let mut object = note("clean");
        object.updated = 2;
        db.update_object_attributed(
            &object,
            None,
            "tester",
            None,
            &ChangeAttribution::transform("run-1", "4"),
        )
        .unwrap();
        object.properties.insert("body".into(), "edited".into());
        object.updated = 3;
        db.update_object_attributed(&object, None, "tester", None, &ChangeAttribution::direct())
            .unwrap();
        let svc = service_from(db);
        let response = svc
            .explain_value(as_principal(explain("n1", "body", 0), "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.value, "edited");
        let steps = response
            .steps
            .iter()
            .map(|step| (step.value.as_str(), step.writer_kind.as_str(), step.hidden))
            .collect::<Vec<_>>();
        // The source transaction and the run left no record this caller
        // can read: hidden, not dropped.
        assert_eq!(
            steps,
            vec![
                ("raw", WRITER_SOURCE_TRANSACTION, true),
                ("clean", WRITER_TRANSFORM_RUN, true),
                ("edited", "direct", false),
            ]
        );
        let source = &response.steps[0];
        assert!(source.writer_ref.is_empty() && source.receipt_id.is_empty());
        assert!(source.changed_by.is_empty() && source.details.is_empty());
        assert_eq!(response.steps[2].changed_by, "tester");
        assert!(!response.complete);
    }

    #[tokio::test]
    async fn a_marking_stamped_by_a_transform_explains_as_its_run() {
        let db = RuntimeDb::memory();
        let artifact = |id: &str, marking: Option<&str>| crate::domain::Object {
            id: id.into(),
            kind: "artifact".into(),
            name: id.into(),
            namespace: "ops".into(),
            external_id: format!("artifact:{id}"),
            properties: marking
                .map(|marking| {
                    HashMap::from([(OBJECT_CLASSIFICATION_PROPERTY.into(), marking.into())])
                })
                .unwrap_or_default(),
            created: 1,
            updated: 1,
        };
        let dataset = |id: &str, object_id: &str| Dataset {
            id: id.into(),
            name: id.into(),
            columns: ["id", "keep"]
                .map(|name| ColumnDef {
                    name: name.into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                })
                .to_vec(),
            object_id: object_id.into(),
            created: 1,
            partition_keys: Vec::new(),
        };
        db.create_object_with_audit(&artifact("in-obj", Some("public")), "tester")
            .unwrap();
        db.create_object_with_audit(&artifact("out-obj", None), "tester")
            .unwrap();
        db.create_dataset(&dataset("in", "in-obj")).unwrap();
        db.create_dataset(&dataset("out", "out-obj")).unwrap();
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
                (OBJECT_CLASSIFICATION_PROPERTY.into(), "public".into()),
            ])],
        )
        .unwrap();
        let transform = GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "t1".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: vec![TransformStep {
                kind: "filter".into(),
                column: "keep".into(),
                op: "eq".into(),
                value: "yes".into(),
                columns: Vec::new(),
            }],
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap();
        db.put_governed_transform(&transform, 10).unwrap();
        // Change rows carry the write time; the run's must follow creation.
        let run = db
            .run_governed_transform("ops", "t1", false, now_millis())
            .unwrap();
        let svc = service_from(db);
        // A marked object needs clearance; the trusted principal has it.
        let response = svc
            .explain_value(as_principal(
                explain("out-obj", OBJECT_CLASSIFICATION_PROPERTY, 0),
                "root",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.value, "public");
        assert_eq!(response.marking, response.value);
        let stamp = response.steps.last().unwrap();
        assert_eq!(stamp.writer_kind, WRITER_TRANSFORM_RUN);
        assert!(!stamp.hidden, "{stamp:?}");
        assert_eq!(stamp.receipt_id, run.run_id);
        assert_eq!(stamp.details["transform_id"], "t1");
        assert_eq!(stamp.details["markings_out"], "public");
        assert_eq!(response.marking_steps, response.steps);
    }

    #[tokio::test]
    async fn missing_objects_ungranted_properties_and_times_before_creation_are_refused() {
        let db = RuntimeDb::memory();
        db.create_object_attributed(&note("raw"), "tester", None, &ChangeAttribution::direct())
            .unwrap();
        let svc = service_from(db);
        let code =
            |result: Result<Response<ExplainValueResponse>, Status>| result.unwrap_err().code();
        assert_eq!(
            code(
                svc.explain_value(as_principal(explain("gone", "body", 0), "tester"))
                    .await
            ),
            tonic::Code::NotFound
        );
        assert_eq!(
            code(
                svc.explain_value(as_principal(explain("n1", "", 0), "tester"))
                    .await
            ),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            code(
                svc.explain_value(as_principal(explain("n1", "body", 1), "tester"))
                    .await
            ),
            tonic::Code::NotFound
        );
    }
}
