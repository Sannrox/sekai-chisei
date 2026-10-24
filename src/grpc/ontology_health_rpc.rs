//! `GetOntologyHealth` (#1463): a health score per namespace from signals
//! the caller may see. Lint runs through `GetOntologyLintReport` with the
//! caller's own request context, so it applies the same visibility; the other
//! parts read as the matching list RPCs would. Trends and threshold events
//! are a separate layer (#1694).

use super::*;
use crate::sekai::ontology_health::{
    self, BoundTarget, DatasetSignals, Finding, PART_ACCESS, PART_CONTRACT, PART_LINT, PART_TRUST,
    Part,
};
use std::collections::HashMap;

/// Namespaces one tenant-wide request scores; more mark it incomplete.
const MAX_HEALTH_NAMESPACES: usize = 20;
/// Datasets one namespace reads; more mark freshness and quality incomplete.
const MAX_HEALTH_DATASETS: usize = 500;
/// Grants of the namespace the access part scores; more mark it incomplete.
const MAX_HEALTH_GRANTS: usize = 10_000;

pub(super) async fn get_ontology_health(
    service: &SekaiServiceImpl,
    req: Request<GetOntologyHealthRequest>,
) -> Result<Response<GetOntologyHealthResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let (metadata, extensions, input) = req.into_parts();
    let (namespaces, complete) = if input.namespace.is_empty() {
        // Namespaces the caller may not read are left out, not named.
        let mut readable: Vec<String> = service
            .db
            .runtime()
            .list_published_definition_namespaces()
            .map_err(|_| Status::internal("namespaces unavailable"))?
            .into_iter()
            .filter(|namespace| {
                authorize_source_sync_namespace(
                    service,
                    &principals,
                    tenant_context.as_ref(),
                    namespace,
                    false,
                )
                .is_ok()
            })
            .collect();
        let complete = readable.len() <= MAX_HEALTH_NAMESPACES;
        readable.truncate(MAX_HEALTH_NAMESPACES);
        (readable, complete)
    } else {
        authorize_source_sync_namespace(
            service,
            &principals,
            tenant_context.as_ref(),
            &input.namespace,
            false,
        )?;
        (vec![input.namespace], true)
    };
    let mut scored = Vec::new();
    for namespace in namespaces {
        let lint_request = Request::from_parts(
            metadata.clone(),
            extensions.clone(),
            GetOntologyLintReportRequest {
                namespace: namespace.clone(),
                branch_id: String::new(),
            },
        );
        let parts = namespace_parts(
            service,
            &principals,
            tenant_context.as_ref(),
            &namespace,
            lint_request,
        )
        .await?;
        scored.push(NamespaceHealth {
            namespace,
            score: ontology_health::total(&parts).map(u32::from),
            parts: parts.into_iter().map(to_proto_part).collect(),
        });
    }
    Ok(Response::new(GetOntologyHealthResponse {
        score: scored.iter().filter_map(|namespace| namespace.score).min(),
        namespaces: scored,
        complete,
    }))
}

async fn namespace_parts(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    namespace: &str,
    lint_request: Request<GetOntologyLintReportRequest>,
) -> Result<Vec<Part>, Status> {
    let db = service.db.runtime();
    let (datasets, datasets_complete) =
        dataset_signals(service, principals, tenant_context, namespace)?;
    let mut parts = vec![
        ontology_health::freshness(&datasets, datasets_complete),
        ontology_health::quality(&datasets, datasets_complete),
    ];
    // The contract and lint parts read the published definition, as a read
    // of it would: every member must be visible.
    let published = db
        .get_published_definition_revision(namespace)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    let members = match &published {
        None => Err("no_published_definition"),
        Some(revision) => match authorize_definition_revision(
            service,
            principals,
            namespace,
            &revision.revision_digest,
            true,
        ) {
            Ok(()) => Ok(db
                .get_definition_members(namespace, &revision.revision_digest)
                .map_err(|_| Status::internal("definition revision unavailable"))?),
            Err(_) => Err("not_permitted"),
        },
    };
    parts.push(match &members {
        Err(reason) => Part::unavailable(PART_CONTRACT, reason),
        Ok(members) => {
            match crate::sekai::definition_consumer_impact::list_blocking_bindings(
                |filter| db.list_objects(filter),
                namespace,
            ) {
                Ok(bindings) => ontology_health::contract(
                    &bindings.iter().map(bound_target).collect::<Vec<_>>(),
                    members,
                ),
                Err(_) => Part::unavailable(PART_CONTRACT, "too_many_bindings"),
            }
        }
    });
    parts.push(match &members {
        Err(reason) => Part::unavailable(PART_LINT, reason),
        Ok(members) => {
            match super::rpc_definitions::get_ontology_lint_report(service, lint_request).await {
                Ok(report) => {
                    let report = report.into_inner();
                    let findings: Vec<Finding> = report
                        .findings
                        .into_iter()
                        .map(|finding| Finding {
                            rule: finding.rule,
                            subject_kind: finding.subject_kind,
                            subject_id: finding.subject_id,
                            severity: finding.severity,
                        })
                        .collect();
                    let members = members
                        .iter()
                        .map(|member| (member.member_kind.clone(), member.member_id.clone()))
                        .collect();
                    ontology_health::lint(&members, &findings, report.complete)
                }
                Err(status) if status.code() == tonic::Code::Internal => return Err(status),
                Err(_) => Part::unavailable(PART_LINT, "not_permitted"),
            }
        }
    });
    // Trust scores are computed per object on request and not stored.
    parts.push(Part::unavailable(PART_TRUST, "not_stored"));
    parts.push(access_part(service, principals, namespace)?);
    Ok(parts)
}

/// Visible datasets bound into `namespace`, as `ListDatasets` shows them,
/// with what their latest checks and alerts say.
fn dataset_signals(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    namespace: &str,
) -> Result<(Vec<DatasetSignals>, bool), Status> {
    use crate::sekai::dataset_health::{
        ALERT_FIRING, ALERT_KIND_SCHEDULE, ALERT_REASON_LATE, KIND_FRESHNESS,
    };
    let db = service.db.runtime();
    let mut signals = Vec::new();
    for dataset in db.list_datasets().map_err(Status::internal)? {
        let in_namespace = !dataset.object_id.is_empty()
            && db
                .get_object(&dataset.object_id)
                .map_err(Status::internal)?
                .is_some_and(|object| object.namespace == namespace);
        if !in_namespace
            || check_dataset_access(db, &service.security, principals, &dataset, false).is_err()
            || !catalog_binding_discoverable(
                db,
                &service.security,
                tenant_context,
                &dataset.object_id,
                principals,
            )
        {
            continue;
        }
        if signals.len() == MAX_HEALTH_DATASETS {
            return Ok((signals, false));
        }
        let kinds: HashMap<String, String> = db
            .list_dataset_health_checks(&dataset.id)
            .map_err(Status::internal)?
            .into_iter()
            .map(|check| (check.check_id, check.kind))
            .collect();
        // Results come oldest first, so the last per check is its latest.
        let mut latest = HashMap::new();
        for result in db
            .list_dataset_health_results(&dataset.id, "")
            .map_err(Status::internal)?
        {
            latest.insert(result.check_id, result.passed);
        }
        let failed = |freshness: bool| {
            latest.iter().any(|(check_id, passed)| {
                !passed
                    && kinds
                        .get(check_id)
                        .is_some_and(|kind| (kind == KIND_FRESHNESS) == freshness)
            })
        };
        let mut alerts = HashMap::new();
        for alert in db
            .list_dataset_alerts(&dataset.id)
            .map_err(Status::internal)?
        {
            alerts.insert((alert.kind.clone(), alert.ref_id.clone()), alert);
        }
        let late = alerts.values().any(|alert| {
            alert.kind == ALERT_KIND_SCHEDULE
                && alert.reason == ALERT_REASON_LATE
                && alert.state == ALERT_FIRING
        });
        signals.push(DatasetSignals {
            stale: late || failed(true),
            failing_check: db
                .dataset_health_state(&dataset.id)
                .map_err(Status::internal)?
                .quarantined
                || failed(false),
            id: dataset.id,
        });
    }
    Ok((signals, true))
}

fn bound_target(object: &domain::Object) -> BoundTarget {
    use crate::sekai::definition_consumer_impact::{binding_digest, binding_from_object};
    BoundTarget {
        id: object.id.clone(),
        target: binding_from_object(object)
            .ok()
            .filter(|binding| binding.declaration_digest == binding_digest(binding))
            .map(|binding| (binding.member_kind, binding.member_id, binding.property)),
    }
}

/// Grants on the namespace and its objects, for a caller who administers
/// the namespace boundary, each as `ListGrants` would show it.
fn access_part(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
) -> Result<Part, Status> {
    let db = service.db.runtime();
    let Some(boundary) = db
        .find_namespace_boundary(namespace)
        .map_err(|_| Status::internal("namespace authorization unavailable"))?
    else {
        return Ok(Part::unavailable(PART_ACCESS, "no_namespace_boundary"));
    };
    if check_object_admin(db, &service.security, &boundary, principals).is_err() {
        return Ok(Part::unavailable(PART_ACCESS, "not_permitted"));
    }
    // Each grant counts only when `ListGrants` would show it to the caller
    // for its target; one it would not makes the part incomplete.
    let mut targets: HashMap<String, Option<bool>> = HashMap::new();
    let mut grants = Vec::new();
    let mut complete = true;
    for grant in db.list_all_grants().map_err(Status::internal)? {
        let visible = match targets.get(&grant.object_id) {
            Some(visible) => *visible,
            None => {
                let visible = db
                    .get_object(&grant.object_id)
                    .map_err(Status::internal)?
                    .filter(|target| target.namespace == namespace || target.id == boundary.id)
                    .map(|target| {
                        let tier = if target.kind == "namespace" {
                            require_credential_admin(principals)
                        } else {
                            check_team_namespace(db, principals, &target.namespace, true)
                        };
                        tier.is_ok()
                            && check_object_admin(db, &service.security, &target, principals)
                                .is_ok()
                    });
                targets.insert(grant.object_id.clone(), visible);
                visible
            }
        };
        match visible {
            None => {}
            Some(false) => complete = false,
            Some(true) if grants.len() == MAX_HEALTH_GRANTS => complete = false,
            Some(true) => grants.push(grant),
        }
    }
    let require_terms = db
        .namespace_grant_policy(namespace)
        .map_err(Status::internal)?
        .is_some_and(|policy| policy.require_terms);
    Ok(ontology_health::access(
        &grants,
        require_terms,
        now_millis(),
        complete,
    ))
}

fn to_proto_part(part: Part) -> OntologyHealthPart {
    OntologyHealthPart {
        part: part.part.into(),
        available: part.score.is_some(),
        score: part.score.map_or(0, u32::from),
        unavailable_reason: part.unavailable_reason.into(),
        problems: part
            .problems
            .into_iter()
            .map(|problem| OntologyHealthProblem {
                subject_kind: problem.subject_kind,
                subject_id: problem.subject_id,
                code: problem.code,
            })
            .collect(),
        complete: part.complete,
    }
}
