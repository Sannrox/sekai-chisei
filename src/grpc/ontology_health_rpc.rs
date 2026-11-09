//! `GetOntologyHealth` (#1463): a health score per namespace from signals
//! the caller may see. Lint runs through `GetOntologyLintReport` with the
//! caller's own request context, so it applies the same visibility; the other
//! parts read as the matching list RPCs would. Stored trends and threshold
//! events (#1694) are recorded and read here too.

use super::*;
use crate::sekai::ontology_health::{
    self, BoundTarget, DatasetSignals, Finding, PART_ACCESS, PART_CONTRACT, PART_LINT, PART_TRUST,
    Part,
};
use crate::sekai::ontology_health_trend::{HealthSnapshot, PartScore};
use std::collections::{BTreeSet, HashMap};

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
        .await?
        .parts;
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

/// A namespace's parts, and what the dataset and definition parts were
/// scored from, so a stored score can be shown only to who may see those.
struct Scored {
    parts: Vec<Part>,
    datasets: Vec<String>,
    definition_revision: Option<String>,
}

async fn namespace_parts(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    namespace: &str,
    lint_request: Request<GetOntologyLintReportRequest>,
) -> Result<Scored, Status> {
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
    Ok(Scored {
        parts,
        datasets: datasets.into_iter().map(|dataset| dataset.id).collect(),
        definition_revision: published.map(|revision| revision.revision_digest),
    })
}

/// Whether `dataset` is bound into `namespace` and the caller may read it, as
/// `ListDatasets` would show it.
fn dataset_readable(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    namespace: &str,
    dataset: &crate::sekai::dataset::Dataset,
) -> Result<bool, Status> {
    let db = service.db.runtime();
    let in_namespace = !dataset.object_id.is_empty()
        && db
            .get_object(&dataset.object_id)
            .map_err(Status::internal)?
            .is_some_and(|object| object.namespace == namespace);
    Ok(in_namespace
        && check_dataset_access(db, &service.security, principals, dataset, false).is_ok()
        && catalog_binding_discoverable(
            db,
            &service.security,
            tenant_context,
            &dataset.object_id,
            principals,
        ))
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
        if !dataset_readable(service, principals, tenant_context, namespace, &dataset)? {
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

/// The reason a part reads unavailable to a caller who may not see it.
const NOT_PERMITTED: &str = "not_permitted";

/// What a caller may see of stored snapshots, judged from their own scoring
/// of the namespace now: no part that reads `not_permitted` to them, no
/// dataset part scored from a dataset they may not read, and no definition
/// part scored from a revision they may not read. Lint and access count only
/// the objects, links and grants their scorer could see, which a stored score
/// cannot prove for anyone else: they show only to the recording principal.
struct Projection<'a> {
    service: &'a SekaiServiceImpl,
    principals: &'a [String],
    tenant_context: Option<&'a RequestEnterpriseContext>,
    namespace: &'a str,
    hidden: BTreeSet<&'static str>,
    datasets: std::cell::RefCell<HashMap<String, bool>>,
    revisions: std::cell::RefCell<HashMap<String, bool>>,
}

impl<'a> Projection<'a> {
    fn new(
        service: &'a SekaiServiceImpl,
        principals: &'a [String],
        tenant_context: Option<&'a RequestEnterpriseContext>,
        namespace: &'a str,
        scored: &Scored,
    ) -> Self {
        Self {
            service,
            principals,
            tenant_context,
            namespace,
            hidden: scored
                .parts
                .iter()
                .filter(|part| part.unavailable_reason == NOT_PERMITTED)
                .map(|part| part.part)
                .collect(),
            datasets: Default::default(),
            revisions: Default::default(),
        }
    }

    fn visible(&self, snapshot: &HealthSnapshot, part: &PartScore) -> bool {
        if self.hidden.contains(part.part.as_str())
            || !part
                .inputs
                .iter()
                .all(|dataset| self.dataset_readable(dataset))
        {
            return false;
        }
        if part.score.is_none() {
            return true;
        }
        // Lint and access show only to their recorder, which was shown the
        // score when it recorded it: nothing it did not already receive.
        let recorder = self.principals.contains(&snapshot.recorded_by);
        match part.part.as_str() {
            PART_ACCESS => return recorder,
            PART_LINT if !recorder => return false,
            PART_LINT | PART_CONTRACT => {}
            _ => return true,
        }
        // The definition parts need read on the revision they were scored
        // from, not only on the one published now.
        let revision = &snapshot.definition_revision;
        !revision.is_empty()
            && *self
                .revisions
                .borrow_mut()
                .entry(revision.clone())
                .or_insert_with(|| {
                    authorize_definition_revision(
                        self.service,
                        self.principals,
                        self.namespace,
                        revision,
                        true,
                    )
                    .is_ok()
                })
    }

    /// Whether the caller may read the dataset `id` now; a dataset gone, or
    /// a read that fails, reads as not readable.
    fn dataset_readable(&self, id: &str) -> bool {
        *self
            .datasets
            .borrow_mut()
            .entry(id.to_owned())
            .or_insert_with(|| {
                self.service
                    .db
                    .runtime()
                    .get_dataset(id)
                    .ok()
                    .flatten()
                    .is_some_and(|dataset| {
                        dataset_readable(
                            self.service,
                            self.principals,
                            self.tenant_context,
                            self.namespace,
                            &dataset,
                        )
                        .unwrap_or(false)
                    })
            })
    }

    /// The snapshot with only the parts the caller may see.
    fn snapshot(&self, snapshot: &HealthSnapshot) -> OntologyHealthSnapshot {
        let parts: Vec<OntologyHealthPartScore> = snapshot
            .parts
            .iter()
            .filter(|part| self.visible(snapshot, part))
            .map(|part| OntologyHealthPartScore {
                part: part.part.clone(),
                score: part.score.map(u32::from),
                complete: part.complete,
            })
            .collect();
        OntologyHealthSnapshot {
            namespace: snapshot.namespace.clone(),
            window_start_ms: snapshot.window_start_ms,
            window_ms: snapshot.window_ms,
            recorded_at_ms: snapshot.recorded_at_ms,
            threshold: u32::from(snapshot.threshold),
            score: parts.iter().filter_map(|part| part.score).min(),
            parts,
        }
    }

    /// Whether the caller may see every part `snapshot`'s total was taken
    /// from, so its threshold event too.
    fn whole(&self, snapshot: &HealthSnapshot) -> bool {
        snapshot
            .parts
            .iter()
            .all(|part| part.score.is_none() || self.visible(snapshot, part))
    }
}

/// Scores `namespace` as the caller, as `GetOntologyHealth` would.
async fn score_as_caller(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    metadata: tonic::metadata::MetadataMap,
    extensions: tonic::Extensions,
    namespace: &str,
) -> Result<Scored, Status> {
    let lint_request = Request::from_parts(
        metadata,
        extensions,
        GetOntologyLintReportRequest {
            namespace: namespace.into(),
            branch_id: String::new(),
        },
    );
    namespace_parts(service, principals, tenant_context, namespace, lint_request).await
}

/// `RecordOntologyHealthSnapshot` (#1694): scores the namespace as its
/// administrator and stores the part scores for the current window, with
/// what they were scored from. The on-demand call; a stored schedule records
/// from the transform schedule tick (#2192). The response
/// shows the caller what they may see of the stored snapshot, a replayed one
/// included.
pub(super) async fn record_ontology_health_snapshot(
    service: &SekaiServiceImpl,
    req: Request<RecordOntologyHealthSnapshotRequest>,
) -> Result<Response<RecordOntologyHealthSnapshotResponse>, Status> {
    use crate::sekai::ontology_health_trend::{self, RecordRequest, Recorded, TrendError};
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let (metadata, extensions, input) = req.into_parts();
    let (recorded_by, scored) = score_as_recorder(
        service,
        &principals,
        tenant_context.as_ref(),
        metadata,
        extensions,
        &input.namespace,
    )
    .await?;
    let recorded = ontology_health_trend::record(
        service.db.runtime(),
        &RecordRequest {
            namespace: &input.namespace,
            window_ms: input.window_ms,
            retention_ms: input.retention_ms,
            threshold: input.threshold,
            recorded_by: &recorded_by,
            now_ms: now_millis(),
        },
        &scored.parts,
        &scored.datasets,
        scored.definition_revision.as_deref().unwrap_or_default(),
    )
    .map_err(|error| match error {
        TrendError::Invalid(message) => Status::invalid_argument(message),
        TrendError::Store(_) => Status::internal("health trend unavailable"),
    })?;
    let (snapshot, event, replay) = match recorded {
        Recorded::Fresh { snapshot, event } => (snapshot, event, false),
        Recorded::Replay(snapshot) => (snapshot, None, true),
        Recorded::Stale => {
            return Err(Status::failed_precondition(
                "a later health window is already recorded",
            ));
        }
    };
    let projection = Projection::new(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        &scored,
    );
    let whole = projection.whole(&snapshot);
    Ok(Response::new(RecordOntologyHealthSnapshotResponse {
        snapshot: Some(projection.snapshot(&snapshot)),
        replay,
        event: event.filter(|_| whole).map(event_to_proto),
    }))
}

/// Scores `namespace` for a record: only its administrator records, so a
/// snapshot scores what the namespace holds. Returns the recorder.
async fn score_as_recorder(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    metadata: tonic::metadata::MetadataMap,
    extensions: tonic::Extensions,
    namespace: &str,
) -> Result<(String, Scored), Status> {
    authorize_source_sync_namespace(service, principals, tenant_context, namespace, true)?;
    let recorded_by = authorize_source_type_namespace_admin(service, principals, namespace)?;
    let scored = score_as_caller(
        service,
        principals,
        tenant_context,
        metadata,
        extensions,
        namespace,
    )
    .await?;
    Ok((recorded_by, scored))
}

/// The ontology health member of the transform schedule tick (#2192):
/// records the due window of every stored schedule, scored and authorized as
/// the administrator that put it, outside any tenant assertion. Schedules
/// record one at a time and each on its own. A recorder refused now (revoked,
/// say) halts its schedule with the reason, so later ticks skip it until a
/// put replaces it; a store failure leaves the window due for the next tick.
/// Either way the first error is returned after every schedule was tried.
/// Returns the number of windows this tick wrote.
pub(super) async fn tick_ontology_health_schedules(
    service: &SekaiServiceImpl,
    now_ms: i64,
) -> Result<usize, Status> {
    use crate::sekai::ontology_health_schedule::{self as schedules, HealthSchedule};
    use crate::sekai::ontology_health_trend::{Recorded, TrendError};
    let db = service.db.runtime();
    let due =
        schedules::due(db, now_ms).map_err(|_| Status::internal("health schedules unavailable"))?;
    // None when the halt was fenced off: a put replaced the schedule, or
    // another plane finished the window, so this tick has nothing to report.
    let halt = |schedule: &HealthSchedule, reason: &str| -> Option<Status> {
        match schedules::halt(db, schedule, now_ms, reason) {
            Ok(true) => Some(Status::failed_precondition(format!(
                "ontology health schedule of {} halted: {reason}",
                schedule.namespace
            ))),
            Ok(false) => None,
            Err(_) => Some(Status::internal("health schedules unavailable")),
        }
    };
    let mut written = 0;
    let mut first_error = None;
    for schedule in due {
        let principals = vec![schedule.recorded_by.clone()];
        let mut metadata = tonic::metadata::MetadataMap::new();
        let Ok(principal) = tonic::metadata::MetadataValue::try_from(schedule.recorded_by.as_str())
        else {
            if let Some(error) = halt(&schedule, "recorder is not a principal") {
                first_error.get_or_insert(error);
            }
            continue;
        };
        metadata.insert("x-principal", principal);
        let scored = score_as_recorder(
            service,
            &principals,
            None,
            metadata,
            tonic::Extensions::default(),
            &schedule.namespace,
        )
        .await;
        let error = match scored {
            Ok((_, scored)) => match schedules::record_due(
                db,
                &schedule,
                now_ms,
                &scored.parts,
                &scored.datasets,
                scored.definition_revision.as_deref().unwrap_or_default(),
            ) {
                Ok(recorded) => {
                    written += usize::from(matches!(recorded, Recorded::Fresh { .. }));
                    continue;
                }
                Err(TrendError::Invalid(message)) => halt(&schedule, &message),
                Err(TrendError::Store(_)) => Some(Status::internal("health trend unavailable")),
            },
            Err(status) if refuses_recorder(status.code()) => halt(&schedule, status.message()),
            Err(status) => Some(status),
        };
        let Some(error) = error else {
            continue;
        };
        tracing::warn!(namespace = %schedule.namespace, error = %error.message(), "ontology health schedule failed");
        first_error.get_or_insert(error);
    }
    first_error.map_or(Ok(written), Err)
}

/// A refusal that a retry would get again, until someone changes a grant or
/// the schedule; anything else may pass on the next tick.
fn refuses_recorder(code: tonic::Code) -> bool {
    matches!(
        code,
        tonic::Code::PermissionDenied
            | tonic::Code::Unauthenticated
            | tonic::Code::NotFound
            | tonic::Code::InvalidArgument
            | tonic::Code::FailedPrecondition
    )
}

/// `ListOntologyHealthTrend` (#1694): the namespace's stored snapshots and
/// threshold events for a reader of the namespace, each snapshot showing only
/// the parts the reader may see now, and an event only when the reader may
/// see every part its score was taken from.
pub(super) async fn list_ontology_health_trend(
    service: &SekaiServiceImpl,
    req: Request<ListOntologyHealthTrendRequest>,
) -> Result<Response<ListOntologyHealthTrendResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let (metadata, extensions, input) = req.into_parts();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    let scored = score_as_caller(
        service,
        &principals,
        tenant_context.as_ref(),
        metadata,
        extensions,
        &input.namespace,
    )
    .await?;
    let (snapshots, events) = service
        .db
        .runtime()
        .list_ontology_health_trend(&input.namespace)
        .map_err(|_| Status::internal("health trend unavailable"))?;
    let projection = Projection::new(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        &scored,
    );
    let whole: BTreeSet<i64> = snapshots
        .iter()
        .filter(|snapshot| projection.whole(snapshot))
        .map(|snapshot| snapshot.window_start_ms)
        .collect();
    // The schedule names its recorder and why it halted: administrators only.
    let schedule =
        if authorize_source_type_namespace_admin(service, &principals, &input.namespace).is_ok() {
            service
                .db
                .runtime()
                .get_ontology_health_schedule(&input.namespace)
                .map_err(|_| Status::internal("health schedule unavailable"))?
                .map(schedule_to_proto)
        } else {
            None
        };
    Ok(Response::new(ListOntologyHealthTrendResponse {
        schedule,
        snapshots: snapshots
            .iter()
            .map(|snapshot| projection.snapshot(snapshot))
            .collect(),
        events: events
            .into_iter()
            .filter(|event| whole.contains(&event.window_start_ms))
            .map(event_to_proto)
            .collect(),
    }))
}

/// The caller and namespace a schedule put or delete is for: the namespace's
/// administrator, outside a tenant assertion, since the tick records with no
/// tenant context (as saved exports run).
fn schedule_admin<T: std::any::Any>(
    service: &SekaiServiceImpl,
    req: &Request<T>,
    namespace: &str,
) -> Result<String, Status> {
    let principals = caller_principals(req);
    require_authenticated(&principals)?;
    if request_tenant_context(service.db.runtime(), req)?.is_some() {
        return Err(Status::failed_precondition(
            "ontology health schedules are for principals outside a tenant assertion",
        ));
    }
    authorize_source_sync_namespace(service, &principals, None, namespace, true)?;
    authorize_source_type_namespace_admin(service, &principals, namespace)
}

/// `PutOntologyHealthSchedule` (#2192): creates or replaces the namespace's
/// schedule, recording as the caller. A replace clears a halt.
pub(super) async fn put_ontology_health_schedule(
    service: &SekaiServiceImpl,
    req: Request<PutOntologyHealthScheduleRequest>,
) -> Result<Response<PutOntologyHealthScheduleResponse>, Status> {
    use crate::sekai::ontology_health_schedule::{self as schedules, PutSchedule};
    use crate::sekai::ontology_health_trend::TrendError;
    let namespace = req
        .get_ref()
        .schedule
        .as_ref()
        .map(|schedule| schedule.namespace.clone())
        .ok_or_else(|| Status::invalid_argument("schedule is required"))?;
    let recorded_by = schedule_admin(service, &req, &namespace)?;
    let input = req.into_inner().schedule.unwrap_or_default();
    let schedule = schedules::put(
        service.db.runtime(),
        &PutSchedule {
            namespace: &namespace,
            window_ms: input.window_ms,
            retention_ms: input.retention_ms,
            threshold: input.threshold,
            recorded_by: &recorded_by,
            now_ms: now_millis(),
        },
    )
    .map_err(|error| match error {
        TrendError::Invalid(message) => Status::invalid_argument(message),
        TrendError::Store(_) => Status::internal("health schedule unavailable"),
    })?;
    Ok(Response::new(PutOntologyHealthScheduleResponse {
        schedule: Some(schedule_to_proto(schedule)),
    }))
}

/// `DeleteOntologyHealthSchedule` (#2192): stops the schedule; the trend stays.
pub(super) async fn delete_ontology_health_schedule(
    service: &SekaiServiceImpl,
    req: Request<DeleteOntologyHealthScheduleRequest>,
) -> Result<Response<DeleteOntologyHealthScheduleResponse>, Status> {
    let namespace = req.get_ref().namespace.clone();
    schedule_admin(service, &req, &namespace)?;
    let deleted = service
        .db
        .runtime()
        .delete_ontology_health_schedule(&namespace)
        .map_err(|_| Status::internal("health schedule unavailable"))?;
    Ok(Response::new(DeleteOntologyHealthScheduleResponse {
        deleted,
    }))
}

fn schedule_to_proto(
    schedule: crate::sekai::ontology_health_schedule::HealthSchedule,
) -> OntologyHealthSchedule {
    OntologyHealthSchedule {
        namespace: schedule.namespace,
        window_ms: schedule.window_ms,
        retention_ms: schedule.retention_ms,
        threshold: u32::from(schedule.threshold),
        recorded_by: schedule.recorded_by,
        updated_at_ms: schedule.updated_at_ms,
        last_window_start_ms: schedule.last_window_start_ms,
        last_error: schedule.last_error,
    }
}

fn event_to_proto(event: crate::sekai::ontology_health_trend::HealthEvent) -> OntologyHealthEvent {
    OntologyHealthEvent {
        namespace: event.namespace,
        window_start_ms: event.window_start_ms,
        kind: event.kind,
        score: u32::from(event.score),
        threshold: u32::from(event.threshold),
        emitted_at_ms: event.emitted_at_ms,
    }
}
