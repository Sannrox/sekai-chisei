//! Sources (`sekai.source/v1`, ADR 0148): `PutSource`, `GetSource`,
//! `ListSources` and `DisableSource`, plus the `source_sync` kind of the
//! claimable-work family (ADR 0149).
//!
//! Put and disable need a namespace administrator; get and list need
//! namespace read access, under the caller's tenant context when it has one.
//! Claiming sync work needs what claiming transform work needs, and
//! placement matches the labels the runtime registered with
//! `RegisterTransformRuntime`.

use super::*;
use crate::sekai::source::{self, PutSource, Source, SourceError, SourceSpec, SourceStatus};
use crate::sekai::source_sync::{self, SyncError, SyncFailure, SyncOutcome};
use crate::sekai::work_claim::{ClaimError, Fence};
use sekai_source_sdk::{ConfigValue, SourceConfig};

/// The caller, once it may administer Sources in `namespace`.
fn source_admin<T: std::any::Any>(
    service: &SekaiServiceImpl,
    req: &Request<T>,
    namespace: &str,
) -> Result<(), Status> {
    let principals = caller_principals(req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), req)?;
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        namespace,
        true,
    )?;
    authorize_source_type_namespace_admin(service, &principals, namespace).map(|_| ())
}

fn source_reader<T: std::any::Any>(
    service: &SekaiServiceImpl,
    req: &Request<T>,
    namespace: &str,
) -> Result<(), Status> {
    let principals = caller_principals(req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), req)?;
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        namespace,
        false,
    )
}

fn source_status(error: SourceError) -> Status {
    match error {
        SourceError::Invalid(message) => Status::invalid_argument(message),
        SourceError::NotFound => Status::not_found("source not found"),
        SourceError::RevisionConflict => Status::aborted(error.to_string()),
        SourceError::TokensOwned => Status::already_exists(error.to_string()),
        _ => Status::internal("source store unavailable"),
    }
}

fn sync_status(error: SyncError) -> Status {
    match error {
        SyncError::NotFound => Status::not_found("no source sync is claimable"),
        SyncError::Owner => Status::invalid_argument("runtime_id required"),
        SyncError::Store(_) => Status::internal("source store unavailable"),
        _ => Status::failed_precondition(error.to_string()),
    }
}

fn spec_from_proto(spec: ConnectorSourceSpec) -> SourceSpec {
    SourceSpec {
        connector_type: spec.connector_type,
        connector_version: spec.connector_version,
        config: spec
            .config
            .into_iter()
            .filter_map(|(name, value)| {
                let value = match value.value? {
                    source_config_value::Value::Text(text) => ConfigValue::Text(text),
                    source_config_value::Value::Integer(integer) => ConfigValue::Integer(integer),
                    source_config_value::Value::Boolean(boolean) => ConfigValue::Boolean(boolean),
                };
                Some((name, value))
            })
            .collect::<SourceConfig>(),
        credential_ref: spec.credential_ref,
        egress: spec.egress,
        placement: spec.placement.into_iter().collect(),
        every_ms: spec.every_ms,
        owner: spec.owner,
        markings: spec.markings,
        certification_id: spec.certification_id,
    }
}

fn spec_to_proto(spec: SourceSpec) -> ConnectorSourceSpec {
    ConnectorSourceSpec {
        connector_type: spec.connector_type,
        connector_version: spec.connector_version,
        config: spec
            .config
            .into_iter()
            .filter_map(|(name, value)| {
                let value = match value {
                    ConfigValue::Text(text) => source_config_value::Value::Text(text),
                    ConfigValue::Integer(integer) => source_config_value::Value::Integer(integer),
                    ConfigValue::Boolean(boolean) => source_config_value::Value::Boolean(boolean),
                    _ => return None,
                };
                Some((name, SourceConfigValue { value: Some(value) }))
            })
            .collect(),
        credential_ref: spec.credential_ref,
        egress: spec.egress,
        placement: spec.placement.into_iter().collect(),
        every_ms: spec.every_ms,
        owner: spec.owner,
        markings: spec.markings,
        certification_id: spec.certification_id,
    }
}

pub(super) fn source_to_proto(source: Source) -> ConnectorSource {
    let sync = &source.sync;
    let held = sync.claim.expires_at_ms > 0;
    let proto_sync = ConnectorSourceSync {
        last_success_at_ms: sync.last_success_at_ms,
        last_failure_at_ms: sync.last_failure_at_ms,
        last_failure: sync.last_failure.clone(),
        last_runtime: sync.last_runtime.clone(),
        claim_owner: if held {
            sync.claim.owner.clone()
        } else {
            String::new()
        },
        claim_expires_at_ms: sync.claim.expires_at_ms,
        due: source.status == SourceStatus::Active && sync.due_bucket > sync.done_bucket,
    };
    ConnectorSource {
        namespace: source.namespace,
        source_id: source.source_id,
        source: source.source,
        source_instance: source.source_instance,
        spec: Some(spec_to_proto(source.spec)),
        status: source.status.as_str().into(),
        revision: source.revision,
        created_at_ms: source.created_at_ms,
        updated_at_ms: source.updated_at_ms,
        sync: Some(proto_sync),
    }
}

fn sync_work(source: Source) -> SourceSyncWork {
    let claim = source.sync.claim.clone();
    SourceSyncWork {
        source: Some(source_to_proto(source)),
        claim_owner: claim.owner,
        claim_generation: claim.generation,
        fencing_token: claim.fencing_token,
        claim_expires_at_ms: claim.expires_at_ms,
    }
}

/// `PutSource`: creates a Source, or replaces the spec of the revision the
/// caller read and re-enables it.
pub(super) async fn put_source(
    service: &SekaiServiceImpl,
    req: Request<PutSourceRequest>,
) -> Result<Response<PutSourceResponse>, Status> {
    let namespace = req.get_ref().namespace.clone();
    source_admin(service, &req, &namespace)?;
    let input = req.into_inner();
    let request = PutSource {
        namespace,
        source_id: input.source_id,
        source: input.source,
        source_instance: input.source_instance,
        spec: spec_from_proto(
            input
                .spec
                .ok_or_else(|| Status::invalid_argument("spec is required"))?,
        ),
        expected_revision: input.expected_revision,
        now_ms: now_millis(),
    };
    let source = source::put(service.db.runtime(), &request).map_err(source_status)?;
    Ok(Response::new(PutSourceResponse {
        source: Some(source_to_proto(source)),
    }))
}

pub(super) async fn get_source(
    service: &SekaiServiceImpl,
    req: Request<GetSourceRequest>,
) -> Result<Response<GetSourceResponse>, Status> {
    let namespace = req.get_ref().namespace.clone();
    source_reader(service, &req, &namespace)?;
    let source = service
        .db
        .runtime()
        .get_source(&namespace, &req.get_ref().source_id)
        .map_err(|_| Status::internal("source store unavailable"))?
        .ok_or_else(|| Status::not_found("source not found"))?;
    Ok(Response::new(GetSourceResponse {
        source: Some(source_to_proto(source)),
    }))
}

pub(super) async fn list_sources(
    service: &SekaiServiceImpl,
    req: Request<ListSourcesRequest>,
) -> Result<Response<ListSourcesResponse>, Status> {
    let namespace = req.get_ref().namespace.clone();
    source_reader(service, &req, &namespace)?;
    let input = req.into_inner();
    let limit = match usize::try_from(input.limit) {
        Ok(0) | Err(_) => 50,
        Ok(limit) => limit.min(source::MAX_LIST_SOURCES),
    };
    let sources = service
        .db
        .runtime()
        .list_sources(&namespace, &input.page_token, limit)
        .map_err(|_| Status::internal("source store unavailable"))?;
    let next_page_token = match sources.last() {
        Some(last) if sources.len() == limit => last.source_id.clone(),
        _ => String::new(),
    };
    Ok(Response::new(ListSourcesResponse {
        sources: sources.into_iter().map(source_to_proto).collect(),
        next_page_token,
    }))
}

/// `DisableSource`: stops the Source's work and raises the generation of
/// its live claims. Idempotent.
pub(super) async fn disable_source(
    service: &SekaiServiceImpl,
    req: Request<DisableSourceRequest>,
) -> Result<Response<DisableSourceResponse>, Status> {
    let namespace = req.get_ref().namespace.clone();
    source_admin(service, &req, &namespace)?;
    let source = source::disable(
        service.db.runtime(),
        &namespace,
        &req.get_ref().source_id,
        now_millis(),
    )
    .map_err(source_status)?;
    Ok(Response::new(DisableSourceResponse {
        source: Some(source_to_proto(source)),
    }))
}

impl SekaiServiceImpl {
    /// The caller may run sync work in `namespace`: what claiming transform
    /// work needs.
    fn source_sync_runtime<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
    ) -> Result<(), Status> {
        let principals = caller_principals(req);
        require_authenticated(&principals)?;
        require_credential_admin(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), req)?;
        check_team_namespace(self.db.runtime(), &principals, namespace, true)?;
        match tenant_context.as_ref() {
            Some(context) => {
                enforce_namespace_tenant_context(self.db.runtime(), Some(context), namespace, true)
            }
            None => Ok(()),
        }
    }

    fn runtime_labels(
        &self,
        namespace: &str,
        runtime_id: &str,
    ) -> Result<std::collections::BTreeMap<String, String>, Status> {
        self.db
            .runtime()
            .registered_runtime_labels(namespace, runtime_id)
            .map_err(|_| Status::internal("runtime labels unavailable"))
    }

    pub(super) fn list_claimable_source_syncs<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
        runtime_id: &str,
        limit: i32,
    ) -> Result<Vec<ConnectorSource>, Status> {
        self.source_sync_runtime(req, namespace)?;
        let labels = self.runtime_labels(namespace, runtime_id)?;
        let limit = usize::try_from(limit)
            .ok()
            .filter(|limit| *limit > 0)
            .unwrap_or(50)
            .min(source::MAX_LIST_SOURCES);
        Ok(
            source_sync::list_claimable(self.db.runtime(), namespace, &labels, now_millis(), limit)
                .map_err(|_| Status::internal("source store unavailable"))?
                .into_iter()
                .map(source_to_proto)
                .collect(),
        )
    }

    pub(super) fn claim_source_sync<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
        runtime_id: &str,
        source_id: &str,
        ttl_ms: i64,
    ) -> Result<SourceSyncWork, Status> {
        self.source_sync_runtime(req, namespace)?;
        if runtime_id.trim().is_empty() {
            return Err(Status::invalid_argument("runtime_id required"));
        }
        let labels = self.runtime_labels(namespace, runtime_id)?;
        let db = self.db.runtime();
        let now = now_millis();
        let claimed = if source_id.is_empty() {
            source_sync::claim_next(db, namespace, runtime_id, &labels, ttl_ms, now)
        } else {
            source_sync::claim(db, namespace, source_id, runtime_id, &labels, ttl_ms, now)
        };
        claimed.map(sync_work).map_err(sync_status)
    }

    pub(super) fn heartbeat_source_sync<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
        source_id: &str,
        fence: Fence<'_>,
        ttl_ms: i64,
    ) -> Result<SourceSyncWork, Status> {
        self.source_sync_runtime(req, namespace)?;
        source_sync::heartbeat(
            self.db.runtime(),
            namespace,
            source_id,
            fence,
            ttl_ms,
            now_millis(),
        )
        .map(sync_work)
        .map_err(sync_status)
    }

    /// `AckWork` for a Source sync: `completed`, or `failed` with the
    /// failure class as reason.
    pub(super) fn ack_source_sync<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
        source_id: &str,
        fence: Fence<'_>,
        outcome: &str,
        reason: &str,
    ) -> Result<ConnectorSource, Status> {
        self.source_sync_runtime(req, namespace)?;
        let outcome = match outcome {
            "completed" => SyncOutcome::Completed,
            "failed" => match SyncFailure::from_wire_name(reason) {
                Some(SyncFailure::LeaseExpired) | None => {
                    return Err(Status::invalid_argument(
                        "a failed source sync names its failure class as reason",
                    ));
                }
                Some(failure) => SyncOutcome::Failed(failure),
            },
            _ => {
                return Err(Status::invalid_argument(
                    "source sync is acknowledged as completed or failed",
                ));
            }
        };
        source_sync::acknowledge(
            self.db.runtime(),
            namespace,
            source_id,
            fence,
            outcome,
            now_millis(),
        )
        .map(source_to_proto)
        .map_err(|error| match error {
            SyncError::Claim(ClaimError::FenceLost) => {
                Status::failed_precondition("claim is not current")
            }
            error => sync_status(error),
        })
    }
}
