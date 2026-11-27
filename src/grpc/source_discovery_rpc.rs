//! Source discovery (#3091): `RequestSourceDiscovery` and
//! `GetSourceDiscovery`, plus the `source_discovery` kind of the
//! claimable-work family (ADR 0149).
//!
//! Requesting and reading need a namespace administrator, as putting a
//! Source does. Only the requester reads a request back, and reading a
//! finished one deletes it. Sample cells are source data: they are returned
//! only to a caller cleared for every marking on the Source, judged when the
//! result is read, and withheld with a reason otherwise. A runtime claims
//! the work as it claims Source sync work, under the Source's placement.
//! The plane audits each sample's row count, never its cells, before it
//! accepts the result.

use super::connector_credential_rpc;
use super::rpc_actions::cleared_for_marking;
use super::source_rpc::{source_admin, source_to_proto};
use super::*;
use crate::sekai::source::{self, Source};
use crate::sekai::source_discovery::{
    self as discovery, DiscoveryError, DiscoveryOutcome, SampledRecordKind, SourceDiscoveryRequest,
};
use crate::sekai::source_sync::SyncFailure;
use crate::sekai::work_claim::{ClaimError, Fence};
use sekai_source_sdk::DiscoverySample;

const SAMPLES_WITHHELD: &str = "the caller is not cleared for every marking on the source";

fn discovery_status(error: DiscoveryError) -> Status {
    match error {
        DiscoveryError::NotFound => Status::not_found(error.to_string()),
        DiscoveryError::SourceDisabled => Status::failed_precondition(error.to_string()),
        DiscoveryError::Owner | DiscoveryError::Invalid(_) => {
            Status::invalid_argument(error.to_string())
        }
        DiscoveryError::Placement => Status::permission_denied(error.to_string()),
        DiscoveryError::Claim(ClaimError::FenceLost) => {
            Status::failed_precondition("claim is not current")
        }
        DiscoveryError::Claim(ClaimError::Held) => Status::aborted(error.to_string()),
        DiscoveryError::Claim(_) => Status::failed_precondition(error.to_string()),
        _ => Status::internal("source discovery store unavailable"),
    }
}

/// The caller's principal, once it may administer Sources in `namespace`.
fn discovery_admin<T: std::any::Any>(
    service: &SekaiServiceImpl,
    req: &Request<T>,
    namespace: &str,
) -> Result<String, Status> {
    source_admin(service, req, namespace)?;
    caller_principals(req)
        .into_iter()
        .next()
        .ok_or_else(|| Status::unauthenticated("principal required"))
}

pub(super) async fn request_source_discovery(
    service: &SekaiServiceImpl,
    req: Request<RequestSourceDiscoveryRequest>,
) -> Result<Response<RequestSourceDiscoveryResponse>, Status> {
    let namespace = req.get_ref().namespace.clone();
    let requester = discovery_admin(service, &req, &namespace)?;
    let request = discovery::request(
        service.db.runtime(),
        &namespace,
        &req.get_ref().source_id,
        &requester,
        now_millis(),
    )
    .map_err(|error| match error {
        DiscoveryError::NotFound => Status::not_found("source not found"),
        error => discovery_status(error),
    })?;
    Ok(Response::new(RequestSourceDiscoveryResponse {
        discovery: Some(to_result(request, Ok(()))),
    }))
}

pub(super) async fn get_source_discovery(
    service: &SekaiServiceImpl,
    req: Request<GetSourceDiscoveryRequest>,
) -> Result<Response<GetSourceDiscoveryResponse>, Status> {
    let namespace = req.get_ref().namespace.clone();
    let requester = discovery_admin(service, &req, &namespace)?;
    let db = service.db.runtime();
    // Judge clearance before the read deletes the result, so a store
    // failure here loses nothing.
    let source_id = db
        .get_source_discovery(&namespace, &req.get_ref().discovery_id)
        .map_err(|_| Status::internal("source discovery store unavailable"))?
        .filter(|request| request.requested_by == requester)
        .ok_or_else(|| Status::not_found("source discovery not found"))?
        .source_id;
    let cleared = cleared_for_source(service, &caller_principals(&req), &namespace, &source_id)?;
    let request = discovery::take(
        db,
        &namespace,
        &req.get_ref().discovery_id,
        &requester,
        now_millis(),
    )
    .map_err(discovery_status)?;
    Ok(Response::new(GetSourceDiscoveryResponse {
        discovery: Some(to_result(
            request,
            if cleared {
                Ok(())
            } else {
                Err(SAMPLES_WITHHELD)
            },
        )),
    }))
}

/// Whether `principals` are cleared for every marking on the Source. A
/// Source that is gone has nothing left to clear against, so its samples
/// are withheld.
fn cleared_for_source(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
    source_id: &str,
) -> Result<bool, Status> {
    let Some(source) = service
        .db
        .runtime()
        .get_source(namespace, source_id)
        .map_err(|_| Status::internal("source store unavailable"))?
    else {
        return Ok(false);
    };
    for marking in &source.spec.markings {
        if !cleared_for_marking(service, principals, namespace, marking)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The proto form; `samples` says whether this caller gets the cells.
fn to_result(
    request: SourceDiscoveryRequest,
    samples: Result<(), &'static str>,
) -> SourceDiscoveryResult {
    let completed = request.status == discovery::STATUS_COMPLETED;
    let (samples, samples_withheld_reason) = match samples {
        _ if !completed => (Vec::new(), String::new()),
        Ok(()) => (
            request.samples().into_iter().map(sample_to_proto).collect(),
            String::new(),
        ),
        Err(reason) => (Vec::new(), reason.to_string()),
    };
    SourceDiscoveryResult {
        discovery_id: request.discovery_id,
        namespace: request.namespace,
        source_id: request.source_id,
        requested_by: request.requested_by,
        status: request.status,
        failure: request.failure,
        discovery_json: request.discovery_json,
        samples,
        samples_withheld_reason,
        created_at_ms: request.created_at_ms,
        finished_at_ms: request.finished_at_ms,
        expires_at_ms: request.expires_at_ms,
    }
}

fn sample_to_proto(sample: SampledRecordKind) -> SourceDiscoverySample {
    SourceDiscoverySample {
        record_kind: sample.record_kind,
        unsupported: sample.unsupported,
        rows: sample
            .rows
            .into_iter()
            .map(|cells| SourceDiscoverySampleRow {
                cells: cells.into_iter().collect(),
            })
            .collect(),
    }
}

fn sample_from_proto(sample: SourceDiscoverySample) -> SampledRecordKind {
    SampledRecordKind {
        record_kind: sample.record_kind,
        unsupported: sample.unsupported,
        rows: sample
            .rows
            .into_iter()
            .map(|row| row.cells.into_iter().collect())
            .collect(),
    }
}

fn discovery_work(request: SourceDiscoveryRequest, source: Source) -> SourceDiscoveryWork {
    SourceDiscoveryWork {
        discovery_id: request.discovery_id,
        source: Some(source_to_proto(source)),
        claim_owner: request.claim.owner,
        claim_generation: request.claim.generation,
        fencing_token: request.claim.fencing_token,
        claim_expires_at_ms: request.claim.expires_at_ms,
        credential: None,
    }
}

fn claimed_discovery_work(
    db: &RuntimeDb,
    request: SourceDiscoveryRequest,
    source: Source,
) -> Result<SourceDiscoveryWork, Status> {
    let credential = connector_credential_rpc::material_for_source(db, &source)?;
    let mut work = discovery_work(request, source);
    work.credential = credential;
    Ok(work)
}

impl SekaiServiceImpl {
    pub(super) fn list_claimable_source_discoveries<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
        runtime_id: &str,
        limit: i32,
        options: SourceDiscoveryWorkOptions,
    ) -> Result<Vec<SourceDiscoveryWork>, Status> {
        self.source_sync_runtime(req, namespace)?;
        let labels = self.runtime_labels(namespace, runtime_id)?;
        let limit = usize::try_from(limit)
            .ok()
            .filter(|limit| *limit > 0)
            .unwrap_or(50)
            .min(discovery::MAX_LIST_DISCOVERIES);
        Ok(discovery::list_claimable(
            self.db.runtime(),
            namespace,
            &labels,
            now_millis(),
            limit,
            implements(&options.connector_types),
        )
        .map_err(|_| Status::internal("source discovery store unavailable"))?
        .into_iter()
        .map(|(request, source)| discovery_work(request, source))
        .collect())
    }

    pub(super) fn claim_source_discovery<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
        runtime_id: &str,
        discovery_id: &str,
        ttl_ms: i64,
    ) -> Result<SourceDiscoveryWork, Status> {
        self.source_sync_runtime(req, namespace)?;
        if runtime_id.trim().is_empty() {
            return Err(Status::invalid_argument("runtime_id required"));
        }
        let labels = self.runtime_labels(namespace, runtime_id)?;
        let db = self.db.runtime();
        let now = now_millis();
        let claimed = if discovery_id.is_empty() {
            discovery::claim_next(db, namespace, runtime_id, &labels, ttl_ms, now, |_| true)
        } else {
            discovery::claim(
                db,
                namespace,
                discovery_id,
                runtime_id,
                &labels,
                ttl_ms,
                now,
            )
        };
        claimed
            .map_err(discovery_status)
            .and_then(|(request, source)| claimed_discovery_work(db, request, source))
    }

    pub(super) fn heartbeat_source_discovery<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
        discovery_id: &str,
        fence: Fence<'_>,
        ttl_ms: i64,
    ) -> Result<SourceDiscoveryWork, Status> {
        self.source_sync_runtime(req, namespace)?;
        let request = discovery::heartbeat(
            self.db.runtime(),
            namespace,
            discovery_id,
            fence,
            ttl_ms,
            now_millis(),
        )
        .map_err(discovery_status)?;
        self.with_source(request)
    }

    fn with_source(&self, request: SourceDiscoveryRequest) -> Result<SourceDiscoveryWork, Status> {
        let source = self
            .db
            .runtime()
            .get_source(&request.namespace, &request.source_id)
            .map_err(|_| Status::internal("source store unavailable"))?
            .ok_or_else(|| Status::not_found("source not found"))?;
        Ok(discovery_work(request, source))
    }

    /// `AckWork` for a Source discovery: `completed` with the result, or
    /// `failed` with a failure class as reason. A completed result's
    /// samples are audited first, by row count, under the requester.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn ack_source_discovery<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
        discovery_id: &str,
        fence: Fence<'_>,
        outcome: &str,
        reason: &str,
        result: Option<SourceDiscoveryAckOptions>,
    ) -> Result<SourceDiscoveryWork, Status> {
        self.source_sync_runtime(req, namespace)?;
        let outcome = match (outcome, result) {
            ("completed", Some(result)) => DiscoveryOutcome::Completed {
                discovery_json: result.discovery_json,
                samples: result.samples.into_iter().map(sample_from_proto).collect(),
            },
            ("failed", None) => match SyncFailure::from_wire_name(reason) {
                Some(SyncFailure::LeaseExpired) | None => {
                    return Err(Status::invalid_argument(
                        "a failed source discovery names its failure class as reason",
                    ));
                }
                Some(failure) => DiscoveryOutcome::Failed(failure),
            },
            _ => {
                return Err(Status::invalid_argument(
                    "source discovery is acknowledged as completed with its result, or failed",
                ));
            }
        };
        let db = self.db.runtime();
        let now = now_millis();
        let current = db
            .get_source_discovery(namespace, discovery_id)
            .map_err(|_| Status::internal("source discovery store unavailable"))?
            .ok_or_else(|| Status::not_found("source discovery not found"))?;
        if let DiscoveryOutcome::Completed { samples, .. } = &outcome
            && current.claim.is_current(current.hold(), fence)
        {
            for sample in samples {
                let audited = if sample.unsupported {
                    DiscoverySample::Unsupported
                } else {
                    DiscoverySample::Rows {
                        cells: sample.rows.clone(),
                    }
                };
                source::record_source_discovery_sample(
                    db,
                    &current.requested_by,
                    namespace,
                    &current.source_id,
                    &sample.record_kind,
                    &audited,
                    now,
                )
                .map_err(|_| Status::internal("audit unavailable"))?;
            }
        }
        let (request, _) = discovery::acknowledge(db, namespace, discovery_id, fence, outcome, now)
            .map_err(discovery_status)?;
        self.with_source(request)
    }
}

/// Whether a Source is of one of `types` (empty means any).
fn implements(types: &[ConnectorTypeRef]) -> impl Fn(&Source) -> bool + '_ {
    move |source| {
        types.is_empty()
            || types.iter().any(|ty| {
                ty.name == source.spec.connector_type && ty.version == source.spec.connector_version
            })
    }
}

/// Trait routes for the facade's `delegate_rpcs!` list.
impl SekaiServiceImpl {
    pub(super) async fn request_source_discovery_rpc(
        &self,
        req: Request<RequestSourceDiscoveryRequest>,
    ) -> Result<Response<RequestSourceDiscoveryResponse>, Status> {
        request_source_discovery(self, req).await
    }
    pub(super) async fn get_source_discovery_rpc(
        &self,
        req: Request<GetSourceDiscoveryRequest>,
    ) -> Result<Response<GetSourceDiscoveryResponse>, Status> {
        get_source_discovery(self, req).await
    }
}
