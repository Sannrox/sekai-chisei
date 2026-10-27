//! Install and run Ezu geofence-event bindings (#1564, ADR 0121).

use super::action_binding::{BoundAction, load_bound_objects};
use super::*;
use crate::sekai::fence_binding::{
    FENCE_RUN_LEASE_MS, FenceBinding, FenceEvent, FenceEventId, FenceEventPage, FenceEventReceipt,
    FenceParameterSource, SKIP_OBJECT_UNAVAILABLE, event_lag_ms,
};
use std::collections::{HashMap, HashSet};
use std::future::Future;

const FENCE_BINDING_UNAVAILABLE: &str = "fence binding unavailable";
/// Address of the Ezu service fence bindings read from.
pub(crate) const EZU_URL_ENV: &str = "SEKAI_EZU_URL";
const EZU_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Where a run reads fence events: one page after `after`, as the Ezu
/// namespace `token` maps to.
pub(crate) trait FenceEventSource {
    fn read_events(
        &self,
        token: &str,
        after: Option<FenceEventId>,
        fences: &[String],
        limit: u32,
    ) -> impl Future<Output = Result<FenceEventPage, Status>> + Send;
}

/// Ezu's `GET /v1/events`.
pub(crate) struct EzuHttp {
    base_url: String,
    client: reqwest::Client,
}

impl EzuHttp {
    pub(crate) fn from_env() -> Result<Self, Status> {
        let base_url = std::env::var(EZU_URL_ENV)
            .ok()
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| Status::failed_precondition("Ezu is not configured"))?;
        let client = reqwest::Client::builder()
            .timeout(EZU_READ_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Status::internal("Ezu client unavailable"))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }
}

impl FenceEventSource for EzuHttp {
    fn read_events(
        &self,
        token: &str,
        after: Option<FenceEventId>,
        fences: &[String],
        limit: u32,
    ) -> impl Future<Output = Result<FenceEventPage, Status>> + Send {
        let mut query = vec![("limit".to_string(), limit.to_string())];
        if let Some((lsn, index)) = after {
            query.push(("after_lsn".into(), lsn.to_string()));
            query.push(("after_index".into(), index.to_string()));
        }
        query.extend(fences.iter().map(|fence| ("fence".into(), fence.clone())));
        let request = self
            .client
            .get(format!("{}/v1/events", self.base_url))
            .bearer_auth(token)
            .query(&query);
        async move {
            let response = request
                .send()
                .await
                .map_err(|_| Status::unavailable("Ezu unavailable"))?;
            let status = response.status();
            if status.is_server_error() {
                return Err(Status::unavailable("Ezu unavailable"));
            }
            if !status.is_success() {
                // A resume point past Ezu's retention, or a refused token:
                // nothing a retry fixes, so the run fails visibly.
                return Err(Status::failed_precondition(format!(
                    "Ezu refused the event read ({})",
                    status.as_u16()
                )));
            }
            response
                .json::<FenceEventPage>()
                .await
                .map_err(|_| Status::unavailable("Ezu answered an unreadable event page"))
        }
    }
}

impl SekaiServiceImpl {
    pub(super) async fn put_fence_binding_definition(
        &self,
        req: Request<PutFenceBindingRequest>,
    ) -> Result<Response<PutFenceBindingResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let binding: FenceBinding = serde_json::from_str(&req.into_inner().binding_json)
            .map_err(|error| Status::invalid_argument(format!("binding_json: {error}")))?;
        binding.validate().map_err(Status::invalid_argument)?;
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &binding.namespace,
            true,
        )?;
        // Installing unattended writes is a namespace-administration act.
        let actor = authorize_source_type_namespace_admin(self, &principals, &binding.namespace)?;
        self.check_bound_action(
            &binding.namespace,
            &binding.type_id,
            &binding.version,
            &binding.run_as,
            &binding.parameters.keys().cloned().collect::<Vec<_>>(),
        )?;
        self.check_binding_markings(&binding.namespace, &binding.markings)?;
        let stored = self
            .db
            .runtime()
            .put_fence_binding(&binding, &actor, now_millis())
            .map_err(map_fence_store_error)?;
        Ok(Response::new(PutFenceBindingResponse {
            binding_json: serde_json::to_string(&stored)
                .map_err(|error| Status::internal(error.to_string()))?,
            revision: stored.revision,
        }))
    }

    pub(super) async fn run_fence_binding_once(
        &self,
        req: Request<RunFenceBindingRequest>,
    ) -> Result<Response<RunFenceBindingResponse>, Status> {
        self.run_fence_binding_with(req, &EzuHttp::from_env()?)
            .await
    }

    /// Reads one bounded page of fence events after the binding's cursor
    /// and submits one Action per bound event as its service principal.
    /// The cursor moves, with every event's receipt, only after all
    /// submits; a crash before that rereads the page, and event-derived
    /// idempotency keys make those resubmits replays.
    pub(super) async fn run_fence_binding_with(
        &self,
        req: Request<RunFenceBindingRequest>,
        source: &impl FenceEventSource,
    ) -> Result<Response<RunFenceBindingResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let input = req.into_inner();
        let (binding, _) = self
            .db
            .runtime()
            .get_fence_binding(input.namespace.trim(), input.binding_id.trim())
            .map_err(map_fence_store_error)?
            .ok_or_else(|| Status::not_found(FENCE_BINDING_UNAVAILABLE))?;
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &binding.namespace,
            true,
        )?;
        let caller_runs_binding = principals
            .iter()
            .any(|principal| principal == &binding.run_as);
        if !caller_runs_binding
            && authorize_source_type_namespace_admin(self, &principals, &binding.namespace).is_err()
        {
            return Err(Status::permission_denied(FENCE_BINDING_UNAVAILABLE));
        }
        if !binding.enabled {
            return Err(Status::failed_precondition("fence binding is disabled"));
        }
        let (caller_tenant, resource_tenant) = self.prepare_bound_run(
            tenant_context.as_ref(),
            &binding.namespace,
            &binding.run_as,
            &binding.type_id,
        )?;
        // The run belongs to the binding, not the caller: the service
        // principal's registered tenant picks the Ezu bearer and admits the
        // Actions, and its freeze stops the run too.
        let tenant = crate::sekai::write_freeze::acting_or_registered_tenant(
            self.db.runtime(),
            "",
            &binding.run_as,
        )
        .map_err(Status::internal)?
        .into_owned();
        if tenant != caller_tenant {
            crate::sekai::write_freeze::refuse_if_frozen_any(
                self.db.runtime(),
                &crate::sekai::write_freeze::write_checks_for_actors(
                    &binding.namespace,
                    &tenant,
                    &binding.run_as,
                    None,
                    binding.type_id.trim(),
                    true,
                ),
            )
            .map_err(crate::grpc::write_freeze_status)?;
        }
        // One run per binding at a time, so concurrent runs cannot record
        // different outcomes for one event; reinstalls clear the lease.
        let run_id = uuid::Uuid::new_v4().to_string();
        let now = now_millis();
        if !self
            .db
            .runtime()
            .lease_fence_run(&binding, &run_id, false, now, now + FENCE_RUN_LEASE_MS)
            .map_err(map_fence_store_error)?
        {
            return Err(Status::aborted(
                "another run of this fence binding is in progress",
            ));
        }
        // Read under the lease: a run that finished between our first read
        // and taking the lease has moved it.
        let cursor = match self
            .db
            .runtime()
            .get_fence_binding(&binding.namespace, &binding.binding_id)
            .map_err(map_fence_store_error)?
        {
            Some((current, cursor)) if current.revision == binding.revision => cursor,
            _ => {
                let _ = self.db.runtime().release_fence_run(&binding, &run_id);
                return Err(Status::aborted(
                    "fence binding changed during the run; run again",
                ));
            }
        };
        let result: Result<Response<RunFenceBindingResponse>, Status> = async {
            let token = self.ezu_token(&tenant, &binding.run_as)?;
            let limit = binding.events_per_run();
            let page = source
                .read_events(&token, cursor, &binding.fences, limit)
                .await?;
            let lag_ms = event_lag_ms(&page, now_millis());
            metrics::gauge!(
                "sekai_fence_binding_lag_ms",
                "namespace" => binding.namespace.clone(),
                "binding" => binding.binding_id.clone()
            )
            .set(lag_ms as f64);

            let run_as = vec![binding.run_as.clone()];
            let object_ids = page
                .events
                .iter()
                .filter(|event| binding.unbound_reason(event).is_none())
                .map(|event| event.entity.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let property_keys = binding
                .parameters
                .values()
                .filter_map(|source| match source {
                    FenceParameterSource::Property(property) => Some(property.clone()),
                    _ => None,
                })
                .collect::<HashSet<_>>();
            let visible = load_bound_objects(
                self,
                &binding.namespace,
                &binding.kind,
                &object_ids,
                &run_as,
                &property_keys,
            )?
            .into_iter()
            .map(|object| (object.id.clone(), object))
            .collect::<HashMap<_, _>>();

            let mut receipts = Vec::with_capacity(page.events.len());
            for event in &page.events {
                let mut receipt = FenceEventReceipt {
                    lsn: event.lsn,
                    index: event.index,
                    fence: event.fence.clone(),
                    entity: event.entity.clone(),
                    kind: event.kind_name().unwrap_or_default().to_string(),
                    ..Default::default()
                };
                match self.submit_fence_event(
                    &binding,
                    &run_id,
                    event,
                    &visible,
                    &tenant,
                    &resource_tenant,
                )? {
                    Ok((instance_id, status, replay)) => {
                        receipt.instance_id = instance_id;
                        receipt.status = status;
                        receipt.replay = replay;
                    }
                    Err(reason) => receipt.skipped_reason = reason,
                }
                receipts.push(receipt);
            }
            if let Some(through) = page.through().filter(|through| Some(*through) > cursor)
                && !self
                    .db
                    .runtime()
                    .advance_fence_binding(&binding, &run_id, through, &receipts, now_millis())
                    .map_err(map_fence_store_error)?
            {
                // The lease lapsed or the binding was reinstalled before the
                // page committed: nothing of it is durable, so say so.
                return Err(Status::aborted(
                    "fence binding changed during the run; run again",
                ));
            }
            let (through_lsn, through_index) = match page.through().or(cursor) {
                Some((lsn, index)) => (Some(lsn), index),
                None => (None, 0),
            };
            Ok(Response::new(RunFenceBindingResponse {
                binding_revision: binding.revision,
                more: page.events.len() >= limit as usize,
                submissions: receipts.into_iter().map(to_proto_submission).collect(),
                through_lsn,
                through_index,
                lag_ms,
            }))
        }
        .await;
        if let Err(error) = self.db.runtime().release_fence_run(&binding, &run_id) {
            // The lease lapses on its own; the next run waits at most that long.
            tracing::warn!(error = %error, "fence binding run lease not released");
        }
        result
    }

    /// One event's outcome: the admitted instance, or why it was skipped.
    /// The outer error stops the run before the cursor moves, so the event
    /// is read again: a write freeze, an admission that failed internally or
    /// is still under way, or a run that lost its lease.
    fn submit_fence_event(
        &self,
        binding: &FenceBinding,
        run_id: &str,
        event: &FenceEvent,
        visible: &HashMap<String, domain::Object>,
        tenant: &str,
        resource_tenant: &str,
    ) -> Result<Result<(String, String, bool), String>, Status> {
        if let Some(reason) = binding.unbound_reason(event) {
            return Ok(Err(reason.into()));
        }
        let idempotency_key = binding
            .idempotency_key(event)
            .map_err(|_| Status::internal("fence event key unavailable"))?;
        // Renewed per event: a reinstall or disable (which bumps the
        // revision and clears the lease) stops an in-flight run at its next
        // submit, and a run that lost its lease submits nothing more.
        let now = now_millis();
        if !self
            .db
            .runtime()
            .lease_fence_run(binding, run_id, true, now, now + FENCE_RUN_LEASE_MS)
            .map_err(map_fence_store_error)?
        {
            return Err(Status::aborted(
                "fence binding changed during the run; run again",
            ));
        }
        // An event already admitted replays exactly as it was admitted, even
        // if the binding was reinstalled or its object changed since. One not
        // yet admitted is built fresh, under the current binding and grants.
        let admitted = self
            .db
            .runtime()
            .get_action_instance_by_idempotency(&binding.namespace, &idempotency_key)
            .map_err(Status::internal)?;
        let (type_id, version, parameters_json) = match admitted {
            Some(existing) => (existing.type_id, existing.version, existing.parameters_json),
            None => {
                let Some(object) = visible.get(&event.entity) else {
                    return Ok(Err(SKIP_OBJECT_UNAVAILABLE.into()));
                };
                match binding.parameters_for(event, object) {
                    Ok(parameters) => {
                        (binding.type_id.clone(), binding.version.clone(), parameters)
                    }
                    Err(reason) => return Ok(Err(reason.into())),
                }
            }
        };
        let markings =
            super::action_binding::snapshot_markings(&binding.markings, visible.get(&event.entity));
        match self.admit_bound_action(
            BoundAction {
                namespace: &binding.namespace,
                markings: &markings,
                source_object_id: &event.entity,
                type_id: &type_id,
                version: &version,
                run_as: &binding.run_as,
                parameters_json,
                idempotency_key,
            },
            tenant,
            resource_tenant,
        ) {
            Ok(admitted) => Ok(Ok(admitted)),
            Err(reason) => {
                if let Some(freeze) = reason
                    .strip_prefix("failed_precondition: ")
                    .filter(|reason| reason.contains("write freeze"))
                {
                    return Err(Status::failed_precondition(freeze.to_string()));
                }
                // Not the event's outcome yet: an admission an earlier attempt
                // left without its receipt cannot be told apart from one
                // still running, and a reservation it left under this key with
                // another request conflicts. The binding waits on either
                // visibly (the run fails, lag grows) rather than guess.
                if reason.starts_with("internal")
                    || reason.contains("still in progress")
                    || reason.starts_with("already_exists")
                {
                    return Err(Status::unavailable("action admission unavailable"));
                }
                Ok(Err(reason))
            }
        }
    }

    /// The bearer for Ezu, resolved as provider `ezu` for the binding's
    /// tenant: its own credential under an enterprise resolver, else the
    /// process `EZU_TOKEN`.
    pub(crate) fn ezu_token(&self, tenant: &str, run_as: &str) -> Result<String, Status> {
        let context = if tenant.is_empty() {
            crate::provider_credentials::community_machine_context(run_as)
        } else {
            crate::provider_credentials::tenant_context(tenant, run_as)
        };
        let credential = match self.db.runtime().enterprise_extension() {
            Some(extension) => extension.resolve_provider_credential(&context, "ezu"),
            None => crate::provider_credentials::resolve_provider_credential(None, &context, "ezu"),
        }
        .map_err(|_| Status::unavailable("Ezu credential unavailable"))?;
        let tenant_matches = credential
            .tenant_id
            .as_deref()
            .is_none_or(|credential_tenant| credential_tenant == tenant);
        if credential.provider != "ezu"
            || !tenant_matches
            || credential.secret.expose().trim().is_empty()
        {
            return Err(Status::unavailable("Ezu credential unavailable"));
        }
        Ok(credential.secret.expose().to_string())
    }
}

fn to_proto_submission(receipt: FenceEventReceipt) -> FenceBindingSubmission {
    FenceBindingSubmission {
        lsn: receipt.lsn,
        index: receipt.index,
        fence: receipt.fence,
        entity: receipt.entity,
        kind: receipt.kind,
        instance_id: receipt.instance_id,
        status: receipt.status,
        replay: receipt.replay,
        skipped_reason: receipt.skipped_reason,
    }
}

fn map_fence_store_error(error: String) -> Status {
    if error.contains("must") || error.contains("unsupported") || error.contains("invalid") {
        Status::invalid_argument(error)
    } else {
        Status::internal(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::action_policy::{ActionDecision, ActionPolicy};
    use crate::sekai::fence_binding::FENCE_BINDING_CONTRACT;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use tonic::metadata::MetadataValue;

    /// Serves `events` after the requested id; with `redeliver`, ignores the
    /// cursor, as a reread after a crash before the cursor moved would.
    struct FakeEzu {
        events: Vec<FenceEvent>,
        redeliver: bool,
        reads: Mutex<Vec<Option<FenceEventId>>>,
        /// Runs during the read, as a concurrent operator would.
        during_read: Option<Box<dyn Fn() + Send + Sync>>,
    }

    impl FenceEventSource for FakeEzu {
        fn read_events(
            &self,
            token: &str,
            after: Option<FenceEventId>,
            _fences: &[String],
            limit: u32,
        ) -> impl Future<Output = Result<FenceEventPage, Status>> + Send {
            assert_eq!(token, "ezu-fleet-token");
            self.reads.lock().unwrap().push(after);
            if let Some(during_read) = &self.during_read {
                during_read();
            }
            let from = if self.redeliver { None } else { after };
            let events = self
                .events
                .iter()
                .filter(|event| from.is_none_or(|from| event.id() > from))
                .take(limit as usize)
                .cloned()
                .collect::<Vec<_>>();
            let through = events.last().map(FenceEvent::id).or(after);
            std::future::ready(Ok(FenceEventPage {
                events,
                through_lsn: through.map(|(lsn, _)| lsn),
                through_index: through.map_or(0, |(_, index)| index),
            }))
        }
    }

    fn event(lsn: u64, entity: &str, kind: i32) -> FenceEvent {
        FenceEvent {
            lsn,
            index: 0,
            fence: "depot".into(),
            collection: "trucks".into(),
            entity: entity.into(),
            kind,
            ts_ms: 1_000,
        }
    }

    fn run_request() -> Request<RunFenceBindingRequest> {
        let mut request = Request::new(RunFenceBindingRequest {
            namespace: "fleet".into(),
            binding_id: "depot".into(),
        });
        request
            .metadata_mut()
            .insert("x-principal", MetadataValue::from_static("local"));
        request
    }

    fn setup(policy: ActionDecision) -> (Arc<RuntimeDb>, SekaiServiceImpl) {
        let db = Arc::new(RuntimeDb::memory());
        let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(
            db.clone(),
        ));
        let (_, grants) = db
            .ensure_team_namespace("fleet", "svc-dispatch", security::Role::Editor, "local")
            .unwrap();
        for grant in grants {
            svc.security.add_grant(&grant);
        }
        db.put_governed_action_type(
            crate::sekai::governed_action_type::GovernedActionType {
                namespace: "fleet".into(),
                type_id: "truck.arrive".into(),
                version: "1".into(),
                description: "Note a truck at the depot".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"truck":{"type":"string"},"event":{"type":"string"}},"required":["truck","event"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec!["notify".into()],
                enabled: true,
                ..Default::default()
            },
            "local",
            1,
        )
        .unwrap();
        let mut action_policy = ActionPolicy::allow_all("fleet");
        action_policy.default_decision = policy;
        db.upsert_action_policy(&action_policy).unwrap();
        db.create_object_with_audit(
            &domain::Object {
                id: "truck-1".into(),
                kind: "truck".into(),
                name: "truck-1".into(),
                namespace: "fleet".into(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            },
            "local",
        )
        .unwrap();
        db.put_fence_binding(
            &FenceBinding {
                contract_version: FENCE_BINDING_CONTRACT.into(),
                binding_id: "depot".into(),
                namespace: "fleet".into(),
                fences: vec!["depot".into()],
                kinds: vec!["enter".into(), "dwell".into(), "exit".into()],
                collection: "trucks".into(),
                kind: "truck".into(),
                type_id: "truck.arrive".into(),
                version: "1".into(),
                run_as: "svc-dispatch".into(),
                parameters: BTreeMap::from([
                    ("truck".into(), FenceParameterSource::ObjectId),
                    ("event".into(), FenceParameterSource::EventKind),
                ]),
                max_events_per_run: 3,
                markings: Vec::new(),
                enabled: true,
                revision: 0,
                created_by: String::new(),
                updated_at_ms: 0,
            },
            "local",
            2,
        )
        .unwrap();
        (db, svc)
    }

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[test]
    fn one_action_per_event_and_rereads_replay() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup(ActionDecision::Allow);
            let ezu = FakeEzu {
                events: vec![
                    event(1, "truck-1", 1),
                    event(2, "truck-1", 4),
                    event(3, "ghost", 1),
                    event(4, "truck-1", 2),
                ],
                redeliver: false,
                reads: Mutex::default(),
                during_read: None,
            };
            let first = block_on(svc.run_fence_binding_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert!(first.more);
            assert_eq!(first.through_lsn, Some(3));
            assert!(first.lag_ms > 0);
            let outcomes = first
                .submissions
                .iter()
                .map(|s| (s.lsn, s.kind.as_str(), s.skipped_reason.as_str()))
                .collect::<Vec<_>>();
            assert_eq!(
                outcomes,
                [
                    (1, "enter", ""),
                    (2, "dwell", ""),
                    (3, "enter", SKIP_OBJECT_UNAVAILABLE)
                ]
            );
            assert!(
                first.submissions[..2]
                    .iter()
                    .all(|s| !s.instance_id.is_empty())
            );
            let second = block_on(svc.run_fence_binding_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert_eq!(second.submissions.len(), 1);
            assert_eq!(second.submissions[0].kind, "exit");
            assert_eq!(*ezu.reads.lock().unwrap(), [None, Some((3, 0))]);
            let receipts = db.list_fence_binding_receipts("fleet", "depot").unwrap();
            assert_eq!(
                receipts.iter().map(|r| r.lsn).collect::<Vec<_>>(),
                [1, 2, 3, 4]
            );

            // A reread of the whole stream, as after a crash before the
            // cursor moved, admits nothing new and keeps the instances even
            // though the object is gone by now.
            db.delete_object("truck-1").unwrap();
            let rereading = FakeEzu {
                redeliver: true,
                ..ezu
            };
            let reread = block_on(svc.run_fence_binding_with(run_request(), &rereading))
                .unwrap()
                .into_inner();
            let instance_ids = |submissions: &[FenceBindingSubmission]| {
                submissions
                    .iter()
                    .map(|s| s.instance_id.clone())
                    .collect::<Vec<_>>()
            };
            assert!(reread.submissions[..2].iter().all(|s| s.replay));
            assert_eq!(
                instance_ids(&reread.submissions[..2]),
                instance_ids(&first.submissions[..2])
            );
            assert_eq!(
                db.list_fence_binding_receipts("fleet", "depot").unwrap(),
                receipts
            );
        });
    }

    #[test]
    fn a_reinstall_during_the_read_stops_the_run_before_any_submit() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup(ActionDecision::Allow);
            let (stored, _) = db.get_fence_binding("fleet", "depot").unwrap().unwrap();
            let reinstall = db.clone();
            let ezu = FakeEzu {
                events: vec![event(1, "truck-1", 1)],
                redeliver: false,
                reads: Mutex::default(),
                during_read: Some(Box::new(move || {
                    reinstall.put_fence_binding(&stored, "local", 3).unwrap();
                })),
            };
            let refused = block_on(svc.run_fence_binding_with(run_request(), &ezu)).unwrap_err();
            assert_eq!(refused.code(), tonic::Code::Aborted);
            assert!(
                db.list_fence_binding_receipts("fleet", "depot")
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                db.get_fence_binding("fleet", "depot").unwrap().unwrap().1,
                None
            );
        });
    }

    #[test]
    fn an_approval_policy_parks_every_bound_action() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (_, svc) = setup(ActionDecision::RequireApproval);
            let ezu = FakeEzu {
                events: vec![event(1, "truck-1", 1)],
                redeliver: false,
                reads: Mutex::default(),
                during_read: None,
            };
            let run = block_on(svc.run_fence_binding_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert_eq!(run.submissions[0].status, "parked");
            assert!(!run.more);
        });
    }

    /// A sealed clearance profile for `principal`, as markings read it.
    fn clear(db: &RuntimeDb, principal: &str, ceiling: &str) {
        use crate::sekai::markings;
        let id = format!("principal-{principal}");
        db.create_object(&domain::Object {
            id: id.clone(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: principal.into(),
            namespace: "fleet".into(),
            external_id: markings::principal_profile_external_id(principal),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    ceiling.into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_grant(&security::Grant {
            id: format!("profile-admin-{principal}"),
            object_id: id,
            principal: "root".into(),
            role: security::Role::Admin,
            created: 1,
            ..Default::default()
        })
        .unwrap();
    }

    #[test]
    fn a_marked_object_marks_its_action_and_hides_it_from_the_uncleared() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup(ActionDecision::Allow);
            let mut truck = db.get_object("truck-1").unwrap().unwrap();
            truck.properties.insert(
                crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "confidential".into(),
            );
            db.update_object_with_audit(&truck, "local").unwrap();
            // The service principal must be able to read what it acts on.
            clear(&db, "svc-dispatch", "confidential");
            let (mut binding, _) = db.get_fence_binding("fleet", "depot").unwrap().unwrap();
            binding.markings = vec!["internal".into()];
            db.put_fence_binding(&binding, "local", 3).unwrap();
            let ezu = FakeEzu {
                events: vec![event(1, "truck-1", 1)],
                redeliver: false,
                reads: Mutex::default(),
                during_read: None,
            };
            let run = block_on(svc.run_fence_binding_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            let instance_id = run.submissions[0].instance_id.clone();
            assert!(!instance_id.is_empty(), "{:?}", run.submissions[0]);
            // The join of the object's confidential and the binding's internal.
            let instance = db.get_action_instance(&instance_id).unwrap().unwrap();
            assert_eq!(instance.marking, "confidential");

            // A namespace admin entitled to the instance, but not cleared.
            let (_, grants) = db
                .ensure_team_namespace("fleet", "auditor", security::Role::Admin, "local")
                .unwrap();
            for grant in grants {
                svc.security.add_grant(&grant);
            }
            svc.security.add_grant(&security::Grant {
                id: "auditor-actions".into(),
                object_id: "action:governed_action:fleet".into(),
                principal: "auditor".into(),
                role: security::Role::Admin,
                created: 1,
                ..Default::default()
            });
            let read = |principal: &'static str| {
                let mut request = Request::new(GetActionInstanceRequest {
                    instance_id: instance_id.clone(),
                    ..Default::default()
                });
                request
                    .metadata_mut()
                    .insert("x-principal", MetadataValue::from_static(principal));
                block_on(svc.get_action_instance(request))
            };
            let hidden = read("auditor").unwrap_err();
            assert_eq!(hidden.code(), tonic::Code::NotFound, "{hidden:?}");
            clear(&db, "auditor", "confidential");
            let shown = read("auditor").unwrap().into_inner().instance.unwrap();
            assert_eq!(shown.marking, "confidential");
        });
    }

    #[test]
    fn a_binding_with_markings_the_lattice_does_not_know_is_refused() {
        let (db, svc) = setup(ActionDecision::Allow);
        assert!(
            svc.check_binding_markings("fleet", &["internal".into()])
                .is_ok()
        );
        assert_eq!(
            svc.check_binding_markings("fleet", &["ultra-secret".into()])
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        drop(db);
    }
}
