use super::*;

pub(super) async fn create_contention_scope(
    service: &SekaiServiceImpl,
    req: Request<CreateContentionScopeRequest>,
) -> Result<Response<CreateContentionScopeResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    if is_managed_team_principal(&service.db, &principals)? {
        return Err(Status::permission_denied(
            "managed team principals cannot create global contention scopes",
        ));
    }
    let inner = req.into_inner();
    let mut scope = inner
        .scope
        .ok_or(Status::invalid_argument("scope required"))
        .map(|scope| from_proto_contention_scope(&scope))?;
    let owner = principals
        .first()
        .cloned()
        .ok_or(Status::unauthenticated("principal required"))?;
    if let Some(existing) = service
        .db
        .get_dedup_request(&inner.request_id, "create_contention_scope")
        .map_err(Status::internal)?
        .filter(|record| record.principal == owner)
    {
        let scope = service
            .db
            .get_contention_scope(&existing.scope_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        return Ok(Response::new(CreateContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }));
    }
    if scope.owner_principal.is_empty() {
        scope.owner_principal = owner;
    }
    service
        .db
        .create_contention_scope(&scope)
        .map_err(Status::invalid_argument)?;
    service
        .db
        .record_dedup_request(&coordination::RequestDedup {
            request_id: inner.request_id,
            operation: "create_contention_scope".into(),
            principal: dedup_principal(&principals),
            scope_id: scope.id.clone(),
            work_unit_id: String::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
        })
        .map_err(Status::internal)?;
    Ok(Response::new(CreateContentionScopeResponse {
        scope: Some(to_proto_contention_scope(&scope)),
    }))
}
pub(super) async fn update_contention_scope(
    service: &SekaiServiceImpl,
    req: Request<UpdateContentionScopeRequest>,
) -> Result<Response<UpdateContentionScopeResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let scope = inner
        .scope
        .ok_or(Status::invalid_argument("scope required"))
        .map(|scope| from_proto_contention_scope(&scope))?;
    let existing = service
        .db
        .get_contention_scope(&scope.id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("scope not found"))?;
    check_scope_write(&existing, &principals)?;
    if let Some(record) = service
        .db
        .get_dedup_request(&inner.request_id, "update_contention_scope")
        .map_err(Status::internal)?
    {
        if record.scope_id == scope.id && record.principal == dedup_principal(&principals) {
            let scope = service
                .db
                .get_contention_scope(&scope.id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            return Ok(Response::new(UpdateContentionScopeResponse {
                scope: Some(to_proto_contention_scope(&scope)),
            }));
        }
    }
    service
        .db
        .update_contention_scope(&scope)
        .map_err(Status::invalid_argument)?;
    service
        .db
        .record_dedup_request(&coordination::RequestDedup {
            request_id: inner.request_id,
            operation: "update_contention_scope".into(),
            principal: dedup_principal(&principals),
            scope_id: scope.id.clone(),
            work_unit_id: String::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
        })
        .map_err(Status::internal)?;
    Ok(Response::new(UpdateContentionScopeResponse {
        scope: Some(to_proto_contention_scope(&scope)),
    }))
}
pub(super) async fn get_contention_scope(
    service: &SekaiServiceImpl,
    req: Request<GetContentionScopeRequest>,
) -> Result<Response<GetContentionScopeResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let scope = service
        .db
        .get_contention_scope(&req.into_inner().id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("scope not found"))?;
    check_scope_read(&scope, &principals)?;
    Ok(Response::new(GetContentionScopeResponse {
        scope: Some(to_proto_contention_scope(&scope)),
    }))
}
pub(super) async fn list_contention_scopes(
    service: &SekaiServiceImpl,
    req: Request<ListContentionScopesRequest>,
) -> Result<Response<ListContentionScopesResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let scopes = service
        .db
        .list_contention_scopes()
        .map_err(Status::internal)?
        .into_iter()
        .filter(|scope| check_scope_read(scope, &principals).is_ok())
        .map(|scope| to_proto_contention_scope(&scope))
        .collect();
    Ok(Response::new(ListContentionScopesResponse { scopes }))
}
pub(super) async fn create_work_unit(
    service: &SekaiServiceImpl,
    req: Request<CreateWorkUnitRequest>,
) -> Result<Response<CreateWorkUnitResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let work_unit = inner
        .work_unit
        .ok_or(Status::invalid_argument("work_unit required"))
        .map(|work_unit| from_proto_work_unit(&work_unit))?;
    let principal = principals
        .first()
        .cloned()
        .ok_or(Status::unauthenticated("principal required"))?;
    let work_unit = WorkUnitLifecycle::new(&service.db)
        .create(
            CreateWorkUnit {
                work_unit,
                request_id: &inner.request_id,
                principal: &principal,
                now_ms: chrono::Utc::now().timestamp_millis(),
            },
            |target| match target {
                CreateAuthorizationTarget::IdempotencyReplay(existing) => {
                    check_work_unit_read(&service.db, &service.security, existing, &principals)
                }
                CreateAuthorizationTarget::New(candidate) => {
                    if !candidate.target_object_id.is_empty() {
                        check_object_namespace_access(
                            &service.db,
                            &principals,
                            &candidate.target_object_id,
                            true,
                        )?;
                        check_write(&service.security, &candidate.target_object_id, &principals)?;
                    } else if is_managed_team_principal(&service.db, &principals)? {
                        return Err(Status::permission_denied(
                            "team work units require a namespace-bound target object",
                        ));
                    }
                    let scope = service
                        .db
                        .get_contention_scope(&candidate.scope_id)
                        .map_err(Status::internal)?
                        .ok_or(Status::not_found("scope not found"))?;
                    check_scope_read(&scope, &principals)
                }
            },
        )
        .map_err(|error| match error {
            CreateWorkUnitError::Authorization(status) => status,
            CreateWorkUnitError::Lifecycle(error) => map_work_unit_lifecycle_error(error),
        })?;
    Ok(Response::new(CreateWorkUnitResponse {
        work_unit: Some(to_proto_work_unit(&work_unit)),
    }))
}
pub(super) async fn get_work_unit(
    service: &SekaiServiceImpl,
    req: Request<GetWorkUnitRequest>,
) -> Result<Response<GetWorkUnitResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let work_unit = service
        .db
        .get_work_unit(&req.into_inner().id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("work unit not found"))?;
    check_work_unit_read(&service.db, &service.security, &work_unit, &principals)?;
    Ok(Response::new(GetWorkUnitResponse {
        work_unit: Some(to_proto_work_unit(&work_unit)),
    }))
}
pub(super) async fn list_work_units(
    service: &SekaiServiceImpl,
    req: Request<ListWorkUnitsRequest>,
) -> Result<Response<ListWorkUnitsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let filter = req.into_inner().filter.unwrap_or_default();
    let limit = filter.limit;
    let mut work_units = if limit > 0 {
        // Paginate over *visible* rows. A single storage page can be mostly
        // invisible after ACL filtering; continue the cursor scan so a short
        // visible page does not look like end-of-storage.
        let visible_limit = limit as usize;
        let batch_size = visible_limit.clamp(50, 200);
        let max_scan = visible_limit.saturating_mul(10).max(200);
        let mut visible = Vec::with_capacity(visible_limit.saturating_add(1).min(batch_size));
        let mut scanned = 0usize;
        let mut page_token = filter.page_token.clone();
        while visible.len() <= visible_limit && scanned < max_scan {
            let mut batch_filter = from_proto_work_unit_filter(&filter);
            batch_filter.limit = batch_size as i32;
            batch_filter.offset = 0;
            batch_filter.page_token = if page_token.is_empty() {
                None
            } else {
                Some(page_token.clone())
            };
            let batch = service
                .db
                .list_work_units(&batch_filter)
                .map_err(Status::internal)?;
            if batch.is_empty() {
                break;
            }
            // DB returns limit+1 when more raw rows may exist.
            let has_more_raw = batch.len() > batch_size;
            let rows = if has_more_raw {
                &batch[..batch_size]
            } else {
                batch.as_slice()
            };
            scanned = scanned.saturating_add(rows.len());
            if let Some(last) = rows.last() {
                page_token = coordination::make_page_token(last.created_at, &last.id);
            }
            for work_unit in rows {
                if check_work_unit_read(&service.db, &service.security, work_unit, &principals)
                    .is_ok()
                {
                    visible.push(work_unit.clone());
                    if visible.len() > visible_limit {
                        break;
                    }
                }
            }
            if !has_more_raw {
                break;
            }
        }
        if visible.len() <= visible_limit && scanned >= max_scan {
            return Err(Status::resource_exhausted(
                "work unit visibility scan limit exceeded; refine filters",
            ));
        }
        visible
    } else {
        service
            .db
            .list_work_units(&from_proto_work_unit_filter(&filter))
            .map_err(Status::internal)?
            .into_iter()
            .filter(|work_unit| {
                check_work_unit_read(&service.db, &service.security, work_unit, &principals).is_ok()
            })
            .collect::<Vec<_>>()
    };
    let next_page_token = if limit > 0 && work_units.len() > limit as usize {
        let next = work_units
            .get((limit as usize).saturating_sub(1))
            .map(|work_unit| coordination::make_page_token(work_unit.created_at, &work_unit.id))
            .unwrap_or_default();
        trim_page(&mut work_units, limit);
        next
    } else {
        String::new()
    };
    Ok(Response::new(ListWorkUnitsResponse {
        work_units: work_units.iter().map(to_proto_work_unit).collect(),
        next_page_token,
    }))
}
pub(super) async fn try_admit_work_unit(
    service: &SekaiServiceImpl,
    req: Request<TryAdmitWorkUnitRequest>,
) -> Result<Response<TryAdmitWorkUnitResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let work_unit_id = inner.work_unit_id;
    let work_unit = service
        .db
        .get_work_unit(&work_unit_id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("work unit not found"))?;
    check_work_unit_write(&service.db, &service.security, &work_unit, &principals)?;
    let owner = principals
        .first()
        .cloned()
        .ok_or(Status::unauthenticated("principal required"))?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let principal = dedup_principal(&principals);
    let result = WorkUnitLifecycle::new(&service.db)
        .admit(AdmitWorkUnit {
            work_unit_id: &work_unit_id,
            request_id: &inner.request_id,
            principal: &principal,
            lease_owner: &owner,
            now_ms,
        })
        .map_err(map_work_unit_lifecycle_error)?;
    Ok(Response::new(TryAdmitWorkUnitResponse {
        admitted: result.admitted,
        queue_position: result.queue_position,
        reason: result.reason,
        work_unit: Some(to_proto_work_unit(&result.work_unit)),
        reservations: result
            .reservations
            .iter()
            .map(to_proto_reservation)
            .collect(),
    }))
}
pub(super) async fn heartbeat_work_unit(
    service: &SekaiServiceImpl,
    req: Request<HeartbeatWorkUnitRequest>,
) -> Result<Response<HeartbeatWorkUnitResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let work_unit_id = inner.work_unit_id;
    let existing = service
        .db
        .get_work_unit(&work_unit_id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("work unit not found"))?;
    check_work_unit_write(&service.db, &service.security, &existing, &principals)?;
    let work_unit = transition_work_unit(
        &service.db,
        &principals,
        &work_unit_id,
        &inner.request_id,
        WorkUnitTransition::Heartbeat,
    )?;
    Ok(Response::new(HeartbeatWorkUnitResponse {
        work_unit: Some(to_proto_work_unit(&work_unit)),
    }))
}
pub(super) async fn complete_work_unit(
    service: &SekaiServiceImpl,
    req: Request<CompleteWorkUnitRequest>,
) -> Result<Response<CompleteWorkUnitResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let work_unit_id = inner.work_unit_id;
    let existing = service
        .db
        .get_work_unit(&work_unit_id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("work unit not found"))?;
    check_work_unit_write(&service.db, &service.security, &existing, &principals)?;
    let work_unit = transition_work_unit(
        &service.db,
        &principals,
        &work_unit_id,
        &inner.request_id,
        WorkUnitTransition::Complete,
    )?;
    Ok(Response::new(CompleteWorkUnitResponse {
        work_unit: Some(to_proto_work_unit(&work_unit)),
    }))
}
pub(super) async fn fail_work_unit(
    service: &SekaiServiceImpl,
    req: Request<FailWorkUnitRequest>,
) -> Result<Response<FailWorkUnitResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let existing = service
        .db
        .get_work_unit(&inner.work_unit_id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("work unit not found"))?;
    check_work_unit_write(&service.db, &service.security, &existing, &principals)?;
    let work_unit = transition_work_unit(
        &service.db,
        &principals,
        &inner.work_unit_id,
        &inner.request_id,
        WorkUnitTransition::Fail(&inner.failure_reason),
    )?;
    Ok(Response::new(FailWorkUnitResponse {
        work_unit: Some(to_proto_work_unit(&work_unit)),
    }))
}
pub(super) async fn cancel_work_unit(
    service: &SekaiServiceImpl,
    req: Request<CancelWorkUnitRequest>,
) -> Result<Response<CancelWorkUnitResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let existing = service
        .db
        .get_work_unit(&inner.work_unit_id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("work unit not found"))?;
    check_work_unit_write(&service.db, &service.security, &existing, &principals)?;
    let work_unit = transition_work_unit(
        &service.db,
        &principals,
        &inner.work_unit_id,
        &inner.request_id,
        WorkUnitTransition::Cancel(&inner.cancel_reason),
    )?;
    Ok(Response::new(CancelWorkUnitResponse {
        work_unit: Some(to_proto_work_unit(&work_unit)),
    }))
}
pub(super) async fn list_reservations(
    service: &SekaiServiceImpl,
    req: Request<ListReservationsRequest>,
) -> Result<Response<ListReservationsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let reservations = service
        .db
        .list_reservations(&coordination::ReservationFilter {
            work_unit_id: if inner.work_unit_id.is_empty() {
                None
            } else {
                Some(inner.work_unit_id)
            },
            scope_id: if inner.scope_id.is_empty() {
                None
            } else {
                Some(inner.scope_id)
            },
            status: if inner.status.is_empty() {
                None
            } else {
                Some(inner.status)
            },
        })
        .map_err(Status::internal)?;
    let mut visible = Vec::new();
    for reservation in reservations {
        if let Some(work_unit) = service
            .db
            .get_work_unit(&reservation.work_unit_id)
            .map_err(Status::internal)?
        {
            if check_work_unit_read(&service.db, &service.security, &work_unit, &principals).is_ok()
            {
                visible.push(to_proto_reservation(&reservation));
            }
        }
    }
    Ok(Response::new(ListReservationsResponse {
        reservations: visible,
    }))
}
pub(super) async fn list_run_events(
    service: &SekaiServiceImpl,
    req: Request<ListRunEventsRequest>,
) -> Result<Response<ListRunEventsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let work_unit = service
        .db
        .get_work_unit(&inner.work_unit_id)
        .map_err(Status::internal)?
        .ok_or(Status::not_found("work unit not found"))?;
    check_work_unit_read(&service.db, &service.security, &work_unit, &principals)?;
    let limit = inner.limit;
    let mut events = service
        .db
        .list_run_events(
            &inner.work_unit_id,
            inner.limit,
            inner.after,
            &inner.event_types,
            if inner.page_token.is_empty() {
                None
            } else {
                Some(inner.page_token.as_str())
            },
        )
        .map_err(Status::internal)?
        .into_iter()
        .collect::<Vec<_>>();
    let next_page_token = if limit > 0 && events.len() > limit as usize {
        let next = events
            .get((limit as usize).saturating_sub(1))
            .map(|event| coordination::make_page_token(event.created_at, &event.id))
            .unwrap_or_default();
        trim_page(&mut events, limit);
        next
    } else {
        String::new()
    };
    Ok(Response::new(ListRunEventsResponse {
        events: events.iter().map(to_proto_run_event).collect(),
        next_page_token,
    }))
}
pub(super) async fn reconcile_work_units(
    service: &SekaiServiceImpl,
    req: Request<ReconcileWorkUnitsRequest>,
) -> Result<Response<ReconcileWorkUnitsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let inner = req.into_inner();
    let summary = WorkUnitLifecycle::new(&service.db)
        .reconcile(ReconcileWorkUnits {
            work_unit_id: &inner.work_unit_id,
            scope_id: &inner.scope_id,
            principals: &principals,
            dry_run: inner.dry_run,
            limit: inner.limit,
            now_ms: chrono::Utc::now().timestamp_millis(),
        })
        .map_err(map_work_unit_lifecycle_error)?;
    Ok(Response::new(ReconcileWorkUnitsResponse {
        work_units_reconciled: summary.work_units_reconciled,
        reservations_released: summary.reservations_released,
        details: summary
            .details
            .iter()
            .map(|detail| ReconciliationDetail {
                work_unit_id: detail.work_unit_id.clone(),
                reservation_id: detail.reservation_id.clone(),
                reason: detail.reason.clone(),
                action: detail.action.clone(),
            })
            .collect(),
    }))
}
