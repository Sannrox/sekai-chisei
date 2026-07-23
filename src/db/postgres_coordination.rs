use crate::db::postgres::PostgresDb;
use crate::sekai::coordination::{
    AdmissionResult, ContentionScope, CoordinationSnapshot, RESERVATION_STATUS_ACTIVE,
    RESERVATION_STATUS_RELEASED, ReconcileFilter, ReconcileSummary, ReconciliationRecord,
    RequestDedup, Reservation, ReservationFilter, RunEvent, ScopeBlockage,
    WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_CANCELLED, WORK_UNIT_STATUS_COMPLETED,
    WORK_UNIT_STATUS_FAILED, WORK_UNIT_STATUS_PENDING, WORK_UNIT_STATUS_RECONCILED,
    WORK_UNIT_STATUS_RUNNING, WORK_UNIT_STATUS_STALE, WORK_UNIT_STATUS_TIMED_OUT, WorkUnit,
    WorkUnitFilter,
};
use postgres::{GenericClient, IsolationLevel, Row, types::ToSql};
use std::collections::{HashMap, HashSet};

const SCOPE_COLUMNS: &str = "id,name,parent_scope_id,max_concurrency,admission_policy,heartbeat_ttl_seconds,timeout_seconds,owner_principal,created,updated";
const WORK_COLUMNS: &str = "id,kind,actor,target_object_id,status,requested_spec,scope_id,priority,timeout_seconds,heartbeat_ttl_seconds,created_at,admitted_at,started_at,finished_at,last_heartbeat_at,failure_reason,cancel_reason,owner_principal,creator_principal,idempotency_key,updated_at";
const RESERVATION_COLUMNS: &str =
    "id,work_unit_id,scope_id,status,lease_owner,leased_at,expires_at,released_at,created_at";
const ADMISSION_LOCK_ID: i64 = 0x5345_4b41_4943_4f01;

impl PostgresDb {
    pub fn create_contention_scope(&self, scope: &ContentionScope) -> Result<(), String> {
        validate_scope(scope)?;
        let max_concurrency = i64::from(scope.max_concurrency);
        let heartbeat_ttl_seconds = i64::from(scope.heartbeat_ttl_seconds);
        let timeout_seconds = i64::from(scope.timeout_seconds);
        self.connection()?.execute(
            "INSERT INTO sekai_contention_scopes
             (id,name,parent_scope_id,max_concurrency,admission_policy,heartbeat_ttl_seconds,timeout_seconds,owner_principal,created,updated)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[&scope.id,&scope.name,&scope.parent_scope_id,&max_concurrency,&scope.admission_policy,
              &heartbeat_ttl_seconds,&timeout_seconds,&scope.owner_principal,&scope.created,&scope.updated],
        ).map(|_| ()).map_err(string)
    }

    pub fn update_contention_scope(&self, scope: &ContentionScope) -> Result<(), String> {
        validate_scope(scope)?;
        let max_concurrency = i64::from(scope.max_concurrency);
        let heartbeat_ttl_seconds = i64::from(scope.heartbeat_ttl_seconds);
        let timeout_seconds = i64::from(scope.timeout_seconds);
        let count = self.connection()?.execute(
            "UPDATE sekai_contention_scopes SET name=$2,parent_scope_id=$3,max_concurrency=$4,
             admission_policy=$5,heartbeat_ttl_seconds=$6,timeout_seconds=$7,owner_principal=$8,updated=$9
             WHERE id=$1",
            &[&scope.id,&scope.name,&scope.parent_scope_id,&max_concurrency,&scope.admission_policy,
              &heartbeat_ttl_seconds,&timeout_seconds,&scope.owner_principal,&scope.updated],
        ).map_err(string)?;
        affected(count, "scope not found")
    }

    pub fn get_contention_scope(&self, id: &str) -> Result<Option<ContentionScope>, String> {
        self.connection()?
            .query_opt(
                &format!("SELECT {SCOPE_COLUMNS} FROM sekai_contention_scopes WHERE id=$1"),
                &[&id],
            )
            .map(|row| row.map(row_to_scope))
            .map_err(string)
    }

    pub fn list_contention_scopes(&self) -> Result<Vec<ContentionScope>, String> {
        self.connection()?
            .query(
                &format!("SELECT {SCOPE_COLUMNS} FROM sekai_contention_scopes ORDER BY name,id"),
                &[],
            )
            .map(|rows| rows.into_iter().map(row_to_scope).collect())
            .map_err(string)
    }

    pub fn contention_scope_chain(&self, scope_id: &str) -> Result<Vec<ContentionScope>, String> {
        let mut connection = self.connection()?;
        scope_chain(&mut *connection, scope_id, false)
    }

    pub fn create_work_unit(&self, work: &WorkUnit) -> Result<(), String> {
        validate_work(work)?;
        let values = work_params(work);
        let params = refs(&values);
        self.connection()?.execute(
            "INSERT INTO sekai_work_units
             (id,kind,actor,target_object_id,status,requested_spec,scope_id,priority,timeout_seconds,
              heartbeat_ttl_seconds,created_at,admitted_at,started_at,finished_at,last_heartbeat_at,
              failure_reason,cancel_reason,owner_principal,creator_principal,idempotency_key,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)",
            &params,
        ).map(|_| ()).map_err(string)
    }

    pub fn get_work_unit(&self, id: &str) -> Result<Option<WorkUnit>, String> {
        self.connection()?
            .query_opt(
                &format!("SELECT {WORK_COLUMNS} FROM sekai_work_units WHERE id=$1"),
                &[&id],
            )
            .map(|row| row.map(row_to_work))
            .map_err(string)
    }

    pub fn get_work_unit_by_idempotency_key(&self, key: &str) -> Result<Option<WorkUnit>, String> {
        if key.is_empty() {
            return Ok(None);
        }
        self.connection()?
            .query_opt(
                &format!("SELECT {WORK_COLUMNS} FROM sekai_work_units WHERE idempotency_key=$1"),
                &[&key],
            )
            .map(|row| row.map(row_to_work))
            .map_err(string)
    }

    pub fn update_work_unit(&self, work: &WorkUnit) -> Result<(), String> {
        validate_work(work)?;
        let values = work_params(work);
        let params = refs(&values);
        let count = self.connection()?.execute(
            "UPDATE sekai_work_units SET kind=$2,actor=$3,target_object_id=$4,status=$5,requested_spec=$6,
             scope_id=$7,priority=$8,timeout_seconds=$9,heartbeat_ttl_seconds=$10,created_at=$11,
             admitted_at=$12,started_at=$13,finished_at=$14,last_heartbeat_at=$15,failure_reason=$16,
             cancel_reason=$17,owner_principal=$18,creator_principal=$19,idempotency_key=$20,updated_at=$21
             WHERE id=$1", &params,
        ).map_err(string)?;
        affected(count, "work unit not found")
    }

    pub fn list_work_units(&self, filter: &WorkUnitFilter) -> Result<Vec<WorkUnit>, String> {
        let mut sql = format!("SELECT {WORK_COLUMNS} FROM sekai_work_units WHERE TRUE");
        let mut values: Vec<Box<dyn ToSql + Sync>> = vec![];
        if !filter.statuses.is_empty() {
            sql.push_str(&format!(
                " AND status = ANY(${})",
                push(&mut values, filter.statuses.clone())
            ));
        } else if let Some(value) = &filter.status {
            sql.push_str(&format!(
                " AND status=${}",
                push(&mut values, value.clone())
            ));
        }
        for (column, value) in [
            ("actor", &filter.actor),
            ("scope_id", &filter.scope_id),
            ("target_object_id", &filter.target_object_id),
            ("owner_principal", &filter.owner_principal),
            ("creator_principal", &filter.creator_principal),
        ] {
            if let Some(value) = value {
                sql.push_str(&format!(
                    " AND {column}=${}",
                    push(&mut values, value.clone())
                ));
            }
        }
        if filter.created_after > 0 {
            sql.push_str(&format!(
                " AND created_at>${}",
                push(&mut values, filter.created_after)
            ));
        }
        if filter.updated_after > 0 {
            sql.push_str(&format!(
                " AND updated_at>${}",
                push(&mut values, filter.updated_after)
            ));
        }
        if let Some((created, id)) = filter.page_token.as_deref().and_then(parse_token) {
            let a = push(&mut values, created);
            let b = push(&mut values, id);
            sql.push_str(&format!(
                " AND (created_at>${a} OR (created_at=${a} AND id>${b}))"
            ));
        }
        sql.push_str(" ORDER BY created_at,id");
        if filter.limit > 0 {
            sql.push_str(&format!(
                " LIMIT ${}",
                push(&mut values, i64::from(filter.limit) + 1)
            ));
        }
        if filter.offset > 0 {
            sql.push_str(&format!(
                " OFFSET ${}",
                push(&mut values, i64::from(filter.offset))
            ));
        }
        let refs = refs(&values);
        self.connection()?
            .query(&sql, &refs)
            .map(|rows| rows.into_iter().map(row_to_work).collect())
            .map_err(string)
    }

    pub fn create_reservation(&self, reservation: &Reservation) -> Result<(), String> {
        self.connection()?.execute(
            "INSERT INTO sekai_reservations
             (id,work_unit_id,scope_id,status,lease_owner,leased_at,expires_at,released_at,created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[&reservation.id,&reservation.work_unit_id,&reservation.scope_id,&reservation.status,
              &reservation.lease_owner,&reservation.leased_at,&reservation.expires_at,
              &reservation.released_at,&reservation.created_at],
        ).map(|_| ()).map_err(string)
    }

    pub fn list_reservations(
        &self,
        filter: &ReservationFilter,
    ) -> Result<Vec<Reservation>, String> {
        let mut sql = format!("SELECT {RESERVATION_COLUMNS} FROM sekai_reservations WHERE TRUE");
        let mut values: Vec<Box<dyn ToSql + Sync>> = vec![];
        for (column, value) in [
            ("work_unit_id", &filter.work_unit_id),
            ("scope_id", &filter.scope_id),
            ("status", &filter.status),
        ] {
            if let Some(value) = value {
                sql.push_str(&format!(
                    " AND {column}=${}",
                    push(&mut values, value.clone())
                ));
            }
        }
        sql.push_str(" ORDER BY leased_at,id");
        let refs = refs(&values);
        self.connection()?
            .query(&sql, &refs)
            .map(|rows| rows.into_iter().map(row_to_reservation).collect())
            .map_err(string)
    }

    pub fn append_run_event(&self, event: &RunEvent) -> Result<(), String> {
        let evidence = serde_json::to_string(&event.evidence).map_err(string)?;
        self.connection()?.execute(
            "INSERT INTO sekai_run_events (id,work_unit_id,event_type,message,evidence_json,created_at)
             VALUES ($1,$2,$3,$4,$5,$6)",
            &[&event.id,&event.work_unit_id,&event.event_type,&event.message,&evidence,&event.created_at],
        ).map(|_| ()).map_err(string)
    }

    pub fn get_dedup_request(
        &self,
        request_id: &str,
        operation: &str,
    ) -> Result<Option<RequestDedup>, String> {
        if request_id.is_empty() {
            return Ok(None);
        }
        self.connection()?
            .query_opt(
                "SELECT request_id,operation,principal,scope_id,work_unit_id,created_at
             FROM sekai_coordination_requests WHERE request_id=$1 AND operation=$2",
                &[&request_id, &operation],
            )
            .map(|row| row.map(row_to_request))
            .map_err(string)
    }

    pub fn record_dedup_request(&self, request: &RequestDedup) -> Result<(), String> {
        if request.request_id.is_empty() {
            return Ok(());
        }
        self.connection()?
            .execute(
                "INSERT INTO sekai_coordination_requests
             (request_id,operation,principal,scope_id,work_unit_id,created_at)
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT(request_id,operation) DO NOTHING",
                &[
                    &request.request_id,
                    &request.operation,
                    &request.principal,
                    &request.scope_id,
                    &request.work_unit_id,
                    &request.created_at,
                ],
            )
            .map(|_| ())
            .map_err(string)
    }

    pub fn list_run_events(
        &self,
        work_unit_id: &str,
        limit: i32,
        after: i64,
        event_types: &[String],
        page_token: Option<&str>,
    ) -> Result<Vec<RunEvent>, String> {
        let mut sql = "SELECT id,work_unit_id,event_type,message,evidence_json,created_at
                       FROM sekai_run_events WHERE work_unit_id=$1 AND created_at >= $2"
            .to_string();
        let mut values: Vec<Box<dyn ToSql + Sync>> =
            vec![Box::new(work_unit_id.to_string()), Box::new(after)];
        if !event_types.is_empty() {
            sql.push_str(&format!(
                " AND event_type=ANY(${})",
                push(&mut values, event_types.to_vec())
            ));
        }
        if let Some((created, id)) = page_token.and_then(parse_token) {
            let a = push(&mut values, created);
            let b = push(&mut values, id);
            sql.push_str(&format!(
                " AND (created_at>${a} OR (created_at=${a} AND id>${b}))"
            ));
        }
        sql.push_str(&format!(
            " ORDER BY created_at,id LIMIT ${}",
            push(
                &mut values,
                if limit > 0 { i64::from(limit) + 1 } else { 101 }
            )
        ));
        let refs = refs(&values);
        self.connection()?
            .query(&sql, &refs)
            .map(|rows| rows.into_iter().map(row_to_event).collect())
            .map_err(string)
    }

    pub fn create_reconciliation_record(
        &self,
        record: &ReconciliationRecord,
    ) -> Result<(), String> {
        self.connection()?.execute(
            "INSERT INTO sekai_reconciliations (id,work_unit_id,reservation_id,reason,action,created_at)
             VALUES ($1,$2,$3,$4,$5,$6)",
            &[&record.id,&record.work_unit_id,&record.reservation_id,&record.reason,&record.action,&record.created_at],
        ).map(|_| ()).map_err(string)
    }

    pub fn try_admit_work_unit(
        &self,
        id: &str,
        owner: &str,
        now: i64,
    ) -> Result<AdmissionResult, String> {
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(string)?;
        // Admission compares the global FIFO queue and may lock several
        // hierarchy rows. A single transaction-scoped lock gives every
        // contender the same first lock and prevents candidate/scope inversion.
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&ADMISSION_LOCK_ID])
            .map_err(string)?;
        let mut work = tx
            .query_opt(
                &format!("SELECT {WORK_COLUMNS} FROM sekai_work_units WHERE id=$1 FOR UPDATE"),
                &[&id],
            )
            .map_err(string)?
            .map(row_to_work)
            .ok_or_else(|| "work unit not found".to_string())?;
        if work.status != WORK_UNIT_STATUS_PENDING {
            return Ok(AdmissionResult {
                admitted: false,
                queue_position: 0,
                reason: format!("work unit is not pending: {}", work.status),
                work_unit: work,
                reservations: vec![],
            });
        }
        // Lock every scope in root-to-leaf order. Overlapping hierarchies then
        // serialize capacity checks and prevent admission races.
        let chain = scope_chain(&mut tx, &work.scope_id, true)?;
        let pending = tx.query(
            &format!("SELECT {WORK_COLUMNS} FROM sekai_work_units WHERE status=$1 ORDER BY created_at,id FOR UPDATE"),
            &[&WORK_UNIT_STATUS_PENDING],
        ).map_err(string)?.into_iter().map(row_to_work).collect::<Vec<_>>();
        let mut older = 0;
        for other in pending {
            if other.id == work.id {
                break;
            }
            if chains_overlap(&chain, &scope_chain(&mut tx, &other.scope_id, true)?) {
                older += 1;
            }
        }
        if older > 0 {
            return Ok(AdmissionResult {
                admitted: false,
                queue_position: older + 1,
                reason: "older pending work unit holds queue precedence".into(),
                work_unit: work,
                reservations: vec![],
            });
        }
        for scope in &chain {
            let active: i64 = tx
                .query_one(
                    "SELECT COUNT(*) FROM sekai_reservations
                 WHERE scope_id=$1 AND status=$2 AND released_at=0 AND expires_at>$3",
                    &[&scope.id, &RESERVATION_STATUS_ACTIVE, &now],
                )
                .map_err(string)?
                .get(0);
            if active >= i64::from(scope.max_concurrency) {
                return Ok(AdmissionResult {
                    admitted: false,
                    queue_position: 1,
                    reason: format!("scope {} is saturated", scope.name),
                    work_unit: work,
                    reservations: vec![],
                });
            }
        }
        let mut reservations = vec![];
        for scope in chain {
            let ttl = if work.heartbeat_ttl_seconds > 0 {
                work.heartbeat_ttl_seconds
            } else {
                scope.heartbeat_ttl_seconds
            };
            let reservation = Reservation {
                id: format!("res:{}:{}", work.id, scope.id),
                work_unit_id: work.id.clone(),
                scope_id: scope.id,
                status: RESERVATION_STATUS_ACTIVE.into(),
                lease_owner: owner.into(),
                leased_at: now,
                expires_at: now + i64::from(ttl) * 1000,
                released_at: 0,
                created_at: now,
            };
            insert_reservation(&mut tx, &reservation)?;
            reservations.push(reservation);
        }
        ensure_transition(&work.status, WORK_UNIT_STATUS_RUNNING)?;
        work.status = WORK_UNIT_STATUS_RUNNING.into();
        work.admitted_at = now;
        work.started_at = now;
        work.last_heartbeat_at = now;
        work.updated_at = now;
        tx.execute(
            "UPDATE sekai_work_units SET status=$2,admitted_at=$3,started_at=$4,last_heartbeat_at=$5,updated_at=$6 WHERE id=$1",
            &[&work.id,&work.status,&now,&now,&now,&now],
        ).map_err(string)?;
        insert_event(
            &mut tx,
            &RunEvent {
                id: format!("evt:{}:admitted:{now}", work.id),
                work_unit_id: work.id.clone(),
                event_type: "admitted".into(),
                message: format!("work unit admitted into scope {}", work.scope_id),
                evidence: HashMap::from([("scope_id".into(), work.scope_id.clone())]),
                created_at: now,
            },
        )?;
        tx.commit().map_err(string)?;
        Ok(AdmissionResult {
            admitted: true,
            queue_position: 0,
            reason: String::new(),
            work_unit: work,
            reservations,
        })
    }

    pub fn heartbeat_work_unit(&self, id: &str, now: i64) -> Result<WorkUnit, String> {
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(string)?;
        // Share admission's first lock so an expired reservation cannot be
        // counted as free capacity while this transaction renews it.
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&ADMISSION_LOCK_ID])
            .map_err(string)?;
        let mut work = locked_work(&mut tx, id)?;
        if work.status != WORK_UNIT_STATUS_RUNNING && work.status != WORK_UNIT_STATUS_ADMITTED {
            return Err(format!("work unit is not active: {}", work.status));
        }
        let reservation_expiries = tx
            .query(
                "SELECT expires_at
                 FROM sekai_reservations
                 WHERE work_unit_id=$1 AND status=$2 AND released_at=0
                 FOR UPDATE",
                &[&id, &RESERVATION_STATUS_ACTIVE],
            )
            .map_err(string)?;
        if reservation_expiries.is_empty()
            || reservation_expiries
                .iter()
                .any(|row| row.get::<_, i64>(0) <= now)
        {
            return Err("work unit reservation lease expired".into());
        }
        let requested_ttl = i64::from(work.heartbeat_ttl_seconds);
        tx.execute(
            "UPDATE sekai_reservations AS reservation
             SET expires_at=$2 + (
                CASE WHEN $3 > 0 THEN $3 ELSE scope.heartbeat_ttl_seconds END
             ) * 1000
             FROM sekai_contention_scopes AS scope
             WHERE reservation.scope_id=scope.id
               AND reservation.work_unit_id=$1
               AND reservation.status=$4
               AND reservation.released_at=0",
            &[&id, &now, &requested_ttl, &RESERVATION_STATUS_ACTIVE],
        )
        .map_err(string)?;
        tx.execute(
            "UPDATE sekai_work_units SET last_heartbeat_at=$2,updated_at=$2 WHERE id=$1",
            &[&id, &now],
        )
        .map_err(string)?;
        work.last_heartbeat_at = now;
        work.updated_at = now;
        insert_event(
            &mut tx,
            &RunEvent {
                id: format!("evt:{id}:heartbeat:{now}"),
                work_unit_id: id.into(),
                event_type: "heartbeat".into(),
                message: "work unit heartbeat".into(),
                evidence: HashMap::new(),
                created_at: now,
            },
        )?;
        tx.commit().map_err(string)?;
        Ok(work)
    }

    pub fn complete_work_unit(&self, id: &str, now: i64) -> Result<WorkUnit, String> {
        self.finish_work_unit(id, WORK_UNIT_STATUS_COMPLETED, "", "", now)
    }
    pub fn fail_work_unit(&self, id: &str, reason: &str, now: i64) -> Result<WorkUnit, String> {
        self.finish_work_unit(id, WORK_UNIT_STATUS_FAILED, reason, "", now)
    }
    pub fn cancel_work_unit(&self, id: &str, reason: &str, now: i64) -> Result<WorkUnit, String> {
        self.finish_work_unit(id, WORK_UNIT_STATUS_CANCELLED, "", reason, now)
    }

    pub fn release_reservations_for_work_unit(&self, id: &str, now: i64) -> Result<i32, String> {
        let count = self
            .connection()?
            .execute(
                "UPDATE sekai_reservations SET status=$2,released_at=$3
             WHERE work_unit_id=$1 AND status=$4 AND released_at=0",
                &[
                    &id,
                    &RESERVATION_STATUS_RELEASED,
                    &now,
                    &RESERVATION_STATUS_ACTIVE,
                ],
            )
            .map_err(string)?;
        i32::try_from(count).map_err(string)
    }

    pub fn reconcile_work_units(
        &self,
        now: i64,
        filter: &ReconcileFilter,
    ) -> Result<ReconcileSummary, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(string)?;
        // Reconciliation locks the same pending rows admission examines, so it
        // participates in the shared first-lock protocol.
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&ADMISSION_LOCK_ID])
            .map_err(string)?;
        let mut sql = format!("SELECT {WORK_COLUMNS} FROM sekai_work_units
            WHERE status=ANY($1) AND ($2::text IS NULL OR id=$2) AND ($3::text IS NULL OR scope_id=$3)
            ORDER BY created_at,id");
        if filter.limit > 0 {
            sql.push_str(" LIMIT $4");
        }
        sql.push_str(" FOR UPDATE");
        let statuses = vec![
            WORK_UNIT_STATUS_PENDING,
            WORK_UNIT_STATUS_ADMITTED,
            WORK_UNIT_STATUS_RUNNING,
        ];
        let limit = i64::from(filter.limit);
        let rows = if filter.limit > 0 {
            tx.query(
                &sql,
                &[&statuses, &filter.work_unit_id, &filter.scope_id, &limit],
            )
        } else {
            tx.query(&sql, &[&statuses, &filter.work_unit_id, &filter.scope_id])
        }
        .map_err(string)?;
        let mut summary = ReconcileSummary::default();
        for mut work in rows.into_iter().map(row_to_work) {
            let reservations = tx
                .query(
                    &format!(
                        "SELECT {RESERVATION_COLUMNS} FROM sekai_reservations
                    WHERE work_unit_id=$1 AND status=$2 AND released_at=0 FOR UPDATE"
                    ),
                    &[&work.id, &RESERVATION_STATUS_ACTIVE],
                )
                .map_err(string)?
                .into_iter()
                .map(row_to_reservation)
                .collect::<Vec<_>>();
            let timed_out = work.started_at > 0
                && work.timeout_seconds > 0
                && now >= work.started_at + i64::from(work.timeout_seconds) * 1000;
            let stale =
                !reservations.is_empty() && reservations.iter().any(|r| r.expires_at <= now);
            if !timed_out && !stale {
                continue;
            }
            let status = if timed_out {
                WORK_UNIT_STATUS_TIMED_OUT
            } else {
                WORK_UNIT_STATUS_STALE
            };
            let reason = if timed_out {
                "work unit exceeded timeout"
            } else {
                "reservation lease expired"
            };
            let record = ReconciliationRecord {
                id: format!("reconcile:{}:{now}", work.id),
                work_unit_id: work.id.clone(),
                reservation_id: String::new(),
                reason: reason.into(),
                action: if filter.dry_run {
                    "would_release_reservations"
                } else {
                    "release_reservations"
                }
                .into(),
                created_at: now,
            };
            summary.reservations_released += reservations.len() as i32;
            summary.work_units_reconciled += 1;
            summary.details.push(record.clone());
            if filter.dry_run {
                continue;
            }
            tx.execute(
                "UPDATE sekai_reservations SET status=$2,released_at=$3
                WHERE work_unit_id=$1 AND status=$4 AND released_at=0",
                &[
                    &work.id,
                    &RESERVATION_STATUS_RELEASED,
                    &now,
                    &RESERVATION_STATUS_ACTIVE,
                ],
            )
            .map_err(string)?;
            work.status = status.into();
            work.finished_at = now;
            work.updated_at = now;
            if timed_out {
                work.failure_reason = reason.into();
            }
            tx.execute("UPDATE sekai_work_units SET status=$2,finished_at=$3,failure_reason=$4,updated_at=$3 WHERE id=$1",
                &[&work.id,&work.status,&now,&work.failure_reason]).map_err(string)?;
            insert_event(
                &mut tx,
                &RunEvent {
                    id: format!("evt:{}:reconcile:{now}", work.id),
                    work_unit_id: work.id.clone(),
                    event_type: if timed_out { "timed_out" } else { "stale" }.into(),
                    message: reason.into(),
                    evidence: HashMap::new(),
                    created_at: now,
                },
            )?;
            tx.execute("INSERT INTO sekai_reconciliations
                (id,work_unit_id,reservation_id,reason,action,created_at) VALUES ($1,$2,$3,$4,$5,$6)",
                &[&record.id,&record.work_unit_id,&record.reservation_id,&record.reason,&record.action,&record.created_at]).map_err(string)?;
        }
        tx.commit().map_err(string)?;
        Ok(summary)
    }

    pub fn coordination_snapshot(&self, now: i64) -> Result<CoordinationSnapshot, String> {
        let works = self.list_work_units(&WorkUnitFilter::default())?;
        let reservations = self.list_reservations(&ReservationFilter::default())?;
        let scopes = self.list_contention_scopes()?;
        let pending = works
            .iter()
            .filter(|w| w.status == WORK_UNIT_STATUS_PENDING)
            .collect::<Vec<_>>();
        let mut blocked_scopes = vec![];
        for scope in &scopes {
            let pending_count = pending.iter().filter(|w| w.scope_id == scope.id).count() as i32;
            if pending_count == 0 {
                continue;
            }
            let active_count = reservations
                .iter()
                .filter(|r| r.scope_id == scope.id && active(r, now))
                .count() as i32;
            blocked_scopes.push(ScopeBlockage {
                scope_id: scope.id.clone(),
                scope_name: scope.name.clone(),
                reason: if active_count >= scope.max_concurrency {
                    format!("scope {} is saturated", scope.name)
                } else {
                    "older pending work unit holds queue precedence".into()
                },
                pending_count,
                active_count,
            });
        }
        Ok(CoordinationSnapshot {
            pending_count: pending.len() as i32,
            running_count: works
                .iter()
                .filter(|w| w.status == WORK_UNIT_STATUS_RUNNING)
                .count() as i32,
            stale_count: works
                .iter()
                .filter(|w| {
                    matches!(
                        w.status.as_str(),
                        WORK_UNIT_STATUS_STALE | WORK_UNIT_STATUS_TIMED_OUT
                    )
                })
                .count() as i32,
            active_reservation_count: reservations.iter().filter(|r| active(r, now)).count() as i32,
            oldest_pending_age_ms: pending
                .iter()
                .map(|w| now.saturating_sub(w.created_at))
                .max()
                .unwrap_or(0),
            oldest_running_age_ms: works
                .iter()
                .filter(|w| w.status == WORK_UNIT_STATUS_RUNNING)
                .map(|w| now.saturating_sub(w.started_at.max(w.created_at)))
                .max()
                .unwrap_or(0),
            stale_reservation_count: reservations
                .iter()
                .filter(|r| {
                    r.status == RESERVATION_STATUS_ACTIVE
                        && r.released_at == 0
                        && r.expires_at <= now
                })
                .count() as i32,
            blocked_scopes,
        })
    }

    fn finish_work_unit(
        &self,
        id: &str,
        status: &str,
        failure: &str,
        cancel: &str,
        now: i64,
    ) -> Result<WorkUnit, String> {
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(string)?;
        let mut work = locked_work(&mut tx, id)?;
        if terminal(&work.status) {
            return Ok(work);
        }
        ensure_transition(&work.status, status)?;
        tx.execute(
            "UPDATE sekai_reservations SET status=$2,released_at=$3
            WHERE work_unit_id=$1 AND status=$4 AND released_at=0",
            &[
                &id,
                &RESERVATION_STATUS_RELEASED,
                &now,
                &RESERVATION_STATUS_ACTIVE,
            ],
        )
        .map_err(string)?;
        work.status = status.into();
        work.finished_at = now;
        work.failure_reason = failure.into();
        work.cancel_reason = cancel.into();
        work.updated_at = now;
        tx.execute("UPDATE sekai_work_units SET status=$2,finished_at=$3,failure_reason=$4,cancel_reason=$5,updated_at=$3 WHERE id=$1",
            &[&id,&work.status,&now,&work.failure_reason,&work.cancel_reason]).map_err(string)?;
        insert_event(
            &mut tx,
            &RunEvent {
                id: format!("evt:{id}:{status}:{now}"),
                work_unit_id: id.into(),
                event_type: status.into(),
                message: if !failure.is_empty() {
                    failure.into()
                } else if !cancel.is_empty() {
                    cancel.into()
                } else {
                    format!("work unit {status}")
                },
                evidence: HashMap::new(),
                created_at: now,
            },
        )?;
        tx.commit().map_err(string)?;
        Ok(work)
    }
}

fn work_params(work: &WorkUnit) -> Vec<Box<dyn ToSql + Sync>> {
    vec![
        Box::new(work.id.clone()),
        Box::new(work.kind.clone()),
        Box::new(work.actor.clone()),
        Box::new(work.target_object_id.clone()),
        Box::new(work.status.clone()),
        Box::new(work.requested_spec.clone()),
        Box::new(work.scope_id.clone()),
        Box::new(i64::from(work.priority)),
        Box::new(i64::from(work.timeout_seconds)),
        Box::new(i64::from(work.heartbeat_ttl_seconds)),
        Box::new(work.created_at),
        Box::new(work.admitted_at),
        Box::new(work.started_at),
        Box::new(work.finished_at),
        Box::new(work.last_heartbeat_at),
        Box::new(work.failure_reason.clone()),
        Box::new(work.cancel_reason.clone()),
        Box::new(work.owner_principal.clone()),
        Box::new(work.creator_principal.clone()),
        Box::new(work.idempotency_key.clone()),
        Box::new(work.updated_at),
    ]
}
fn insert_reservation(client: &mut impl GenericClient, r: &Reservation) -> Result<(), String> {
    client
        .execute(
            "INSERT INTO sekai_reservations
        (id,work_unit_id,scope_id,status,lease_owner,leased_at,expires_at,released_at,created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &r.id,
                &r.work_unit_id,
                &r.scope_id,
                &r.status,
                &r.lease_owner,
                &r.leased_at,
                &r.expires_at,
                &r.released_at,
                &r.created_at,
            ],
        )
        .map(|_| ())
        .map_err(string)
}
fn insert_event(client: &mut impl GenericClient, event: &RunEvent) -> Result<(), String> {
    let evidence = serde_json::to_string(&event.evidence).map_err(string)?;
    client.execute("INSERT INTO sekai_run_events (id,work_unit_id,event_type,message,evidence_json,created_at)
        VALUES ($1,$2,$3,$4,$5,$6)", &[&event.id,&event.work_unit_id,&event.event_type,&event.message,&evidence,&event.created_at])
        .map(|_|()).map_err(string)
}
fn locked_work(client: &mut impl GenericClient, id: &str) -> Result<WorkUnit, String> {
    client
        .query_opt(
            &format!("SELECT {WORK_COLUMNS} FROM sekai_work_units WHERE id=$1 FOR UPDATE"),
            &[&id],
        )
        .map_err(string)?
        .map(row_to_work)
        .ok_or_else(|| "work unit not found".into())
}
fn scope_chain(
    client: &mut impl GenericClient,
    id: &str,
    lock: bool,
) -> Result<Vec<ContentionScope>, String> {
    let mut chain = vec![];
    let mut current = id.to_string();
    let mut seen = HashSet::new();
    while !current.is_empty() {
        if !seen.insert(current.clone()) {
            return Err(format!("scope cycle detected at {current}"));
        }
        let suffix = if lock { " FOR UPDATE" } else { "" };
        let scope = client
            .query_opt(
                &format!("SELECT {SCOPE_COLUMNS} FROM sekai_contention_scopes WHERE id=$1{suffix}"),
                &[&current],
            )
            .map_err(string)?
            .map(row_to_scope)
            .ok_or_else(|| format!("scope not found: {id}"))?;
        current = scope.parent_scope_id.clone();
        chain.push(scope);
    }
    chain.reverse();
    Ok(chain)
}
fn chains_overlap(left: &[ContentionScope], right: &[ContentionScope]) -> bool {
    let ids = left.iter().map(|s| s.id.as_str()).collect::<HashSet<_>>();
    right.iter().any(|s| ids.contains(s.id.as_str()))
}
fn validate_scope(s: &ContentionScope) -> Result<(), String> {
    if s.id.is_empty() {
        Err("scope id required".into())
    } else if s.name.is_empty() {
        Err("scope name required".into())
    } else if s.max_concurrency < 1 {
        Err("scope max_concurrency must be >= 1".into())
    } else if s.admission_policy.is_empty() {
        Err("scope admission policy required".into())
    } else {
        Ok(())
    }
}
fn validate_work(w: &WorkUnit) -> Result<(), String> {
    for (value, message) in [
        (&w.id, "work unit id required"),
        (&w.kind, "work unit kind required"),
        (&w.actor, "work unit actor required"),
        (&w.scope_id, "work unit scope_id required"),
        (&w.status, "work unit status required"),
        (&w.owner_principal, "work unit owner_principal required"),
        (&w.creator_principal, "work unit creator_principal required"),
    ] {
        if value.is_empty() {
            return Err(message.into());
        }
    }
    Ok(())
}
fn ensure_transition(current: &str, next: &str) -> Result<(), String> {
    let legal = matches!(
        (current, next),
        (WORK_UNIT_STATUS_PENDING, WORK_UNIT_STATUS_RUNNING)
            | (WORK_UNIT_STATUS_PENDING, WORK_UNIT_STATUS_CANCELLED)
            | (WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_RUNNING)
            | (WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_COMPLETED)
            | (WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_FAILED)
            | (WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_CANCELLED)
            | (WORK_UNIT_STATUS_RUNNING, WORK_UNIT_STATUS_COMPLETED)
            | (WORK_UNIT_STATUS_RUNNING, WORK_UNIT_STATUS_FAILED)
            | (WORK_UNIT_STATUS_RUNNING, WORK_UNIT_STATUS_CANCELLED)
            | (WORK_UNIT_STATUS_RUNNING, WORK_UNIT_STATUS_STALE)
            | (WORK_UNIT_STATUS_RUNNING, WORK_UNIT_STATUS_TIMED_OUT)
            | (WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_STALE)
            | (WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_TIMED_OUT)
    );
    if legal {
        Ok(())
    } else {
        Err(format!("invalid work unit transition: {current} -> {next}"))
    }
}
fn terminal(status: &str) -> bool {
    matches!(
        status,
        WORK_UNIT_STATUS_COMPLETED
            | WORK_UNIT_STATUS_FAILED
            | WORK_UNIT_STATUS_TIMED_OUT
            | WORK_UNIT_STATUS_CANCELLED
            | WORK_UNIT_STATUS_STALE
            | WORK_UNIT_STATUS_RECONCILED
    )
}
fn active(r: &Reservation, now: i64) -> bool {
    r.status == RESERVATION_STATUS_ACTIVE && r.released_at == 0 && r.expires_at > now
}
fn affected(count: u64, message: &str) -> Result<(), String> {
    if count == 0 {
        Err(message.into())
    } else {
        Ok(())
    }
}
fn push<T: ToSql + Sync + 'static>(values: &mut Vec<Box<dyn ToSql + Sync>>, value: T) -> usize {
    values.push(Box::new(value));
    values.len()
}
fn refs(values: &[Box<dyn ToSql + Sync>]) -> Vec<&(dyn ToSql + Sync)> {
    values.iter().map(|v| v.as_ref()).collect()
}
fn parse_token(token: &str) -> Option<(i64, String)> {
    let (a, b) = token.split_once('|')?;
    Some((a.parse().ok()?, b.into()))
}
fn string(error: impl ToString) -> String {
    error.to_string()
}
fn row_to_scope(row: Row) -> ContentionScope {
    ContentionScope {
        id: row.get(0),
        name: row.get(1),
        parent_scope_id: row.get(2),
        max_concurrency: narrow(row.get(3), "max_concurrency"),
        admission_policy: row.get(4),
        heartbeat_ttl_seconds: narrow(row.get(5), "heartbeat_ttl_seconds"),
        timeout_seconds: narrow(row.get(6), "timeout_seconds"),
        owner_principal: row.get(7),
        created: row.get(8),
        updated: row.get(9),
    }
}
fn row_to_work(row: Row) -> WorkUnit {
    WorkUnit {
        id: row.get(0),
        kind: row.get(1),
        actor: row.get(2),
        target_object_id: row.get(3),
        status: row.get(4),
        requested_spec: row.get(5),
        scope_id: row.get(6),
        priority: narrow(row.get(7), "priority"),
        timeout_seconds: narrow(row.get(8), "timeout_seconds"),
        heartbeat_ttl_seconds: narrow(row.get(9), "heartbeat_ttl_seconds"),
        created_at: row.get(10),
        admitted_at: row.get(11),
        started_at: row.get(12),
        finished_at: row.get(13),
        last_heartbeat_at: row.get(14),
        failure_reason: row.get(15),
        cancel_reason: row.get(16),
        owner_principal: row.get(17),
        creator_principal: row.get(18),
        idempotency_key: row.get(19),
        updated_at: row.get(20),
    }
}
fn row_to_reservation(row: Row) -> Reservation {
    Reservation {
        id: row.get(0),
        work_unit_id: row.get(1),
        scope_id: row.get(2),
        status: row.get(3),
        lease_owner: row.get(4),
        leased_at: row.get(5),
        expires_at: row.get(6),
        released_at: row.get(7),
        created_at: row.get(8),
    }
}
fn row_to_event(row: Row) -> RunEvent {
    let evidence: String = row.get(4);
    RunEvent {
        id: row.get(0),
        work_unit_id: row.get(1),
        event_type: row.get(2),
        message: row.get(3),
        evidence: serde_json::from_str(&evidence).unwrap_or_default(),
        created_at: row.get(5),
    }
}
fn row_to_request(row: Row) -> RequestDedup {
    RequestDedup {
        request_id: row.get(0),
        operation: row.get(1),
        principal: row.get(2),
        scope_id: row.get(3),
        work_unit_id: row.get(4),
        created_at: row.get(5),
    }
}

fn narrow(value: i64, field: &str) -> i32 {
    i32::try_from(value).unwrap_or_else(|_| panic!("PostgreSQL {field} value exceeds i32"))
}
