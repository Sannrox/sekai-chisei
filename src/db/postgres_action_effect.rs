//! PostgreSQL ActionEffect store (#398).

use crate::db::postgres::PostgresDb;
use crate::sekai::action_effect::{
    ActionEffect, EFFECT_STATUS_PENDING, RuntimeWorkPressure, RuntimeWorkPressureAggregate,
    aggregate_count, canonical_runtime_from_payload, runtime_id_is_blank, validate_no_nul,
};
use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;
use crate::sekai::parked_work::{
    ActionWorkContinuation, ActionWorkPark, ParkResult, ParkedWorkResolutionAction,
    ParkedWorkResolutionInput, ResolutionResult, canonical_json, sha256_digest,
    validate_checkpoint_tuple, validate_reason, validate_request_id,
};

impl PostgresDb {
    #[allow(clippy::too_many_arguments)]
    pub fn park_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token_in: &str,
        reason: &str,
        request_id: &str,
        checkpoint_store_id: &str,
        checkpoint_ref: &str,
        checkpoint_digest: &str,
        parked_by: &str,
        now_ms: i64,
    ) -> Result<ParkResult, String> {
        use crate::sekai::action_effect::{
            EFFECT_LIFECYCLE_AWAITING_CONTINUATION, EFFECT_STATUS_CLAIMED, EFFECT_STATUS_PARKED,
        };
        for (label, value) in [
            ("reason", reason),
            ("request_id", request_id),
            ("checkpoint_store_id", checkpoint_store_id),
            ("checkpoint_ref", checkpoint_ref),
            ("checkpoint_digest", checkpoint_digest),
            ("parked_by", parked_by),
        ] {
            validate_no_nul(label, value)?;
        }
        validate_request_id(request_id)?;
        validate_reason(reason)?;
        validate_checkpoint_tuple(checkpoint_store_id, checkpoint_ref, checkpoint_digest)?;
        if !checkpoint_store_id.is_empty() && !pg_checkpoint_store_allowed(checkpoint_store_id) {
            return Err("checkpoint store is not allowlisted".into());
        }
        let request_digest = sha256_digest(
            &serde_json::json!({
                "effect_id": effect_id,
                "runtime_id": runtime_id,
                "claim_generation": generation,
                "fencing_token_digest": sha256_digest(fencing_token_in),
                "outcome": "parked",
                "reason": reason,
                "checkpoint_store_id": checkpoint_store_id,
                "checkpoint_ref": checkpoint_ref,
                "checkpoint_digest": checkpoint_digest,
            })
            .to_string(),
        );
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        if let Some(row) = tx
            .query_opt(
                "SELECT request_digest,body_json FROM sekai_action_work_parks
                 WHERE effect_id=$1 AND request_id=$2",
                &[&effect_id, &request_id],
            )
            .map_err(|error| error.to_string())?
        {
            let stored: String = row.get(0);
            if stored != request_digest {
                return Err("park acknowledgement idempotency conflict".into());
            }
            let park = parse_pg_json::<ActionWorkPark>(row.get(1), "park record")?;
            let effect = pg_load_effect(&mut tx, effect_id, false)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(ParkResult {
                effect,
                park,
                replay: true,
            });
        }
        let mut effect = pg_load_effect(&mut tx, effect_id, true)?;
        if effect.kind != EFFECT_KIND_RUNTIME_DISPATCH {
            return Err("only runtime_dispatch effects support park".into());
        }
        if effect.status != EFFECT_STATUS_CLAIMED {
            return Err(format!("effect not claimed (status={})", effect.status));
        }
        if !effect.legacy_claim_fence_matches(runtime_id, fencing_token_in) {
            validate_no_nul("runtime_id", runtime_id)?;
            validate_no_nul("fencing_token", fencing_token_in)?;
        }
        if effect.claim_expires_at_ms <= now_ms {
            return Err("claim lease expired".into());
        }
        if !effect.fence_matches(runtime_id, generation, fencing_token_in) {
            return Err("fencing token or generation mismatch".into());
        }
        if effect.max_park_cycles > 0 && effect.park_count >= effect.max_park_cycles {
            use crate::sekai::action_effect::{
                EFFECT_LIFECYCLE_DEAD_LETTERED, EFFECT_STATUS_DEAD_LETTERED,
            };
            effect.status = EFFECT_STATUS_DEAD_LETTERED.into();
            effect.lifecycle_state = EFFECT_LIFECYCLE_DEAD_LETTERED.into();
            effect.failure_reason = "park_cycle_limit_exceeded".into();
            effect.updated_at_ms = now_ms;
            pg_update_effect(&mut tx, &effect)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Err("park retry limit exceeded; effect dead-lettered".into());
        }
        effect.park_generation = effect.park_generation.saturating_add(1);
        effect.park_count = effect.park_count.saturating_add(1);
        effect.status = EFFECT_STATUS_PARKED.into();
        effect.lifecycle_state = EFFECT_LIFECYCLE_AWAITING_CONTINUATION.into();
        effect.failure_reason = reason.into();
        effect.active_resolution_id.clear();
        effect.claim_expires_at_ms = 0;
        effect.updated_at_ms = now_ms;
        let park = ActionWorkPark {
            park_id: format!("park-{}", uuid::Uuid::new_v4().simple()),
            effect_id: effect.effect_id.clone(),
            namespace: effect.namespace.clone(),
            operation_id: effect.operation_id.clone(),
            park_generation: effect.park_generation,
            claim_generation: generation,
            checkpoint_ref: checkpoint_ref.into(),
            checkpoint_digest: checkpoint_digest.into(),
            reason: reason.into(),
            parked_by: parked_by.into(),
            parked_at_ms: now_ms,
            request_id: request_id.into(),
            request_digest,
            checkpoint_store_id: checkpoint_store_id.into(),
        };
        let generation_i64 = park.park_generation as i64;
        let body = serde_json::to_string(&park).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_action_work_parks
             (park_id,effect_id,park_generation,request_id,request_digest,body_json)
             VALUES ($1,$2,$3,$4,$5,$6)",
            &[
                &park.park_id,
                &park.effect_id,
                &generation_i64,
                &park.request_id,
                &park.request_digest,
                &body,
            ],
        )
        .map_err(|error| error.to_string())?;
        pg_update_effect(&mut tx, &effect)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(ParkResult {
            effect,
            park,
            replay: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_parked_resolution(
        &self,
        effect_id: &str,
        expected_park_generation: u64,
        input_json: &str,
        reason: &str,
        request_id: &str,
        submitted_by: &str,
        policy_version: &str,
        status: &str,
        approval_id: &str,
        now_ms: i64,
    ) -> Result<ResolutionResult, String> {
        use crate::sekai::action_effect::{
            EFFECT_LIFECYCLE_AWAITING_CONTINUATION, EFFECT_LIFECYCLE_READY, EFFECT_STATUS_PENDING,
        };
        validate_request_id(request_id)?;
        validate_reason(reason)?;
        let input_json = canonical_json(input_json)?;
        if !matches!(
            status,
            "denied" | "pending_execution" | "pending_approval" | "invoked"
        ) {
            return Err("invalid initial resolution action status".into());
        }
        let request_digest = sha256_digest(
            &serde_json::json!({
                "effect_id": effect_id,
                "expected_park_generation": expected_park_generation,
                "input_json": input_json,
                "reason": reason,
                "submitted_by": submitted_by,
            })
            .to_string(),
        );
        let generation_i64 = expected_park_generation as i64;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        if let Some(row) = tx
            .query_opt(
                "SELECT request_digest,body_json FROM sekai_parked_resolution_actions
             WHERE effect_id=$1 AND request_id=$2",
                &[&effect_id, &request_id],
            )
            .map_err(|error| error.to_string())?
        {
            let stored: String = row.get(0);
            if stored != request_digest {
                return Err("resolution action idempotency conflict".into());
            }
            let action =
                parse_pg_json::<ParkedWorkResolutionAction>(row.get(1), "resolution action")?;
            let effect = pg_load_effect(&mut tx, effect_id, false)?;
            let park = pg_load_park(&mut tx, effect_id, expected_park_generation)?;
            let continuation = pg_load_continuation(&mut tx, effect_id, expected_park_generation)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(ResolutionResult {
                effect,
                action,
                continuation,
                park,
                replay: true,
            });
        }
        let mut effect = pg_load_effect(&mut tx, effect_id, true)?;
        if effect.effective_lifecycle_state() != EFFECT_LIFECYCLE_AWAITING_CONTINUATION {
            return Err(format!(
                "effect is not awaiting continuation ({})",
                effect.status
            ));
        }
        if effect.park_generation != expected_park_generation {
            return Err("stale park generation".into());
        }
        let park = pg_load_park(&mut tx, effect_id, expected_park_generation)?;
        let input = ParkedWorkResolutionInput {
            resolution_input_id: format!("pri-{}", uuid::Uuid::new_v4().simple()),
            effect_id: effect_id.into(),
            park_generation: expected_park_generation,
            input_digest: sha256_digest(&input_json),
            input_json,
            reason: reason.into(),
            submitted_by: submitted_by.into(),
            submitted_at_ms: now_ms,
        };
        let input_body = serde_json::to_string(&input).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_parked_resolution_inputs
             (resolution_input_id,effect_id,park_generation,body_json) VALUES ($1,$2,$3,$4)",
            &[
                &input.resolution_input_id,
                &input.effect_id,
                &generation_i64,
                &input_body,
            ],
        )
        .map_err(|error| error.to_string())?;
        let mut action = ParkedWorkResolutionAction {
            resolution_action_id: format!("pra-{}", uuid::Uuid::new_v4().simple()),
            effect_id: effect_id.into(),
            namespace: effect.namespace.clone(),
            expected_park_generation,
            status: status.into(),
            policy_version: policy_version.into(),
            approval_id: approval_id.into(),
            decided_by: submitted_by.into(),
            created_at_ms: now_ms,
            invoked_at_ms: 0,
            resolution_input_id: input.resolution_input_id.clone(),
            request_id: request_id.into(),
            request_digest: request_digest.clone(),
        };
        let continuation = if status == "invoked" {
            pg_stale_competing_resolutions(
                &mut tx,
                effect_id,
                expected_park_generation,
                &action.resolution_action_id,
                submitted_by,
                now_ms,
            )?;
            action.invoked_at_ms = now_ms;
            let continuation =
                pg_materialize_continuation(&effect, &park, &input, &action, submitted_by, now_ms);
            pg_insert_continuation(&mut tx, &continuation)?;
            effect.status = EFFECT_STATUS_PENDING.into();
            effect.lifecycle_state = EFFECT_LIFECYCLE_READY.into();
            effect.active_resolution_id = continuation.resolution_id.clone();
            effect.updated_at_ms = now_ms;
            pg_update_effect(&mut tx, &effect)?;
            Some(continuation)
        } else {
            None
        };
        let action_body = serde_json::to_string(&action).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_parked_resolution_actions
             (resolution_action_id,effect_id,park_generation,request_id,request_digest,status,body_json)
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
            &[&action.resolution_action_id, &action.effect_id, &generation_i64, &action.request_id, &action.request_digest, &action.status, &action_body],
        ).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(ResolutionResult {
            effect,
            action,
            continuation,
            park,
            replay: false,
        })
    }

    pub fn invoke_parked_resolution(
        &self,
        resolution_action_id: &str,
        effect_id: &str,
        park_generation: u64,
        actor: &str,
        now_ms: i64,
    ) -> Result<ActionWorkContinuation, String> {
        use crate::sekai::action_effect::{
            EFFECT_LIFECYCLE_AWAITING_CONTINUATION, EFFECT_LIFECYCLE_READY, EFFECT_STATUS_PENDING,
        };
        let generation_i64 = park_generation as i64;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let row = tx
            .query_one(
                "SELECT body_json FROM sekai_parked_resolution_actions
             WHERE resolution_action_id=$1 AND effect_id=$2 AND park_generation=$3 FOR UPDATE",
                &[&resolution_action_id, &effect_id, &generation_i64],
            )
            .map_err(|_| "resolution action not found".to_string())?;
        let mut action =
            parse_pg_json::<ParkedWorkResolutionAction>(row.get(0), "resolution action")?;
        if action.status == "invoked" {
            let continuation = pg_load_continuation(&mut tx, effect_id, park_generation)?
                .ok_or_else(|| "invoked resolution is missing its continuation".to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(continuation);
        }
        if !matches!(
            action.status.as_str(),
            "pending_execution" | "execution_accounted"
        ) {
            return Err("resolution action is not invokable".into());
        }
        let mut effect = pg_load_effect(&mut tx, effect_id, true)?;
        if effect.effective_lifecycle_state() != EFFECT_LIFECYCLE_AWAITING_CONTINUATION
            || effect.park_generation != park_generation
        {
            return Err("resolution action is stale".into());
        }
        let input_row = tx
            .query_one(
                "SELECT body_json FROM sekai_parked_resolution_inputs WHERE resolution_input_id=$1",
                &[&action.resolution_input_id],
            )
            .map_err(|_| "resolution input not found".to_string())?;
        let input =
            parse_pg_json::<ParkedWorkResolutionInput>(input_row.get(0), "resolution input")?;
        let park = pg_load_park(&mut tx, effect_id, park_generation)?;
        let continuation =
            pg_materialize_continuation(&effect, &park, &input, &action, actor, now_ms);
        pg_insert_continuation(&mut tx, &continuation)?;
        pg_stale_competing_resolutions(
            &mut tx,
            effect_id,
            park_generation,
            &action.resolution_action_id,
            actor,
            now_ms,
        )?;
        action.status = "invoked".into();
        action.decided_by = actor.into();
        action.invoked_at_ms = now_ms;
        let action_body = serde_json::to_string(&action).map_err(|error| error.to_string())?;
        let updated = tx
            .execute(
                "UPDATE sekai_parked_resolution_actions SET status='invoked',body_json=$1
             WHERE resolution_action_id=$2
               AND status IN ('pending_execution','execution_accounted')",
                &[&action_body, &action.resolution_action_id],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("resolution action is not invokable".into());
        }
        effect.status = EFFECT_STATUS_PENDING.into();
        effect.lifecycle_state = EFFECT_LIFECYCLE_READY.into();
        effect.active_resolution_id = continuation.resolution_id.clone();
        effect.updated_at_ms = now_ms;
        pg_update_effect(&mut tx, &effect)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(continuation)
    }

    pub fn authorize_parked_resolution_approval(
        &self,
        resolution_action_id: &str,
        approval_id: &str,
    ) -> Result<(), String> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let row = tx
            .query_opt(
                "SELECT body_json FROM sekai_parked_resolution_actions
                 WHERE resolution_action_id=$1 FOR UPDATE",
                &[&resolution_action_id],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "resolution action not found".to_string())?;
        let mut action =
            parse_pg_json::<ParkedWorkResolutionAction>(row.get(0), "resolution action")?;
        if action.approval_id != approval_id {
            return Err("resolution approval binding mismatch".into());
        }
        if action.status == "execution_accounted" {
            return Ok(());
        }
        if action.status != "pending_approval" {
            return Err("resolution action is not awaiting approval".into());
        }
        action.status = "execution_accounted".into();
        let body = serde_json::to_string(&action).map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE sekai_parked_resolution_actions SET status='execution_accounted',body_json=$1
             WHERE resolution_action_id=$2 AND status='pending_approval'",
            &[&body, &resolution_action_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn bind_parked_resolution_approval(
        &self,
        resolution_action_id: &str,
        approval_id: &str,
    ) -> Result<(), String> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let row = tx
            .query_opt(
                "SELECT body_json FROM sekai_parked_resolution_actions
                 WHERE resolution_action_id=$1 FOR UPDATE",
                &[&resolution_action_id],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "resolution action not found".to_string())?;
        let mut action =
            parse_pg_json::<ParkedWorkResolutionAction>(row.get(0), "resolution action")?;
        if action.status == "pending_approval" && action.approval_id == approval_id {
            return Ok(());
        }
        if action.status != "pending_execution" {
            return Err("resolution action is not pending execution".into());
        }
        action.status = "pending_approval".into();
        action.approval_id = approval_id.into();
        let body = serde_json::to_string(&action).map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE sekai_parked_resolution_actions
             SET status='pending_approval',body_json=$1
             WHERE resolution_action_id=$2 AND status='pending_execution'",
            &[&body, &resolution_action_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn mark_parked_resolution_accounted(
        &self,
        resolution_action_id: &str,
    ) -> Result<(), String> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let row = tx
            .query_opt(
                "SELECT body_json FROM sekai_parked_resolution_actions
                 WHERE resolution_action_id=$1 FOR UPDATE",
                &[&resolution_action_id],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "resolution action not found".to_string())?;
        let mut action =
            parse_pg_json::<ParkedWorkResolutionAction>(row.get(0), "resolution action")?;
        if action.status == "execution_accounted" {
            return Ok(());
        }
        if action.status != "execution_reserved" {
            return Err("resolution action is not reserved for execution".into());
        }
        action.status = "execution_accounted".into();
        let body = serde_json::to_string(&action).map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE sekai_parked_resolution_actions SET status='execution_accounted',body_json=$1
             WHERE resolution_action_id=$2 AND status='execution_reserved'",
            &[&body, &resolution_action_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn reserve_parked_resolution_execution(
        &self,
        resolution_action_id: &str,
        effect_id: &str,
        park_generation: u64,
    ) -> Result<(), String> {
        use crate::sekai::action_effect::EFFECT_LIFECYCLE_AWAITING_CONTINUATION;
        let generation = park_generation as i64;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let effect = pg_load_effect(&mut tx, effect_id, true)?;
        if effect.effective_lifecycle_state() != EFFECT_LIFECYCLE_AWAITING_CONTINUATION
            || effect.park_generation != park_generation
        {
            return Err("resolution action is stale".into());
        }
        let row = tx
            .query_opt(
                "SELECT body_json FROM sekai_parked_resolution_actions
                 WHERE resolution_action_id=$1 AND effect_id=$2 AND park_generation=$3 FOR UPDATE",
                &[&resolution_action_id, &effect_id, &generation],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "resolution action not found".to_string())?;
        let mut action =
            parse_pg_json::<ParkedWorkResolutionAction>(row.get(0), "resolution action")?;
        if matches!(
            action.status.as_str(),
            "execution_reserved" | "execution_accounted"
        ) {
            return Ok(());
        }
        if action.status != "pending_execution" {
            return Err("resolution action is not pending execution".into());
        }
        let winner: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM sekai_parked_resolution_actions
                 WHERE effect_id=$1 AND park_generation=$2
                   AND status IN ('execution_reserved','execution_accounted')
                   AND resolution_action_id<>$3",
                &[&effect_id, &generation, &resolution_action_id],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if winner > 0 {
            return Err("another resolution action already reserved execution".into());
        }
        action.status = "execution_reserved".into();
        let body = serde_json::to_string(&action).map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE sekai_parked_resolution_actions SET status='execution_reserved',body_json=$1
             WHERE resolution_action_id=$2 AND status='pending_execution'",
            &[&body, &resolution_action_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn reject_parked_resolution(
        &self,
        approval_id: &str,
        status: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        if !matches!(status, "rejected" | "cancelled" | "stale") {
            return Err("invalid resolution rejection status".into());
        }
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let rows = tx
            .query(
                "SELECT body_json FROM sekai_parked_resolution_actions FOR UPDATE",
                &[],
            )
            .map_err(|error| error.to_string())?;
        let mut action = None;
        for row in rows {
            let candidate =
                parse_pg_json::<ParkedWorkResolutionAction>(row.get(0), "resolution action")?;
            if candidate.approval_id == approval_id {
                action = Some(candidate);
                break;
            }
        }
        let mut action = action.ok_or_else(|| "pending resolution action not found".to_string())?;
        if action.status == status {
            return Ok(());
        }
        if action.status != "pending_approval" {
            return Err("resolution action is already terminal".into());
        }
        action.status = status.into();
        action.decided_by = actor.into();
        action.invoked_at_ms = now_ms;
        let body = serde_json::to_string(&action).map_err(|error| error.to_string())?;
        let updated = tx
            .execute(
                "UPDATE sekai_parked_resolution_actions SET status=$1,body_json=$2
                 WHERE resolution_action_id=$3 AND status='pending_approval'",
                &[&status, &body, &action.resolution_action_id],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("pending resolution action not found".into());
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn get_active_continuation(
        &self,
        effect: &ActionEffect,
    ) -> Result<
        Option<(
            crate::sekai::parked_work::ActionWorkContinuation,
            crate::sekai::parked_work::ActionWorkPark,
        )>,
        String,
    > {
        if effect.active_resolution_id.is_empty() {
            return Ok(None);
        }
        let mut conn = self.connection()?;
        let row = conn
            .query_opt(
                "SELECT body_json FROM sekai_action_work_continuations WHERE resolution_id=$1",
                &[&effect.active_resolution_id],
            )
            .map_err(|error| error.to_string())?;
        let Some(row) = row else {
            return Err("active continuation missing".into());
        };
        let continuation = parse_pg_json::<ActionWorkContinuation>(row.get(0), "continuation")?;
        let row = conn
            .query_one(
                "SELECT body_json FROM sekai_action_work_parks WHERE park_id=$1",
                &[&continuation.park_id],
            )
            .map_err(|_| "park record missing".to_string())?;
        let park = parse_pg_json::<ActionWorkPark>(row.get(0), "park record")?;
        Ok(Some((continuation, park)))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn report_action_claim_event(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token: &str,
        kind: &str,
        checkpoint_digest: &str,
        reason_code: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        use crate::sekai::action_effect::EFFECT_STATUS_CLAIMED;
        validate_request_id(request_id)?;
        if !matches!(
            kind,
            "resume_started"
                | "resume_succeeded"
                | "checkpoint_unavailable"
                | "replacement_started"
        ) {
            return Err("invalid claim event kind".into());
        }
        if reason_code.len() > 128 || checkpoint_digest.len() > 71 {
            return Err("claim event metadata exceeds bounds".into());
        }
        let request_digest = sha256_digest(
            &serde_json::json!({
                "effect_id": effect_id, "runtime_id": runtime_id, "generation": generation,
                "kind": kind, "checkpoint_digest": checkpoint_digest, "reason_code": reason_code,
            })
            .to_string(),
        );
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        if let Some(row) = tx.query_opt(
            "SELECT request_digest FROM sekai_action_claim_events WHERE effect_id=$1 AND request_id=$2",
            &[&effect_id, &request_id],
        ).map_err(|error| error.to_string())? {
            let stored: String = row.get(0);
            if stored != request_digest {
                return Err("claim event idempotency conflict".into());
            }
            return Ok(true);
        }
        let effect = pg_load_effect(&mut tx, effect_id, true)?;
        if effect.status != EFFECT_STATUS_CLAIMED
            || effect.claim_expires_at_ms <= now_ms
            || !effect.fence_matches(runtime_id, generation, fencing_token)
        {
            return Err("claim event has no live matching fence".into());
        }
        let body = serde_json::json!({
            "effect_id": effect_id, "operation_id": effect.operation_id,
            "park_generation": effect.park_generation, "resolution_id": effect.active_resolution_id,
            "claim_generation": generation, "runtime_id": runtime_id, "kind": kind,
            "checkpoint_digest": checkpoint_digest, "reason_code": reason_code,
            "recorded_at_ms": now_ms,
        })
        .to_string();
        tx.execute(
            "INSERT INTO sekai_action_claim_events
             (effect_id,request_id,request_digest,body_json) VALUES ($1,$2,$3,$4)",
            &[&effect_id, &request_id, &request_digest, &body],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(false)
    }

    pub fn put_action_effect(&self, effect: &ActionEffect) -> Result<ActionEffect, String> {
        effect.validate()?;
        let body_json = serde_json::to_string(effect).map_err(|e| e.to_string())?;
        let pressure_runtime = pressure_runtime_for_postgres(effect);
        self.connection()?
            .execute(
                "INSERT INTO sekai_action_effects
                 (effect_id, instance_id, namespace, operation_id, kind, status,
                  payload_json, failure_reason, created_at_ms, updated_at_ms, body_json,
                  pressure_runtime, pressure_jsonb_compatible)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,TRUE)",
                &[
                    &effect.effect_id,
                    &effect.instance_id,
                    &effect.namespace,
                    &effect.operation_id,
                    &effect.kind,
                    &effect.status,
                    &effect.payload_json,
                    &effect.failure_reason,
                    &effect.created_at_ms,
                    &effect.updated_at_ms,
                    &body_json,
                    &pressure_runtime,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(effect.clone())
    }

    pub fn put_action_effects(
        &self,
        effects: &[ActionEffect],
    ) -> Result<Vec<ActionEffect>, String> {
        let mut out = Vec::with_capacity(effects.len());
        for effect in effects {
            out.push(self.put_action_effect(effect)?);
        }
        Ok(out)
    }

    pub fn get_action_effect(&self, effect_id: &str) -> Result<Option<ActionEffect>, String> {
        self.connection()?
            .query_opt(
                "SELECT body_json FROM sekai_action_effects WHERE effect_id = $1",
                &[&effect_id],
            )
            .map_err(|e| e.to_string())?
            .map(|row| {
                let body: String = row.get(0);
                serde_json::from_str(&body).map_err(|e| format!("corrupt action effect body: {e}"))
            })
            .transpose()
    }

    pub fn list_action_effects_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Vec<ActionEffect>, String> {
        let rows = self
            .connection()?
            .query(
                "SELECT body_json FROM sekai_action_effects
                 WHERE instance_id = $1
                 ORDER BY created_at_ms, effect_id",
                &[&instance_id],
            )
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let body: String = row.get(0);
            out.push(
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action effect body: {e}"))?,
            );
        }
        Ok(out)
    }

    pub fn list_pending_runtime_dispatch_effects(
        &self,
        namespace: &str,
        limit: usize,
    ) -> Result<Vec<ActionEffect>, String> {
        let limit = limit.clamp(1, 500) as i64;
        let kind = EFFECT_KIND_RUNTIME_DISPATCH;
        let status = EFFECT_STATUS_PENDING;
        let rows = self
            .connection()?
            .query(
                "SELECT body_json FROM sekai_action_effects
                 WHERE namespace = $1 AND kind = $2 AND status = $3
                 ORDER BY created_at_ms
                 LIMIT $4",
                &[&namespace, &kind, &status, &limit],
            )
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let body: String = row.get(0);
            out.push(
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action effect body: {e}"))?,
            );
        }
        Ok(out)
    }

    pub fn update_action_effect(
        &self,
        effect: &crate::sekai::action_effect::ActionEffect,
    ) -> Result<crate::sekai::action_effect::ActionEffect, String> {
        effect.validate()?;
        let body_json = serde_json::to_string(effect).map_err(|e| e.to_string())?;
        let pressure_runtime = pressure_runtime_for_postgres(effect);
        let pressure_jsonb_compatible = effect.jsonb_compatible();
        let updated = self
            .connection()?
            .execute(
                "UPDATE sekai_action_effects
                     SET status = $1, payload_json = $2, failure_reason = $3,
                     updated_at_ms = $4, body_json = $5, pressure_runtime = $6,
                     pressure_jsonb_compatible = $7
                 WHERE effect_id = $8",
                &[
                    &effect.status,
                    &effect.payload_json,
                    &effect.failure_reason,
                    &effect.updated_at_ms,
                    &body_json,
                    &pressure_runtime,
                    &pressure_jsonb_compatible,
                    &effect.effect_id,
                ],
            )
            .map_err(|e| e.to_string())?;
        if updated == 0 {
            return Err("action effect not found".into());
        }
        Ok(effect.clone())
    }

    pub fn list_claimable_action_work(
        &self,
        namespace: &str,
        runtime_id: Option<&str>,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<ActionEffect>, String> {
        let limit = limit.clamp(1, 500);
        let kind = EFFECT_KIND_RUNTIME_DISPATCH;
        let rows = self
            .connection()?
            .query(
                "SELECT body_json FROM sekai_action_effects
                 WHERE namespace = $1 AND kind = $2
                 ORDER BY created_at_ms
                 LIMIT 2000",
                &[&namespace, &kind],
            )
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let body: String = row.get(0);
            let effect: ActionEffect = serde_json::from_str(&body)
                .map_err(|e| format!("corrupt action effect body: {e}"))?;
            if !effect.is_claimable_at(now_ms) {
                continue;
            }
            if let Some(runtime_id) = runtime_id.filter(|r| !runtime_id_is_blank(r)) {
                let payload: serde_json::Value =
                    serde_json::from_str(&effect.payload_json).unwrap_or(serde_json::json!({}));
                let runtime = payload
                    .get("runtime")
                    .and_then(|v| v.as_str())
                    .filter(|runtime| !runtime_id_is_blank(runtime))
                    .unwrap_or("default");
                if runtime != runtime_id {
                    continue;
                }
            }
            out.push(effect);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// Aggregate pressure for one namespace/runtime without loading effect
    /// bodies or task payloads into the process.
    pub fn runtime_work_pressure(
        &self,
        namespace: &str,
        runtime_id: &str,
        sampled_at_ms: i64,
    ) -> Result<RuntimeWorkPressure, String> {
        RuntimeWorkPressure::validate_scope(namespace, runtime_id)?;
        let kind = EFFECT_KIND_RUNTIME_DISPATCH;
        let mut connection = self.connection()?;
        let rows = connection
            .query_one(
                "SELECT
                    (SELECT EXISTS (
                         SELECT 1
                         FROM sekai_action_effects AS compatibility
                         WHERE compatibility.namespace = $1
                           AND compatibility.kind = $2
                           AND NOT compatibility.pressure_jsonb_compatible
                     )),
                    COALESCE(SUM(CASE
                        WHEN status = 'pending'
                          OR (status = 'claimed'
                              AND COALESCE((body_json::jsonb ->> 'claim_expires_at_ms')::BIGINT, 0) > 0
                              AND COALESCE((body_json::jsonb ->> 'claim_expires_at_ms')::BIGINT, 0) <= $4)
                        THEN 1 ELSE 0 END), 0),
                    MIN(CASE
                        WHEN status = 'pending'
                          OR (status = 'claimed'
                              AND COALESCE((body_json::jsonb ->> 'claim_expires_at_ms')::BIGINT, 0) > 0
                              AND COALESCE((body_json::jsonb ->> 'claim_expires_at_ms')::BIGINT, 0) <= $4)
                        THEN created_at_ms END),
                    COALESCE(SUM(CASE
                        WHEN status = 'claimed'
                         AND COALESCE((body_json::jsonb ->> 'claim_expires_at_ms')::BIGINT, 0) > $4
                        THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE
                        WHEN status = 'claimed'
                         AND COALESCE((body_json::jsonb ->> 'claim_expires_at_ms')::BIGINT, 0) > 0
                         AND COALESCE((body_json::jsonb ->> 'claim_expires_at_ms')::BIGINT, 0) <= $4
                        THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status = 'parked' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN status = 'dead_lettered' THEN 1 ELSE 0 END), 0)
                 FROM sekai_action_effects
                 WHERE namespace = $1
                   AND kind = $2
                   AND left(pressure_runtime, 128) = left($3, 128)
                   AND pressure_runtime = $3",
                &[&namespace, &kind, &runtime_id, &sampled_at_ms],
            )
            .map_err(|e| e.to_string())?;
        let has_jsonb_incompatible_effect: bool = rows.get(0);
        if has_jsonb_incompatible_effect {
            return Err(
                "runtime work pressure contains an effect unsupported by PostgreSQL jsonb".into(),
            );
        }
        let aggregate = RuntimeWorkPressureAggregate {
            claimable_count: aggregate_count(rows.get::<_, i64>(1)),
            oldest_claimable_created_at_ms: rows.get(2),
            active_claim_count: aggregate_count(rows.get::<_, i64>(3)),
            expired_claim_count: aggregate_count(rows.get::<_, i64>(4)),
            parked_count: aggregate_count(rows.get::<_, i64>(5)),
            failed_count: aggregate_count(rows.get::<_, i64>(6)),
            dead_lettered_count: aggregate_count(rows.get::<_, i64>(7)),
        };
        Ok(RuntimeWorkPressure::from_aggregate(
            namespace,
            runtime_id,
            sampled_at_ms,
            aggregate,
        ))
    }

    pub fn claim_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        request_id: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<ActionEffect, String> {
        use crate::sekai::action_effect::{
            EFFECT_LIFECYCLE_CLAIMED, EFFECT_LIFECYCLE_DEAD_LETTERED, EFFECT_STATUS_CLAIMED,
            EFFECT_STATUS_DEAD_LETTERED,
        };
        use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;
        if runtime_id_is_blank(runtime_id) {
            return Err("runtime_id required".into());
        }
        if request_id.trim().is_empty() {
            return Err("request_id required".into());
        }
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let mut effect = pg_load_effect(&mut tx, effect_id, true)?;
        let legacy_replay = effect.claim_expires_at_ms > now_ms
            && effect.legacy_claim_replay_matches(runtime_id, request_id);
        if !legacy_replay {
            validate_no_nul("runtime_id", runtime_id)?;
            validate_no_nul("request_id", request_id)?;
        }
        if effect.kind != EFFECT_KIND_RUNTIME_DISPATCH {
            return Err("only runtime_dispatch effects are claimable".into());
        }
        if effect.status == EFFECT_STATUS_CLAIMED
            && effect.claim_owner == runtime_id
            && effect.claim_request_id == request_id
            && effect.claim_expires_at_ms > now_ms
        {
            return Ok(effect);
        }
        if !effect.is_claimable_at(now_ms) {
            if effect.status == EFFECT_STATUS_CLAIMED && effect.claim_expires_at_ms > now_ms {
                return Err(format!("effect already claimed by {}", effect.claim_owner));
            }
            return Err(format!("effect not claimable in status {}", effect.status));
        }
        if effect.status == EFFECT_STATUS_CLAIMED && effect.claim_expires_at_ms <= now_ms {
            effect.lease_expiry_count = effect.lease_expiry_count.saturating_add(1);
            if effect.max_lease_expiries > 0
                && effect.lease_expiry_count >= effect.max_lease_expiries
            {
                effect.status = EFFECT_STATUS_DEAD_LETTERED.into();
                effect.lifecycle_state = EFFECT_LIFECYCLE_DEAD_LETTERED.into();
                effect.failure_reason = "lease_expiry_limit_exceeded".into();
                effect.updated_at_ms = now_ms;
                pg_update_effect(&mut tx, &effect)?;
                tx.commit().map_err(|error| error.to_string())?;
                return Err("lease expiry retry limit exceeded; effect dead-lettered".into());
            }
        }
        if effect.max_claim_attempts > 0 && effect.claim_attempt_count >= effect.max_claim_attempts
        {
            effect.status = EFFECT_STATUS_DEAD_LETTERED.into();
            effect.lifecycle_state = EFFECT_LIFECYCLE_DEAD_LETTERED.into();
            effect.failure_reason = "claim_attempt_limit_exceeded".into();
            effect.updated_at_ms = now_ms;
            pg_update_effect(&mut tx, &effect)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Err("claim retry limit exceeded; effect dead-lettered".into());
        }
        let generation = effect.claim_generation.saturating_add(1).max(1);
        let ttl = if ttl_ms <= 0 { 60_000 } else { ttl_ms };
        if ttl > 24 * 60 * 60 * 1_000 {
            return Err("ttl_ms exceeds max".into());
        }
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(effect_id.as_bytes());
        hasher.update(b":");
        hasher.update(generation.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(runtime_id.as_bytes());
        let token = format!("fx-{:x}", hasher.finalize());
        effect.status = EFFECT_STATUS_CLAIMED.into();
        effect.lifecycle_state = EFFECT_LIFECYCLE_CLAIMED.into();
        effect.claim_attempt_count = effect.claim_attempt_count.saturating_add(1);
        effect.claim_owner = runtime_id.into();
        effect.claim_generation = generation;
        effect.claim_fencing_token = token;
        effect.claim_expires_at_ms = now_ms.saturating_add(ttl);
        effect.claim_request_id = request_id.into();
        effect.updated_at_ms = now_ms;
        effect.failure_reason.clear();
        pg_update_effect(&mut tx, &effect)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(effect)
    }

    pub fn heartbeat_action_claim(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token_in: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<ActionEffect, String> {
        use crate::sekai::action_effect::EFFECT_STATUS_CLAIMED;
        let ttl = if ttl_ms <= 0 { 60_000 } else { ttl_ms };
        if ttl > 24 * 60 * 60 * 1_000 {
            return Err("ttl_ms exceeds max".into());
        }
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let mut effect = pg_load_effect(&mut tx, effect_id, true)?;
        if !effect.legacy_claim_fence_matches(runtime_id, fencing_token_in) {
            validate_no_nul("runtime_id", runtime_id)?;
            validate_no_nul("fencing_token", fencing_token_in)?;
        }
        if effect.status != EFFECT_STATUS_CLAIMED {
            return Err(format!("effect not claimed (status={})", effect.status));
        }
        if effect.claim_expires_at_ms <= now_ms {
            return Err("claim lease expired".into());
        }
        if !effect.fence_matches(runtime_id, generation, fencing_token_in) {
            return Err("fencing token or generation mismatch".into());
        }
        effect.claim_expires_at_ms = now_ms.saturating_add(ttl);
        effect.updated_at_ms = now_ms;
        pg_update_effect(&mut tx, &effect)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(effect)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ack_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token_in: &str,
        outcome: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<ActionEffect, String> {
        use crate::sekai::action_effect::{
            ACK_OUTCOME_COMPLETED, ACK_OUTCOME_FAILED, EFFECT_LIFECYCLE_AWAITING_CONTINUATION,
            EFFECT_LIFECYCLE_COMPLETED, EFFECT_LIFECYCLE_FAILED, EFFECT_STATUS_CLAIMED,
            EFFECT_STATUS_COMPLETED, EFFECT_STATUS_FAILED, EFFECT_STATUS_PARKED,
        };
        use crate::sekai::governed_action_type::EFFECT_KIND_RUNTIME_DISPATCH;
        validate_no_nul("reason", reason)?;
        let status = match outcome {
            ACK_OUTCOME_COMPLETED => EFFECT_STATUS_COMPLETED,
            ACK_OUTCOME_FAILED => EFFECT_STATUS_FAILED,
            other => {
                return Err(format!(
                    "invalid ack outcome {other:?}; parked requires park_action_work"
                ));
            }
        };
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let mut effect = pg_load_effect(&mut tx, effect_id, true)?;
        if effect.kind != EFFECT_KIND_RUNTIME_DISPATCH {
            return Err("only runtime_dispatch effects support ack".into());
        }
        let legacy_ack_replay = effect.legacy_claim_fence_matches(runtime_id, fencing_token_in)
            || (effect.status == status
                && effect.legacy_claim_terminal_replay_matches(runtime_id, fencing_token_in));
        if !legacy_ack_replay {
            validate_no_nul("runtime_id", runtime_id)?;
            validate_no_nul("fencing_token", fencing_token_in)?;
        }
        if effect.status == status {
            return Ok(effect);
        }
        if effect.status != EFFECT_STATUS_CLAIMED {
            return Err(format!("effect not claimed (status={})", effect.status));
        }
        if effect.claim_expires_at_ms <= now_ms {
            return Err("claim lease expired".into());
        }
        if !effect.fence_matches(runtime_id, generation, fencing_token_in) {
            return Err("fencing token or generation mismatch".into());
        }
        effect.status = status.into();
        effect.lifecycle_state = match status {
            EFFECT_STATUS_COMPLETED => EFFECT_LIFECYCLE_COMPLETED,
            EFFECT_STATUS_FAILED => EFFECT_LIFECYCLE_FAILED,
            EFFECT_STATUS_PARKED => EFFECT_LIFECYCLE_AWAITING_CONTINUATION,
            _ => status,
        }
        .into();
        effect.failure_reason = reason.to_string();
        effect.updated_at_ms = now_ms;
        pg_update_effect(&mut tx, &effect)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(effect)
    }
}

fn parse_pg_json<T: serde::de::DeserializeOwned>(body: String, label: &str) -> Result<T, String> {
    serde_json::from_str(&body).map_err(|error| format!("corrupt {label}: {error}"))
}

fn pg_checkpoint_store_allowed(store_id: &str) -> bool {
    std::env::var("SEKAI_CHECKPOINT_STORES")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|configured| configured == store_id)
        })
        .unwrap_or(false)
}

fn pressure_runtime_for_postgres(effect: &ActionEffect) -> String {
    match canonical_runtime_from_payload(&effect.payload_json) {
        Ok(runtime) if !runtime.contains('\0') => runtime,
        _ => "invalid".into(),
    }
}

fn pg_load_effect(
    tx: &mut postgres::Transaction<'_>,
    effect_id: &str,
    lock: bool,
) -> Result<ActionEffect, String> {
    let sql = if lock {
        "SELECT body_json FROM sekai_action_effects WHERE effect_id=$1 FOR UPDATE"
    } else {
        "SELECT body_json FROM sekai_action_effects WHERE effect_id=$1"
    };
    let row = tx
        .query_opt(sql, &[&effect_id])
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "action effect not found".to_string())?;
    parse_pg_json(row.get(0), "action effect")
}

fn pg_update_effect(
    tx: &mut postgres::Transaction<'_>,
    effect: &ActionEffect,
) -> Result<(), String> {
    effect.validate_for_lifecycle_update()?;
    let body = serde_json::to_string(effect).map_err(|error| error.to_string())?;
    let pressure_runtime = pressure_runtime_for_postgres(effect);
    let pressure_jsonb_compatible = effect.jsonb_compatible();
    let updated = tx
        .execute(
            "UPDATE sekai_action_effects SET status=$1,payload_json=$2,failure_reason=$3,
             updated_at_ms=$4,body_json=$5,pressure_runtime=$6,
             pressure_jsonb_compatible=$7 WHERE effect_id=$8",
            &[
                &effect.status,
                &effect.payload_json,
                &effect.failure_reason,
                &effect.updated_at_ms,
                &body,
                &pressure_runtime,
                &pressure_jsonb_compatible,
                &effect.effect_id,
            ],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err("action effect not found".into());
    }
    Ok(())
}

fn pg_load_park(
    tx: &mut postgres::Transaction<'_>,
    effect_id: &str,
    park_generation: u64,
) -> Result<ActionWorkPark, String> {
    let generation = park_generation as i64;
    let row = tx
        .query_opt(
            "SELECT body_json FROM sekai_action_work_parks
             WHERE effect_id=$1 AND park_generation=$2",
            &[&effect_id, &generation],
        )
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "park record not found".to_string())?;
    parse_pg_json(row.get(0), "park record")
}

fn pg_load_continuation(
    tx: &mut postgres::Transaction<'_>,
    effect_id: &str,
    park_generation: u64,
) -> Result<Option<ActionWorkContinuation>, String> {
    let generation = park_generation as i64;
    tx.query_opt(
        "SELECT body_json FROM sekai_action_work_continuations
         WHERE effect_id=$1 AND park_generation=$2",
        &[&effect_id, &generation],
    )
    .map_err(|error| error.to_string())?
    .map(|row| parse_pg_json(row.get(0), "continuation"))
    .transpose()
}

fn pg_stale_competing_resolutions(
    tx: &mut postgres::Transaction<'_>,
    effect_id: &str,
    park_generation: u64,
    winning_action_id: &str,
    actor: &str,
    now_ms: i64,
) -> Result<(), String> {
    let generation = park_generation as i64;
    let rows = tx
        .query(
            "SELECT body_json FROM sekai_parked_resolution_actions
             WHERE effect_id=$1 AND park_generation=$2
               AND status IN ('pending_execution','execution_reserved','execution_accounted','pending_approval')
               AND resolution_action_id<>$3 FOR UPDATE",
            &[&effect_id, &generation, &winning_action_id],
        )
        .map_err(|error| error.to_string())?;
    for row in rows {
        let mut action =
            parse_pg_json::<ParkedWorkResolutionAction>(row.get(0), "resolution action")?;
        action.status = "stale".into();
        action.decided_by = actor.into();
        action.invoked_at_ms = now_ms;
        let body = serde_json::to_string(&action).map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE sekai_parked_resolution_actions SET status='stale',body_json=$1
             WHERE resolution_action_id=$2
               AND status IN ('pending_execution','execution_reserved','execution_accounted','pending_approval')",
            &[&body, &action.resolution_action_id],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn pg_materialize_continuation(
    effect: &ActionEffect,
    park: &ActionWorkPark,
    input: &ParkedWorkResolutionInput,
    action: &ParkedWorkResolutionAction,
    actor: &str,
    now_ms: i64,
) -> ActionWorkContinuation {
    ActionWorkContinuation {
        resolution_id: format!("res-{}", uuid::Uuid::new_v4().simple()),
        effect_id: effect.effect_id.clone(),
        namespace: effect.namespace.clone(),
        operation_id: effect.operation_id.clone(),
        park_generation: park.park_generation,
        input_json: input.input_json.clone(),
        input_digest: input.input_digest.clone(),
        park_id: park.park_id.clone(),
        resolution_action_id: action.resolution_action_id.clone(),
        resolution_input_id: input.resolution_input_id.clone(),
        reason: input.reason.clone(),
        decided_by: actor.into(),
        decided_at_ms: now_ms,
        request_id: action.request_id.clone(),
    }
}

fn pg_insert_continuation(
    tx: &mut postgres::Transaction<'_>,
    continuation: &ActionWorkContinuation,
) -> Result<(), String> {
    let generation = continuation.park_generation as i64;
    let body = serde_json::to_string(continuation).map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_action_work_continuations
         (resolution_id,effect_id,park_generation,body_json) VALUES ($1,$2,$3,$4)",
        &[
            &continuation.resolution_id,
            &continuation.effect_id,
            &generation,
            &body,
        ],
    )
    .map_err(|error| {
        if error.to_string().contains("duplicate key") {
            "park generation already resolved".into()
        } else {
            error.to_string()
        }
    })?;
    Ok(())
}
