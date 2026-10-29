//! Dual-backend community-store dispatch for transforms.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn put_governed_transform(
        &self,
        transform: &crate::sekai::governed_transform::GovernedTransform,
        created_at_ms: i64,
    ) -> Result<(), String> {
        self.put_governed_transform_owned(transform, created_at_ms, "")
    }

    /// See [`crate::db::sekai::SekaiDb::put_governed_transform_read_as`].
    pub fn put_governed_transform_read_as(
        &self,
        transform: &crate::sekai::governed_transform::GovernedTransform,
        created_at_ms: i64,
        tenant_id: &str,
        reader: Option<&str>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.put_governed_transform_read_as(transform, created_at_ms, tenant_id, reader)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_governed_transform_read_as(transform, created_at_ms, tenant_id, reader)
            }),
        }
    }

    pub fn put_governed_transform_owned(
        &self,
        transform: &crate::sekai::governed_transform::GovernedTransform,
        created_at_ms: i64,
        tenant_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.put_governed_transform_owned(transform, created_at_ms, tenant_id)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_governed_transform_owned(transform, created_at_ms, tenant_id)
            }),
        }
    }

    pub fn get_governed_transform(
        &self,
        namespace: &str,
        transform_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::GovernedTransform>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_transform(namespace, transform_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_governed_transform(namespace, transform_id)
            }),
        }
    }

    pub fn admitted_isolated_transform(
        &self,
        run_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::GovernedTransform>, String> {
        match self {
            Self::Sqlite(db) => db.admitted_isolated_transform(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.admitted_isolated_transform(run_id))
            }
        }
    }

    pub fn run_governed_transform(
        &self,
        namespace: &str,
        transform_id: &str,
        incremental: bool,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_transform::TransformRun, String> {
        self.run_governed_transform_owned(namespace, transform_id, incremental, now_ms, "", "")
    }

    /// See [`crate::db::sekai::SekaiDb::load_object_set_pin`].
    pub fn load_object_set_pin(
        &self,
        namespace: &str,
        alias: &str,
        digest: &str,
        budget: &mut crate::sekai::governed_transform::InputLoadBudget,
    ) -> Result<Option<crate::sekai::object_set_input::PinnedObjectSet>, String> {
        match self {
            Self::Sqlite(db) => db.load_object_set_pin(namespace, alias, digest, budget),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.load_object_set_pin(namespace, alias, digest, budget)
            }),
        }
    }

    /// See [`crate::db::sekai::SekaiDb::object_set_pin_at`].
    pub fn object_set_pin_at(
        &self,
        namespace: &str,
        transform_id: &str,
        alias: &str,
        as_of_ms: i64,
    ) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.object_set_pin_at(namespace, transform_id, alias, as_of_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.object_set_pin_at(namespace, transform_id, alias, as_of_ms)
            }),
        }
    }

    /// See [`crate::db::sekai::SekaiDb::set_transform_reader`].
    pub fn set_transform_reader(
        &self,
        namespace: &str,
        transform_id: &str,
        principal: &str,
        definition_digest: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.set_transform_reader(namespace, transform_id, principal, definition_digest)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_transform_reader(namespace, transform_id, principal, definition_digest)
            }),
        }
    }

    /// See [`crate::db::sekai::SekaiDb::transform_reader`].
    pub fn transform_reader(
        &self,
        namespace: &str,
        transform_id: &str,
    ) -> Result<Option<(String, String)>, String> {
        match self {
            Self::Sqlite(db) => db.transform_reader(namespace, transform_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.transform_reader(namespace, transform_id))
            }
        }
    }

    /// See [`crate::db::sekai::SekaiDb::run_governed_transform_with_object_sets`].
    pub fn run_governed_transform_with_object_sets(
        &self,
        namespace: &str,
        transform_id: &str,
        object_sets: &[crate::sekai::object_set_input::PinnedObjectSet],
        now_ms: i64,
        tenant_id: &str,
        expected_definition_digest: &str,
    ) -> Result<crate::sekai::governed_transform::TransformRun, String> {
        match self {
            Self::Sqlite(db) => db.run_governed_transform_with_object_sets(
                namespace,
                transform_id,
                object_sets,
                now_ms,
                tenant_id,
                expected_definition_digest,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.run_governed_transform_with_object_sets(
                    namespace,
                    transform_id,
                    object_sets,
                    now_ms,
                    tenant_id,
                    expected_definition_digest,
                )
            }),
        }
    }

    pub fn run_governed_transform_owned(
        &self,
        namespace: &str,
        transform_id: &str,
        incremental: bool,
        now_ms: i64,
        tenant_id: &str,
        expected_definition_digest: &str,
    ) -> Result<crate::sekai::governed_transform::TransformRun, String> {
        match self {
            Self::Sqlite(db) => db.run_governed_transform_owned(
                namespace,
                transform_id,
                incremental,
                now_ms,
                tenant_id,
                expected_definition_digest,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.run_governed_transform_owned(
                    namespace,
                    transform_id,
                    incremental,
                    now_ms,
                    tenant_id,
                    expected_definition_digest,
                )
            }),
        }
    }

    pub fn get_governed_transform_run(
        &self,
        run_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::TransformRun>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_transform_run(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_governed_transform_run(run_id))
            }
        }
    }

    pub fn list_governed_transforms(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::governed_transform::GovernedTransform>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_transforms(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_governed_transforms(namespace))
            }
        }
    }

    pub fn list_governed_transform_runs(
        &self,
        namespace: &str,
        limit: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::TransformRun>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_transform_runs(namespace, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_governed_transform_runs(namespace, limit)
            }),
        }
    }

    /// Admits unowned in-process work. Owned Put-tenant in-process work is
    /// listed by [`Self::list_due_owned_in_process_transforms`] and committed
    /// after Tick admits on `quota_runtime()`.
    pub fn tick_governed_transforms(
        &self,
        now_ms: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::TransformRun>, String> {
        match self {
            Self::Sqlite(db) => db.tick_governed_transforms(now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.tick_governed_transforms(now_ms))
            }
        }
    }

    pub fn list_due_owned_in_process_transforms(
        &self,
        now_ms: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::DueOwnedInProcessTransform>, String> {
        match self {
            Self::Sqlite(db) => db.list_due_owned_in_process_transforms(now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_due_owned_in_process_transforms(now_ms))
            }
        }
    }

    pub fn commit_due_owned_in_process_transform(
        &self,
        namespace: &str,
        transform_id: &str,
        now_ms: i64,
        expected_tenant_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::TransformRun>, String> {
        match self {
            Self::Sqlite(db) => db.commit_due_owned_in_process_transform(
                namespace,
                transform_id,
                now_ms,
                expected_tenant_id,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.commit_due_owned_in_process_transform(
                    namespace,
                    transform_id,
                    now_ms,
                    expected_tenant_id,
                )
            }),
        }
    }

    pub fn get_transform_output_state(
        &self,
        namespace: &str,
        dataset_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::TransformOutputState>, String> {
        match self {
            Self::Sqlite(db) => db.get_transform_output_state(namespace, dataset_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_transform_output_state(namespace, dataset_id)
            }),
        }
    }

    pub fn set_transform_namespace_concurrency(
        &self,
        namespace: &str,
        max_concurrent: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_transform_namespace_concurrency(namespace, max_concurrent),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_transform_namespace_concurrency(namespace, max_concurrent)
            }),
        }
    }

    pub fn note_source_change(
        &self,
        namespace: &str,
        object_or_dataset_ids: &[String],
        cause: &str,
        cause_ref: &str,
        now_ms: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::TransformRun>, String> {
        match self {
            Self::Sqlite(db) => {
                db.note_source_change(namespace, object_or_dataset_ids, cause, cause_ref, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.note_source_change(namespace, object_or_dataset_ids, cause, cause_ref, now_ms)
            }),
        }
    }

    pub fn cancel_governed_transform_run(
        &self,
        run_id: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_transform::TransformRun, String> {
        match self {
            Self::Sqlite(db) => db.cancel_governed_transform_run(run_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.cancel_governed_transform_run(run_id, now_ms)
            }),
        }
    }

    pub fn register_transform_runtime(
        &self,
        namespace: &str,
        runtime_id: &str,
        labels: &std::collections::BTreeMap<String, String>,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_transform::TransformRuntime, String> {
        match self {
            Self::Sqlite(db) => {
                db.register_transform_runtime(namespace, runtime_id, labels, actor, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.register_transform_runtime(namespace, runtime_id, labels, actor, now_ms)
            }),
        }
    }

    /// Transform work queue depth per worker pool (#1732).
    pub fn transform_pool_depths(
        &self,
        now_ms: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::TransformPoolDepth>, String> {
        match self {
            Self::Sqlite(db) => db.transform_pool_depths(now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.transform_pool_depths(now_ms))
            }
        }
    }

    pub fn list_claimable_transform_work(
        &self,
        namespace: &str,
        runtime_id: &str,
        now_ms: i64,
        limit: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::TransformWork>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_claimable_transform_work(namespace, runtime_id, now_ms, limit)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_claimable_transform_work(namespace, runtime_id, now_ms, limit)
            }),
        }
    }

    pub fn claim_transform_work(
        &self,
        namespace: &str,
        runtime_id: &str,
        run_id: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<
        Option<(
            crate::sekai::governed_transform::TransformWork,
            crate::sekai::governed_transform::GovernedTransform,
        )>,
        String,
    > {
        match self {
            Self::Sqlite(db) => {
                db.claim_transform_work(namespace, runtime_id, run_id, ttl_ms, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.claim_transform_work(namespace, runtime_id, run_id, ttl_ms, now_ms)
            }),
        }
    }

    pub fn claim_transform_work_outcome(
        &self,
        namespace: &str,
        runtime_id: &str,
        run_id: &str,
        ttl_ms: i64,
        now_ms: i64,
        skip_run_ids: &[String],
    ) -> Result<crate::sekai::governed_transform::ClaimTransformWorkOutcome, String> {
        match self {
            Self::Sqlite(db) => db.claim_transform_work_outcome(
                namespace,
                runtime_id,
                run_id,
                ttl_ms,
                now_ms,
                skip_run_ids,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.claim_transform_work_outcome(
                    namespace,
                    runtime_id,
                    run_id,
                    ttl_ms,
                    now_ms,
                    skip_run_ids,
                )
            }),
        }
    }

    pub fn refuse_transform_claim(
        &self,
        run_id: &str,
        runtime_id: &str,
        claim_generation: i64,
        fencing_token: &str,
        refusal: &crate::enterprise::IsolatedProcessRefusal,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.refuse_transform_claim(
                run_id,
                runtime_id,
                claim_generation,
                fencing_token,
                refusal,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.refuse_transform_claim(
                    run_id,
                    runtime_id,
                    claim_generation,
                    fencing_token,
                    refusal,
                    now_ms,
                )
            }),
        }
    }

    /// When the run finished and how long it computed (#1651).
    pub fn transform_run_output_version(&self, run_id: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.transform_run_output_version(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.transform_run_output_version(run_id))
            }
        }
    }

    pub fn list_runs_of_governed_transform(
        &self,
        namespace: &str,
        transform_id: &str,
        limit: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::TransformRun>, String> {
        match self {
            Self::Sqlite(db) => db.list_runs_of_governed_transform(namespace, transform_id, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_runs_of_governed_transform(namespace, transform_id, limit)
            }),
        }
    }

    pub fn transform_run_finish(&self, run_id: &str) -> Result<Option<(i64, Option<i64>)>, String> {
        match self {
            Self::Sqlite(db) => db.transform_run_finish(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.transform_run_finish(run_id))
            }
        }
    }

    pub fn transform_run_refusal(
        &self,
        run_id: &str,
    ) -> Result<Option<crate::enterprise::IsolatedProcessRefusal>, String> {
        match self {
            Self::Sqlite(db) => db.transform_run_refusal(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.transform_run_refusal(run_id))
            }
        }
    }

    pub fn release_transform_claim(
        &self,
        run_id: &str,
        runtime_id: &str,
        claim_generation: i64,
        fencing_token: &str,
        now_ms: i64,
        restore_lease_expiry: bool,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.release_transform_claim(
                run_id,
                runtime_id,
                claim_generation,
                fencing_token,
                now_ms,
                restore_lease_expiry,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.release_transform_claim(
                    run_id,
                    runtime_id,
                    claim_generation,
                    fencing_token,
                    now_ms,
                    restore_lease_expiry,
                )
            }),
        }
    }

    pub fn put_transform_quota_hold(
        &self,
        run_id: &str,
        tenant_id: &str,
        reserved_concurrency: bool,
        claim_generation: i64,
        fencing_token: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.put_transform_quota_hold(
                run_id,
                tenant_id,
                reserved_concurrency,
                claim_generation,
                fencing_token,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_transform_quota_hold(
                    run_id,
                    tenant_id,
                    reserved_concurrency,
                    claim_generation,
                    fencing_token,
                )
            }),
        }
    }

    pub fn restore_transform_quota_hold(
        &self,
        run_id: &str,
        tenant_id: &str,
        reserved_concurrency: bool,
        claim_generation: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.restore_transform_quota_hold(
                run_id,
                tenant_id,
                reserved_concurrency,
                claim_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.restore_transform_quota_hold(
                    run_id,
                    tenant_id,
                    reserved_concurrency,
                    claim_generation,
                )
            }),
        }
    }

    pub fn restore_abandoned_quota_hold(
        &self,
        run_id: &str,
        tenant_id: &str,
        reserved_concurrency: bool,
        refund_request: bool,
        refund_tokens: i32,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.restore_abandoned_quota_hold(
                run_id,
                tenant_id,
                reserved_concurrency,
                refund_request,
                refund_tokens,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.restore_abandoned_quota_hold(
                    run_id,
                    tenant_id,
                    reserved_concurrency,
                    refund_request,
                    refund_tokens,
                )
            }),
        }
    }

    pub fn reclaim_transform_quota_hold(
        &self,
        run_id: &str,
        claim_generation: i64,
        fencing_token: &str,
    ) -> Result<Option<(String, bool, i64)>, String> {
        match self {
            Self::Sqlite(db) => {
                db.reclaim_transform_quota_hold(run_id, claim_generation, fencing_token)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reclaim_transform_quota_hold(run_id, claim_generation, fencing_token)
            }),
        }
    }

    pub fn take_transform_quota_hold(
        &self,
        run_id: &str,
        claim_generation: Option<i64>,
        older_than: bool,
    ) -> Result<Option<(String, bool, i64)>, String> {
        match self {
            Self::Sqlite(db) => db.take_transform_quota_hold(run_id, claim_generation, older_than),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.take_transform_quota_hold(run_id, claim_generation, older_than)
            }),
        }
    }

    pub fn take_retryable_quota_hold(
        &self,
        run_id: &str,
        claim_generation: i64,
    ) -> Result<Option<crate::db::governed_transform::TakenTransformQuotaHold>, String> {
        match self {
            Self::Sqlite(db) => db.take_retryable_quota_hold(run_id, claim_generation),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.take_retryable_quota_hold(run_id, claim_generation)
            }),
        }
    }

    pub fn list_retryable_quota_holds(&self) -> Result<Vec<(String, String, bool, i64)>, String> {
        match self {
            Self::Sqlite(db) => db.list_retryable_quota_holds(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_retryable_quota_holds())
            }
        }
    }

    pub fn peek_transform_quota_hold(
        &self,
        run_id: &str,
        claim_generation: i64,
    ) -> Result<Option<(String, bool, i64)>, String> {
        match self {
            Self::Sqlite(db) => db.peek_transform_quota_hold(run_id, claim_generation),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.peek_transform_quota_hold(run_id, claim_generation)
            }),
        }
    }

    pub fn defer_transform_work(&self, run_id: &str, now_ms: i64) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.defer_transform_work(run_id, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.defer_transform_work(run_id, now_ms))
            }
        }
    }

    pub fn bind_transform_work_tenant(
        &self,
        run_id: &str,
        tenant_id: &str,
        claim_generation: i64,
        fencing_token: &str,
    ) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => {
                db.bind_transform_work_tenant(run_id, tenant_id, claim_generation, fencing_token)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.bind_transform_work_tenant(run_id, tenant_id, claim_generation, fencing_token)
            }),
        }
    }

    pub fn list_transform_usage_pending(&self) -> Result<Vec<(String, String, i64)>, String> {
        match self {
            Self::Sqlite(db) => db.list_transform_usage_pending(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_transform_usage_pending())
            }
        }
    }

    pub fn transform_usage_pending(&self, run_id: &str) -> Result<Option<(String, i64)>, String> {
        match self {
            Self::Sqlite(db) => db.transform_usage_pending(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.transform_usage_pending(run_id))
            }
        }
    }

    pub fn take_transform_usage_pending(&self, run_id: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.take_transform_usage_pending(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.take_transform_usage_pending(run_id))
            }
        }
    }

    pub fn transform_work_tenant(&self, run_id: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.transform_work_tenant(run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.transform_work_tenant(run_id))
            }
        }
    }

    pub fn transform_quota_owner(
        &self,
        namespace: &str,
        transform_id: &str,
    ) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.transform_quota_owner(namespace, transform_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.transform_quota_owner(namespace, transform_id)
            }),
        }
    }

    pub fn heartbeat_transform_work(
        &self,
        run_id: &str,
        runtime_id: &str,
        claim_generation: i64,
        fencing_token: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_transform::TransformWork, String> {
        match self {
            Self::Sqlite(db) => db.heartbeat_transform_work(
                run_id,
                runtime_id,
                claim_generation,
                fencing_token,
                ttl_ms,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.heartbeat_transform_work(
                    run_id,
                    runtime_id,
                    claim_generation,
                    fencing_token,
                    ttl_ms,
                    now_ms,
                )
            }),
        }
    }

    pub fn read_transform_run_input(
        &self,
        command: &crate::sekai::governed_transform::WriteTransformRunCommand,
        alias: &str,
        after_alias: &str,
        after_row_id: i64,
        limit: i64,
        now_ms: i64,
    ) -> Result<Vec<crate::sekai::governed_transform::TransformRunInputRow>, String> {
        match self {
            Self::Sqlite(db) => db.read_transform_run_input(
                command,
                alias,
                after_alias,
                after_row_id,
                limit,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.read_transform_run_input(
                    command,
                    alias,
                    after_alias,
                    after_row_id,
                    limit,
                    now_ms,
                )
            }),
        }
    }

    pub fn write_transform_run(
        &self,
        command: crate::sekai::governed_transform::WriteTransformRunCommand,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_transform::TransformRun, String> {
        match self {
            Self::Sqlite(db) => db.write_transform_run(command, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.write_transform_run(command, now_ms))
            }
        }
    }

    pub fn peek_streaming_transform_apply(
        &self,
        run_id: &str,
        runtime_id: &str,
        claim_generation: i64,
        fencing_token: &str,
        checkpoint: &str,
        now_ms: i64,
    ) -> Result<
        Option<crate::sekai::streaming_transform_apply::StreamingTransformApplyReceipt>,
        crate::sekai::streaming_transform_apply::StreamingApplyError,
    > {
        match self {
            Self::Sqlite(db) => db.peek_streaming_transform_apply(
                run_id,
                runtime_id,
                claim_generation,
                fencing_token,
                checkpoint,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.peek_streaming_transform_apply(
                    run_id,
                    runtime_id,
                    claim_generation,
                    fencing_token,
                    checkpoint,
                    now_ms,
                )
            }),
        }
    }

    pub fn apply_streaming_transform_batch(
        &self,
        batch: crate::sekai::streaming_transform_apply::StreamingTransformApplyBatch,
        actor: &str,
        now_ms: i64,
    ) -> Result<
        crate::sekai::streaming_transform_apply::StreamingTransformApplyReceipt,
        crate::sekai::streaming_transform_apply::StreamingApplyError,
    > {
        match self {
            Self::Sqlite(db) => db.apply_streaming_transform_batch(batch, actor, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.apply_streaming_transform_batch(batch, actor, now_ms)
            }),
        }
    }

    pub fn preview_governed_transform(
        &self,
        transform: &crate::sekai::governed_transform::GovernedTransform,
        row_cap: usize,
        now_ms: i64,
        tenant_id: &str,
        column_allowlists: &std::collections::HashMap<String, Vec<String>>,
        object_sets: &[crate::sekai::object_set_input::PinnedObjectSet],
    ) -> Result<crate::sekai::governed_transform::PreviewGovernedTransformResult, String> {
        match self {
            Self::Sqlite(db) => db.preview_governed_transform(
                transform,
                row_cap,
                now_ms,
                tenant_id,
                column_allowlists,
                object_sets,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.preview_governed_transform(
                    transform,
                    row_cap,
                    now_ms,
                    tenant_id,
                    column_allowlists,
                    object_sets,
                )
            }),
        }
    }

    pub fn get_preview_governed_transform(
        &self,
        preview_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::PreviewGovernedTransformResult>, String>
    {
        match self {
            Self::Sqlite(db) => db.get_preview_governed_transform(preview_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_preview_governed_transform(preview_id))
            }
        }
    }

    pub fn get_preview_column_allowlists(
        &self,
        preview_id: &str,
    ) -> Result<std::collections::HashMap<String, Vec<String>>, String> {
        match self {
            Self::Sqlite(db) => db.get_preview_column_allowlists(preview_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_preview_column_allowlists(preview_id))
            }
        }
    }

    pub fn run_governed_transform_on_branch(
        &self,
        namespace: &str,
        transform_id: &str,
        branch: &str,
        actor: &str,
        tenant: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranchRun, String> {
        match self {
            Self::Sqlite(db) => db.run_governed_transform_on_branch(
                namespace,
                transform_id,
                branch,
                actor,
                tenant,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.run_governed_transform_on_branch(
                    namespace,
                    transform_id,
                    branch,
                    actor,
                    tenant,
                    now_ms,
                )
            }),
        }
    }
}
