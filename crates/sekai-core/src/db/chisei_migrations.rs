//! SQLite migrations for Chisei-named families that share `SekaiDb`.
//!
//! These tables are created with the store because `SekaiDb::migrate_all`
//! still opens Shared and Chisei planes. Method bodies other than schema
//! setup stay in the root crate as free functions.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::collections::{BTreeSet, HashMap};

use crate::db::sekai::SekaiDb;

const CHISEI_LOOKUP_INDEX_BACKFILL_VERSION: i64 = 1;

const EVAL_RUN_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS chisei_dataset_runs (
    namespace TEXT NOT NULL,
    run_id TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    lease_holder TEXT NOT NULL DEFAULT '',
    lease_until_ms INTEGER NOT NULL DEFAULT 0,
    uncertain_micros INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, run_id)
);
CREATE TABLE IF NOT EXISTS chisei_dataset_run_artifacts (
    namespace TEXT NOT NULL,
    run_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    PRIMARY KEY (namespace, run_id)
);
CREATE TABLE IF NOT EXISTS chisei_dataset_run_cases (
    namespace TEXT NOT NULL,
    run_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    result_json TEXT NOT NULL,
    cost_micros INTEGER NOT NULL,
    recorded_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, run_id, case_id)
);
";

const MODEL_REVIEW_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS chisei_model_review (
    namespace TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    artifact_digest TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, provider, model, artifact_digest)
);
CREATE TABLE IF NOT EXISTS chisei_model_family_enablement (
    namespace TEXT NOT NULL,
    region_label TEXT NOT NULL,
    family_id TEXT NOT NULL,
    status TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, region_label, family_id)
);
";

const POLICY_SHADOW_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS chisei_policy_shadow (
    namespace TEXT PRIMARY KEY,
    shadow_id TEXT NOT NULL,
    candidate_json TEXT NOT NULL,
    candidate_version TEXT NOT NULL,
    active_version TEXT NOT NULL,
    min_evaluations INTEGER NOT NULL,
    min_match_rate_bps INTEGER NOT NULL,
    started_by TEXT NOT NULL,
    started_at_ms INTEGER NOT NULL,
    evaluated INTEGER NOT NULL DEFAULT 0,
    unchanged INTEGER NOT NULL DEFAULT 0,
    re_routed INTEGER NOT NULL DEFAULT 0,
    would_deny INTEGER NOT NULL DEFAULT 0,
    would_allow INTEGER NOT NULL DEFAULT 0,
    activation_claimed_at_ms INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS chisei_policy_shadow_sample (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shadow_id TEXT NOT NULL,
    delta TEXT NOT NULL,
    preferred_runtime TEXT NOT NULL,
    preferred_model TEXT NOT NULL,
    active TEXT NOT NULL,
    candidate TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS chisei_policy_shadow_by_run
    ON chisei_policy_shadow (shadow_id);
CREATE INDEX IF NOT EXISTS chisei_policy_shadow_sample_by_class
    ON chisei_policy_shadow_sample (shadow_id, delta);
";

const MODEL_RELEASE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS chisei_model_release_trust (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    roots_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chisei_model_runtime_evidence (
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    ingested_at_ms INTEGER NOT NULL,
    PRIMARY KEY (provider, model, profile_version, artifact_digest, endpoint)
);
CREATE TABLE IF NOT EXISTS chisei_model_evaluation_export (
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    exported_at_ms INTEGER NOT NULL,
    PRIMARY KEY (provider, model, profile_version, artifact_digest, endpoint)
);
CREATE TABLE IF NOT EXISTS chisei_model_release_feedback (
    id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    actor TEXT NOT NULL,
    note TEXT NOT NULL,
    recorded_at_ms INTEGER NOT NULL
);
";

const ALTER_ROUTING: &[&str] = &[
    "ALTER TABLE chisei_routing_profiles ADD COLUMN require_runtime_evidence INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE chisei_routing_profiles ADD COLUMN evidence_provider TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE chisei_routing_profiles ADD COLUMN evidence_model TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE chisei_routing_profiles ADD COLUMN evidence_profile_version TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE chisei_routing_profiles ADD COLUMN evidence_artifact_digest TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE chisei_routing_profiles ADD COLUMN evidence_endpoint TEXT NOT NULL DEFAULT ''",
];

fn ensure_external_permit_tables_on(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chisei_external_action_permits (
                permit_id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL UNIQUE,
                issuance_idempotency_key TEXT NOT NULL, permit_json TEXT NOT NULL, issued_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS chisei_external_action_redemptions (
                permit_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, execution_id TEXT NOT NULL,
                redemption_json TEXT NOT NULL, redeemed_at_ms INTEGER NOT NULL,
                invocation_ordinal INTEGER NOT NULL, redemption_id TEXT,
                evidence_due_at_ms INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(permit_id,idempotency_key), UNIQUE(permit_id,execution_id),
                UNIQUE(permit_id,invocation_ordinal)
             );
             CREATE TABLE IF NOT EXISTS chisei_external_action_revocations (
                revocation_handle TEXT PRIMARY KEY, reason TEXT NOT NULL, revoked_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS chisei_external_action_kill_switches (
                scope_kind TEXT NOT NULL, scope_value TEXT NOT NULL, reason TEXT NOT NULL,
                enabled_at_ms INTEGER NOT NULL, PRIMARY KEY(scope_kind,scope_value)
             );
             CREATE TABLE IF NOT EXISTS chisei_external_action_delegated_permits (
                permit_id TEXT PRIMARY KEY, parent_permit_id TEXT NOT NULL,
                permit_json TEXT NOT NULL, issued_at_ms INTEGER NOT NULL
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_external_action_one_child_per_parent
             ON chisei_external_action_delegated_permits(parent_permit_id);
             CREATE TABLE IF NOT EXISTS chisei_external_permit_policies (
                scope TEXT PRIMARY KEY, policy_json TEXT NOT NULL, updated_at_ms INTEGER NOT NULL
             );"
        ).map_err(|error| error.to_string())?;
    for (column, definition) in [
        ("redemption_id", "TEXT"),
        ("evidence_due_at_ms", "INTEGER NOT NULL DEFAULT 0"),
    ] {
        let exists = {
            let mut statement = conn
                .prepare("PRAGMA table_info(chisei_external_action_redemptions)")
                .map_err(|error| error.to_string())?;
            statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
                .iter()
                .any(|name| name == column)
        };
        if !exists {
            conn.execute_batch(&format!(
                "ALTER TABLE chisei_external_action_redemptions ADD COLUMN {column} {definition}"
            ))
            .map_err(|error| error.to_string())?;
        }
    }
    conn.execute_batch(
        "UPDATE chisei_external_action_redemptions
             SET redemption_id=COALESCE(
                     redemption_id,
                     json_extract(redemption_json,'$.redemption_id')
                 ),
                 evidence_due_at_ms=CASE
                     WHEN evidence_due_at_ms=0 THEN COALESCE(
                         json_extract(redemption_json,'$.evidence_due_at_ms'),
                         (SELECT json_extract(p.permit_json,'$.expires_at_ms')
                          FROM chisei_external_action_permits p
                          WHERE p.permit_id=chisei_external_action_redemptions.permit_id),
                         0
                     )
                     ELSE evidence_due_at_ms
                 END
             WHERE redemption_id IS NULL OR evidence_due_at_ms=0;
             UPDATE chisei_external_action_redemptions
             SET redemption_json=json_set(
                 redemption_json,
                 '$.evidence_due_at_ms',
                 evidence_due_at_ms
             )
             WHERE COALESCE(json_extract(redemption_json,'$.evidence_due_at_ms'),0)
                   != evidence_due_at_ms;
             CREATE INDEX IF NOT EXISTS idx_external_action_redemptions_evidence_due
             ON chisei_external_action_redemptions(evidence_due_at_ms,redemption_id);",
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

impl SekaiDb {
    /// Per-store receipt table, including Combined Split admission receipts
    /// on the Sekai dest. Legacy files may lack later columns; add those
    /// before creating indexes that name them.
    pub fn migrate_operation_receipts(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chisei_operation_receipts (
                    operation_id TEXT PRIMARY KEY,
                    request_id TEXT,
                    lookup_request_id TEXT,
                    initiating_actor TEXT,
                    caller_scope TEXT,
                    alias_retired INTEGER NOT NULL DEFAULT 0,
                    namespace TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );",
        )
        .map_err(|e| e.to_string())?;
        Self::ensure_operation_receipt_columns(&conn)?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_chisei_operation_receipts_namespace
                    ON chisei_operation_receipts(namespace, updated_at);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_operation_receipts_request
                    ON chisei_operation_receipts(request_id) WHERE request_id IS NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_operation_receipts_lookup
                    ON chisei_operation_receipts(caller_scope, lookup_request_id)
                    WHERE caller_scope IS NOT NULL AND lookup_request_id IS NOT NULL;",
        )
        .map_err(|e| e.to_string())
    }

    fn ensure_operation_receipt_columns(conn: &Connection) -> Result<(), String> {
        for statement in [
            "ALTER TABLE chisei_operation_receipts ADD COLUMN request_id TEXT",
            "ALTER TABLE chisei_operation_receipts ADD COLUMN lookup_request_id TEXT",
            "ALTER TABLE chisei_operation_receipts ADD COLUMN initiating_actor TEXT",
            "ALTER TABLE chisei_operation_receipts ADD COLUMN caller_scope TEXT",
            "ALTER TABLE chisei_operation_receipts ADD COLUMN alias_retired INTEGER NOT NULL DEFAULT 0",
        ] {
            match conn.execute(statement, []) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                    if message.contains("duplicate column name") => {}
                Err(err) => return Err(err.to_string()),
            }
        }
        Ok(())
    }

    pub fn migrate_chisei(&self) -> Result<(), String> {
        let mut conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chisei_eval_suites (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                cases_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chisei_eval_runs (
                id TEXT PRIMARY KEY,
                suite_id TEXT NOT NULL,
                config_ref TEXT NOT NULL,
                results_json TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_eval_runs_suite ON chisei_eval_runs(suite_id, timestamp);
            CREATE TABLE IF NOT EXISTS chisei_eval_iterations (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                suite_id TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT '',
                changed_file TEXT NOT NULL,
                diff_hash TEXT NOT NULL,
                parent_iteration_id TEXT NOT NULL,
                baseline_run_id TEXT NOT NULL,
                candidate_run_id TEXT NOT NULL,
                delta REAL NOT NULL,
                regressed INTEGER NOT NULL,
                created INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_eval_iterations_suite ON chisei_eval_iterations(suite_id, created);
            CREATE INDEX IF NOT EXISTS idx_chisei_eval_iterations_file ON chisei_eval_iterations(changed_file, created);
            CREATE TABLE IF NOT EXISTS chisei_evolve_tasks (
                id TEXT PRIMARY KEY,
                task_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chisei_sample_observations (
                request_id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL DEFAULT '',
                spec TEXT NOT NULL DEFAULT '',
                resolved_model TEXT NOT NULL DEFAULT '',
                output_content TEXT NOT NULL DEFAULT '',
                sample_reason TEXT NOT NULL DEFAULT '',
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                stop_reason TEXT NOT NULL DEFAULT '',
                timestamp INTEGER NOT NULL,
                scored INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                task_class TEXT NOT NULL DEFAULT '',
                cost_usd_micros INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_sample_observations_scored ON chisei_sample_observations(scored, timestamp);
            CREATE TABLE IF NOT EXISTS chisei_operation_receipts (
                operation_id TEXT PRIMARY KEY,
                request_id TEXT,
                lookup_request_id TEXT,
                initiating_actor TEXT,
                caller_scope TEXT,
                alias_retired INTEGER NOT NULL DEFAULT 0,
                namespace TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_operation_receipts_namespace
                ON chisei_operation_receipts(namespace, updated_at);
            CREATE TABLE IF NOT EXISTS chisei_gateway_request_aliases (
                caller_scope TEXT NOT NULL,
                request_alias TEXT NOT NULL,
                request_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                reserved_at INTEGER NOT NULL,
                dispatch_started INTEGER NOT NULL DEFAULT 0,
                dispatch_token TEXT,
                PRIMARY KEY(caller_scope, request_alias)
            );
            CREATE TABLE IF NOT EXISTS chisei_gunshi_allocation_state (
                namespace TEXT PRIMARY KEY,
                revision_id TEXT NOT NULL,
                changed_at_ms INTEGER NOT NULL,
                state_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chisei_operation_reservations (
                namespace TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                actor TEXT NOT NULL,
                budget_subject TEXT NOT NULL DEFAULT '',
                incurred_usage INTEGER NOT NULL DEFAULT 0,
                sekai_instance_id TEXT NOT NULL DEFAULT '',
                sekai_status TEXT NOT NULL DEFAULT '',
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER NOT NULL,
                charge_key TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (namespace, operation_id)
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_operation_reservations_status
                ON chisei_operation_reservations(status, expires_at_ms);",
        )
        .map_err(|e| e.to_string())?;
        Self::ensure_operation_receipt_columns(&conn)?;
        for statement in [
            "ALTER TABLE chisei_gateway_request_aliases ADD COLUMN dispatch_started INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE chisei_gateway_request_aliases ADD COLUMN dispatch_token TEXT",
            // #1902: the budget key a reservation's charge was made under.
            "ALTER TABLE chisei_operation_reservations ADD COLUMN charge_key TEXT NOT NULL DEFAULT ''",
        ] {
            match conn.execute(statement, []) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                    if message.contains("duplicate column name") => {}
                Err(err) => return Err(err.to_string()),
            }
        }
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let schema_version: i64 = tx
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|error| error.to_string())?;
        if schema_version < CHISEI_LOOKUP_INDEX_BACKFILL_VERSION {
            tx.execute_batch(
            r#"WITH candidates AS (
               SELECT receipts.operation_id,
                      json_extract(
                        CASE WHEN events.type='object' THEN events.value ELSE '{}' END,
                        '$.attributes.request_id'
                      ) AS request_id
               FROM chisei_operation_receipts AS receipts,
                    json_each(
                      CASE WHEN json_valid(receipts.receipt_json)
                           THEN receipts.receipt_json
                           ELSE '{"events":[]}' END,
                      '$.events'
                    ) AS events
               WHERE json_extract(
                       CASE WHEN events.type='object' THEN events.value ELSE '{}' END,
                       '$.kind'
                     )='intent_recorded'
                 AND json_type(
                       CASE WHEN events.type='object' THEN events.value ELSE '{}' END,
                       '$.attributes.request_id'
                     )='text'
             ), unique_candidates AS (
               SELECT operation_id, request_id
               FROM candidates
               WHERE request_id IS NOT NULL AND request_id != ''
                 AND request_id IN (
                   SELECT request_id FROM candidates GROUP BY request_id HAVING COUNT(*)=1
                 )
             )
             UPDATE chisei_operation_receipts
             SET request_id=(
               SELECT request_id FROM unique_candidates
               WHERE unique_candidates.operation_id=chisei_operation_receipts.operation_id
             )
             WHERE request_id IS NULL
               AND operation_id IN (SELECT operation_id FROM unique_candidates);
             DROP INDEX IF EXISTS idx_chisei_operation_receipts_lookup;
             WITH ranked_aliases AS (
               SELECT operation_id,
                      row_number() OVER (
                        PARTITION BY
                          COALESCE(
                            caller_scope,
                            substr(request_id, 8, instr(substr(request_id, 8), ':') - 1)
                          ),
                          lookup_request_id
                        ORDER BY (caller_scope IS NOT NULL) DESC,
                                 updated_at DESC,
                                 operation_id DESC
                      ) AS alias_rank
               FROM chisei_operation_receipts
               WHERE lookup_request_id IS NOT NULL
                 AND (
                   caller_scope IS NOT NULL
                   OR (request_id LIKE 'chisei:%:%' AND instr(substr(request_id, 8), ':') > 1)
                 )
             )
             UPDATE chisei_operation_receipts
             SET lookup_request_id=NULL, alias_retired=1
             WHERE operation_id IN (
               SELECT operation_id FROM ranked_aliases WHERE alias_rank > 1
             );
             UPDATE chisei_operation_receipts
             SET alias_retired=1
             WHERE lookup_request_id IS NULL
               AND alias_retired=0
               AND EXISTS (
                 SELECT 1
                 FROM json_each(
                   CASE WHEN json_valid(chisei_operation_receipts.receipt_json)
                        THEN chisei_operation_receipts.receipt_json
                        ELSE '{"events":[]}' END,
                   '$.events'
                 ) AS events
                 WHERE json_extract(
                         CASE WHEN events.type='object' THEN events.value ELSE '{}' END,
                         '$.kind'
                       )='intent_recorded'
                   AND json_type(
                         CASE WHEN events.type='object' THEN events.value ELSE '{}' END,
                         '$.attributes.lookup_request_id'
                       )='text'
                   AND COALESCE(
                         json_extract(
                           CASE WHEN events.type='object' THEN events.value ELSE '{}' END,
                           '$.attributes.lookup_request_id'
                         ),
                         ''
                       ) != ''
               );
             UPDATE chisei_operation_receipts
             SET caller_scope=substr(request_id, 8, instr(substr(request_id, 8), ':') - 1)
             WHERE caller_scope IS NULL
               AND lookup_request_id IS NOT NULL
               AND request_id LIKE 'chisei:%:%'
               AND instr(substr(request_id, 8), ':') > 1;
             CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_operation_receipts_request
               ON chisei_operation_receipts(request_id) WHERE request_id IS NOT NULL;
             CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_operation_receipts_lookup
               ON chisei_operation_receipts(caller_scope, lookup_request_id)
               WHERE caller_scope IS NOT NULL AND lookup_request_id IS NOT NULL;
             INSERT OR IGNORE INTO chisei_gateway_request_aliases(
               caller_scope, request_alias, request_id, operation_id, reserved_at
             )
             SELECT caller_scope,
                    COALESCE(
                      lookup_request_id,
                      (SELECT json_extract(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.attributes.lookup_request_id')
                       FROM json_each(CASE WHEN json_valid(receipt_json) THEN receipt_json ELSE '{"events":[]}' END, '$.events') AS events
                       WHERE json_extract(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.kind')='intent_recorded'
                         AND json_type(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.attributes.lookup_request_id')='text'
                         AND json_extract(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.attributes.lookup_request_id') != ''
                       LIMIT 1)
                    ),
                    COALESCE(request_id, operation_id), operation_id, updated_at
             FROM chisei_operation_receipts
             WHERE caller_scope IS NOT NULL
               AND COALESCE(
                     lookup_request_id,
                     (SELECT json_extract(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.attributes.lookup_request_id')
                      FROM json_each(CASE WHEN json_valid(receipt_json) THEN receipt_json ELSE '{"events":[]}' END, '$.events') AS events
                      WHERE json_extract(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.kind')='intent_recorded'
                        AND json_type(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.attributes.lookup_request_id')='text'
                        AND json_extract(CASE WHEN events.type='object' THEN events.value ELSE '{}' END, '$.attributes.lookup_request_id') != ''
                      LIMIT 1)
                   ) IS NOT NULL;"#,
            )
            .map_err(|error| error.to_string())?;
            tx.pragma_update(None, "user_version", CHISEI_LOOKUP_INDEX_BACKFILL_VERSION)
                .map_err(|error| error.to_string())?;
        }
        tx.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_operation_receipts_lookup
               ON chisei_operation_receipts(caller_scope, lookup_request_id)
               WHERE caller_scope IS NOT NULL AND lookup_request_id IS NOT NULL;",
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        match conn.execute(
            "ALTER TABLE chisei_eval_iterations ADD COLUMN namespace TEXT NOT NULL DEFAULT ''",
            [],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message.contains("duplicate column name") => {}
            Err(err) => return Err(err.to_string()),
        }
        match conn.execute(
            "ALTER TABLE chisei_sample_observations ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0",
            [],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message.contains("duplicate column name") => {}
            Err(err) => return Err(err.to_string()),
        }
        match conn.execute(
            "ALTER TABLE chisei_sample_observations ADD COLUMN task_class TEXT NOT NULL DEFAULT ''",
            [],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message.contains("duplicate column name") => {}
            Err(err) => return Err(err.to_string()),
        }
        match conn.execute(
            "ALTER TABLE chisei_sample_observations ADD COLUMN cost_usd_micros INTEGER NOT NULL DEFAULT 0",
            [],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message.contains("duplicate column name") => {}
            Err(err) => return Err(err.to_string()),
        }

        if table_exists(&conn, "aipp_eval_suites")?
            && table_exists(&conn, "aipp_eval_runs")?
            && table_exists(&conn, "aipp_eval_iterations")?
            && table_exists(&conn, "aipp_evolve_tasks")?
        {
            let aipp_namespace_projection =
                legacy_namespace_projection_column(&conn, "aipp_eval_iterations", true)?
                    .unwrap_or_else(|| "''".to_string());

            conn.execute(
                "INSERT OR IGNORE INTO chisei_eval_suites(id, name, description, cases_json)
                 SELECT id, name, description, cases_json FROM aipp_eval_suites",
                [],
            )
            .map_err(|e| e.to_string())?;
            conn.execute(
                "INSERT OR IGNORE INTO chisei_eval_runs(id, suite_id, config_ref, results_json, timestamp)
                 SELECT id, suite_id, config_ref, results_json, timestamp FROM aipp_eval_runs",
                [],
            )
            .map_err(|e| e.to_string())?;
            conn.execute(
                &format!(
                    "INSERT OR IGNORE INTO chisei_eval_iterations(
                        id, run_id, suite_id, namespace, changed_file, diff_hash, parent_iteration_id,
                        baseline_run_id, candidate_run_id, delta, regressed, created
                     )
                     SELECT id, run_id, suite_id, {aipp_namespace_projection}, changed_file, diff_hash,
                            parent_iteration_id, baseline_run_id, candidate_run_id, delta, regressed, created
                     FROM aipp_eval_iterations"
                ),
                [],
            )
            .map_err(|e| e.to_string())?;
            conn.execute(
                "INSERT OR IGNORE INTO chisei_evolve_tasks(id, task_json)
                 SELECT id, task_json FROM aipp_evolve_tasks",
                [],
            )
            .map_err(|e| e.to_string())?;
        }

        if let Some(legacy_namespace_column) =
            legacy_namespace_projection_column(&conn, "chisei_eval_iterations", false)?
        {
            let update_sql = format!(
                "UPDATE chisei_eval_iterations SET namespace = COALESCE(NULLIF(namespace, ''), {legacy_namespace_column})
                 WHERE namespace = '' AND COALESCE({legacy_namespace_column}, '') <> ''"
            );
            conn.execute(&update_sql, []).map_err(|e| e.to_string())?;
        }

        let legacy_rows = {
            let mut stmt = conn
                .prepare(
                    "SELECT i.id, i.changed_file, s.cases_json, r.results_json
                     FROM chisei_eval_iterations i
                     LEFT JOIN chisei_eval_suites s ON s.id = i.suite_id
                     LEFT JOIN chisei_eval_runs r ON r.id = i.run_id
                     WHERE i.namespace = ''",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
        };
        for (id, changed_file, cases_json, results_json) in legacy_rows {
            let Some(namespace) = infer_legacy_iteration_namespace(
                &changed_file,
                cases_json.as_deref(),
                results_json.as_deref(),
            ) else {
                continue;
            };
            conn.execute(
                "UPDATE chisei_eval_iterations SET namespace = ?1 WHERE id = ?2 AND namespace = ''",
                params![namespace, id],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn migrate_evaluation_plans(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_evaluator_definitions (
                    definition_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    evaluator_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    implementation_digest TEXT NOT NULL,
                    content_digest TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    UNIQUE(namespace, evaluator_id, version)
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_evaluator_definitions_namespace
                    ON chisei_evaluator_definitions(namespace, evaluator_id, version);
                CREATE TABLE IF NOT EXISTS chisei_evaluator_availability (
                    definition_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    changed_at_ms INTEGER NOT NULL,
                    FOREIGN KEY(definition_id) REFERENCES chisei_evaluator_definitions(definition_id)
                );
                CREATE TABLE IF NOT EXISTS chisei_evaluator_availability_events (
                    definition_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    changed_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(definition_id, request_id),
                    FOREIGN KEY(definition_id) REFERENCES chisei_evaluator_definitions(definition_id)
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_evaluator_availability_events_time
                    ON chisei_evaluator_availability_events(definition_id, changed_at_ms);
                CREATE TABLE IF NOT EXISTS chisei_evaluation_plans (
                    plan_version_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    plan_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    content_digest TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    UNIQUE(namespace, plan_id, version)
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_plans_namespace
                    ON chisei_evaluation_plans(namespace, plan_id, version);",
            )
            .map_err(|error| error.to_string())
    }

    pub fn migrate_evaluation_manifests(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_evaluation_manifests (
                    manifest_digest TEXT PRIMARY KEY,
                    manifest_id TEXT NOT NULL UNIQUE,
                    namespace TEXT NOT NULL,
                    plan_version_id TEXT NOT NULL,
                    subject_identity TEXT NOT NULL,
                    evaluation_time_ms INTEGER NOT NULL,
                    body_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_manifests_namespace
                    ON chisei_evaluation_manifests(
                        namespace, plan_version_id, subject_identity, evaluation_time_ms
                    );
                CREATE TABLE IF NOT EXISTS chisei_evaluation_manifest_requests (
                    namespace TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    manifest_digest TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, actor, request_id),
                    FOREIGN KEY(manifest_digest)
                        REFERENCES chisei_evaluation_manifests(manifest_digest)
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_manifest_requests_manifest
                    ON chisei_evaluation_manifest_requests(manifest_digest);",
            )
            .map_err(|error| error.to_string())
    }

    pub fn migrate_evaluation_executions(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_evaluation_executions (
                    manifest_digest TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    namespace TEXT NOT NULL,
                    executor_version TEXT NOT NULL,
                    started_by TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    FOREIGN KEY(manifest_digest)
                        REFERENCES chisei_evaluation_manifests(manifest_digest),
                    FOREIGN KEY(operation_id)
                        REFERENCES chisei_operation_receipts(operation_id)
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_executions_namespace
                    ON chisei_evaluation_executions(namespace, created_at_ms, operation_id);",
            )
            .map_err(|error| error.to_string())
    }

    pub fn migrate_learning_changes(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_learning_changes (
                    change_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    learning_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_chisei_learning_changes_learning
                    ON chisei_learning_changes(namespace, learning_id);",
            )
            .map_err(|error| error.to_string())
    }

    pub fn migrate_data_quality_rules(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_data_quality_rules (
                    namespace TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_digest TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    published_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (namespace, rule_id)
                );
                CREATE TABLE IF NOT EXISTS chisei_data_quality_results (
                    result_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    evaluated_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_data_quality_results_ns
                    ON chisei_data_quality_results(namespace, rule_id);",
            )
            .map_err(|error| error.to_string())
    }

    pub fn migrate_kioku(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chisei_kioku_memories (
                id TEXT NOT NULL,
                version INTEGER NOT NULL,
                namespace TEXT NOT NULL,
                state TEXT NOT NULL,
                classification TEXT NOT NULL,
                expires_at_ms INTEGER,
                memory_json TEXT NOT NULL,
                PRIMARY KEY (id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_kioku_memory_retrieval
                ON chisei_kioku_memories(namespace, state, expires_at_ms);
            CREATE TABLE IF NOT EXISTS chisei_kioku_evidence_links (
                memory_id TEXT NOT NULL,
                memory_version INTEGER NOT NULL,
                operation_id TEXT NOT NULL,
                stance TEXT NOT NULL,
                link_json TEXT NOT NULL,
                PRIMARY KEY (memory_id, memory_version, operation_id),
                FOREIGN KEY (memory_id, memory_version)
                    REFERENCES chisei_kioku_memories(id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_kioku_evidence_operation
                ON chisei_kioku_evidence_links(operation_id);
            CREATE TABLE IF NOT EXISTS chisei_kioku_lifecycle_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                memory_id TEXT NOT NULL,
                memory_version INTEGER NOT NULL,
                action TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                recorded_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kioku_lifecycle_memory
                ON chisei_kioku_lifecycle_events(memory_id, memory_version, id);
            CREATE TABLE IF NOT EXISTS chisei_kioku_outcomes (
                memory_id TEXT NOT NULL,
                memory_version INTEGER NOT NULL,
                operation_id TEXT NOT NULL,
                memory_applied INTEGER NOT NULL,
                outcome_metric TEXT NOT NULL,
                outcome_value REAL NOT NULL,
                passed INTEGER NOT NULL,
                recorded_at_ms INTEGER NOT NULL,
                PRIMARY KEY (memory_id, memory_version, operation_id),
                FOREIGN KEY (memory_id, memory_version)
                    REFERENCES chisei_kioku_memories(id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_kioku_outcome_comparison
                ON chisei_kioku_outcomes(memory_id, memory_version, memory_applied);",
        )
        .map_err(|error| error.to_string())
    }

    pub fn migrate_portfolio(&self) -> Result<(), String> {
        let mut conn = self.conn();
        let observation_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chisei_portfolio_observations')",
                [],
                |row| row.get(0),
            )
            .map_err(|err| err.to_string())?;
        let has_prompt_variant = if observation_exists {
            let mut statement = conn
                .prepare("PRAGMA table_info(chisei_portfolio_observations)")
                .map_err(|err| err.to_string())?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|err| err.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| err.to_string())?;
            columns.iter().any(|column| column == "prompt_variant")
        } else {
            true
        };
        let transaction = conn.transaction().map_err(|err| err.to_string())?;
        if observation_exists && !has_prompt_variant {
            transaction.execute_batch(
                "ALTER TABLE chisei_portfolio_observations RENAME TO chisei_portfolio_observations_legacy;
                 CREATE TABLE chisei_portfolio_observations (
                    namespace TEXT NOT NULL, task_class TEXT NOT NULL, model TEXT NOT NULL,
                    prompt_variant TEXT NOT NULL, quality_score REAL NOT NULL,
                    cost_usd_micros INTEGER NOT NULL, sample_count INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (namespace, task_class, model, prompt_variant));
                 INSERT INTO chisei_portfolio_observations
                    (namespace, task_class, model, prompt_variant, quality_score,
                     cost_usd_micros, sample_count, updated_at)
                 SELECT namespace, task_class, model, 'legacy@1', quality_score,
                        cost_usd_micros, sample_count, updated_at
                 FROM chisei_portfolio_observations_legacy;
                 DROP TABLE chisei_portfolio_observations_legacy;",
            ).map_err(|err| err.to_string())?;
        }
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_portfolio_observations (
                namespace TEXT NOT NULL,
                task_class TEXT NOT NULL,
                model TEXT NOT NULL,
                prompt_variant TEXT NOT NULL,
                quality_score REAL NOT NULL,
                cost_usd_micros INTEGER NOT NULL,
                sample_count INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (namespace, task_class, model, prompt_variant)
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_portfolio_frontier
                ON chisei_portfolio_observations(namespace, task_class, cost_usd_micros);
            CREATE TABLE IF NOT EXISTS chisei_portfolio_objectives (
                namespace TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                budget_usd_micros INTEGER NOT NULL,
                quality_bar REAL NOT NULL,
                min_samples INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chisei_portfolio_routes (
                namespace TEXT NOT NULL,
                task_class TEXT NOT NULL,
                current_model TEXT NOT NULL,
                pending_model TEXT NOT NULL DEFAULT '',
                pending_count INTEGER NOT NULL DEFAULT 0,
                shifted_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (namespace, task_class)
            );",
            )
            .map_err(|err| err.to_string())?;
        for statement in [
            "ALTER TABLE chisei_portfolio_routes ADD COLUMN current_prompt_variant TEXT NOT NULL DEFAULT 'legacy@1'",
            "ALTER TABLE chisei_portfolio_routes ADD COLUMN pending_prompt_variant TEXT NOT NULL DEFAULT ''",
        ] {
            if let Err(error) = transaction.execute(statement, [])
                && !error.to_string().contains("duplicate column name")
            {
                return Err(error.to_string());
            }
        }
        transaction.commit().map_err(|err| err.to_string())
    }

    pub fn migrate_routing_profiles(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_routing_profiles (
                    namespace TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    endpoint_origin TEXT NOT NULL,
                    model_patterns_json TEXT NOT NULL,
                    credential_ref TEXT NOT NULL,
                    registered_by TEXT NOT NULL,
                    registered_at_ms INTEGER NOT NULL,
                    revoked_at_ms INTEGER,
                    artifact_digest TEXT,
                    require_runtime_evidence INTEGER NOT NULL DEFAULT 0,
                    evidence_provider TEXT NOT NULL DEFAULT '',
                    evidence_model TEXT NOT NULL DEFAULT '',
                    evidence_profile_version TEXT NOT NULL DEFAULT '',
                    evidence_artifact_digest TEXT NOT NULL DEFAULT '',
                    evidence_endpoint TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (namespace, profile_id)
                 );",
            )
            .map_err(|error| error.to_string())?;
        // Stores created before #1499 lack the digest column.
        match self.conn().execute(
            "ALTER TABLE chisei_routing_profiles ADD COLUMN artifact_digest TEXT",
            [],
        ) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message.contains("duplicate column name") =>
            {
                Ok(())
            }
            Err(error) => Err(error.to_string()),
        }
    }

    pub fn migrate_model_review(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(MODEL_REVIEW_SQLITE)
            .map_err(|error| error.to_string())
    }

    pub fn migrate_policy_shadow(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(POLICY_SHADOW_SQLITE)
            .map_err(|error| error.to_string())
    }

    pub fn migrate_eval_runs(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(EVAL_RUN_SQLITE)
            .map_err(|error| error.to_string())
    }

    pub fn migrate_model_release_evidence(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(MODEL_RELEASE_SQLITE)
            .map_err(|error| error.to_string())?;
        for statement in ALTER_ROUTING {
            conn.execute(statement, []).map(|_| ()).or_else(|error| {
                let text = error.to_string();
                if text.contains("duplicate column") {
                    Ok(())
                } else {
                    Err(text)
                }
            })?;
        }
        Ok(())
    }

    pub fn migrate_usage_ledger(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_usage_events (
                    event_id TEXT PRIMARY KEY,
                    version TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    unit TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    receipt_operation_id TEXT NOT NULL,
                    dedupe_key TEXT NOT NULL UNIQUE,
                    event_time_ms INTEGER NOT NULL,
                    corrects_event_id TEXT,
                    CHECK (unit IN ('tokens', 'requests')),
                    CHECK (source IN ('measured', 'provider_reported', 'estimated', 'correction'))
                );
                CREATE INDEX IF NOT EXISTS idx_usage_events_tenant_time
                    ON chisei_usage_events(tenant_id, event_time_ms, event_id);
                CREATE INDEX IF NOT EXISTS idx_usage_events_receipt
                    ON chisei_usage_events(receipt_operation_id);",
            )
            .map_err(|e| e.to_string())
    }

    pub fn ensure_external_permit_tables(&self) -> Result<(), String> {
        ensure_external_permit_tables_on(&self.conn())
    }

    pub fn ensure_external_action_tables(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_external_action_reservations (
                    actor TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    mutations INTEGER NOT NULL,
                    deletes INTEGER NOT NULL,
                    PRIMARY KEY(actor, namespace, operation_id)
                );
                CREATE TABLE IF NOT EXISTS chisei_external_action_authorizations (
                    actor TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    authorization_id TEXT NOT NULL UNIQUE,
                    record_json TEXT,
                    claimed_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(actor, operation_id, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS chisei_external_action_releases (
                    authorization_id TEXT PRIMARY KEY,
                    released_at_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chisei_external_action_blast_claims (
                    authorization_id TEXT PRIMARY KEY,
                    actor TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    mutations INTEGER NOT NULL,
                    deletes INTEGER NOT NULL
                );",
            )
            .map_err(|error| error.to_string())
    }
}

fn infer_legacy_iteration_namespace(
    changed_file: &str,
    cases_json: Option<&str>,
    results_json: Option<&str>,
) -> Option<String> {
    let cases: Vec<serde_json::Value> = serde_json::from_str(cases_json?).ok()?;
    let results: Vec<serde_json::Value> = serde_json::from_str(results_json?).ok()?;
    let case_namespaces: HashMap<_, _> = cases
        .into_iter()
        .filter_map(|case| {
            let id = case.get("id")?.as_str()?.to_string();
            legacy_case_namespace(&case).map(|namespace| (id, namespace))
        })
        .collect();
    let namespaces: BTreeSet<String> = results
        .iter()
        .filter_map(|result| {
            result
                .get("case_id")
                .and_then(|value| value.as_str())
                .and_then(|id| case_namespaces.get(id).cloned())
        })
        .collect();
    if namespaces.len() == 1 {
        return namespaces.into_iter().next();
    }
    let matching: Vec<String> = namespaces
        .into_iter()
        .filter(|namespace| changed_file.contains(namespace))
        .collect();
    if matching.len() == 1 {
        Some(matching[0].clone())
    } else {
        None
    }
}

fn table_exists(conn: &rusqlite::Connection, table_name: &str) -> Result<bool, String> {
    let exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name = ?1",
            params![table_name],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    Ok(exists.is_some())
}

fn legacy_namespace_projection_column(
    conn: &rusqlite::Connection,
    table_name: &str,
    prefer_exact_namespace: bool,
) -> Result<Option<String>, String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table_name})"))
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            let name: String = row.get(1)?;
            let column_type: String = row.get(2)?;
            Ok((name, column_type))
        })
        .map_err(|e| e.to_string())?;
    let mut unknown_text_columns: Vec<String> = Vec::new();
    for row in rows {
        let (column_name, column_type) = row.map_err(|e| e.to_string())?;
        if column_name == "namespace" && prefer_exact_namespace {
            return Ok(Some("\"namespace\"".to_string()));
        }
        if !is_known_namespace_column(table_name, &column_name)
            && is_text_affinity_column(&column_type)
        {
            unknown_text_columns.push(format!("\"{column_name}\""));
        }
    }
    if unknown_text_columns.len() == 1 {
        return Ok(unknown_text_columns.into_iter().next());
    }
    Ok(None)
}

fn is_known_namespace_column(table_name: &str, column_name: &str) -> bool {
    match table_name {
        "chisei_eval_iterations" => matches!(
            column_name,
            "id" | "run_id"
                | "suite_id"
                | "namespace"
                | "changed_file"
                | "diff_hash"
                | "parent_iteration_id"
                | "baseline_run_id"
                | "candidate_run_id"
                | "delta"
                | "regressed"
                | "created"
        ),
        "aipp_eval_iterations" => matches!(
            column_name,
            "id" | "run_id"
                | "suite_id"
                | "changed_file"
                | "diff_hash"
                | "parent_iteration_id"
                | "baseline_run_id"
                | "candidate_run_id"
                | "delta"
                | "regressed"
                | "created"
        ),
        _ => false,
    }
}

fn is_text_affinity_column(column_type: &str) -> bool {
    let normalized = column_type.trim().to_uppercase();
    normalized.is_empty()
        || normalized.contains("CHAR")
        || normalized.contains("CLOB")
        || normalized.contains("TEXT")
}

fn legacy_case_namespace(case: &serde_json::Value) -> Option<String> {
    case.get("namespace")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .or_else(|| {
            case.as_object().and_then(|object| {
                let mut candidates: Vec<String> = object
                    .iter()
                    .filter_map(|(key, value)| {
                        if is_legacy_case_namespace_key(key) && value.is_string() {
                            value.as_str().map(str::to_string)
                        } else {
                            None
                        }
                    })
                    .collect();
                if candidates.len() == 1 {
                    candidates.pop()
                } else {
                    None
                }
            })
        })
}

fn is_legacy_case_namespace_key(key: &str) -> bool {
    !matches!(key, "id" | "name" | "assertions" | "spec")
}
