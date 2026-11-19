pub mod action_governance;
pub mod agent_autonomy_store;
pub mod attestation;
pub mod autonomous_envelope_store;
pub mod capability_package_store;
pub mod chisei_budget;
pub mod chisei_migrations;
pub mod chisei_receipt;
pub mod chisei_receipt_postgres;
pub mod chisei_receipt_sqlite;
pub mod chisei_rpc_inventory;
pub mod client_package_store;
pub mod connector_certification_store;
pub mod coordination;
pub mod credential;
pub mod dataset;
pub mod dataset_branch;
pub mod decision;
pub mod deduplication;
pub mod definition_branch;
pub mod definition_migration;
pub mod document_store;
#[cfg(test)]
pub mod event_backend_conformance;
pub mod event_stream_store;
pub mod event_subscription_store;
pub mod evidence;
pub mod federation_conflict_store;
pub mod federation_network_store;
pub mod federation_revocation_store;
pub mod federation_store;
pub mod function;
pub mod gateway_log_cursor;
pub mod governed_facts;
pub mod governed_transform;
pub mod graph;
pub mod guarded_mutation;
pub mod handoff;
pub mod image_store;
pub mod lakehouse_snapshot_store;
pub mod lease;
pub mod media_upload;
pub mod model_platform_store;
pub mod model_stage_store;
pub mod model_version_store;
pub mod namespace_snapshot_store;
pub mod object_log_ingest;
pub mod object_security;
pub mod object_source_record;
pub mod object_sync;
pub mod object_type_index;
pub mod ontology;
pub mod open_table_store;
pub mod peer_import_store;
pub mod postgres;
pub mod postgres_receipt_chain;
pub mod receipt_chain;
pub mod source_batch_dataset;
pub mod source_batch_recovery;
pub(crate) mod sqlite_manager;
pub mod sync_scope;
pub mod transform_chain;
pub mod transform_replay;
pub mod transform_shadow;
#[cfg(any(test, feature = "gateway-test-support"))]
pub use postgres::ScratchDatabase;
pub use postgres::off_runtime;
pub mod postgres_action_binding;
pub mod postgres_action_effect;
pub mod postgres_action_governance;
pub mod postgres_action_instance;
pub mod postgres_attestation;
pub mod postgres_audit;
pub mod postgres_authorization;
pub mod postgres_capability_package;
pub mod postgres_catalog_criticality;
pub mod postgres_client_package;
pub mod postgres_connector_certification;
pub mod postgres_consumer_violation;
pub mod postgres_coordination;
pub mod postgres_dataset;
pub mod postgres_dataset_branch;
pub mod postgres_dataset_health;
pub mod postgres_decision;
pub mod postgres_deduplication;
pub mod postgres_definition_branch;
pub mod postgres_document;
pub mod postgres_embedding_index;
pub mod postgres_event_stream;
pub mod postgres_evidence;
pub mod postgres_federation;
pub mod postgres_function;
pub mod postgres_governed_action_type;
pub mod postgres_governed_transform;
pub mod postgres_grants;
pub mod postgres_guarded_mutation;
pub mod postgres_gunshi;
pub mod postgres_handoff;
pub mod postgres_image;
pub mod postgres_lease;
pub mod postgres_media_upload;
pub mod postgres_object_security;
pub mod postgres_object_security_terms;
pub mod postgres_object_sync;
pub mod postgres_object_type_index;
pub mod postgres_objects;
pub mod postgres_ontology;
pub mod postgres_open_table;
pub mod postgres_retention;
pub mod postgres_schema;
pub mod postgres_search_index;
pub mod postgres_service_principal;
pub mod postgres_source_registry;
pub mod postgres_sync_scope;
pub mod postgres_team_namespace;
pub mod postgres_transform_chain;
pub mod postgres_workflow_action;
pub mod postgres_write_freeze;
pub mod schema_plane;
pub use schema_plane::SchemaPlane;
pub mod embedding_index;
pub mod replica_conformance;
pub mod replica_safety;
pub mod retention;
pub mod reusable;
pub mod runtime_db;
pub mod search_index;
pub mod sekai;
pub mod sekai_rpc_inventory;
pub mod service_principal;
pub mod source_type_descriptor_store;
pub mod source_webhook_store;
pub mod store;
pub mod store_plane;
pub mod team_namespace;
pub mod warehouse_projection_store;
pub mod workflow_action_store;

/// Where a newest-first listing resumes: rows strictly older than
/// `(at_ms, id)` in `(at_ms DESC, id DESC)` order. Stores apply it as a
/// row-value range on an index, so a page reads only its own rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OlderThan<'a> {
    pub at_ms: i64,
    pub id: &'a str,
}

impl OlderThan<'_> {
    /// The first page. A row stamped `i64::MAX` is never listed.
    pub const START: OlderThan<'static> = OlderThan {
        at_ms: i64::MAX,
        id: "",
    };
}

#[cfg(test)]
mod older_than_tests {
    use super::OlderThan;
    use super::sekai::SekaiDb;

    /// Each pending-decision listing seeks its index from the keyset
    /// position, so a page reads only its own rows, however deep it is.
    #[test]
    fn pending_decision_listings_seek_their_index_from_the_position() {
        let db = SekaiDb::new(":memory:").unwrap();
        // Each listing creates its tables on first use.
        db.list_action_instances_older_than("ns", None, "parked", 1, OlderThan::START)
            .unwrap();
        db.list_pending_plan_reviews("ns", 1, OlderThan::START)
            .unwrap();
        db.list_open_definition_proposals("ns", 1, OlderThan::START)
            .unwrap();
        db.list_open_dataset_branch_proposals("t", "ns", 1, OlderThan::START)
            .unwrap();
        let conn = db.conn();
        for (sql, index) in [
            (
                crate::sekai::action_instance::SQLITE_ACTION_INSTANCES_OLDER_THAN,
                "idx_action_instances_ns_status",
            ),
            (
                crate::sekai::action_plan_store::SQLITE_PENDING_PLAN_REVIEWS,
                "idx_sekai_plan_reviews_pending",
            ),
            (
                super::definition_branch::SQLITE_OPEN_DEFINITION_PROPOSALS,
                "idx_definition_proposal_open",
            ),
            (
                super::dataset_branch::SQLITE_OPEN_DATASET_BRANCH_PROPOSALS,
                "idx_sekai_dataset_branch_proposals_open",
            ),
        ] {
            let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let count = stmt.parameter_count();
            let plan: Vec<String> = stmt
                .query_map(
                    rusqlite::params_from_iter(std::iter::repeat_n("x", count)),
                    |row| row.get(3),
                )
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert!(
                plan.iter()
                    .any(|step| step.contains(&format!("USING INDEX {index}"))
                        && step.contains(")<(?,?)")),
                "{index}: {plan:?}"
            );
            assert!(
                plan.iter().all(|step| !step.contains("TEMP B-TREE")),
                "{index}: {plan:?}"
            );
        }
    }
}

/// Run an additive `ALTER TABLE ... ADD COLUMN`, treating an already-present
/// column as success. Any other failure (busy, I/O, read-only) is returned so
/// a migration never reports Ok over a missing column.
pub(crate) fn add_sqlite_column(
    conn: &rusqlite::Connection,
    statement: &str,
) -> Result<(), String> {
    match conn.execute(statement, []) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(_, Some(message)))
            if message.contains("duplicate column name") =>
        {
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod add_sqlite_column_tests {
    use super::add_sqlite_column;

    #[test]
    fn an_existing_column_is_success_and_other_failures_are_returned() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (a TEXT)").unwrap();
        add_sqlite_column(&conn, "ALTER TABLE t ADD COLUMN b TEXT").unwrap();
        add_sqlite_column(&conn, "ALTER TABLE t ADD COLUMN b TEXT").unwrap();
        let error = add_sqlite_column(&conn, "ALTER TABLE missing ADD COLUMN b TEXT").unwrap_err();
        assert!(error.contains("no such table"), "{error}");
    }
}
