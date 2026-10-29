//! PostgreSQL schema for Chisei-owned families.
//!
//! Applied when a [`crate::chisei_store::ChiseiStore`] opens. Version numbers
//! match the history `sekai-core` records so dest-pair upgrades stay aligned.

use sekai_core::db::postgres::{PlaneSql, PostgresDb};

const fn plane(
    version: i64,
    name: &'static str,
    sql: &'static str,
    catch_up_relation: Option<&'static str>,
) -> PlaneSql {
    PlaneSql {
        version,
        name,
        sql,
        catch_up_relation,
    }
}

pub const CHISEI_PLANE_SQL: &[PlaneSql] = &[
    plane(
        1,
        "control_plane",
        include_str!("postgres/0001_control_plane_chisei.sql"),
        Some("chisei_eval_suites"),
    ),
    plane(
        2,
        "sample_leases",
        include_str!("postgres/0002_sample_leases.sql"),
        None,
    ),
    plane(
        4,
        "portfolio_prompt_variants",
        include_str!("postgres/0004_portfolio_prompt_variants.sql"),
        None,
    ),
    plane(
        16,
        "chisei_execution_parity",
        include_str!("postgres/0017_chisei_execution_parity.sql"),
        None,
    ),
    plane(
        17,
        "budget_topology",
        include_str!("postgres/0018_budget_topology.sql"),
        None,
    ),
    plane(
        23,
        "evaluation_plans",
        include_str!("postgres/0024_evaluation_plans.sql"),
        None,
    ),
    plane(
        24,
        "evaluation_manifests",
        include_str!("postgres/0025_evaluation_manifests.sql"),
        None,
    ),
    plane(
        25,
        "evaluation_executions",
        include_str!("postgres/0026_evaluation_executions.sql"),
        None,
    ),
    plane(
        26,
        "governed_subject_provenance",
        include_str!("postgres/0027_governed_subject_provenance.sql"),
        None,
    ),
    plane(
        45,
        "chisei_operation_reservations",
        include_str!("postgres/0046_chisei_operation_reservations.sql"),
        None,
    ),
    plane(
        48,
        "chisei_routing_profiles",
        include_str!("postgres/0049_chisei_routing_profiles.sql"),
        None,
    ),
    plane(
        60,
        "chisei_model_review",
        include_str!("postgres/0061_chisei_model_review.sql"),
        None,
    ),
    plane(
        61,
        "routing_profile_artifact_digest",
        include_str!("postgres/0062_routing_profile_artifact_digest.sql"),
        None,
    ),
    plane(
        62,
        "chisei_model_release_evidence",
        include_str!("postgres/0063_chisei_model_release_evidence.sql"),
        None,
    ),
    plane(
        66,
        "chisei_gunshi_allocation_state",
        include_str!("postgres/0067_chisei_gunshi_allocation_state.sql"),
        None,
    ),
    plane(
        76,
        "chisei_usage_events",
        include_str!("postgres/0077_chisei_usage_events.sql"),
        None,
    ),
    plane(
        80,
        "receipt_chain",
        include_str!("postgres/0081_receipt_chain.sql"),
        None,
    ),
    plane(
        89,
        "chisei_policy_shadow",
        include_str!("postgres/0090_chisei_policy_shadow.sql"),
        None,
    ),
    plane(
        95,
        "chisei_dataset_runs",
        include_str!("postgres/0096_chisei_dataset_runs.sql"),
        None,
    ),
    plane(
        98,
        "chisei_dataset_run_artifacts",
        include_str!("postgres/0099_chisei_dataset_run_artifacts.sql"),
        None,
    ),
    plane(
        122,
        "chisei_reservation_charge_key",
        include_str!("postgres/0123_chisei_reservation_charge_key.sql"),
        None,
    ),
    plane(
        124,
        "budget_work_unit_defaults",
        include_str!("postgres/0125_budget_work_unit_defaults.sql"),
        None,
    ),
];

pub fn apply_chisei_postgres_schema(db: &PostgresDb) -> Result<(), String> {
    sekai_core::db::postgres::off_runtime(|| db.apply_plane_sql(CHISEI_PLANE_SQL))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sql(name: &str) -> &'static str {
        CHISEI_PLANE_SQL
            .iter()
            .find(|migration| migration.name == name)
            .map(|migration| migration.sql)
            .expect(name)
    }

    #[test]
    fn control_plane_covers_chisei_families_and_shared_leftovers() {
        let schema = sql("control_plane");
        for table in [
            "sekai_decisions",
            "sekai_ledger_anchors",
            "chisei_eval_suites",
            "chisei_eval_runs",
            "chisei_eval_iterations",
            "chisei_budget_limits",
            "chisei_budget_usage",
        ] {
            assert!(
                schema.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL Chisei control-plane table {table}"
            );
        }
        assert!(!schema.contains("sekai_objects"));
    }

    #[test]
    fn family_sql_covers_owned_tables() {
        let sample = sql("sample_leases");
        assert!(sample.contains("chisei_sample_observations"));
        assert!(sample.contains("lease_expires_at"));
        assert!(sample.contains("IF NOT EXISTS"));

        let portfolio = sql("portfolio_prompt_variants");
        assert!(portfolio.contains("DEFAULT 'legacy@1'"));
        assert!(
            portfolio.contains("ADD PRIMARY KEY (namespace, task_class, model, prompt_variant)")
        );

        let execution = sql("chisei_execution_parity");
        for table in [
            "chisei_operation_receipts",
            "chisei_gateway_request_aliases",
            "chisei_budget_usage_events",
            "chisei_budget_attributions",
            "chisei_kioku_memories",
            "chisei_external_action_authorizations",
            "chisei_external_action_permits",
        ] {
            assert!(
                execution.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL table {table}"
            );
        }
        for excluded in ["tenant", "oauth", "oidc"] {
            assert!(!execution.contains(excluded));
        }
        assert!(!execution.contains("AUTOINCREMENT"));
        assert!(!execution.contains("INSERT OR"));

        assert!(
            sql("chisei_operation_reservations")
                .contains("CREATE TABLE IF NOT EXISTS chisei_operation_reservations")
        );

        let budget = sql("budget_topology");
        for table in ["chisei_budget_pools", "chisei_budget_transfers"] {
            assert!(
                budget.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "missing PostgreSQL table {table}"
            );
        }
        assert!(budget.contains("home_site_id"));
        assert!(budget.contains("pool_id"));

        assert!(
            sql("chisei_usage_events").contains("CREATE TABLE IF NOT EXISTS chisei_usage_events")
        );
    }
}
