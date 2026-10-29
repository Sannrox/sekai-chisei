//! Dual-backend community-store dispatch for datasets.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn append_rows(
        &self,
        dataset_id: &str,
        rows: &[HashMap<String, String>],
    ) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.append_rows(dataset_id, rows),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.append_dataset_rows(dataset_id, rows))
            }
        }
    }

    pub fn create_dataset(&self, d: &Dataset) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_dataset(d),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_dataset(d)),
        }
    }

    pub fn create_virtual_table(&self, vt: &VirtualTable) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_virtual_table(vt),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_virtual_table(vt)),
        }
    }

    pub fn get_dataset(&self, id: &str) -> Result<Option<Dataset>, String> {
        match self {
            Self::Sqlite(db) => db.get_dataset(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_dataset(id)),
        }
    }

    pub fn list_datasets(&self) -> Result<Vec<Dataset>, String> {
        match self {
            Self::Sqlite(db) => db.list_datasets(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_datasets()),
        }
    }

    pub fn list_virtual_tables(&self) -> Result<Vec<VirtualTable>, String> {
        match self {
            Self::Sqlite(db) => db.list_virtual_tables(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_virtual_tables()),
        }
    }

    pub fn query_rows(
        &self,
        dataset_id: &str,
        q: &RowQuery,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        match self {
            Self::Sqlite(db) => db.query_rows(dataset_id, q),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.query_dataset_rows(dataset_id, q))
            }
        }
    }

    /// The dataset's newest version id; empty when it has none.
    pub fn latest_dataset_version_id(&self, dataset_id: &str) -> Result<String, String> {
        Ok(self
            .list_dataset_versions(dataset_id)?
            .into_iter()
            .max_by_key(|version| version.seq)
            .map(|version| version.version_id)
            .unwrap_or_default())
    }

    pub fn list_dataset_versions(&self, dataset_id: &str) -> Result<Vec<DatasetVersion>, String> {
        match self {
            Self::Sqlite(db) => db.list_dataset_versions(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_dataset_versions(dataset_id))
            }
        }
    }

    pub fn get_dataset_version(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<DatasetVersion, String> {
        match self {
            Self::Sqlite(db) => db.get_dataset_version(dataset_id, version_id, as_of_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_dataset_version(dataset_id, version_id, as_of_ms)
            }),
        }
    }

    pub fn query_dataset_version_rows(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        Ok(self
            .load_dataset_version(dataset_id, version_id, as_of_ms)?
            .1)
    }

    pub fn load_dataset_version(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<(DatasetVersion, Vec<HashMap<String, String>>), String> {
        match self {
            Self::Sqlite(db) => db.load_dataset_version(dataset_id, version_id, as_of_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.load_dataset_version(dataset_id, version_id, as_of_ms)
            }),
        }
    }

    pub fn create_dataset_branch(
        &self,
        request: &crate::sekai::dataset_branch::CreateDatasetBranch,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranch, String> {
        match self {
            Self::Sqlite(db) => db.create_dataset_branch(request),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.create_dataset_branch(request))
            }
        }
    }

    pub fn list_dataset_branches(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<crate::sekai::dataset_branch::DatasetBranch>, String> {
        match self {
            Self::Sqlite(db) => db.list_dataset_branches(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_dataset_branches(dataset_id))
            }
        }
    }

    pub fn dataset_branch_rows(
        &self,
        dataset_id: &str,
        name: &str,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        match self {
            Self::Sqlite(db) => db.dataset_branch_rows(dataset_id, name),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.dataset_branch_rows(dataset_id, name))
            }
        }
    }

    pub fn write_dataset_branch_rows(
        &self,
        dataset_id: &str,
        name: &str,
        rows: &[HashMap<String, String>],
        replace: bool,
    ) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.write_dataset_branch_rows(dataset_id, name, rows, replace),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.write_dataset_branch_rows(dataset_id, name, rows, replace)
            }),
        }
    }

    /// Every object type binding of `dataset_id`, as (namespace, kind).
    pub fn dataset_bindings(&self, dataset_id: &str) -> Result<Vec<(String, String)>, String> {
        match self {
            Self::Sqlite(db) => db.dataset_bindings(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.dataset_bindings(dataset_id))
            }
        }
    }

    /// Fill an unwritten branch from its base version; see the backend docs.
    pub fn fill_dataset_branch_from_base(
        &self,
        dataset_id: &str,
        name: &str,
        incarnation: &str,
        compute: &crate::sekai::dataset_branch::BranchCompute<'_>,
    ) -> Result<
        (
            crate::sekai::dataset_branch::BranchRows,
            crate::sekai::dataset_branch::BranchRows,
        ),
        String,
    > {
        match self {
            Self::Sqlite(db) => {
                db.fill_dataset_branch_from_base(dataset_id, name, incarnation, compute)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.fill_dataset_branch_from_base(dataset_id, name, incarnation, compute)
            }),
        }
    }

    pub fn compare_dataset_branch(
        &self,
        dataset_id: &str,
        name: &str,
        tenant: &str,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranchDiff, String> {
        match self {
            Self::Sqlite(db) => db.compare_dataset_branch(dataset_id, name, tenant),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.compare_dataset_branch(dataset_id, name, tenant)
            }),
        }
    }

    pub fn delete_dataset_branch(
        &self,
        dataset_id: &str,
        name: &str,
        tenant: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_dataset_branch(dataset_id, name, tenant),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.delete_dataset_branch(dataset_id, name, tenant)
            }),
        }
    }

    pub fn propose_dataset_branch(
        &self,
        request: &crate::sekai::dataset_branch::ProposeDatasetBranch,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranchProposal, String> {
        match self {
            Self::Sqlite(db) => db.propose_dataset_branch(request),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.propose_dataset_branch(request))
            }
        }
    }

    pub fn get_dataset_branch_proposal(
        &self,
        dataset_id: &str,
        id: &str,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranchProposal, String> {
        match self {
            Self::Sqlite(db) => db.get_dataset_branch_proposal(dataset_id, id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_dataset_branch_proposal(dataset_id, id))
            }
        }
    }

    pub fn merge_dataset_branch(
        &self,
        request: &crate::sekai::dataset_branch::MergeDatasetBranch,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranchProposal, String> {
        match self {
            Self::Sqlite(db) => db.merge_dataset_branch(request),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.merge_dataset_branch(request))
            }
        }
    }

    pub fn merge_dataset_branch_checked(
        &self,
        request: &crate::sekai::dataset_branch::MergeDatasetBranch,
        check: &dyn Fn(&[crate::sekai::dataset::ColumnDef]) -> Result<(), String>,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranchProposal, String> {
        match self {
            Self::Sqlite(db) => db.merge_dataset_branch_checked(request, check),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.merge_dataset_branch_checked(request, check))
            }
        }
    }

    pub fn rollback_dataset(&self, request: &DatasetRollback) -> Result<DatasetVersion, String> {
        match self {
            Self::Sqlite(db) => db.rollback_dataset(request),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.rollback_dataset(request)),
        }
    }

    pub fn dataset_version_retention(&self, dataset_id: &str) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.dataset_version_retention(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.dataset_version_retention(dataset_id))
            }
        }
    }

    pub fn set_dataset_version_retention(
        &self,
        dataset_id: &str,
        retain_count: i32,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_dataset_version_retention(dataset_id, retain_count),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_dataset_version_retention(dataset_id, retain_count)
            }),
        }
    }

    pub fn put_dataset_health_check(&self, check: &DatasetHealthCheck) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_dataset_health_check(check),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_dataset_health_check(check))
            }
        }
    }

    pub fn list_dataset_health_checks(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<DatasetHealthCheck>, String> {
        match self {
            Self::Sqlite(db) => db.list_dataset_health_checks(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_dataset_health_checks(dataset_id))
            }
        }
    }

    pub fn list_dataset_health_results(
        &self,
        dataset_id: &str,
        version_id: &str,
    ) -> Result<Vec<DatasetHealthResult>, String> {
        match self {
            Self::Sqlite(db) => db.list_dataset_health_results(dataset_id, version_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_dataset_health_results(dataset_id, version_id)
            }),
        }
    }

    pub fn dataset_health_state(&self, dataset_id: &str) -> Result<DatasetHealthState, String> {
        match self {
            Self::Sqlite(db) => db.dataset_health_state(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.dataset_health_state(dataset_id))
            }
        }
    }

    pub fn list_dataset_alerts(&self, dataset_id: &str) -> Result<Vec<DatasetAlert>, String> {
        match self {
            Self::Sqlite(db) => db.list_dataset_alerts(dataset_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_dataset_alerts(dataset_id))
            }
        }
    }

    pub fn run_dataset_health_checks(
        &self,
        dataset_id: &str,
        now_ms: i64,
    ) -> Result<Vec<DatasetHealthResult>, String> {
        match self {
            Self::Sqlite(db) => db.run_dataset_health_checks(dataset_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.run_dataset_health_checks(dataset_id, now_ms)
            }),
        }
    }

    pub fn emit_consumer_violation(
        &self,
        emit: &crate::sekai::consumer_violation::EmitViolation<'_>,
    ) -> Result<usize, String> {
        match self {
            Self::Sqlite(db) => db.emit_consumer_violation(emit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.emit_consumer_violation(emit))
            }
        }
    }

    pub fn list_consumer_violation_deliveries(
        &self,
        query: &crate::sekai::consumer_violation::ListViolationDeliveries,
    ) -> Result<
        (
            Vec<crate::sekai::consumer_violation::ViolationDelivery>,
            String,
        ),
        String,
    > {
        match self {
            Self::Sqlite(db) => db.list_consumer_violation_deliveries(query),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_consumer_violation_deliveries(query))
            }
        }
    }

    pub fn get_consumer_violation_delivery(
        &self,
        recipients: &[String],
        event_id: &str,
    ) -> Result<Option<crate::sekai::consumer_violation::ViolationDelivery>, String> {
        match self {
            Self::Sqlite(db) => db.get_consumer_violation_delivery(recipients, event_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_consumer_violation_delivery(recipients, event_id)
            }),
        }
    }

    pub fn acknowledge_consumer_violation(
        &self,
        recipients: &[String],
        event_id: &str,
        now_ms: i64,
    ) -> Result<Option<crate::sekai::consumer_violation::ViolationDelivery>, String> {
        match self {
            Self::Sqlite(db) => db.acknowledge_consumer_violation(recipients, event_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.acknowledge_consumer_violation(recipients, event_id, now_ms)
            }),
        }
    }

    pub fn insert_catalog_criticality_event(
        &self,
        event: &crate::sekai::catalog_criticality::CriticalityEvent,
        expected_updated: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.insert_catalog_criticality_event(event, expected_updated),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.insert_catalog_criticality_event(event, expected_updated)
            }),
        }
    }

    pub fn latest_catalog_criticality_event(
        &self,
        entry_id: &str,
    ) -> Result<Option<crate::sekai::catalog_criticality::CriticalityEvent>, String> {
        match self {
            Self::Sqlite(db) => db.latest_catalog_criticality_event(entry_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.latest_catalog_criticality_event(entry_id))
            }
        }
    }

    pub fn list_catalog_criticality_outbox(
        &self,
        namespace: &str,
        page_size: i32,
        page_token: &str,
    ) -> Result<
        (
            Vec<crate::sekai::catalog_criticality::CriticalityEvent>,
            String,
        ),
        String,
    > {
        match self {
            Self::Sqlite(db) => {
                db.list_catalog_criticality_outbox(namespace, page_size, page_token)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_catalog_criticality_outbox(namespace, page_size, page_token)
            }),
        }
    }

    pub fn add_dataset_columns(
        &self,
        dataset_id: &str,
        columns: &[crate::sekai::dataset::ColumnDef],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.add_dataset_columns(dataset_id, columns),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.add_dataset_columns(dataset_id, columns))
            }
        }
    }

    pub fn update_dataset(&self, d: &Dataset) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_dataset(d),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.update_dataset(d)),
        }
    }
}
