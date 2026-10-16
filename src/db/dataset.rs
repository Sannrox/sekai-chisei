//! Backend-neutral persistence contract for reusable Sekai datasets.

use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::dataset::{Dataset, DatasetRedaction, RowFilter, RowQuery, VirtualTable};
use crate::sekai::dataset_health::{
    DatasetAlert, DatasetHealthCheck, DatasetHealthResult, DatasetHealthState,
};
use crate::sekai::dataset_version::{DatasetRollback, DatasetVersion};
use std::collections::HashMap;

pub trait DatasetBackend: Send + Sync {
    fn create_dataset(&self, dataset: &Dataset) -> Result<(), String>;
    fn update_dataset(&self, dataset: &Dataset) -> Result<(), String>;
    fn get_dataset(&self, id: &str) -> Result<Option<Dataset>, String>;
    fn list_datasets(&self) -> Result<Vec<Dataset>, String>;
    fn append_rows(
        &self,
        dataset_id: &str,
        rows: &[HashMap<String, String>],
    ) -> Result<i32, String>;
    fn query_rows(
        &self,
        dataset_id: &str,
        query: &RowQuery,
    ) -> Result<Vec<HashMap<String, String>>, String>;
    fn redact_dataset_fields(
        &self,
        dataset_id: &str,
        classification: &str,
        filters: &[RowFilter],
    ) -> Result<DatasetRedaction, String>;
    fn create_virtual_table(&self, table: &VirtualTable) -> Result<(), String>;
    fn list_virtual_tables(&self) -> Result<Vec<VirtualTable>, String>;
    fn list_dataset_versions(&self, dataset_id: &str) -> Result<Vec<DatasetVersion>, String>;
    fn get_dataset_version(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<DatasetVersion, String>;
    fn query_dataset_version_rows(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<Vec<HashMap<String, String>>, String>;
    fn rollback_dataset(&self, request: &DatasetRollback) -> Result<DatasetVersion, String>;
    fn dataset_version_retention(&self, dataset_id: &str) -> Result<i32, String>;
    fn set_dataset_version_retention(
        &self,
        dataset_id: &str,
        retain_count: i32,
    ) -> Result<(), String>;
    fn put_dataset_health_check(&self, check: &DatasetHealthCheck) -> Result<(), String>;
    fn list_dataset_health_checks(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<DatasetHealthCheck>, String>;
    fn list_dataset_health_results(
        &self,
        dataset_id: &str,
        version_id: &str,
    ) -> Result<Vec<DatasetHealthResult>, String>;
    fn dataset_health_state(&self, dataset_id: &str) -> Result<DatasetHealthState, String>;
    fn list_dataset_alerts(&self, dataset_id: &str) -> Result<Vec<DatasetAlert>, String>;
    fn run_dataset_health_checks(
        &self,
        dataset_id: &str,
        now_ms: i64,
    ) -> Result<Vec<DatasetHealthResult>, String>;
}

macro_rules! sqlite_forward {
    ($name:ident($($arg:ident : $ty:ty),*) -> $result:ty) => {
        fn $name(&self, $($arg: $ty),*) -> $result {
            SekaiDb::$name(self, $($arg),*)
        }
    };
}

impl DatasetBackend for SekaiDb {
    sqlite_forward!(create_dataset(dataset: &Dataset) -> Result<(), String>);
    sqlite_forward!(update_dataset(dataset: &Dataset) -> Result<(), String>);
    sqlite_forward!(get_dataset(id: &str) -> Result<Option<Dataset>, String>);
    sqlite_forward!(list_datasets() -> Result<Vec<Dataset>, String>);
    sqlite_forward!(append_rows(dataset_id: &str, rows: &[HashMap<String, String>]) -> Result<i32, String>);
    sqlite_forward!(query_rows(dataset_id: &str, query: &RowQuery) -> Result<Vec<HashMap<String, String>>, String>);
    sqlite_forward!(redact_dataset_fields(dataset_id: &str, classification: &str, filters: &[RowFilter]) -> Result<DatasetRedaction, String>);
    sqlite_forward!(create_virtual_table(table: &VirtualTable) -> Result<(), String>);
    sqlite_forward!(list_virtual_tables() -> Result<Vec<VirtualTable>, String>);
    sqlite_forward!(list_dataset_versions(dataset_id: &str) -> Result<Vec<DatasetVersion>, String>);
    sqlite_forward!(get_dataset_version(dataset_id: &str, version_id: &str, as_of_ms: i64) -> Result<DatasetVersion, String>);
    sqlite_forward!(query_dataset_version_rows(dataset_id: &str, version_id: &str, as_of_ms: i64) -> Result<Vec<HashMap<String, String>>, String>);
    sqlite_forward!(rollback_dataset(request: &DatasetRollback) -> Result<DatasetVersion, String>);
    sqlite_forward!(dataset_version_retention(dataset_id: &str) -> Result<i32, String>);
    sqlite_forward!(set_dataset_version_retention(dataset_id: &str, retain_count: i32) -> Result<(), String>);
    sqlite_forward!(put_dataset_health_check(check: &DatasetHealthCheck) -> Result<(), String>);
    sqlite_forward!(list_dataset_health_checks(dataset_id: &str) -> Result<Vec<DatasetHealthCheck>, String>);
    sqlite_forward!(list_dataset_health_results(dataset_id: &str, version_id: &str) -> Result<Vec<DatasetHealthResult>, String>);
    sqlite_forward!(dataset_health_state(dataset_id: &str) -> Result<DatasetHealthState, String>);
    sqlite_forward!(list_dataset_alerts(dataset_id: &str) -> Result<Vec<DatasetAlert>, String>);
    sqlite_forward!(run_dataset_health_checks(dataset_id: &str, now_ms: i64) -> Result<Vec<DatasetHealthResult>, String>);
}

impl DatasetBackend for PostgresDb {
    fn create_dataset(&self, dataset: &Dataset) -> Result<(), String> {
        self.create_dataset(dataset)
    }
    fn update_dataset(&self, dataset: &Dataset) -> Result<(), String> {
        self.update_dataset(dataset)
    }
    fn get_dataset(&self, id: &str) -> Result<Option<Dataset>, String> {
        self.get_dataset(id)
    }
    fn list_datasets(&self) -> Result<Vec<Dataset>, String> {
        self.list_datasets()
    }
    fn append_rows(
        &self,
        dataset_id: &str,
        rows: &[HashMap<String, String>],
    ) -> Result<i32, String> {
        self.append_dataset_rows(dataset_id, rows)
    }
    fn query_rows(
        &self,
        dataset_id: &str,
        query: &RowQuery,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        self.query_dataset_rows(dataset_id, query)
    }
    fn redact_dataset_fields(
        &self,
        dataset_id: &str,
        classification: &str,
        filters: &[RowFilter],
    ) -> Result<DatasetRedaction, String> {
        self.redact_dataset_fields(dataset_id, classification, filters)
    }
    fn create_virtual_table(&self, table: &VirtualTable) -> Result<(), String> {
        self.create_virtual_table(table)
    }
    fn list_virtual_tables(&self) -> Result<Vec<VirtualTable>, String> {
        self.list_virtual_tables()
    }
    fn list_dataset_versions(&self, dataset_id: &str) -> Result<Vec<DatasetVersion>, String> {
        self.list_dataset_versions(dataset_id)
    }
    fn get_dataset_version(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<DatasetVersion, String> {
        self.get_dataset_version(dataset_id, version_id, as_of_ms)
    }
    fn query_dataset_version_rows(
        &self,
        dataset_id: &str,
        version_id: &str,
        as_of_ms: i64,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        self.query_dataset_version_rows(dataset_id, version_id, as_of_ms)
    }
    fn rollback_dataset(&self, request: &DatasetRollback) -> Result<DatasetVersion, String> {
        self.rollback_dataset(request)
    }
    fn dataset_version_retention(&self, dataset_id: &str) -> Result<i32, String> {
        self.dataset_version_retention(dataset_id)
    }
    fn set_dataset_version_retention(
        &self,
        dataset_id: &str,
        retain_count: i32,
    ) -> Result<(), String> {
        self.set_dataset_version_retention(dataset_id, retain_count)
    }
    fn put_dataset_health_check(&self, check: &DatasetHealthCheck) -> Result<(), String> {
        self.put_dataset_health_check(check)
    }
    fn list_dataset_health_checks(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<DatasetHealthCheck>, String> {
        self.list_dataset_health_checks(dataset_id)
    }
    fn list_dataset_health_results(
        &self,
        dataset_id: &str,
        version_id: &str,
    ) -> Result<Vec<DatasetHealthResult>, String> {
        self.list_dataset_health_results(dataset_id, version_id)
    }
    fn dataset_health_state(&self, dataset_id: &str) -> Result<DatasetHealthState, String> {
        self.dataset_health_state(dataset_id)
    }
    fn list_dataset_alerts(&self, dataset_id: &str) -> Result<Vec<DatasetAlert>, String> {
        self.list_dataset_alerts(dataset_id)
    }
    fn run_dataset_health_checks(
        &self,
        dataset_id: &str,
        now_ms: i64,
    ) -> Result<Vec<DatasetHealthResult>, String> {
        self.run_dataset_health_checks(dataset_id, now_ms)
    }
}
