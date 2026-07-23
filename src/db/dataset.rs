//! Backend-neutral persistence contract for reusable Sekai datasets.

use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::dataset::{Dataset, DatasetRedaction, RowFilter, RowQuery, VirtualTable};
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
}
