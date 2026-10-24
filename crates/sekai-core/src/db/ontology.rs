//! Backend-neutral durable ontology definition contract.

use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::ontology::{OntologyClass, OntologyRelation};

pub trait OntologyBackend: Send + Sync {
    fn upsert_ontology_class(&self, class: &OntologyClass) -> Result<(), String>;
    fn delete_ontology_class(&self, name: &str) -> Result<bool, String>;
    fn get_ontology_class(&self, name: &str) -> Result<Option<OntologyClass>, String>;
    fn list_ontology_classes(&self) -> Result<Vec<OntologyClass>, String>;
    fn upsert_ontology_relation(&self, relation: &OntologyRelation) -> Result<(), String>;
    fn delete_ontology_relation(&self, name: &str) -> Result<bool, String>;
    fn get_ontology_relation(&self, name: &str) -> Result<Option<OntologyRelation>, String>;
    fn list_ontology_relations(&self) -> Result<Vec<OntologyRelation>, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn upsert_ontology_class(&self, class: &OntologyClass) -> Result<(), String> {
            <$target>::upsert_ontology_class(self, class)
        }
        fn delete_ontology_class(&self, name: &str) -> Result<bool, String> {
            <$target>::delete_ontology_class(self, name)
        }
        fn get_ontology_class(&self, name: &str) -> Result<Option<OntologyClass>, String> {
            <$target>::get_ontology_class(self, name)
        }
        fn list_ontology_classes(&self) -> Result<Vec<OntologyClass>, String> {
            <$target>::list_ontology_classes(self)
        }
        fn upsert_ontology_relation(&self, relation: &OntologyRelation) -> Result<(), String> {
            <$target>::upsert_ontology_relation(self, relation)
        }
        fn delete_ontology_relation(&self, name: &str) -> Result<bool, String> {
            <$target>::delete_ontology_relation(self, name)
        }
        fn get_ontology_relation(&self, name: &str) -> Result<Option<OntologyRelation>, String> {
            <$target>::get_ontology_relation(self, name)
        }
        fn list_ontology_relations(&self) -> Result<Vec<OntologyRelation>, String> {
            <$target>::list_ontology_relations(self)
        }
    };
}

impl OntologyBackend for SekaiDb {
    forward!(SekaiDb);
}

impl OntologyBackend for PostgresDb {
    forward!(PostgresDb);
}
