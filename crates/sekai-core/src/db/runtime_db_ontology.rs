//! Dual-backend community-store dispatch for ontology.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn delete_ontology_class_with_audit(
        &self,
        name: &str,
        actor: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_ontology_class_with_audit(name, actor),
            Self::Postgres(_) => Err("delete_ontology_class_with_audit is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn delete_ontology_relation_with_audit(
        &self,
        name: &str,
        actor: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_ontology_relation_with_audit(name, actor),
            Self::Postgres(_) => Err("delete_ontology_relation_with_audit is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn get_ontology_class(&self, name: &str) -> Result<Option<OntologyClass>, String> {
        match self {
            Self::Sqlite(db) => db.get_ontology_class(name),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_ontology_class(name)),
        }
    }

    pub fn get_ontology_relation(&self, name: &str) -> Result<Option<OntologyRelation>, String> {
        match self {
            Self::Sqlite(db) => db.get_ontology_relation(name),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_ontology_relation(name))
            }
        }
    }

    pub fn list_ontology_classes(&self) -> Result<Vec<OntologyClass>, String> {
        match self {
            Self::Sqlite(db) => db.list_ontology_classes(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_ontology_classes()),
        }
    }

    pub fn list_ontology_relations(&self) -> Result<Vec<OntologyRelation>, String> {
        match self {
            Self::Sqlite(db) => db.list_ontology_relations(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_ontology_relations()),
        }
    }

    pub fn list_readable_ontology_classes(
        &self,
        principals: &[String],
        deadline: Instant,
        limit: u32,
    ) -> Result<Vec<OntologyClass>, String> {
        match self {
            Self::Sqlite(db) => db.list_readable_ontology_classes(principals, deadline, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_readable_ontology_classes(principals, deadline, limit)
            }),
        }
    }

    pub fn list_readable_ontology_relations(
        &self,
        principals: &[String],
        deadline: Instant,
        limit: u32,
    ) -> Result<Vec<OntologyRelation>, String> {
        match self {
            Self::Sqlite(db) => db.list_readable_ontology_relations(principals, deadline, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_readable_ontology_relations(principals, deadline, limit)
            }),
        }
    }

    pub fn load_ontology_registry(&self) -> Result<OntologyRegistry, String> {
        match self {
            Self::Sqlite(db) => db.load_ontology_registry(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                Ok(OntologyRegistry::from_parts(
                    db.list_ontology_classes()?,
                    db.list_ontology_relations()?,
                ))
            }),
        }
    }

    pub fn upsert_ontology_class_with_audit(
        &self,
        class: &OntologyClass,
        actor: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_class_with_audit(class, actor),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.upsert_ontology_class_with_audit(class, actor)
            }),
        }
    }

    pub fn upsert_ontology_relation_with_audit(
        &self,
        relation: &OntologyRelation,
        actor: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_relation_with_audit(relation, actor),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.upsert_ontology_relation_with_audit(relation, actor)
            }),
        }
    }

    pub fn upsert_projected_ontology_class_with_audit(
        &self,
        class: &OntologyClass,
        actor: &str,
        source_grants: &[Grant],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_projected_ontology_class_with_audit(class, actor, source_grants),
            Self::Postgres(_) => Err("upsert_projected_ontology_class_with_audit is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn upsert_ontology_class(&self, class: &OntologyClass) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_class(class),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.upsert_ontology_class(class))
            }
        }
    }

    pub fn upsert_ontology_relation(&self, relation: &OntologyRelation) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_relation(relation),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.upsert_ontology_relation(relation))
            }
        }
    }
}
