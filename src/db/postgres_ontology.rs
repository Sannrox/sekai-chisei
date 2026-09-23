use crate::db::postgres::PostgresDb;
use crate::sekai::ontology::{OntologyClass, OntologyRelation};

const CLASS_COLUMNS: &str =
    "name,description,superclasses_json,equivalent_json,disjoint_json,properties_json,mapped_kind";
const RELATION_COLUMNS: &str =
    "name,description,domain,range,cardinality_json,inverse,transitive,mapped_relation";

impl PostgresDb {
    pub fn upsert_ontology_class(&self, class: &OntologyClass) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        upsert_class_row(&mut *self.connection()?, class, now)
    }

    /// Writes the class and its chained audit decision in one transaction,
    /// the same record the SQLite runtime keeps.
    pub fn upsert_ontology_class_with_audit(
        &self,
        class: &OntologyClass,
        actor: &str,
    ) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let existed: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM sekai_ontology_classes WHERE name = $1)",
                &[&class.name],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        upsert_class_row(&mut transaction, class, now)?;
        insert_ontology_audit(
            &mut transaction,
            actor,
            if existed {
                "ontology.class.update"
            } else {
                "ontology.class.create"
            },
            &format!("ontology:class:{}", class.name),
            &class.name,
            now,
        )?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn delete_ontology_class(&self, name: &str) -> Result<bool, String> {
        self.connection()?
            .execute("DELETE FROM sekai_ontology_classes WHERE name=$1", &[&name])
            .map(|deleted| deleted > 0)
            .map_err(|error| error.to_string())
    }

    pub fn get_ontology_class(&self, name: &str) -> Result<Option<OntologyClass>, String> {
        self.connection()?
            .query_opt(
                &format!("SELECT {CLASS_COLUMNS} FROM sekai_ontology_classes WHERE name=$1"),
                &[&name],
            )
            .map_err(|error| error.to_string())?
            .map(class_from_row)
            .transpose()
    }

    pub fn list_ontology_classes(&self) -> Result<Vec<OntologyClass>, String> {
        self.connection()?
            .query(
                &format!("SELECT {CLASS_COLUMNS} FROM sekai_ontology_classes ORDER BY name"),
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(class_from_row)
            .collect()
    }

    pub fn upsert_ontology_relation(&self, relation: &OntologyRelation) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        upsert_relation_row(&mut transaction, relation, now)?;
        transaction.commit().map_err(|error| error.to_string())
    }

    /// Writes the relation and its chained audit decision in one transaction.
    pub fn upsert_ontology_relation_with_audit(
        &self,
        relation: &OntologyRelation,
        actor: &str,
    ) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let existed: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM sekai_ontology_relations WHERE name = $1)",
                &[&relation.name],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        upsert_relation_row(&mut transaction, relation, now)?;
        insert_ontology_audit(
            &mut transaction,
            actor,
            if existed {
                "ontology.relation.update"
            } else {
                "ontology.relation.create"
            },
            &format!("ontology:relation:{}", relation.name),
            &relation.name,
            now,
        )?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn delete_ontology_relation(&self, name: &str) -> Result<bool, String> {
        self.connection()?
            .execute(
                "DELETE FROM sekai_ontology_relations WHERE name=$1",
                &[&name],
            )
            .map(|deleted| deleted > 0)
            .map_err(|error| error.to_string())
    }

    pub fn get_ontology_relation(&self, name: &str) -> Result<Option<OntologyRelation>, String> {
        self.connection()?
            .query_opt(
                &format!("SELECT {RELATION_COLUMNS} FROM sekai_ontology_relations WHERE name=$1"),
                &[&name],
            )
            .map_err(|error| error.to_string())?
            .map(relation_from_row)
            .transpose()
    }

    pub fn list_ontology_relations(&self) -> Result<Vec<OntologyRelation>, String> {
        self.connection()?
            .query(
                &format!("SELECT {RELATION_COLUMNS} FROM sekai_ontology_relations ORDER BY name"),
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(relation_from_row)
            .collect()
    }
}

fn class_from_row(row: postgres::Row) -> Result<OntologyClass, String> {
    Ok(OntologyClass {
        name: row.get(0),
        description: row.get(1),
        superclasses: decode(&row, 2, "superclasses")?,
        equivalent_classes: decode(&row, 3, "equivalent classes")?,
        disjoint_classes: decode(&row, 4, "disjoint classes")?,
        properties: decode(&row, 5, "ontology properties")?,
        is_builtin: false,
        mapped_kind: row.get(6),
    })
}

fn relation_from_row(row: postgres::Row) -> Result<OntologyRelation, String> {
    let transitive: i64 = row.get(6);
    Ok(OntologyRelation {
        name: row.get(0),
        description: row.get(1),
        domain: row.get(2),
        range: row.get(3),
        cardinality: decode(&row, 4, "cardinality")?,
        inverse: row.get(5),
        transitive: transitive != 0,
        is_builtin: false,
        mapped_relation: row.get(7),
    })
}

fn decode<T: serde::de::DeserializeOwned>(
    row: &postgres::Row,
    column: usize,
    field: &str,
) -> Result<T, String> {
    let value: String = row.get(column);
    serde_json::from_str(&value).map_err(|error| format!("corrupt {field}: {error}"))
}

fn upsert_class_row(
    client: &mut impl postgres::GenericClient,
    class: &OntologyClass,
    now: i64,
) -> Result<(), String> {
    let superclasses =
        serde_json::to_string(&class.superclasses).map_err(|error| error.to_string())?;
    let equivalent =
        serde_json::to_string(&class.equivalent_classes).map_err(|error| error.to_string())?;
    let disjoint =
        serde_json::to_string(&class.disjoint_classes).map_err(|error| error.to_string())?;
    let properties = serde_json::to_string(&class.properties).map_err(|error| error.to_string())?;
    client
        .execute(
            "INSERT INTO sekai_ontology_classes
                (name,description,superclasses_json,equivalent_json,disjoint_json,
                 properties_json,mapped_kind,created,updated)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)
             ON CONFLICT(name) DO UPDATE SET
                description=EXCLUDED.description,
                superclasses_json=EXCLUDED.superclasses_json,
                equivalent_json=EXCLUDED.equivalent_json,
                disjoint_json=EXCLUDED.disjoint_json,
                properties_json=EXCLUDED.properties_json,
                mapped_kind=EXCLUDED.mapped_kind,
                updated=EXCLUDED.updated",
            &[
                &class.name,
                &class.description,
                &superclasses,
                &equivalent,
                &disjoint,
                &properties,
                &class.mapped_kind,
                &now,
            ],
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Serializes against link admissions for the mapped relation and refuses a
/// maximum below the existing graph (ADR 0087), then writes the row.
fn upsert_relation_row(
    transaction: &mut postgres::Transaction<'_>,
    relation: &OntologyRelation,
    now: i64,
) -> Result<(), String> {
    let cardinality =
        serde_json::to_string(&relation.cardinality).map_err(|error| error.to_string())?;
    let transitive = i64::from(relation.transitive);
    if !relation.mapped_relation.is_empty() {
        crate::db::postgres_objects::relation_maximum_lock(
            transaction,
            &relation.mapped_relation,
            true,
        )?;
    }
    if let Some(maximum) = relation.cardinality.max
        && !relation.mapped_relation.is_empty()
    {
        let violating = crate::db::postgres_objects::postgres_sources_over_link_maximum(
            transaction,
            &relation.mapped_relation,
            maximum,
        )?;
        if violating > 0 {
            return Err(crate::sekai::ontology::tightened_maximum_error(
                violating, maximum,
            ));
        }
    }
    transaction
        .execute(
            "INSERT INTO sekai_ontology_relations
                (name,description,domain,range,cardinality_json,inverse,transitive,
                 mapped_relation,created,updated)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)
             ON CONFLICT(name) DO UPDATE SET
                description=EXCLUDED.description,
                domain=EXCLUDED.domain,
                range=EXCLUDED.range,
                cardinality_json=EXCLUDED.cardinality_json,
                inverse=EXCLUDED.inverse,
                transitive=EXCLUDED.transitive,
                mapped_relation=EXCLUDED.mapped_relation,
                updated=EXCLUDED.updated",
            &[
                &relation.name,
                &relation.description,
                &relation.domain,
                &relation.range,
                &cardinality,
                &relation.inverse,
                &transitive,
                &relation.mapped_relation,
                &now,
            ],
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn insert_ontology_audit(
    transaction: &mut postgres::Transaction<'_>,
    actor: &str,
    action: &str,
    target_id: &str,
    definition_name: &str,
    timestamp: i64,
) -> Result<(), String> {
    crate::db::postgres_decision::insert_chained_decision(
        transaction,
        &crate::sekai::audit::Decision {
            id: format!("ontology-audit-{}", uuid::Uuid::new_v4().simple()),
            timestamp,
            actor: actor.to_string(),
            action: action.to_string(),
            reason: "ontology definition mutation".into(),
            evidence: std::collections::HashMap::from([
                ("definition_name".into(), definition_name.to_string()),
                ("data_class".into(), "unclassified".into()),
            ]),
            target_id: target_id.to_string(),
            outcome: "applied".into(),
        },
    )
}
