use crate::db::postgres::PostgresDb;
use crate::db::team_namespace::validate_team_namespace_bootstrap;
use crate::domain::Object;
use crate::sekai::audit::{ObjectChange, object_diff_changes};
use crate::sekai::security::{Grant, Role};
use std::collections::HashMap;

const OBJECT_COLUMNS: &str = "id, kind, name, namespace, external_id, properties, created, updated";

impl PostgresDb {
    pub fn find_namespace_boundary(&self, namespace: &str) -> Result<Option<Object>, String> {
        let external_id = format!("namespace:{}", namespace.trim());
        let objects = self
            .connection()?
            .query(
                &format!(
                    "SELECT {OBJECT_COLUMNS} FROM sekai_objects
                     WHERE external_id=$1 ORDER BY id LIMIT 2"
                ),
                &[&external_id.as_str()],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_object)
            .collect::<Result<Vec<_>, _>>()?;
        if objects.len() > 1 || objects.iter().any(|object| object.kind != "namespace") {
            return Err(format!(
                "canonical namespace identity {external_id:?} is not uniquely held by a namespace boundary"
            ));
        }
        Ok(objects.into_iter().next())
    }

    pub fn is_team_principal(&self, principal: &str) -> Result<bool, String> {
        self.connection()?
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM sekai_team_principals WHERE principal=$1)",
                &[&principal],
            )
            .map(|row| row.get(0))
            .map_err(|error| error.to_string())
    }

    pub fn ensure_team_namespace(
        &self,
        namespace: &str,
        principal: &str,
        member_role: Role,
        actor: &str,
    ) -> Result<(Object, Vec<Grant>), String> {
        validate_team_namespace_bootstrap(namespace, principal)?;
        let namespace = namespace.trim();
        let principal = principal.trim();
        let external_id = format!("namespace:{namespace}");
        let now = chrono::Utc::now().timestamp_millis();
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        // Serialize concurrent bootstrap for the same canonical boundary.
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 265))",
            &[&external_id.as_str()],
        )
        .map_err(|error| error.to_string())?;

        let objects = tx
            .query(
                &format!(
                    "SELECT {OBJECT_COLUMNS} FROM sekai_objects
                     WHERE external_id=$1 ORDER BY id LIMIT 2 FOR UPDATE"
                ),
                &[&external_id.as_str()],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_object)
            .collect::<Result<Vec<_>, _>>()?;
        if objects.len() > 1 || objects.iter().any(|object| object.kind != "namespace") {
            return Err(format!(
                "canonical namespace identity {external_id:?} is not uniquely held by a namespace boundary"
            ));
        }

        tx.execute(
            "INSERT INTO sekai_team_principals (principal, created)
             VALUES ($1, $2) ON CONFLICT (principal) DO NOTHING",
            &[&principal, &now],
        )
        .map_err(|error| error.to_string())?;

        let object = if let Some(mut object) = objects.into_iter().next() {
            let original = object.clone();
            object.namespace = namespace.into();
            object
                .properties
                .insert("team_managed".into(), "true".into());
            object
                .properties
                .insert("runtime_boundary".into(), namespace.into());
            if object.namespace != original.namespace || object.properties != original.properties {
                object.updated = now;
                let properties =
                    serde_json::to_string(&object.properties).map_err(|error| error.to_string())?;
                tx.execute(
                    "UPDATE sekai_objects
                     SET namespace=$1, properties=$2, updated=$3
                     WHERE id=$4",
                    &[
                        &object.namespace.as_str(),
                        &properties.as_str(),
                        &object.updated,
                        &object.id.as_str(),
                    ],
                )
                .map_err(|error| error.to_string())?;
                insert_changes(
                    &mut tx,
                    &object_diff_changes(actor, Some(&original), Some(&object), now),
                )?;
            }
            object
        } else {
            let orphan_grants: i64 = tx
                .query_one(
                    "SELECT COUNT(*) FROM sekai_grants WHERE object_id=$1",
                    &[&external_id.as_str()],
                )
                .map_err(|error| error.to_string())?
                .get(0);
            if orphan_grants > 0 {
                return Err(format!(
                    "namespace {namespace:?} has grants without a namespace boundary"
                ));
            }
            let object = Object {
                id: external_id.clone(),
                kind: "namespace".into(),
                name: namespace.into(),
                namespace: namespace.into(),
                external_id: external_id.clone(),
                properties: HashMap::from([
                    ("team_managed".into(), "true".into()),
                    ("runtime_boundary".into(), namespace.into()),
                ]),
                created: now,
                updated: now,
            };
            let properties =
                serde_json::to_string(&object.properties).map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO sekai_objects
                    (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
                &[
                    &object.id.as_str(),
                    &object.kind.as_str(),
                    &object.name.as_str(),
                    &object.namespace.as_str(),
                    &object.external_id.as_str(),
                    &properties.as_str(),
                    &object.created,
                    &object.updated,
                ],
            )
            .map_err(|error| error.to_string())?;
            insert_changes(
                &mut tx,
                &object_diff_changes(actor, None, Some(&object), now),
            )?;
            object
        };

        let grants = [
            ("root", Role::Admin),
            ("local", Role::Admin),
            (principal, member_role),
        ]
        .into_iter()
        .map(|(grant_principal, role)| Grant {
            id: format!("team:{namespace}:{grant_principal}"),
            object_id: object.id.clone(),
            principal: grant_principal.into(),
            role,
            created: now,
        })
        .collect::<Vec<_>>();
        for grant in &grants {
            tx.execute(
                "INSERT INTO sekai_grants (id, object_id, principal, role, created)
                 VALUES ($1,$2,$3,$4,$5)
                 ON CONFLICT (object_id, principal) DO UPDATE SET
                    id=EXCLUDED.id, role=EXCLUDED.role, created=EXCLUDED.created",
                &[
                    &grant.id.as_str(),
                    &grant.object_id.as_str(),
                    &grant.principal.as_str(),
                    &grant.role.as_str(),
                    &grant.created,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok((object, grants))
    }
}

fn insert_changes(
    transaction: &mut postgres::Transaction<'_>,
    changes: &[ObjectChange],
) -> Result<(), String> {
    for change in changes {
        transaction
            .execute(
                "INSERT INTO sekai_object_changes
                    (id, object_id, field, old_value, new_value, changed_by, timestamp)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &change.id,
                    &change.object_id,
                    &change.field,
                    &change.old_value,
                    &change.new_value,
                    &change.changed_by,
                    &change.timestamp,
                ],
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn row_to_object(row: postgres::Row) -> Result<Object, String> {
    let properties_json: String = row.get(5);
    Ok(Object {
        id: row.get(0),
        kind: row.get(1),
        name: row.get(2),
        namespace: row.get(3),
        external_id: row.get(4),
        properties: serde_json::from_str(&properties_json)
            .map_err(|error| format!("invalid object properties: {error}"))?,
        created: row.get(6),
        updated: row.get(7),
    })
}
