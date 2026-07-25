use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::domain::{KIND_LEARNING, Link, Object, REL_TOUCHES};
use crate::sekai::schema::SchemaRegistry;
use rusqlite::{OptionalExtension, params};
use std::collections::HashMap;

pub const RECORD_LEARNING_ACTION: &str = "record_learning";

const RECORD_LEARNING_PARAMS: [&str; 12] = [
    "id",
    "target_id",
    "title",
    "prevention",
    "reasoning",
    "source_request_id",
    "score",
    "passed",
    "task_class",
    "model",
    "producer",
    "status",
];

const LEARNING_STATUSES: [&str; 4] = ["candidate", "active", "superseded", "rejected"];
const MAX_OBJECT_ID_CHARS: usize = 256;
const MAX_TITLE_CHARS: usize = 256;
const MAX_PREVENTION_CHARS: usize = 2_048;
const MAX_REASONING_CHARS: usize = 4_096;
const MAX_SOURCE_REQUEST_ID_CHARS: usize = 256;
const MAX_TASK_CLASS_CHARS: usize = 128;
const MAX_MODEL_CHARS: usize = 256;
const MAX_PRODUCER_CHARS: usize = 128;
const MAX_NAMESPACE_CHARS: usize = 256;

#[derive(Debug, Clone)]
pub(crate) struct RecordLearningInput {
    pub id: String,
    pub target_id: String,
    title: String,
    prevention: String,
    reasoning: String,
    source_request_id: String,
    score: String,
    passed: String,
    task_class: String,
    model: String,
    producer: String,
    status: String,
}

impl RecordLearningInput {
    pub(crate) fn from_params(params: &HashMap<String, String>) -> Result<Self, String> {
        for key in params.keys() {
            if !RECORD_LEARNING_PARAMS.contains(&key.as_str()) {
                return Err(format!("unknown param: {key}"));
            }
        }

        let input = Self {
            id: required_param(params, "id", MAX_OBJECT_ID_CHARS, true)?,
            target_id: required_param(params, "target_id", MAX_OBJECT_ID_CHARS, true)?,
            title: required_param(params, "title", MAX_TITLE_CHARS, false)?,
            prevention: required_param(params, "prevention", MAX_PREVENTION_CHARS, false)?,
            reasoning: required_param(params, "reasoning", MAX_REASONING_CHARS, false)?,
            source_request_id: required_param(
                params,
                "source_request_id",
                MAX_SOURCE_REQUEST_ID_CHARS,
                true,
            )?,
            score: required_param(params, "score", 3, true)?,
            passed: required_param(params, "passed", 5, true)?,
            task_class: required_param(params, "task_class", MAX_TASK_CLASS_CHARS, true)?,
            model: required_param(params, "model", MAX_MODEL_CHARS, true)?,
            producer: required_param(params, "producer", MAX_PRODUCER_CHARS, true)?,
            status: required_param(params, "status", 16, true)?,
        };

        if input.id == input.target_id {
            return Err("learning id must differ from target_id".into());
        }
        match input.score.parse::<u8>() {
            Ok(score) if score <= 100 => {}
            _ => return Err("param score must be an integer from 0 through 100".into()),
        }
        if !matches!(input.passed.as_str(), "true" | "false") {
            return Err("param passed must be true or false".into());
        }
        if !LEARNING_STATUSES.contains(&input.status.as_str()) {
            return Err(format!(
                "param status must be one of: {}",
                LEARNING_STATUSES.join(", ")
            ));
        }
        Ok(input)
    }

    fn object(&self, namespace: &str, now: i64) -> Object {
        Object {
            id: self.id.clone(),
            kind: KIND_LEARNING.into(),
            name: "Scored learning".into(),
            namespace: namespace.to_string(),
            external_id: self.id.clone(),
            properties: HashMap::from([
                ("title".into(), self.title.clone()),
                ("prevention".into(), self.prevention.clone()),
                ("reasoning".into(), self.reasoning.clone()),
                ("source_request_id".into(), self.source_request_id.clone()),
                ("score".into(), self.score.clone()),
                ("passed".into(), self.passed.clone()),
                ("task_class".into(), self.task_class.clone()),
                ("model".into(), self.model.clone()),
                ("producer".into(), self.producer.clone()),
                ("status".into(), self.status.clone()),
            ]),
            created: now,
            updated: now,
        }
    }

    fn link(&self, now: i64) -> Link {
        Link {
            id: format!("{}->{}", self.id, self.target_id),
            from_id: self.id.clone(),
            to_id: self.target_id.clone(),
            relation: REL_TOUCHES.into(),
            created: now,
        }
    }
}

fn required_param(
    params: &HashMap<String, String>,
    key: &str,
    max_chars: usize,
    single_line: bool,
) -> Result<String, String> {
    let value = params
        .get(key)
        .ok_or_else(|| format!("missing required param: {key}"))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("param {key} must not be empty"));
    }
    if trimmed.chars().count() > max_chars {
        return Err(format!("param {key} exceeds {max_chars} characters"));
    }
    if single_line && trimmed.chars().any(char::is_control) {
        return Err(format!("param {key} must not contain control characters"));
    }
    Ok(trimmed.to_string())
}

fn learning_namespace(target: &Object) -> String {
    if target.kind == "namespace" {
        return target
            .external_id
            .strip_prefix("namespace:")
            .map(str::trim)
            .filter(|namespace| !namespace.is_empty())
            .unwrap_or_else(|| target.name.trim())
            .to_string();
    }
    target.namespace.trim().to_string()
}

fn governed_learning_namespace(target: &Object) -> Result<String, String> {
    let namespace = learning_namespace(target);
    if namespace.is_empty() {
        return Err(format!(
            "learning target {} has no governed namespace",
            target.id
        ));
    }
    if namespace.chars().count() > MAX_NAMESPACE_CHARS || namespace.chars().any(char::is_control) {
        return Err(format!(
            "learning target {} has an invalid governed namespace",
            target.id
        ));
    }
    Ok(namespace)
}

pub(crate) fn record_learning_target_ids(
    db: &RuntimeDb,
    params: &HashMap<String, String>,
) -> Result<Vec<String>, String> {
    let input = RecordLearningInput::from_params(params)?;
    let target = db
        .get_object(&input.target_id)?
        .ok_or_else(|| format!("object not found: {}", input.target_id))?;
    governed_learning_namespace(&target)?;
    Ok(vec![input.target_id, input.id])
}

pub(crate) fn record_learning(
    db: &RuntimeDb,
    schema: &SchemaRegistry,
    params: &HashMap<String, String>,
    actor: &str,
) -> Result<String, String> {
    let input = RecordLearningInput::from_params(params)?;
    if actor.trim().is_empty() {
        return Err("actor required to record learning".into());
    }

    let mut conn = db.conn();
    let tx = conn.transaction().map_err(|error| error.to_string())?;
    let target = tx
        .query_row(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE id = ?1",
            params![input.target_id],
            crate::db::sekai::row_to_object,
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("object not found: {}", input.target_id))?;

    let namespace = governed_learning_namespace(&target)?;
    let now = chrono::Utc::now().timestamp();
    let learning = input.object(&namespace, now);
    let link = input.link(now);
    schema.validate(&learning)?;
    let expected_grants = expected_learning_grants(&tx, &target.id, actor)?;

    let existing = tx
        .query_row(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated FROM sekai_objects WHERE id = ?1",
            params![learning.id],
            crate::db::sekai::row_to_object,
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if let Some(existing) = existing {
        ensure_matching_retry(&tx, &existing, &learning, &link, &expected_grants)?;
        tx.commit().map_err(|error| error.to_string())?;
        return Ok(format!("recorded learning {}", learning.id));
    }

    let link_collision = tx
        .query_row(
            "SELECT 1 FROM sekai_links WHERE id = ?1",
            params![link.id],
            |_| Ok(()),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .is_some();
    if link_collision {
        return Err(format!("link id collision: {}", link.id));
    }

    let properties = serde_json::to_string(&learning.properties).map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO sekai_objects (id, kind, name, namespace, external_id, properties, created, updated) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            learning.id,
            learning.kind,
            learning.name,
            learning.namespace,
            learning.external_id,
            properties,
            learning.created,
            learning.updated,
        ],
    )
    .map_err(|error| error.to_string())?;
    crate::sekai::ontology::validate_link_constraint(
        &tx,
        &link.from_id,
        &link.to_id,
        &link.relation,
    )?;
    tx.execute(
        "INSERT INTO sekai_links (id, from_id, to_id, relation, created) VALUES (?1,?2,?3,?4,?5)",
        params![
            link.id,
            link.from_id,
            link.to_id,
            link.relation,
            link.created
        ],
    )
    .map_err(|error| error.to_string())?;

    for (principal, role) in &expected_grants {
        tx.execute(
            "INSERT INTO sekai_grants (id, object_id, principal, role, created) VALUES (?1,?2,?3,?4,?5)",
            params![
                format!("grant-{}", uuid::Uuid::new_v4().simple()),
                learning.id,
                principal,
                role,
                now,
            ],
        )
        .map_err(|error| error.to_string())?;
    }

    let changes = crate::sekai::audit::object_diff_changes(
        actor,
        None,
        Some(&learning),
        chrono::Utc::now().timestamp_millis(),
    );
    crate::sekai::audit::insert_object_changes(&tx, &changes)?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(format!("recorded learning {}", learning.id))
}

fn expected_learning_grants(
    conn: &rusqlite::Connection,
    target_id: &str,
    actor: &str,
) -> Result<Vec<(String, String)>, String> {
    let mut grants = {
        let mut stmt = conn
            .prepare(
                "SELECT principal, role FROM sekai_grants WHERE object_id = ?1 ORDER BY principal, role, id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![target_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    if grants.is_empty() {
        grants.push((actor.to_string(), "admin".to_string()));
    }
    grants.sort();
    Ok(grants)
}

fn ensure_matching_retry(
    conn: &rusqlite::Connection,
    existing: &Object,
    expected: &Object,
    expected_link: &Link,
    expected_grants: &[(String, String)],
) -> Result<(), String> {
    let object_matches = existing.kind == expected.kind
        && existing.name == expected.name
        && existing.namespace == expected.namespace
        && existing.external_id == expected.external_id
        && existing.properties == expected.properties;
    if !object_matches {
        return Err(format!("object id collision: {}", expected.id));
    }

    let link = conn
        .query_row(
            "SELECT id, from_id, to_id, relation, created FROM sekai_links WHERE id = ?1",
            params![expected_link.id],
            |row| {
                Ok(Link {
                    id: row.get(0)?,
                    from_id: row.get(1)?,
                    to_id: row.get(2)?,
                    relation: row.get(3)?,
                    created: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(link) = link else {
        return Err(format!("learning record collision: {}", expected.id));
    };
    if link.from_id != expected_link.from_id
        || link.to_id != expected_link.to_id
        || link.relation != expected_link.relation
    {
        return Err(format!("learning record collision: {}", expected.id));
    }

    let mut actual_grants = {
        let mut stmt = conn
            .prepare(
                "SELECT principal, role FROM sekai_grants WHERE object_id = ?1 ORDER BY principal, role, id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![expected.id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    actual_grants.sort();
    if actual_grants != expected_grants {
        return Err(format!("learning ACL collision: {}", expected.id));
    }

    let creation_marker = conn
        .query_row(
            "SELECT COUNT(*) FROM sekai_object_changes WHERE object_id = ?1 AND field = '_created' AND new_value = ?2",
            params![expected.id, format!("{}/{}", expected.kind, expected.name)],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| error.to_string())?;
    if creation_marker != 1 {
        return Err(format!("learning audit collision: {}", expected.id));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Direction;
    use crate::sekai::action::{ActionExecutor, RiskClass};
    use crate::sekai::security::{Grant, Role};

    fn target(id: &str) -> Object {
        Object {
            id: id.into(),
            kind: "component".into(),
            name: "checkout".into(),
            namespace: "payments".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        }
    }

    fn record_params() -> HashMap<String, String> {
        HashMap::from([
            ("id".into(), "learning-request-42".into()),
            ("target_id".into(), "target-1".into()),
            ("title".into(), "Validate retries".into()),
            ("prevention".into(), "Check the prior record first".into()),
            (
                "reasoning".into(),
                "The retry repeated a side effect".into(),
            ),
            ("source_request_id".into(), "request-42".into()),
            ("score".into(), "72".into()),
            ("passed".into(), "false".into()),
            ("task_class".into(), "reasoning".into()),
            ("model".into(), "judge-model".into()),
            ("producer".into(), "scoring-job".into()),
            ("status".into(), "candidate".into()),
        ])
    }

    #[test]
    fn record_learning_action_is_governed_as_two_sensitive_writes() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        db.create_object(&target("target-1")).unwrap();
        let executor = ActionExecutor::new();
        let params = record_params();

        assert_eq!(
            executor
                .target_ids(&db, RECORD_LEARNING_ACTION, &params)
                .unwrap(),
            vec!["target-1".to_string(), "learning-request-42".to_string()]
        );
        assert_eq!(
            executor.action_risk_class(RECORD_LEARNING_ACTION),
            RiskClass::Write
        );
        assert_eq!(
            executor.action_op_counts(RECORD_LEARNING_ACTION, &params),
            (2, 0)
        );
        assert_eq!(
            executor
                .schema_kinds(&db, RECORD_LEARNING_ACTION, &params)
                .unwrap(),
            vec![KIND_LEARNING.to_string()]
        );
        assert_eq!(
            executor
                .planned_ops(RECORD_LEARNING_ACTION, &params)
                .unwrap()
                .len(),
            2
        );
        let sensitive = executor.sensitive_param_names(RECORD_LEARNING_ACTION);
        for name in [
            "title",
            "prevention",
            "reasoning",
            "source_request_id",
            "score",
            "passed",
            "task_class",
            "model",
            "producer",
            "status",
        ] {
            assert!(sensitive.contains(name));
        }
    }

    #[test]
    fn record_learning_atomically_creates_object_link_acl_and_audit() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        db.create_object(&target("target-1")).unwrap();
        let executor = ActionExecutor::new();
        let params = record_params();

        executor
            .execute(
                &db,
                &SchemaRegistry::new(),
                RECORD_LEARNING_ACTION,
                &params,
                "worker-1",
            )
            .unwrap();

        let learning = db.get_object("learning-request-42").unwrap().unwrap();
        assert_eq!(learning.kind, KIND_LEARNING);
        assert_eq!(learning.namespace, "payments");
        assert_eq!(learning.name, "Scored learning");
        assert_eq!(learning.properties["status"], "candidate");
        assert_eq!(learning.properties["source_request_id"], "request-42");

        let links = db
            .get_links("learning-request-42", REL_TOUCHES, &Direction::Outgoing)
            .unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].to_id, "target-1");

        let grants = db.list_grants("learning-request-42").unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].principal, "worker-1");
        assert_eq!(grants[0].role, Role::Admin);

        let changes = db
            .list_object_changes("learning-request-42", 10, 0)
            .unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "_created");
        assert_eq!(changes[0].changed_by, "worker-1");
    }

    #[test]
    fn record_learning_copies_acl_and_exact_retry_is_idempotent() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        db.create_object(&target("target-1")).unwrap();
        for (id, principal, role) in [
            ("grant-alice", "alice", Role::Editor),
            ("grant-reviewers", "reviewers", Role::Viewer),
        ] {
            db.create_grant(&Grant {
                id: id.into(),
                object_id: "target-1".into(),
                principal: principal.into(),
                role,
                created: 1,
            })
            .unwrap();
        }
        let executor = ActionExecutor::new();
        let params = record_params();
        let schema = SchemaRegistry::new();

        for _ in 0..2 {
            executor
                .execute(&db, &schema, RECORD_LEARNING_ACTION, &params, "alice")
                .unwrap();
        }

        let mut grants = db
            .list_grants("learning-request-42")
            .unwrap()
            .into_iter()
            .map(|grant| (grant.principal, grant.role.as_str().to_string()))
            .collect::<Vec<_>>();
        grants.sort();
        assert_eq!(
            grants,
            vec![
                ("alice".to_string(), "editor".to_string()),
                ("reviewers".to_string(), "viewer".to_string()),
            ]
        );
        assert_eq!(
            db.get_links("learning-request-42", REL_TOUCHES, &Direction::Outgoing)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            db.list_object_changes("learning-request-42", 10, 0)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn record_learning_rejects_untrusted_properties_and_collisions() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        db.create_object(&target("target-1")).unwrap();
        let executor = ActionExecutor::new();
        let schema = SchemaRegistry::new();

        for key in ["classification", "chisei.egress.allow_provider"] {
            let mut params = record_params();
            params.insert(key.into(), "public".into());
            let error = executor
                .target_ids(&db, RECORD_LEARNING_ACTION, &params)
                .unwrap_err();
            assert!(error.contains("unknown param"));
        }

        db.create_object(&Object {
            id: "learning-request-42".into(),
            ..target("other")
        })
        .unwrap();
        let error = executor
            .execute(
                &db,
                &schema,
                RECORD_LEARNING_ACTION,
                &record_params(),
                "worker-1",
            )
            .unwrap_err();
        assert!(error.contains("object id collision"));
        assert!(
            db.get_links("learning-request-42", REL_TOUCHES, &Direction::Outgoing)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn record_learning_rolls_back_when_link_id_collides() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        db.create_object(&target("target-1")).unwrap();
        db.create_link(&Link {
            id: "learning-request-42->target-1".into(),
            from_id: "someone-else".into(),
            to_id: "target-1".into(),
            relation: REL_TOUCHES.into(),
            created: 1,
        })
        .unwrap();
        let error =
            record_learning(&db, &SchemaRegistry::new(), &record_params(), "worker-1").unwrap_err();
        assert!(error.contains("link id collision"));
        assert!(db.get_object("learning-request-42").unwrap().is_none());
        assert!(
            db.list_object_changes("learning-request-42", 10, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn record_learning_rejects_a_forged_partial_retry() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let target = target("target-1");
        db.create_object(&target).unwrap();
        let input = RecordLearningInput::from_params(&record_params()).unwrap();
        db.create_object(&input.object("payments", 1)).unwrap();
        db.create_link(&input.link(1)).unwrap();
        db.create_grant(&Grant {
            id: "forged-grant".into(),
            object_id: input.id.clone(),
            principal: "worker-1".into(),
            role: Role::Admin,
            created: 1,
        })
        .unwrap();

        let error =
            record_learning(&db, &SchemaRegistry::new(), &record_params(), "worker-1").unwrap_err();
        assert!(error.contains("learning audit collision"));
    }

    #[test]
    fn namespace_targets_preserve_their_namespace_identity() {
        let target = Object {
            id: "namespace-object".into(),
            kind: "namespace".into(),
            name: "fallback-name".into(),
            namespace: String::new(),
            external_id: "namespace:payments".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        };
        assert_eq!(learning_namespace(&target), "payments");

        let target_without_external_id = Object {
            external_id: String::new(),
            ..target
        };
        assert_eq!(
            learning_namespace(&target_without_external_id),
            "fallback-name"
        );
    }

    #[test]
    fn record_learning_rejects_unbounded_fields_and_unscoped_targets() {
        let mut oversized = record_params();
        oversized.insert("reasoning".into(), "x".repeat(MAX_REASONING_CHARS + 1));
        assert!(
            RecordLearningInput::from_params(&oversized)
                .unwrap_err()
                .contains("exceeds")
        );

        let mut invalid_id = record_params();
        invalid_id.insert("source_request_id".into(), "request\nforged".into());
        assert!(
            RecordLearningInput::from_params(&invalid_id)
                .unwrap_err()
                .contains("control characters")
        );

        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        db.create_object(&Object {
            id: "unscoped".into(),
            kind: "component".into(),
            name: "unscoped".into(),
            namespace: String::new(),
            external_id: "component:unscoped".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        let mut params = record_params();
        params.insert("target_id".into(), "unscoped".into());
        assert!(
            record_learning_target_ids(&db, &params)
                .unwrap_err()
                .contains("no governed namespace")
        );
    }
}
