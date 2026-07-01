use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, Object};
use rusqlite::{OptionalExtension, params};
use std::collections::HashMap;

type PipelineRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

#[derive(Debug, Clone)]
pub struct FuncParam {
    pub name: String,
    pub param_type: String,
    pub required: bool,
}

#[derive(Debug, Clone)]
pub struct PipelineStep {
    pub op: String,
    pub kind: String,
    pub property: String,
    pub value: String,
    pub relation: String,
    pub dir: String,
    pub func: String,
    pub field: String,
    pub alias: String,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub description: String,
    pub params: Vec<FuncParam>,
    pub pipeline: Vec<PipelineStep>,
    pub created: i64,
}

#[derive(Debug, Clone, Default)]
pub struct FunctionResult {
    pub objects: Vec<Object>,
    pub aggregates: HashMap<String, String>,
}

pub fn validate_function(f: &Function) -> Result<(), String> {
    if f.name.is_empty() {
        return Err("function name required".into());
    }
    if f.pipeline.is_empty() {
        return Err("pipeline must have at least one step".into());
    }
    for (i, step) in f.pipeline.iter().enumerate() {
        match step.op.as_str() {
            "filter" => {
                if step.kind.is_empty() {
                    return Err(format!("step {}: filter requires kind", i));
                }
            }
            "traverse" => {
                if step.relation.is_empty() {
                    return Err(format!("step {}: traverse requires relation", i));
                }
            }
            "aggregate" => {
                if step.func.is_empty() {
                    return Err(format!("step {}: aggregate requires func", i));
                }
            }
            "transform" => {
                if step.field.is_empty() {
                    return Err(format!("step {}: transform requires field", i));
                }
            }
            other => {
                return Err(format!("step {}: unknown op {:?}", i, other));
            }
        }
    }
    Ok(())
}

pub fn execute(
    db: &SekaiDb,
    f: &Function,
    params: &HashMap<String, String>,
) -> Result<FunctionResult, String> {
    execute_with_filter(db, f, params, |_| true)
}

pub fn execute_with_filter<F>(
    db: &SekaiDb,
    f: &Function,
    params: &HashMap<String, String>,
    allow: F,
) -> Result<FunctionResult, String>
where
    F: Fn(&Object) -> bool,
{
    let mut objects: Vec<Object> = Vec::new();
    let mut result = FunctionResult::default();

    for step in &f.pipeline {
        match step.op.as_str() {
            "filter" => {
                let filter = crate::domain::ListFilter {
                    kind: Some(step.kind.clone()),
                    ..Default::default()
                };
                let mut filtered = db.list_objects(&filter)?;
                if !step.property.is_empty() && !step.value.is_empty() {
                    let val = resolve_param(&step.value, params);
                    filtered.retain(|o| {
                        o.properties
                            .get(&step.property)
                            .map(|v| *v == val)
                            .unwrap_or(false)
                    });
                }
                filtered.retain(&allow);
                objects = filtered;
            }
            "traverse" => {
                let dir = if step.dir == "incoming" {
                    Direction::Incoming
                } else {
                    Direction::Outgoing
                };
                let mut next = Vec::new();
                for obj in &objects {
                    let linked = db.get_linked_objects(&obj.id, &step.relation, &dir)?;
                    next.extend(linked);
                }
                next.retain(&allow);
                objects = next;
            }
            "aggregate" => {
                let alias = if step.alias.is_empty() {
                    &step.func
                } else {
                    &step.alias
                };
                let val = match step.func.as_str() {
                    "count" => objects.len().to_string(),
                    "sum" | "avg" | "min" | "max" => {
                        let nums: Vec<f64> = objects
                            .iter()
                            .filter_map(|o| o.properties.get(&step.field))
                            .filter_map(|v| v.parse::<f64>().ok())
                            .collect();
                        match step.func.as_str() {
                            "sum" => nums.iter().sum::<f64>().to_string(),
                            "avg" => {
                                if nums.is_empty() {
                                    "0".into()
                                } else {
                                    (nums.iter().sum::<f64>() / nums.len() as f64).to_string()
                                }
                            }
                            "min" => nums
                                .iter()
                                .cloned()
                                .reduce(f64::min)
                                .unwrap_or(0.0)
                                .to_string(),
                            "max" => nums
                                .iter()
                                .cloned()
                                .reduce(f64::max)
                                .unwrap_or(0.0)
                                .to_string(),
                            _ => "0".into(),
                        }
                    }
                    _ => "0".into(),
                };
                result.aggregates.insert(alias.to_string(), val);
            }
            "transform" => {
                // Keep only objects that have the field set
                objects.retain(|o| o.properties.contains_key(&step.field));
            }
            _ => {}
        }
    }
    result.objects = objects;
    Ok(result)
}

fn resolve_param(value: &str, params: &HashMap<String, String>) -> String {
    if let Some(key) = value.strip_prefix('$') {
        params.get(key).cloned().unwrap_or_default()
    } else {
        value.to_string()
    }
}

impl SekaiDb {
    pub fn migrate_functions(&self) {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_functions (
                name TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                params TEXT NOT NULL DEFAULT '[]',
                pipeline TEXT NOT NULL DEFAULT '[]',
                created INTEGER NOT NULL
            );",
        )
        .unwrap();
    }

    pub fn create_function(&self, f: &Function) -> Result<(), String> {
        validate_function(f)?;
        let conn = self.conn.lock().unwrap();
        let params_json = serde_json::to_string(
            &f.params
                .iter()
                .map(|p| (&p.name, &p.param_type, p.required))
                .collect::<Vec<_>>(),
        )
        .map_err(|e| e.to_string())?;
        let pipeline_json = serde_json::to_string(
            &f.pipeline
                .iter()
                .map(|s| {
                    (
                        &s.op,
                        &s.kind,
                        &s.property,
                        &s.value,
                        &s.relation,
                        &s.dir,
                        &s.func,
                        &s.field,
                        &s.alias,
                    )
                })
                .collect::<Vec<_>>(),
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO sekai_functions (name,description,params,pipeline,created) VALUES (?1,?2,?3,?4,?5)",
            params![f.name, f.description, params_json, pipeline_json, f.created],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_function(&self, name: &str) -> Result<Option<Function>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT name,description,params,pipeline,created FROM sekai_functions WHERE name=?1",
            params![name],
            |row| {
                let params_json: String = row.get(2)?;
                let pipeline_json: String = row.get(3)?;
                let params_vec: Vec<(String, String, bool)> =
                    serde_json::from_str(&params_json).unwrap_or_default();
                let pipeline_vec: Vec<PipelineRow> =
                    serde_json::from_str(&pipeline_json).unwrap_or_default();
                Ok(Function {
                    name: row.get(0)?,
                    description: row.get(1)?,
                    params: params_vec
                        .into_iter()
                        .map(|(name, param_type, required)| FuncParam {
                            name,
                            param_type,
                            required,
                        })
                        .collect(),
                    pipeline: pipeline_vec
                        .into_iter()
                        .map(
                            |(op, kind, property, value, relation, dir, func, field, alias)| {
                                PipelineStep {
                                    op,
                                    kind,
                                    property,
                                    value,
                                    relation,
                                    dir,
                                    func,
                                    field,
                                    alias,
                                }
                            },
                        )
                        .collect(),
                    created: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_functions(&self) -> Result<Vec<Function>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT name,description,params,pipeline,created FROM sekai_functions ORDER BY name")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                let params_json: String = row.get(2)?;
                let pipeline_json: String = row.get(3)?;
                let params_vec: Vec<(String, String, bool)> =
                    serde_json::from_str(&params_json).unwrap_or_default();
                let pipeline_vec: Vec<PipelineRow> =
                    serde_json::from_str(&pipeline_json).unwrap_or_default();
                Ok(Function {
                    name: row.get(0)?,
                    description: row.get(1)?,
                    params: params_vec
                        .into_iter()
                        .map(|(name, param_type, required)| FuncParam {
                            name,
                            param_type,
                            required,
                        })
                        .collect(),
                    pipeline: pipeline_vec
                        .into_iter()
                        .map(
                            |(op, kind, property, value, relation, dir, func, field, alias)| {
                                PipelineStep {
                                    op,
                                    kind,
                                    property,
                                    value,
                                    relation,
                                    dir,
                                    func,
                                    field,
                                    alias,
                                }
                            },
                        )
                        .collect(),
                    created: row.get(4)?,
                })
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KIND_COMPONENT, Link};

    fn step(op: &str, kind: &str, relation: &str, func: &str, field: &str) -> PipelineStep {
        PipelineStep {
            op: op.into(),
            kind: kind.into(),
            property: "".into(),
            value: "".into(),
            relation: relation.into(),
            dir: "".into(),
            func: func.into(),
            field: field.into(),
            alias: "".into(),
        }
    }

    #[test]
    fn test_validate_ok() {
        let f = Function {
            name: "test".into(),
            description: "".into(),
            params: vec![],
            pipeline: vec![step("filter", "namespace", "", "", "")],
            created: 0,
        };
        assert!(validate_function(&f).is_ok());
    }

    #[test]
    fn test_validate_empty_pipeline() {
        let f = Function {
            name: "test".into(),
            description: "".into(),
            params: vec![],
            pipeline: vec![],
            created: 0,
        };
        assert!(validate_function(&f).is_err());
    }

    #[test]
    fn test_execute_count_components() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "r1".into(),
            kind: "namespace".into(),
            name: "namespace".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "a".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c2".into(),
            kind: KIND_COMPONENT.into(),
            name: "b".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l1".into(),
            from_id: "r1".into(),
            to_id: "c1".into(),
            relation: "contains".into(),
            created: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l2".into(),
            from_id: "r1".into(),
            to_id: "c2".into(),
            relation: "contains".into(),
            created: 0,
        })
        .unwrap();

        let f = Function {
            name: "count_components".into(),
            description: "".into(),
            params: vec![],
            created: 0,
            pipeline: vec![
                step("filter", "namespace", "", "", ""),
                step("traverse", "", "contains", "", ""),
                step("aggregate", "", "", "count", ""),
            ],
        };
        let res = execute(&db, &f, &HashMap::new()).unwrap();
        assert_eq!(res.aggregates["count"], "2");
    }

    #[test]
    fn test_execute_with_param() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "a".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([
                ("language".into(), "rust".into()),
                ("task_total".into(), "5".into()),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c2".into(),
            kind: KIND_COMPONENT.into(),
            name: "b".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([
                ("language".into(), "go".into()),
                ("task_total".into(), "3".into()),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();

        let f = Function {
            name: "sum_tasks".into(),
            description: "".into(),
            params: vec![FuncParam {
                name: "lang".into(),
                param_type: "string".into(),
                required: true,
            }],
            created: 0,
            pipeline: vec![
                PipelineStep {
                    op: "filter".into(),
                    kind: KIND_COMPONENT.into(),
                    property: "language".into(),
                    value: "$lang".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    alias: "".into(),
                },
                PipelineStep {
                    op: "aggregate".into(),
                    kind: "".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "sum".into(),
                    field: "task_total".into(),
                    alias: "total".into(),
                },
            ],
        };
        let params = HashMap::from([("lang".into(), "rust".into())]);
        let res = execute(&db, &f, &params).unwrap();
        assert_eq!(res.aggregates["total"], "5");
    }

    #[test]
    fn test_function_persistence() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.migrate_functions();
        let f = Function {
            name: "sum_tasks".into(),
            description: "sum task totals".into(),
            params: vec![FuncParam {
                name: "lang".into(),
                param_type: "string".into(),
                required: true,
            }],
            pipeline: vec![PipelineStep {
                op: "filter".into(),
                kind: KIND_COMPONENT.into(),
                property: "language".into(),
                value: "$lang".into(),
                relation: "".into(),
                dir: "".into(),
                func: "".into(),
                field: "".into(),
                alias: "".into(),
            }],
            created: 42,
        };
        db.create_function(&f).unwrap();
        let loaded = db.get_function("sum_tasks").unwrap().unwrap();
        assert_eq!(loaded.name, f.name);
        assert_eq!(loaded.params.len(), 1);
        assert_eq!(db.list_functions().unwrap().len(), 1);
    }
}
