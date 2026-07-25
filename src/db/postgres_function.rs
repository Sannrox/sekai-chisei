use crate::db::postgres::PostgresDb;
use crate::sekai::function::{FuncParam, Function, PipelineStep, validate_function};

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

impl PostgresDb {
    pub fn create_function(&self, function: &Function) -> Result<(), String> {
        validate_function(function)?;
        let params_json = serialize_params(function)?;
        let pipeline_json = serialize_pipeline(function)?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_functions (name,description,params,pipeline,created)
                 VALUES ($1,$2,$3,$4,$5)",
                &[
                    &function.name,
                    &function.description,
                    &params_json,
                    &pipeline_json,
                    &function.created,
                ],
            )
            .map(|_| ())
            .map_err(|error| {
                let message = error.to_string();
                if message.contains("duplicate key") || message.contains("unique") {
                    "function already exists".into()
                } else {
                    message
                }
            })
    }

    pub fn get_function(&self, name: &str) -> Result<Option<Function>, String> {
        self.connection()?
            .query_opt(
                "SELECT name,description,params,pipeline,created
                 FROM sekai_functions WHERE name=$1",
                &[&name],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_function)
            .transpose()
    }

    pub fn list_functions(&self) -> Result<Vec<Function>, String> {
        self.connection()?
            .query(
                "SELECT name,description,params,pipeline,created
                 FROM sekai_functions ORDER BY name",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_function)
            .collect()
    }
}

fn serialize_params(function: &Function) -> Result<String, String> {
    serde_json::to_string(
        &function
            .params
            .iter()
            .map(|param| (&param.name, &param.param_type, param.required))
            .collect::<Vec<_>>(),
    )
    .map_err(|error| error.to_string())
}

fn serialize_pipeline(function: &Function) -> Result<String, String> {
    serde_json::to_string(
        &function
            .pipeline
            .iter()
            .map(|step| {
                (
                    &step.op,
                    &step.kind,
                    &step.property,
                    &step.value,
                    &step.relation,
                    &step.dir,
                    &step.func,
                    &step.field,
                    &step.alias,
                )
            })
            .collect::<Vec<_>>(),
    )
    .map_err(|error| error.to_string())
}

fn row_to_function(row: postgres::Row) -> Result<Function, String> {
    let name: String = row.get(0);
    let params_json: String = row.get(2);
    let pipeline_json: String = row.get(3);
    let params_vec: Vec<(String, String, bool)> = serde_json::from_str(&params_json)
        .map_err(|error| format!("corrupt function params for {name}: {error}"))?;
    let pipeline_vec: Vec<PipelineRow> = serde_json::from_str(&pipeline_json)
        .map_err(|error| format!("corrupt function pipeline for {name}: {error}"))?;
    Ok(Function {
        name,
        description: row.get(1),
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
                |(op, kind, property, value, relation, dir, func, field, alias)| PipelineStep {
                    op,
                    kind,
                    property,
                    value,
                    relation,
                    dir,
                    func,
                    field,
                    alias,
                },
            )
            .collect(),
        created: row.get(4),
    })
}
