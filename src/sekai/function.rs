use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, Object};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Instant;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FuncParam {
    pub name: String,
    pub param_type: String,
    pub required: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OperatorStep {
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LlmStep {
    pub prompt_revision: String,
    pub input_bindings: BTreeMap<String, String>,
    pub output_schema: String,
    pub model_route: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum PipelineStep {
    Operator(OperatorStep),
    Llm(LlmStep),
}

impl PipelineStep {
    pub fn operator(
        op: impl Into<String>,
        kind: impl Into<String>,
        relation: impl Into<String>,
        func: impl Into<String>,
        field: impl Into<String>,
    ) -> Self {
        Self::Operator(OperatorStep {
            op: op.into(),
            kind: kind.into(),
            property: String::new(),
            value: String::new(),
            relation: relation.into(),
            dir: String::new(),
            func: func.into(),
            field: field.into(),
            alias: String::new(),
        })
    }
}

/// Scripted or governed LLM completion for one function step (#1310).
///
/// Production hosts must use the same policy, budget, and egress path as
/// native chat (`provider_execution`). The default host fail-closes.
pub trait LlmStepHost {
    fn complete(
        &self,
        prompt_revision: &str,
        model_route: &str,
        bound_inputs: &serde_json::Value,
        output_schema: &str,
    ) -> Result<serde_json::Value, String>;
}

pub struct RejectLlmHost;

impl LlmStepHost for RejectLlmHost {
    fn complete(
        &self,
        _prompt_revision: &str,
        _model_route: &str,
        _bound_inputs: &serde_json::Value,
        _output_schema: &str,
    ) -> Result<serde_json::Value, String> {
        Err("llm step requires a host".into())
    }
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
    pub structured: Option<serde_json::Value>,
    pub schema_error: String,
    pub llm_prompt_digest: String,
    pub llm_model_route: String,
    pub llm_input_digest: String,
}

#[derive(Debug, Clone)]
pub struct FunctionBudget {
    pub max_time_ms: u64,
    pub max_output_bytes: usize,
    pub max_steps: u32,
}

impl Default for FunctionBudget {
    fn default() -> Self {
        Self {
            max_time_ms: 50,
            max_output_bytes: 1_048_576,
            max_steps: 32,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionHost {
    pub now_ms: i64,
    pub rng_seed: u64,
}

#[derive(Debug, Clone)]
pub struct FunctionReceipt {
    pub function_name: String,
    pub function_digest: String,
    pub now_ms: i64,
    pub rng_seed: u64,
    pub elapsed_ms: u64,
    pub steps: u32,
    pub budget_exceeded: String,
    pub output_digest: String,
    pub prompt_digest: String,
    pub model_route: String,
    pub input_digest: String,
    pub schema_error: String,
}

#[derive(Debug, Clone)]
pub struct FunctionInvocation {
    pub result: FunctionResult,
    pub receipt: FunctionReceipt,
}

struct BudgetChecker {
    started: Instant,
    steps: u32,
    budget: FunctionBudget,
}

impl BudgetChecker {
    fn tick(&mut self) -> Result<(), String> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.budget.max_steps {
            return Err("function budget exceeded: max_steps".into());
        }
        self.check_time()
    }

    fn check_time(&self) -> Result<(), String> {
        if self.started.elapsed().as_millis() as u64 > self.budget.max_time_ms {
            return Err("function budget exceeded: max_time_ms".into());
        }
        Ok(())
    }
}

pub fn validate_function(f: &Function) -> Result<(), String> {
    if f.name.is_empty() {
        return Err("function name required".into());
    }
    if f.pipeline.is_empty() {
        return Err("pipeline must have at least one step".into());
    }
    if f.pipeline
        .iter()
        .filter(|step| matches!(step, PipelineStep::Llm(_)))
        .count()
        > 1
    {
        return Err("pipeline may contain at most one llm step".into());
    }
    for (i, step) in f.pipeline.iter().enumerate() {
        match step {
            PipelineStep::Operator(step) => match step.op.as_str() {
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
                "self" => {}
                "transform" => {
                    if step.field.is_empty() {
                        return Err(format!("step {}: transform requires field", i));
                    }
                }
                "repeat" => {}
                other => {
                    return Err(format!("step {}: unknown op {:?}", i, other));
                }
            },
            PipelineStep::Llm(step) => {
                if step.prompt_revision.is_empty() {
                    return Err(format!("step {}: llm requires prompt_revision", i));
                }
                if step.output_schema.is_empty() {
                    return Err(format!("step {}: llm requires output_schema", i));
                }
                if step.model_route.is_empty() {
                    return Err(format!("step {}: llm requires model_route", i));
                }
                validate_output_schema(&step.output_schema)
                    .map_err(|error| format!("step {i}: {error}"))?;
            }
        }
    }
    Ok(())
}

pub fn execute(
    db: &RuntimeDb,
    f: &Function,
    params: &HashMap<String, String>,
) -> Result<FunctionResult, String> {
    execute_with_filter(db, f, params, |_| true)
}

pub fn execute_with_filter<F>(
    db: &RuntimeDb,
    f: &Function,
    params: &HashMap<String, String>,
    allow: F,
) -> Result<FunctionResult, String>
where
    F: Fn(&Object) -> bool,
{
    execute_with_result_filter(db, f, params, |object| Ok(allow(object)))
}

pub fn execute_for_object_with_filter<F>(
    db: &RuntimeDb,
    f: &Function,
    source: &Object,
    params: &HashMap<String, String>,
    allow: F,
) -> Result<FunctionResult, String>
where
    F: Fn(&Object) -> bool,
{
    execute_for_object_with_result_filter(db, f, source, params, |object| Ok(allow(object)))
}

pub fn execute_with_result_filter<F>(
    db: &RuntimeDb,
    f: &Function,
    params: &HashMap<String, String>,
    allow: F,
) -> Result<FunctionResult, String>
where
    F: Fn(&Object) -> Result<bool, String>,
{
    execute_with_source_and_result_filter(db, f, params, None, allow, None, &RejectLlmHost)
}

pub fn execute_for_object_with_result_filter<F>(
    db: &RuntimeDb,
    f: &Function,
    source: &Object,
    params: &HashMap<String, String>,
    allow: F,
) -> Result<FunctionResult, String>
where
    F: Fn(&Object) -> Result<bool, String>,
{
    execute_with_source_and_result_filter(db, f, params, Some(source), allow, None, &RejectLlmHost)
}

pub fn function_digest(function: &Function) -> String {
    let mut hasher = Sha256::new();
    hasher.update(function.name.as_bytes());
    hasher.update(
        serde_json::to_vec(
            &function
                .pipeline
                .iter()
                .map(|step| match step {
                    PipelineStep::Operator(step) => serde_json::json!([
                        "operator",
                        step.op,
                        step.kind,
                        step.property,
                        step.value,
                        step.relation,
                        step.func,
                        step.field,
                        step.alias
                    ]),
                    PipelineStep::Llm(step) => serde_json::json!([
                        "llm",
                        step.prompt_revision,
                        step.model_route,
                        step.output_schema,
                        step.input_bindings
                    ]),
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default(),
    );
    format!("sha256:{:x}", hasher.finalize())
}

pub fn result_digest(result: &FunctionResult) -> String {
    let mut hasher = Sha256::new();
    let mut ids: Vec<_> = result
        .objects
        .iter()
        .map(|object| object.id.as_str())
        .collect();
    ids.sort_unstable();
    hasher.update(ids.join(",").as_bytes());
    let mut aggregates: Vec<_> = result.aggregates.iter().collect();
    aggregates.sort_by(|left, right| left.0.cmp(right.0));
    hasher.update(serde_json::to_vec(&aggregates).unwrap_or_default());
    if let Some(structured) = &result.structured {
        hasher.update(serde_json::to_vec(structured).unwrap_or_default());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

const OUTPUT_SCHEMA_KEYS: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "description",
];

/// Fail closed unless the schema is the supported object subset (#1310).
pub fn validate_output_schema(schema_json: &str) -> Result<(), String> {
    let schema: serde_json::Value = serde_json::from_str(schema_json)
        .map_err(|error| format!("llm output_schema is not JSON: {error}"))?;
    validate_output_schema_value(&schema)
}

fn validate_output_schema_value(schema: &serde_json::Value) -> Result<(), String> {
    let object = schema
        .as_object()
        .ok_or_else(|| "llm output_schema must be an object".to_string())?;
    for key in object.keys() {
        if !OUTPUT_SCHEMA_KEYS.contains(&key.as_str()) {
            return Err(format!("unsupported output schema keyword {key}"));
        }
    }
    let expected = schema_type(object)?;
    if expected != "object" {
        return Err(format!("unsupported output schema type {expected}"));
    }
    if let Some(flag) = object.get("additionalProperties")
        && !flag.is_boolean()
    {
        return Err("additionalProperties must be a boolean".into());
    }
    if let Some(required) = object.get("required") {
        let required = required
            .as_array()
            .ok_or_else(|| "schema required is not an array".to_string())?;
        for key in required {
            if !key.is_string() {
                return Err("schema required is not a string".into());
            }
        }
    }
    if let Some(properties) = object.get("properties") {
        let properties = properties
            .as_object()
            .ok_or_else(|| "schema properties is not an object".to_string())?;
        for nested in properties.values() {
            validate_property_schema(nested)?;
        }
    }
    Ok(())
}

fn validate_property_schema(schema: &serde_json::Value) -> Result<(), String> {
    let object = schema
        .as_object()
        .ok_or_else(|| "property schema must be an object".to_string())?;
    for key in object.keys() {
        if !OUTPUT_SCHEMA_KEYS.contains(&key.as_str()) {
            return Err(format!("unsupported output schema keyword {key}"));
        }
    }
    let expected = schema_type(object)?;
    match expected {
        "object" => validate_output_schema_value(schema),
        "string" | "integer" | "number" | "boolean" => {
            if object.contains_key("properties")
                || object.contains_key("required")
                || object.contains_key("additionalProperties")
            {
                return Err(format!(
                    "unsupported keywords on {expected} property schema"
                ));
            }
            Ok(())
        }
        other => Err(format!("unsupported output schema type {other}")),
    }
}

/// Fail closed when JSON does not match a simple object schema (#1310).
pub fn validate_structured_output(
    schema_json: &str,
    value: &serde_json::Value,
) -> Result<(), String> {
    let schema: serde_json::Value = serde_json::from_str(schema_json)
        .map_err(|error| format!("output schema is not JSON: {error}"))?;
    validate_output_schema_value(&schema)?;
    validate_against_schema(&schema, value)
}

fn schema_type(object: &serde_json::Map<String, serde_json::Value>) -> Result<&str, String> {
    match object.get("type") {
        None => Ok("object"),
        Some(value) => value
            .as_str()
            .ok_or_else(|| "schema type must be a string".into()),
    }
}

fn validate_against_schema(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), String> {
    let object = schema
        .as_object()
        .ok_or_else(|| "output schema must be an object".to_string())?;
    let expected = schema_type(object)?;
    match expected {
        "object" => {
            let object = value
                .as_object()
                .ok_or_else(|| "output is not an object".to_string())?;
            if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
                for key in required {
                    let name = key
                        .as_str()
                        .ok_or_else(|| "schema required is not a string".to_string())?;
                    if !object.contains_key(name) {
                        return Err(format!("missing required property {name}"));
                    }
                }
            }
            if schema
                .get("additionalProperties")
                .and_then(|flag| flag.as_bool())
                == Some(false)
            {
                let allowed: BTreeSet<&str> = schema
                    .get("properties")
                    .and_then(|p| p.as_object())
                    .map(|p| p.keys().map(String::as_str).collect())
                    .unwrap_or_default();
                for key in object.keys() {
                    if !allowed.contains(key.as_str()) {
                        return Err(format!("unexpected property {key}"));
                    }
                }
            }
            if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
                for (name, nested) in properties {
                    if let Some(child) = object.get(name) {
                        validate_against_schema(nested, child)?;
                    }
                }
            }
            Ok(())
        }
        "string" => {
            if value.is_string() {
                Ok(())
            } else {
                Err("output is not a string".into())
            }
        }
        "integer" => {
            if value.is_i64() || value.is_u64() {
                Ok(())
            } else {
                Err("output is not an integer".into())
            }
        }
        "number" => {
            if value.is_number() {
                Ok(())
            } else {
                Err("output is not a number".into())
            }
        }
        "boolean" => {
            if value.is_boolean() {
                Ok(())
            } else {
                Err("output is not a boolean".into())
            }
        }
        other => Err(format!("unsupported schema type {other}")),
    }
}

/// Invoke a function on the in-process host (#882 / ADR 0072).
///
/// Clock and randomness are host-provided and recorded. The host API has no
/// network or filesystem capability. Authorization is the `allow` filter.
pub fn invoke<F>(
    db: &RuntimeDb,
    function: &Function,
    params: &HashMap<String, String>,
    allow: F,
    host: FunctionHost,
    budget: FunctionBudget,
) -> Result<FunctionInvocation, String>
where
    F: Fn(&Object) -> Result<bool, String>,
{
    invoke_with_source(db, function, params, None, allow, host, budget)
}

pub fn invoke_with_source<F>(
    db: &RuntimeDb,
    function: &Function,
    params: &HashMap<String, String>,
    source: Option<&Object>,
    allow: F,
    host: FunctionHost,
    budget: FunctionBudget,
) -> Result<FunctionInvocation, String>
where
    F: Fn(&Object) -> Result<bool, String>,
{
    invoke_with_source_and_llm(
        db,
        function,
        params,
        source,
        allow,
        InvokeOpts {
            host,
            budget,
            llm_host: &RejectLlmHost,
        },
    )
}

fn bind_llm_inputs(
    step: &LlmStep,
    objects: &[Object],
    params: &HashMap<String, String>,
) -> serde_json::Value {
    let mut bound = serde_json::Map::new();
    if step.input_bindings.is_empty() {
        bound.insert(
            "objects".into(),
            serde_json::Value::Array(
                objects
                    .iter()
                    .map(|object| {
                        let properties: BTreeMap<_, _> = object.properties.iter().collect();
                        serde_json::json!({
                            "id": object.id,
                            "kind": object.kind,
                            "properties": properties,
                        })
                    })
                    .collect(),
            ),
        );
        let params: BTreeMap<_, _> = params.iter().collect();
        bound.insert(
            "params".into(),
            serde_json::to_value(params).unwrap_or_default(),
        );
        return serde_json::Value::Object(bound);
    }
    for (name, source) in &step.input_bindings {
        if let Some(param) = params.get(source) {
            bound.insert(name.clone(), serde_json::Value::String(param.clone()));
            continue;
        }
        let value = objects.iter().find_map(|object| {
            object
                .properties
                .get(source)
                .cloned()
                .map(serde_json::Value::String)
        });
        bound.insert(name.clone(), value.unwrap_or(serde_json::Value::Null));
    }
    serde_json::Value::Object(bound)
}

/// Invoke with a governed or scripted LLM host (#1310).
pub fn invoke_with_llm<F>(
    db: &RuntimeDb,
    function: &Function,
    params: &HashMap<String, String>,
    allow: F,
    host: FunctionHost,
    budget: FunctionBudget,
    llm_host: &dyn LlmStepHost,
) -> Result<FunctionInvocation, String>
where
    F: Fn(&Object) -> Result<bool, String>,
{
    invoke_with_source_and_llm(
        db,
        function,
        params,
        None,
        allow,
        InvokeOpts {
            host,
            budget,
            llm_host,
        },
    )
}

struct InvokeOpts<'a> {
    host: FunctionHost,
    budget: FunctionBudget,
    llm_host: &'a dyn LlmStepHost,
}

fn invoke_with_source_and_llm<F>(
    db: &RuntimeDb,
    function: &Function,
    params: &HashMap<String, String>,
    source: Option<&Object>,
    allow: F,
    opts: InvokeOpts<'_>,
) -> Result<FunctionInvocation, String>
where
    F: Fn(&Object) -> Result<bool, String>,
{
    let mut checker = BudgetChecker {
        started: Instant::now(),
        steps: 0,
        budget: opts.budget.clone(),
    };
    let executed = execute_with_source_and_result_filter(
        db,
        function,
        params,
        source,
        allow,
        Some(&mut checker),
        opts.llm_host,
    );
    let elapsed_ms = checker.started.elapsed().as_millis() as u64;
    let (result, budget_exceeded) = match executed {
        Ok(result) => {
            let encoded = serde_json::to_vec(&result.aggregates)
                .unwrap_or_default()
                .len()
                + result.objects.len() * 64
                + result
                    .structured
                    .as_ref()
                    .map(|value| serde_json::to_vec(value).unwrap_or_default().len())
                    .unwrap_or(0);
            if encoded > opts.budget.max_output_bytes {
                (
                    FunctionResult::default(),
                    "function budget exceeded: max_output_bytes".into(),
                )
            } else {
                (result, String::new())
            }
        }
        Err(error) if error.starts_with("function budget exceeded:") => {
            (FunctionResult::default(), error)
        }
        Err(error) => return Err(error),
    };
    Ok(FunctionInvocation {
        receipt: FunctionReceipt {
            function_name: function.name.clone(),
            function_digest: function_digest(function),
            now_ms: opts.host.now_ms,
            rng_seed: opts.host.rng_seed,
            elapsed_ms,
            steps: checker.steps,
            budget_exceeded,
            output_digest: result_digest(&result),
            prompt_digest: result.llm_prompt_digest.clone(),
            model_route: result.llm_model_route.clone(),
            input_digest: result.llm_input_digest.clone(),
            schema_error: result.schema_error.clone(),
        },
        result,
    })
}

fn execute_with_source_and_result_filter<F>(
    db: &RuntimeDb,
    f: &Function,
    params: &HashMap<String, String>,
    source: Option<&Object>,
    allow: F,
    mut budget: Option<&mut BudgetChecker>,
    llm_host: &dyn LlmStepHost,
) -> Result<FunctionResult, String>
where
    F: Fn(&Object) -> Result<bool, String>,
{
    let mut objects: Vec<Object> = Vec::new();
    let mut result = FunctionResult::default();
    let mut last_kind = source.map(|object| object.kind.clone());

    for step in &f.pipeline {
        if let Some(checker) = budget.as_mut() {
            checker.tick()?;
        }
        let step = match step {
            PipelineStep::Llm(llm) => {
                let bound = bind_llm_inputs(llm, &objects, params);
                let bound_bytes = serde_json::to_vec(&bound).unwrap_or_default();
                result.llm_prompt_digest = digest_bytes(llm.prompt_revision.as_bytes());
                result.llm_model_route = llm.model_route.clone();
                result.llm_input_digest = digest_bytes(&bound_bytes);
                let value = llm_host.complete(
                    &llm.prompt_revision,
                    &llm.model_route,
                    &bound,
                    &llm.output_schema,
                )?;
                if let Some(checker) = budget.as_mut() {
                    checker.check_time()?;
                }
                match validate_structured_output(&llm.output_schema, &value) {
                    Ok(()) => result.structured = Some(value),
                    Err(error) => {
                        result.schema_error = error;
                        result.structured = None;
                    }
                }
                continue;
            }
            PipelineStep::Operator(step) => step,
        };
        match step.op.as_str() {
            "self" => {
                objects = match source {
                    Some(object) if allow(object)? => {
                        vec![db.project_object_property_grants(object.clone())?]
                    }
                    _ => Vec::new(),
                };
            }
            "filter" => {
                reject_named_property(
                    db,
                    source
                        .map(|object| object.namespace.as_str())
                        .filter(|namespace| !namespace.is_empty()),
                    if step.kind.is_empty() {
                        None
                    } else {
                        Some(step.kind.as_str())
                    },
                    &step.property,
                )?;
                let val = if !step.property.is_empty() && !step.value.is_empty() {
                    Some(resolve_param(&step.value, params))
                } else {
                    None
                };
                if let Some(value) = &val {
                    db.reject_ungranted_value_instance_query(
                        source
                            .map(|object| object.namespace.as_str())
                            .filter(|namespace| !namespace.is_empty()),
                        if step.kind.is_empty() {
                            None
                        } else {
                            Some(step.kind.as_str())
                        },
                        [(step.property.as_str(), value.as_str())],
                    )?;
                }
                let filter = crate::domain::ListFilter {
                    kind: Some(step.kind.clone()),
                    ..Default::default()
                };
                let mut filtered = db.list_all_objects(&filter)?;
                retain_and_project(db, &mut filtered, &allow)?;
                reject_named_property_for_objects(db, &filtered, &step.property)?;
                if let Some(val) = val {
                    filtered.retain(|o| {
                        o.properties
                            .get(&step.property)
                            .map(|v| *v == val)
                            .unwrap_or(false)
                    });
                }
                if !step.kind.is_empty() {
                    last_kind = Some(step.kind.clone());
                }
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
                retain_and_project(db, &mut next, &allow)?;
                objects = next;
            }
            "aggregate" => {
                if matches!(step.func.as_str(), "sum" | "avg" | "min" | "max") {
                    reject_pipeline_field(db, source, &objects, last_kind.as_deref(), &step.field)?;
                }
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
                reject_pipeline_field(db, source, &objects, last_kind.as_deref(), &step.field)?;
                objects.retain(|o| o.properties.contains_key(&step.field));
            }
            "repeat" => {
                let extra = step.value.parse::<u32>().unwrap_or(0);
                for _ in 0..extra {
                    if let Some(checker) = budget.as_mut() {
                        checker.tick()?;
                    }
                }
            }
            _ => {}
        }
    }
    result.objects = objects;
    Ok(result)
}

fn retain_allowed<F>(objects: &mut Vec<Object>, allow: &F) -> Result<(), String>
where
    F: Fn(&Object) -> Result<bool, String>,
{
    let mut allowed = Vec::with_capacity(objects.len());
    for object in objects.drain(..) {
        if allow(&object)? {
            allowed.push(object);
        }
    }
    *objects = allowed;
    Ok(())
}

fn retain_and_project<F>(db: &RuntimeDb, objects: &mut Vec<Object>, allow: &F) -> Result<(), String>
where
    F: Fn(&Object) -> Result<bool, String>,
{
    retain_allowed(objects, allow)?;
    for object in objects.iter_mut() {
        *object = db.project_object_property_grants(object.clone())?;
    }
    Ok(())
}

fn reject_named_property(
    db: &RuntimeDb,
    namespace: Option<&str>,
    kind: Option<&str>,
    property: &str,
) -> Result<(), String> {
    if property.is_empty() {
        return Ok(());
    }
    db.reject_ungranted_property_query(namespace, kind, [property])
}

fn reject_pipeline_field(
    db: &RuntimeDb,
    source: Option<&Object>,
    objects: &[Object],
    last_kind: Option<&str>,
    property: &str,
) -> Result<(), String> {
    if property.is_empty() {
        return Ok(());
    }
    if !objects.is_empty() {
        return reject_named_property_for_objects(db, objects, property);
    }
    reject_named_property(
        db,
        source
            .map(|object| object.namespace.as_str())
            .filter(|namespace| !namespace.is_empty()),
        last_kind.or(source.map(|object| object.kind.as_str())),
        property,
    )
}

pub(crate) fn encode_pipeline(pipeline: &[PipelineStep]) -> Result<String, serde_json::Error> {
    serde_json::to_string(pipeline)
}

type LegacyOperatorTuple = (
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

pub(crate) fn decode_pipeline(pipeline_json: &str) -> Result<Vec<PipelineStep>, String> {
    if let Ok(steps) = serde_json::from_str::<Vec<PipelineStep>>(pipeline_json) {
        return Ok(steps);
    }
    let tuples: Vec<LegacyOperatorTuple> =
        serde_json::from_str(pipeline_json).map_err(|error| error.to_string())?;
    Ok(tuples
        .into_iter()
        .map(
            |(op, kind, property, value, relation, dir, func, field, alias)| {
                PipelineStep::Operator(OperatorStep {
                    op,
                    kind,
                    property,
                    value,
                    relation,
                    dir,
                    func,
                    field,
                    alias,
                })
            },
        )
        .collect())
}

fn reject_named_property_for_objects(
    db: &RuntimeDb,
    objects: &[Object],
    property: &str,
) -> Result<(), String> {
    if property.is_empty() || objects.is_empty() {
        return Ok(());
    }
    let mut scopes = objects
        .iter()
        .map(|object| (object.namespace.as_str(), object.kind.as_str()))
        .collect::<Vec<_>>();
    scopes.sort_unstable();
    scopes.dedup();
    for (namespace, kind) in scopes {
        reject_named_property(
            db,
            if namespace.is_empty() {
                None
            } else {
                Some(namespace)
            },
            Some(kind),
            property,
        )?;
    }
    Ok(())
}

fn resolve_param(value: &str, params: &HashMap<String, String>) -> String {
    if let Some(key) = value.strip_prefix('$') {
        params.get(key).cloned().unwrap_or_default()
    } else {
        value.to_string()
    }
}

impl SekaiDb {
    pub(crate) fn migrate_functions(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_functions (
                name TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                params TEXT NOT NULL DEFAULT '[]',
                pipeline TEXT NOT NULL DEFAULT '[]',
                created INTEGER NOT NULL
            );",
        )
        .map_err(|e| e.to_string())
    }

    pub fn create_function(&self, f: &Function) -> Result<(), String> {
        validate_function(f)?;
        let conn = self.conn();
        let params_json = serde_json::to_string(
            &f.params
                .iter()
                .map(|p| (&p.name, &p.param_type, p.required))
                .collect::<Vec<_>>(),
        )
        .map_err(|e| e.to_string())?;
        let pipeline_json = encode_pipeline(&f.pipeline).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO sekai_functions (name,description,params,pipeline,created) VALUES (?1,?2,?3,?4,?5)",
            params![f.name, f.description, params_json, pipeline_json, f.created],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_function(&self, name: &str) -> Result<Option<Function>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT name,description,params,pipeline,created FROM sekai_functions WHERE name=?1",
            params![name],
            |row| {
                let params_json: String = row.get(2)?;
                let pipeline_json: String = row.get(3)?;
                let params_vec: Vec<(String, String, bool)> =
                    serde_json::from_str(&params_json).map_err(sqlite_json_error)?;
                let pipeline = decode_pipeline(&pipeline_json).map_err(sqlite_json_error)?;
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
                    pipeline,
                    created: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_functions(&self) -> Result<Vec<Function>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT name,description,params,pipeline,created FROM sekai_functions ORDER BY name")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                let params_json: String = row.get(2)?;
                let pipeline_json: String = row.get(3)?;
                let params_vec: Vec<(String, String, bool)> =
                    serde_json::from_str(&params_json).map_err(sqlite_json_error)?;
                let pipeline = decode_pipeline(&pipeline_json).map_err(sqlite_json_error)?;
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
                    pipeline,
                    created: row.get(4)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
}

fn sqlite_json_error(error: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        3,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KIND_COMPONENT, Link};

    fn step(op: &str, kind: &str, relation: &str, func: &str, field: &str) -> PipelineStep {
        PipelineStep::operator(op, kind, relation, func, field)
    }

    fn op_fields(op: &str, kind: &str, relation: &str, func: &str, field: &str) -> OperatorStep {
        OperatorStep {
            op: op.into(),
            kind: kind.into(),
            property: String::new(),
            value: String::new(),
            relation: relation.into(),
            dir: String::new(),
            func: func.into(),
            field: field.into(),
            alias: String::new(),
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
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
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

        let f = Function {
            name: "component_count".into(),
            description: "".into(),
            params: vec![],
            created: 0,
            pipeline: vec![
                step("self", "", "", "", ""),
                step("traverse", "", "contains", "", ""),
                PipelineStep::Operator(OperatorStep {
                    alias: "component_count".into(),
                    ..op_fields("aggregate", "", "", "count", "")
                }),
            ],
        };
        let source = db.get_object("r1").unwrap().unwrap();
        let res =
            execute_for_object_with_filter(&db, &f, &source, &HashMap::new(), |_| true).unwrap();
        assert_eq!(res.aggregates["component_count"], "2");
        let error =
            execute_for_object_with_result_filter(&db, &f, &source, &HashMap::new(), |_| {
                Err("policy unavailable".into())
            })
            .unwrap_err();
        assert_eq!(error, "policy unavailable");
    }

    #[test]
    fn test_execute_with_param() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
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
                PipelineStep::Operator(OperatorStep {
                    op: "filter".into(),
                    kind: KIND_COMPONENT.into(),
                    property: "language".into(),
                    value: "$lang".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    alias: "".into(),
                }),
                PipelineStep::Operator(OperatorStep {
                    op: "aggregate".into(),
                    kind: "".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "sum".into(),
                    field: "task_total".into(),
                    alias: "total".into(),
                }),
            ],
        };
        let params = HashMap::from([("lang".into(), "rust".into())]);
        let res = execute(&db, &f, &params).unwrap();
        assert_eq!(res.aggregates["total"], "5");
    }

    #[test]
    fn test_function_persistence() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let f = Function {
            name: "sum_tasks".into(),
            description: "sum task totals".into(),
            params: vec![FuncParam {
                name: "lang".into(),
                param_type: "string".into(),
                required: true,
            }],
            pipeline: vec![PipelineStep::Operator(OperatorStep {
                op: "filter".into(),
                kind: KIND_COMPONENT.into(),
                property: "language".into(),
                value: "$lang".into(),
                relation: "".into(),
                dir: "".into(),
                func: "".into(),
                field: "".into(),
                alias: "".into(),
            })],
            created: 42,
        };
        db.create_function(&f).unwrap();
        let loaded = db.get_function("sum_tasks").unwrap().unwrap();
        assert_eq!(loaded.name, f.name);
        assert_eq!(loaded.params.len(), 1);
        assert_eq!(db.list_functions().unwrap().len(), 1);
    }

    #[test]
    fn computed_pipeline_denies_hidden_property_predicates_and_aggregates() {
        use crate::sekai::object_security::{
            OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityOperation, ObjectSecurityPolicy,
            ObjectSecurityPredicate, ObjectSecurityRule, PropertyGrant, PropertyGrantAccess,
        };
        use std::collections::BTreeMap;

        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let namespace = "compute-grants";
        db.create_object(&Object {
            id: format!("{namespace}:worker"),
            kind: "document".into(),
            name: "worker".into(),
            namespace: namespace.into(),
            external_id: format!("{namespace}:worker"),
            properties: HashMap::from([
                ("owner".into(), "alice".into()),
                ("salary".into(), "120".into()),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
        let policy = ObjectSecurityPolicy {
            contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: namespace.into(),
            kind: "document".into(),
            rules: vec![ObjectSecurityRule {
                operation: ObjectSecurityOperation::Read,
                predicates: vec![ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: Some(vec![PropertyGrant {
                property: "owner".into(),
                access: PropertyGrantAccess::Read,
            }]),
            value_instance_grants: None,
            required_purpose: None,
        };
        let revision = db
            .put_object_security_policy(&policy, "root", "put-compute-grants", 1)
            .unwrap();
        db.activate_object_security_policies(
            namespace,
            &BTreeMap::from([("document".into(), revision.revision_digest)]),
            "root",
            "activate-compute-grants",
            2,
        )
        .unwrap();

        let hidden_filter = Function {
            name: "filter_salary".into(),
            description: "".into(),
            params: vec![],
            created: 0,
            pipeline: vec![PipelineStep::Operator(OperatorStep {
                op: "filter".into(),
                kind: "document".into(),
                property: "salary".into(),
                value: "120".into(),
                relation: "".into(),
                dir: "".into(),
                func: "".into(),
                field: "".into(),
                alias: "".into(),
            })],
        };
        assert!(
            execute(&db, &hidden_filter, &HashMap::new())
                .unwrap_err()
                .contains("object_security_denied")
        );

        let hidden_sum = Function {
            name: "sum_salary".into(),
            description: "".into(),
            params: vec![],
            created: 0,
            pipeline: vec![
                step("filter", "document", "", "", ""),
                PipelineStep::Operator(OperatorStep {
                    op: "aggregate".into(),
                    kind: "".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "sum".into(),
                    field: "salary".into(),
                    alias: "total".into(),
                }),
            ],
        };
        assert!(
            execute(&db, &hidden_sum, &HashMap::new())
                .unwrap_err()
                .contains("object_security_denied")
        );

        let empty_then_sum = Function {
            name: "empty_sum_salary".into(),
            description: "".into(),
            params: vec![],
            created: 0,
            pipeline: vec![
                PipelineStep::Operator(OperatorStep {
                    op: "filter".into(),
                    kind: "document".into(),
                    property: "owner".into(),
                    value: "nobody".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    alias: "".into(),
                }),
                PipelineStep::Operator(OperatorStep {
                    op: "aggregate".into(),
                    kind: "".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "sum".into(),
                    field: "salary".into(),
                    alias: "total".into(),
                }),
            ],
        };
        assert!(
            execute(&db, &empty_then_sum, &HashMap::new())
                .unwrap_err()
                .contains("object_security_denied"),
            "aggregating a hidden field must deny even when the prior filter is empty"
        );

        db.delete_object(&format!("{namespace}:worker")).unwrap();
        assert!(
            execute(&db, &hidden_filter, &HashMap::new())
                .unwrap_err()
                .contains("object_security_denied"),
            "naming a hidden property must deny even when no rows survive"
        );
    }

    #[test]
    fn invoke_records_host_clock_and_replays() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        db.create_object(&Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "a".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("language".into(), "rust".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        let function = Function {
            name: "count_rust".into(),
            description: "".into(),
            params: vec![],
            created: 0,
            pipeline: vec![
                PipelineStep::Operator(OperatorStep {
                    property: "language".into(),
                    value: "rust".into(),
                    ..op_fields("filter", KIND_COMPONENT, "", "", "")
                }),
                step("aggregate", "", "", "count", ""),
            ],
        };
        let host = FunctionHost {
            now_ms: 1_700_000_000_000,
            rng_seed: 42,
        };
        let first = invoke(
            &db,
            &function,
            &HashMap::new(),
            |_| Ok(true),
            host.clone(),
            FunctionBudget::default(),
        )
        .unwrap();
        assert!(first.receipt.elapsed_ms < 50);
        assert_eq!(first.receipt.now_ms, host.now_ms);
        assert_eq!(first.receipt.rng_seed, 42);
        assert!(first.receipt.budget_exceeded.is_empty());
        assert_eq!(first.result.aggregates["count"], "1");
        let second = invoke(
            &db,
            &function,
            &HashMap::new(),
            |_| Ok(true),
            host,
            FunctionBudget::default(),
        )
        .unwrap();
        assert_eq!(first.receipt.output_digest, second.receipt.output_digest);
        assert_eq!(
            first.receipt.function_digest,
            second.receipt.function_digest
        );
    }

    #[test]
    fn invoke_terminates_repeat_at_step_budget() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let function = Function {
            name: "loop".into(),
            description: "".into(),
            params: vec![],
            created: 0,
            pipeline: vec![PipelineStep::Operator(OperatorStep {
                op: "repeat".into(),
                value: "1000000".into(),
                ..op_fields("repeat", "", "", "", "")
            })],
        };
        let invocation = invoke(
            &db,
            &function,
            &HashMap::new(),
            |_| Ok(true),
            FunctionHost {
                now_ms: 1,
                rng_seed: 1,
            },
            FunctionBudget {
                max_time_ms: 50,
                max_output_bytes: 1024,
                max_steps: 8,
            },
        )
        .unwrap();
        assert_eq!(
            invocation.receipt.budget_exceeded,
            "function budget exceeded: max_steps"
        );
    }

    #[test]
    fn invoke_cannot_read_unauthorized_objects() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        db.create_object(&Object {
            id: "secret".into(),
            kind: KIND_COMPONENT.into(),
            name: "s".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("language".into(), "rust".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        let function = Function {
            name: "all".into(),
            description: "".into(),
            params: vec![],
            created: 0,
            pipeline: vec![
                step("filter", KIND_COMPONENT, "", "", ""),
                step("aggregate", "", "", "count", ""),
            ],
        };
        let invocation = invoke(
            &db,
            &function,
            &HashMap::new(),
            |_| Ok(false),
            FunctionHost {
                now_ms: 1,
                rng_seed: 1,
            },
            FunctionBudget::default(),
        )
        .unwrap();
        assert_eq!(invocation.result.aggregates["count"], "0");
    }

    const LLM_OUTPUT_SCHEMA: &str = r#"{"type":"object","properties":{"label":{"type":"string"}},"required":["label"],"additionalProperties":false}"#;

    struct ScriptedHost {
        output: serde_json::Value,
    }

    impl LlmStepHost for ScriptedHost {
        fn complete(
            &self,
            _prompt_revision: &str,
            _model_route: &str,
            _bound_inputs: &serde_json::Value,
            _output_schema: &str,
        ) -> Result<serde_json::Value, String> {
            Ok(self.output.clone())
        }
    }

    fn fixture_component(db: &RuntimeDb) {
        db.create_object(&Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "a".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("language".into(), "rust".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    }

    fn classify_function() -> Function {
        Function {
            name: "classify".into(),
            description: "".into(),
            params: vec![],
            created: 0,
            pipeline: vec![
                PipelineStep::Operator(OperatorStep {
                    property: "language".into(),
                    value: "rust".into(),
                    ..op_fields("filter", KIND_COMPONENT, "", "", "")
                }),
                PipelineStep::Llm(LlmStep {
                    prompt_revision: "classify/v1".into(),
                    input_bindings: BTreeMap::from([("language".into(), "language".into())]),
                    output_schema: LLM_OUTPUT_SCHEMA.into(),
                    model_route: "native/scripted".into(),
                }),
            ],
        }
    }

    fn invoke_host() -> FunctionHost {
        FunctionHost {
            now_ms: 1_700_000_000_000,
            rng_seed: 7,
        }
    }

    #[test]
    fn llm_step_returns_schema_valid_structured_output() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        fixture_component(&db);
        let function = classify_function();
        assert!(validate_function(&function).is_ok());
        let host = ScriptedHost {
            output: serde_json::json!({"label": "systems"}),
        };
        let invocation = invoke_with_llm(
            &db,
            &function,
            &HashMap::new(),
            |_| Ok(true),
            invoke_host(),
            FunctionBudget::default(),
            &host,
        )
        .unwrap();
        assert!(invocation.receipt.schema_error.is_empty());
        assert_eq!(
            invocation.result.structured,
            Some(serde_json::json!({"label": "systems"}))
        );
        assert_eq!(invocation.receipt.model_route, "native/scripted");
        assert!(invocation.receipt.prompt_digest.starts_with("sha256:"));
        assert!(invocation.receipt.input_digest.starts_with("sha256:"));
        assert!(invocation.receipt.output_digest.starts_with("sha256:"));
        assert!(invocation.receipt.function_digest.starts_with("sha256:"));
    }

    #[test]
    fn llm_step_receipt_is_stable_for_the_same_scripted_response() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        fixture_component(&db);
        let function = classify_function();
        let host = ScriptedHost {
            output: serde_json::json!({"label": "systems"}),
        };
        let first = invoke_with_llm(
            &db,
            &function,
            &HashMap::new(),
            |_| Ok(true),
            invoke_host(),
            FunctionBudget::default(),
            &host,
        )
        .unwrap();
        let second = invoke_with_llm(
            &db,
            &function,
            &HashMap::new(),
            |_| Ok(true),
            invoke_host(),
            FunctionBudget::default(),
            &host,
        )
        .unwrap();
        assert_eq!(
            first.receipt.function_digest,
            second.receipt.function_digest
        );
        assert_eq!(first.receipt.prompt_digest, second.receipt.prompt_digest);
        assert_eq!(first.receipt.model_route, second.receipt.model_route);
        assert_eq!(first.receipt.input_digest, second.receipt.input_digest);
        assert_eq!(first.receipt.output_digest, second.receipt.output_digest);
        assert_eq!(first.receipt.schema_error, second.receipt.schema_error);
        assert_eq!(first.receipt.now_ms, second.receipt.now_ms);
        assert_eq!(first.receipt.rng_seed, second.receipt.rng_seed);
    }

    #[test]
    fn llm_step_schema_invalid_output_records_an_error_on_the_receipt() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        fixture_component(&db);
        let function = classify_function();
        let host = ScriptedHost {
            output: serde_json::json!({"score": 1}),
        };
        let invocation = invoke_with_llm(
            &db,
            &function,
            &HashMap::new(),
            |_| Ok(true),
            invoke_host(),
            FunctionBudget::default(),
            &host,
        )
        .unwrap();
        assert!(invocation.result.structured.is_none());
        assert_eq!(
            invocation.receipt.schema_error,
            "missing required property label"
        );
        assert_eq!(
            invocation.result.schema_error,
            invocation.receipt.schema_error
        );
        assert_eq!(invocation.receipt.model_route, "native/scripted");
        assert!(invocation.receipt.prompt_digest.starts_with("sha256:"));
        assert!(invocation.receipt.output_digest.starts_with("sha256:"));
    }

    #[test]
    fn llm_step_without_a_host_fails_closed() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        fixture_component(&db);
        let error = invoke(
            &db,
            &classify_function(),
            &HashMap::new(),
            |_| Ok(true),
            invoke_host(),
            FunctionBudget::default(),
        )
        .unwrap_err();
        assert_eq!(error, "llm step requires a host");
    }

    #[test]
    fn llm_step_requires_prompt_schema_and_pinned_route() {
        let mut function = classify_function();
        if let PipelineStep::Llm(step) = &mut function.pipeline[1] {
            step.model_route.clear();
        }
        assert!(
            validate_function(&function)
                .unwrap_err()
                .contains("llm requires model_route")
        );
    }

    #[test]
    fn decode_pipeline_reads_legacy_operator_tuples() {
        let pipeline = decode_pipeline(r#"[["filter","component","","","","","","",""]]"#).unwrap();
        match &pipeline[0] {
            PipelineStep::Operator(step) => {
                assert_eq!(step.op, "filter");
                assert_eq!(step.kind, "component");
            }
            PipelineStep::Llm(_) => panic!("expected operator step"),
        }
    }

    #[test]
    fn encode_pipeline_roundtrips_an_llm_step() {
        let pipeline = classify_function().pipeline;
        let encoded = encode_pipeline(&pipeline).unwrap();
        assert!(encoded.contains("\"step\":\"llm\""));
        let decoded = decode_pipeline(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        match &decoded[1] {
            PipelineStep::Llm(step) => {
                assert_eq!(step.prompt_revision, "classify/v1");
                assert_eq!(step.model_route, "native/scripted");
            }
            PipelineStep::Operator(_) => panic!("expected llm step"),
        }
    }

    #[test]
    fn get_function_reads_legacy_tuple_pipeline() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.conn()
            .execute(
                "INSERT INTO sekai_functions (name,description,params,pipeline,created) VALUES (?1,?2,?3,?4,?5)",
                params![
                    "legacy",
                    "",
                    "[]",
                    r#"[["filter","component","","","","","","",""]]"#,
                    0
                ],
            )
            .unwrap();
        let stored = db.get_function("legacy").unwrap().unwrap();
        match &stored.pipeline[0] {
            PipelineStep::Operator(step) => assert_eq!(step.op, "filter"),
            PipelineStep::Llm(_) => panic!("expected operator step"),
        }
    }

    #[test]
    fn llm_step_rejects_a_second_llm_step() {
        let mut function = classify_function();
        function.pipeline.push(PipelineStep::Llm(LlmStep {
            prompt_revision: "classify/v2".into(),
            input_bindings: BTreeMap::new(),
            output_schema: LLM_OUTPUT_SCHEMA.into(),
            model_route: "native/scripted".into(),
        }));
        assert!(
            validate_function(&function)
                .unwrap_err()
                .contains("at most one llm step")
        );
    }

    #[test]
    fn llm_step_rejects_non_string_schema_type() {
        let mut function = classify_function();
        if let PipelineStep::Llm(step) = &mut function.pipeline[1] {
            step.output_schema = r#"{"type":1,"properties":{"label":{"type":"string"}}}"#.into();
        }
        assert!(
            validate_function(&function)
                .unwrap_err()
                .contains("schema type must be a string")
        );
    }

    #[test]
    fn llm_step_rejects_unsupported_output_schema_keywords() {
        let mut function = classify_function();
        if let PipelineStep::Llm(step) = &mut function.pipeline[1] {
            step.output_schema =
                r#"{"type":"object","properties":{"label":{"type":"string","enum":["a"]}},"required":["label"]}"#
                    .into();
        }
        assert!(
            validate_function(&function)
                .unwrap_err()
                .contains("unsupported output schema keyword enum")
        );
    }

    #[test]
    fn llm_step_structured_output_counts_toward_output_budget() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        fixture_component(&db);
        let host = ScriptedHost {
            output: serde_json::json!({"label": "this-label-is-too-long-for-the-budget"}),
        };
        let invocation = invoke_with_llm(
            &db,
            &classify_function(),
            &HashMap::new(),
            |_| Ok(true),
            invoke_host(),
            FunctionBudget {
                max_time_ms: 50,
                max_output_bytes: 8,
                max_steps: 32,
            },
            &host,
        )
        .unwrap();
        assert_eq!(
            invocation.receipt.budget_exceeded,
            "function budget exceeded: max_output_bytes"
        );
        assert!(invocation.result.structured.is_none());
    }
}
