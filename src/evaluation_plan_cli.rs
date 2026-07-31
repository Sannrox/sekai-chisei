//! Operator CLI for immutable, situation-specific evaluation plans.
//!
//! The CLI deliberately keeps plan validation, publication, resolution, and
//! execution as separate authority boundaries. Human output never emits
//! parameters, evidence identifiers, evidence payloads, source references, or
//! subject identities.

use crate::chisei::evaluation_execution::{
    EXECUTION_REQUEST_CONTRACT, EXECUTOR_VERSION, EvaluationExecutionRequest as DomainExecution,
};
use crate::chisei::evaluation_manifest::{
    EvaluationResolutionRequest as DomainResolution, RESOLUTION_REQUEST_CONTRACT,
    RESOLUTION_RESOLVED, RESOLUTION_UNAVAILABLE, RESOLUTION_UNKNOWN, RESOLVER_VERSION,
    prepare_resolution_request,
};
use crate::chisei::evaluation_plan::{
    AVAILABILITY_ENABLED, EvaluationInputBinding as DomainInputBinding,
    EvaluationPlan as DomainPlan, EvaluationPlanNode as DomainPlanNode, NODE_REQUIRED,
    STOCHASTIC_EXECUTION_CLASS, prepare_plan, validate_parameters,
};
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::grpc::pb::chisei::{
    EvaluationExecutionProjection, EvaluationExecutionRequest, EvaluationInputBinding,
    EvaluationPlan, EvaluationPlanNode, EvaluationResolutionRequest,
    ExecuteEvaluationManifestRequest, GetEvaluationPlanRequest, GetEvaluatorDefinitionRequest,
    ListEvaluationPlansRequest, PutEvaluationPlanRequest, ResolveEvaluationPlanRequest,
    ResolvedEvaluationManifest,
};
use crate::grpc::pb::sekai::GetGovernedFactVersionRequest;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use tonic::{Code, Status};

pub const EXIT_VALIDATION: i32 = 2;
pub const EXIT_AUTHORIZATION: i32 = 3;
pub const EXIT_UNKNOWN: i32 = 4;
pub const EXIT_UNAVAILABLE: i32 = 5;
pub const EXIT_COMPATIBILITY: i32 = 6;
pub const EXIT_DENIED: i32 = 7;

const OUTPUT_SCHEMA: &str = "sekaictl.evaluation-plan-output/v1";

pub fn usage() -> &'static str {
    "Usage: sekaictl admin evaluation plan <command> ...\n\
     \n\
     Commands:\n\
       validate <plan.json> [--offline] [--target <url-or-socket>] [--json]\n\
       apply <plan.json> [--target <url-or-socket>] [--json]\n\
       list --namespace <name> [--plan-id <id>] [--target <url-or-socket>] [--json]\n\
       inspect <plan-version-id> [--target <url-or-socket>] [--json]\n\
       resolve <resolution.json> [--target <url-or-socket>] [--json]\n\
       execute <namespace> <manifest-digest> --yes [--max-duration-ms <ms>] [--target <url-or-socket>] [--json]\n\
     \n\
     validate is read-only. It checks exact live evaluator and invariant versions\n\
     unless --offline is supplied. resolve never executes evaluators. execute\n\
     accepts only an already resolved manifest digest and requires --yes."
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    Validation,
    Authorization,
    Unknown,
    Unavailable,
    Compatibility,
    Denied,
}

#[derive(Debug)]
pub struct EvaluationCliError {
    kind: ErrorKind,
    message: String,
}

impl EvaluationCliError {
    fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn validation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Validation, message)
    }

    pub fn exit_code(&self) -> i32 {
        match self.kind {
            ErrorKind::Validation => EXIT_VALIDATION,
            ErrorKind::Authorization => EXIT_AUTHORIZATION,
            ErrorKind::Unknown => EXIT_UNKNOWN,
            ErrorKind::Unavailable => EXIT_UNAVAILABLE,
            ErrorKind::Compatibility => EXIT_COMPATIBILITY,
            ErrorKind::Denied => EXIT_DENIED,
        }
    }
}

impl fmt::Display for EvaluationCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for EvaluationCliError {}

#[derive(Debug, Default)]
struct ParsedArgs {
    positionals: Vec<String>,
    values: BTreeMap<String, String>,
    switches: BTreeSet<String>,
}

impl ParsedArgs {
    fn parse(args: &[String]) -> Result<Self, EvaluationCliError> {
        let mut parsed = Self::default();
        let mut index = 0;
        while index < args.len() {
            let argument = &args[index];
            if matches!(
                argument.as_str(),
                "--target" | "--namespace" | "--plan-id" | "--max-duration-ms"
            ) {
                let value = args
                    .get(index + 1)
                    .filter(|value| !value.starts_with('-'))
                    .ok_or_else(|| {
                        EvaluationCliError::validation(format!("{argument} requires a value"))
                    })?;
                if parsed
                    .values
                    .insert(argument.clone(), value.clone())
                    .is_some()
                {
                    return Err(EvaluationCliError::validation(format!(
                        "{argument} may be supplied only once"
                    )));
                }
                index += 2;
            } else if matches!(argument.as_str(), "--json" | "--offline" | "--yes") {
                if !parsed.switches.insert(argument.clone()) {
                    return Err(EvaluationCliError::validation(format!(
                        "{argument} may be supplied only once"
                    )));
                }
                index += 1;
            } else if argument.starts_with('-') {
                return Err(EvaluationCliError::validation(format!(
                    "unknown option {argument:?}"
                )));
            } else {
                parsed.positionals.push(argument.clone());
                index += 1;
            }
        }
        Ok(parsed)
    }

    fn validate_options(
        &self,
        value_options: &[&str],
        switches: &[&str],
    ) -> Result<(), EvaluationCliError> {
        for option in self.values.keys() {
            if !value_options.contains(&option.as_str()) {
                return Err(EvaluationCliError::validation(format!(
                    "{option} is not valid for this command"
                )));
            }
        }
        for option in &self.switches {
            if !switches.contains(&option.as_str()) {
                return Err(EvaluationCliError::validation(format!(
                    "{option} is not valid for this command"
                )));
            }
        }
        Ok(())
    }

    fn target(&self) -> String {
        self.values
            .get("--target")
            .cloned()
            .or_else(|| std::env::var("CHISEI_GRPC_URL").ok())
            .or_else(|| std::env::var("SEKAI_SOCKET").ok())
            .unwrap_or_else(|| "./data/sekai.sock".into())
    }

    fn json(&self) -> bool {
        self.switches.contains("--json")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanDocument {
    #[serde(default)]
    contract_version: String,
    namespace: String,
    plan_id: String,
    version: String,
    accepted_subject_profiles: Vec<String>,
    nodes: Vec<PlanNodeDocument>,
    reducer: String,
    source_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanNodeDocument {
    node_id: String,
    evaluator_definition_id: String,
    #[serde(default)]
    depends_on_node_ids: Vec<String>,
    input_bindings: Vec<PlanInputBindingDocument>,
    #[serde(default)]
    parameters: Option<Value>,
    #[serde(default)]
    parameters_json: Option<String>,
    invariant_version_ids: Vec<String>,
    classification: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanInputBindingDocument {
    name: String,
    source_kind: String,
    schema_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolutionDocument {
    #[serde(default = "default_resolution_contract")]
    contract_version: String,
    #[serde(default = "default_resolver_version")]
    resolver_version: String,
    namespace: String,
    request_id: String,
    plan_version_id: String,
    subject_profile: String,
    subject_identity: String,
    subject_content_digest: String,
    #[serde(default)]
    evidence_object_ids: Vec<String>,
    evaluation_time_ms: i64,
}

fn default_resolution_contract() -> String {
    RESOLUTION_REQUEST_CONTRACT.into()
}

fn default_resolver_version() -> String {
    RESOLVER_VERSION.into()
}

pub async fn run(args: Vec<String>) -> Result<(), EvaluationCliError> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(EvaluationCliError::validation(usage()));
    };
    let parsed = ParsedArgs::parse(&args[1..])?;
    match command {
        "validate" => validate_command(parsed).await,
        "apply" => apply_command(parsed).await,
        "list" => list_command(parsed).await,
        "inspect" => inspect_command(parsed).await,
        "resolve" => resolve_command(parsed).await,
        "execute" => execute_command(parsed).await,
        _ => Err(EvaluationCliError::validation(usage())),
    }
}

async fn validate_command(args: ParsedArgs) -> Result<(), EvaluationCliError> {
    args.validate_options(&["--target"], &["--json", "--offline"])?;
    let path = one_path(&args.positionals, "validate")?;
    let plan = read_and_prepare_plan(&path)?;
    let mode = if args.switches.contains("--offline") {
        "offline"
    } else {
        validate_live_references(&args.target(), &plan).await?;
        "live"
    };
    print_plan_output("validate", "valid", &plan, Some(mode), args.json())
}

async fn apply_command(args: ParsedArgs) -> Result<(), EvaluationCliError> {
    args.validate_options(&["--target"], &["--json"])?;
    let path = one_path(&args.positionals, "apply")?;
    let plan = read_and_prepare_plan(&path)?;
    let channel = connect_sekai(&args.target())
        .await
        .map_err(|error| transport_error("connect to evaluation service", error))?;
    let response = ChiseiServiceClient::new(channel)
        .put_evaluation_plan(PutEvaluationPlanRequest {
            plan: Some(to_proto_plan(&plan)),
        })
        .await
        .map_err(|status| rpc_error("apply evaluation plan", status))?
        .into_inner()
        .plan
        .ok_or_else(|| compatibility_error("apply response omitted evaluation plan"))?;
    print_plan_output(
        "apply",
        "stored",
        &from_proto_plan(response),
        None,
        args.json(),
    )
}

async fn list_command(args: ParsedArgs) -> Result<(), EvaluationCliError> {
    args.validate_options(&["--target", "--namespace", "--plan-id"], &["--json"])?;
    if !args.positionals.is_empty() {
        return Err(EvaluationCliError::validation(
            "list accepts no positional arguments",
        ));
    }
    let namespace = args
        .values
        .get("--namespace")
        .ok_or_else(|| EvaluationCliError::validation("list requires --namespace"))?;
    let channel = connect_sekai(&args.target())
        .await
        .map_err(|error| transport_error("connect to evaluation service", error))?;
    let plans = ChiseiServiceClient::new(channel)
        .list_evaluation_plans(ListEvaluationPlansRequest {
            namespace: namespace.clone(),
            plan_id: args.values.get("--plan-id").cloned().unwrap_or_default(),
        })
        .await
        .map_err(|status| rpc_error("list evaluation plans", status))?
        .into_inner()
        .plans
        .into_iter()
        .map(from_proto_plan)
        .collect::<Vec<_>>();
    if args.json() {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema_version": OUTPUT_SCHEMA,
                "command": "list",
                "status": "ok",
                "plans": plans.iter().map(plan_summary).collect::<Vec<_>>(),
            }))
            .map_err(json_error)?
        );
    } else if plans.is_empty() {
        println!("No authorized evaluation plans found.");
    } else {
        for plan in &plans {
            println!(
                "{}  {}  {}@{}  {} nodes",
                plan.plan_version_id,
                plan.content_digest,
                plan.plan_id,
                plan.version,
                plan.nodes.len()
            );
        }
    }
    Ok(())
}

async fn inspect_command(args: ParsedArgs) -> Result<(), EvaluationCliError> {
    args.validate_options(&["--target"], &["--json"])?;
    let plan_version_id = one_positional(&args.positionals, "inspect", "<plan-version-id>")?;
    validate_exact_id("plan_version_id", &plan_version_id, "evaluation-plan:")?;
    let channel = connect_sekai(&args.target())
        .await
        .map_err(|error| transport_error("connect to evaluation service", error))?;
    let plan = ChiseiServiceClient::new(channel)
        .get_evaluation_plan(GetEvaluationPlanRequest { plan_version_id })
        .await
        .map_err(|status| rpc_error("inspect evaluation plan", status))?
        .into_inner()
        .plan
        .ok_or_else(|| compatibility_error("inspect response omitted evaluation plan"))?;
    print_plan_output(
        "inspect",
        "found",
        &from_proto_plan(plan),
        None,
        args.json(),
    )
}

async fn resolve_command(args: ParsedArgs) -> Result<(), EvaluationCliError> {
    args.validate_options(&["--target"], &["--json"])?;
    let path = one_path(&args.positionals, "resolve")?;
    let resolution = read_resolution(&path)?;
    validate_resolution(&resolution)?;
    let channel = connect_sekai(&args.target())
        .await
        .map_err(|error| transport_error("connect to evaluation service", error))?;
    let response = ChiseiServiceClient::new(channel)
        .resolve_evaluation_plan(ResolveEvaluationPlanRequest {
            resolution: Some(to_proto_resolution(resolution)),
        })
        .await
        .map_err(|status| rpc_error("resolve evaluation plan", status))?
        .into_inner();
    print_resolution_output(
        &response.status,
        response.manifest.as_ref(),
        &response.findings,
        args.json(),
    )?;
    match response.status.as_str() {
        RESOLUTION_RESOLVED => Ok(()),
        RESOLUTION_UNKNOWN => Err(EvaluationCliError::new(
            ErrorKind::Unknown,
            "evaluation resolution is unknown",
        )),
        RESOLUTION_UNAVAILABLE => Err(EvaluationCliError::new(
            ErrorKind::Unavailable,
            "evaluation resolution is unavailable",
        )),
        _ => Err(compatibility_error(
            "server returned an unsupported evaluation resolution status",
        )),
    }
}

async fn execute_command(args: ParsedArgs) -> Result<(), EvaluationCliError> {
    args.validate_options(&["--target", "--max-duration-ms"], &["--json", "--yes"])?;
    if args.positionals.len() != 2 {
        return Err(EvaluationCliError::validation(
            "execute requires <namespace> <manifest-digest>",
        ));
    }
    if !args.switches.contains("--yes") {
        return Err(EvaluationCliError::validation(
            "execute requires --yes; resolve is the non-executing dry-run boundary",
        ));
    }
    let namespace = args.positionals[0].clone();
    let manifest_digest = args.positionals[1].clone();
    validate_digest("manifest_digest", &manifest_digest)?;
    let max_total_duration_ms = args
        .values
        .get("--max-duration-ms")
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                EvaluationCliError::validation("--max-duration-ms must be an unsigned integer")
            })
        })
        .transpose()?
        .unwrap_or(0);
    let execution = DomainExecution {
        contract_version: EXECUTION_REQUEST_CONTRACT.into(),
        executor_version: EXECUTOR_VERSION.into(),
        namespace: namespace.clone(),
        manifest_digest: manifest_digest.clone(),
        max_total_duration_ms,
    };
    crate::chisei::evaluation_execution::prepare_execution_request(execution.clone())
        .map_err(EvaluationCliError::validation)?;
    let channel = connect_sekai(&args.target())
        .await
        .map_err(|error| transport_error("connect to evaluation service", error))?;
    let projection = ChiseiServiceClient::new(channel)
        .execute_evaluation_manifest(ExecuteEvaluationManifestRequest {
            execution: Some(EvaluationExecutionRequest {
                contract_version: execution.contract_version,
                executor_version: execution.executor_version,
                namespace,
                manifest_digest,
                max_total_duration_ms,
            }),
        })
        .await
        .map_err(|status| rpc_error("execute evaluation manifest", status))?
        .into_inner()
        .execution
        .ok_or_else(|| compatibility_error("execute response omitted execution projection"))?;
    print_execution_output(&projection, args.json())?;
    match projection.status.as_str() {
        "allow" => Ok(()),
        "deny" => Err(EvaluationCliError::new(
            ErrorKind::Denied,
            "evaluation gate denied",
        )),
        "unknown" => Err(EvaluationCliError::new(
            ErrorKind::Unknown,
            "evaluation execution is unknown",
        )),
        "unavailable" | "cancelled" | "running" => Err(EvaluationCliError::new(
            ErrorKind::Unavailable,
            format!("evaluation execution is {}", projection.status),
        )),
        _ => Err(compatibility_error(
            "server returned an unsupported evaluation execution status",
        )),
    }
}

fn one_path(positionals: &[String], command: &str) -> Result<PathBuf, EvaluationCliError> {
    Ok(PathBuf::from(one_positional(
        positionals,
        command,
        "<document.json>",
    )?))
}

fn one_positional(
    positionals: &[String],
    command: &str,
    expected: &str,
) -> Result<String, EvaluationCliError> {
    if positionals.len() != 1 {
        return Err(EvaluationCliError::validation(format!(
            "{command} requires exactly one {expected}"
        )));
    }
    Ok(positionals[0].clone())
}

fn read_and_prepare_plan(path: &Path) -> Result<DomainPlan, EvaluationCliError> {
    let bytes = std::fs::read(path).map_err(|error| {
        EvaluationCliError::validation(format!("read {}: {error}", path.display()))
    })?;
    let document: PlanDocument = serde_json::from_slice(&bytes).map_err(|error| {
        EvaluationCliError::validation(format!("parse {}: {error}", path.display()))
    })?;
    let plan = document.into_domain()?;
    let plan = prepare_plan(plan, "sekaictl-local-validation", 1).map_err(|error| {
        EvaluationCliError::validation(format!("invalid evaluation plan: {error}"))
    })?;
    validate_exact_plan_references(&plan)?;
    Ok(plan)
}

impl PlanDocument {
    fn into_domain(self) -> Result<DomainPlan, EvaluationCliError> {
        let mut nodes = Vec::with_capacity(self.nodes.len());
        for node in self.nodes {
            let parameters_json = match (node.parameters, node.parameters_json) {
                (Some(_), Some(_)) => {
                    return Err(EvaluationCliError::validation(format!(
                        "node {:?} must supply only one of parameters or parameters_json",
                        node.node_id
                    )));
                }
                (Some(parameters), None) => {
                    serde_json::to_string(&parameters).map_err(json_error)?
                }
                (None, Some(parameters_json)) => parameters_json,
                (None, None) => {
                    return Err(EvaluationCliError::validation(format!(
                        "node {:?} requires parameters or parameters_json",
                        node.node_id
                    )));
                }
            };
            nodes.push(DomainPlanNode {
                node_id: node.node_id,
                evaluator_definition_id: node.evaluator_definition_id,
                depends_on_node_ids: node.depends_on_node_ids,
                input_bindings: node
                    .input_bindings
                    .into_iter()
                    .map(|binding| DomainInputBinding {
                        name: binding.name,
                        source_kind: binding.source_kind,
                        schema_id: binding.schema_id,
                    })
                    .collect(),
                parameters_json,
                invariant_version_ids: node.invariant_version_ids,
                classification: node.classification,
            });
        }
        Ok(DomainPlan {
            contract_version: self.contract_version,
            plan_version_id: String::new(),
            namespace: self.namespace,
            plan_id: self.plan_id,
            version: self.version,
            accepted_subject_profiles: self.accepted_subject_profiles,
            nodes,
            reducer: self.reducer,
            source_ref: self.source_ref,
            content_digest: String::new(),
            created_by: String::new(),
            created_at_ms: 0,
        })
    }
}

fn read_resolution(path: &Path) -> Result<DomainResolution, EvaluationCliError> {
    let bytes = std::fs::read(path).map_err(|error| {
        EvaluationCliError::validation(format!("read {}: {error}", path.display()))
    })?;
    let document: ResolutionDocument = serde_json::from_slice(&bytes).map_err(|error| {
        EvaluationCliError::validation(format!("parse {}: {error}", path.display()))
    })?;
    Ok(DomainResolution {
        contract_version: document.contract_version,
        resolver_version: document.resolver_version,
        namespace: document.namespace,
        request_id: document.request_id,
        plan_version_id: document.plan_version_id,
        subject_profile: document.subject_profile,
        subject_identity: document.subject_identity,
        subject_content_digest: document.subject_content_digest,
        evidence_object_ids: document.evidence_object_ids,
        evaluation_time_ms: document.evaluation_time_ms,
    })
}

fn validate_resolution(resolution: &DomainResolution) -> Result<(), EvaluationCliError> {
    validate_exact_id(
        "plan_version_id",
        &resolution.plan_version_id,
        "evaluation-plan:",
    )?;
    prepare_resolution_request(resolution.clone(), "sekaictl-local-validation").map_err(
        |error| EvaluationCliError::validation(format!("invalid resolution request: {error}")),
    )?;
    if resolution.evaluation_time_ms > chrono::Utc::now().timestamp_millis() {
        return Err(EvaluationCliError::validation(
            "evaluation_time_ms cannot be in the future",
        ));
    }
    Ok(())
}

fn validate_exact_plan_references(plan: &DomainPlan) -> Result<(), EvaluationCliError> {
    for node in &plan.nodes {
        validate_exact_id(
            "evaluator_definition_id",
            &node.evaluator_definition_id,
            "evaluator-definition:",
        )?;
        for invariant_id in &node.invariant_version_ids {
            validate_exact_id("invariant_version_id", invariant_id, "governed-fact-")?;
        }
    }
    Ok(())
}

fn validate_exact_id(field: &str, value: &str, prefix: &str) -> Result<(), EvaluationCliError> {
    let suffix = value.strip_prefix(prefix).unwrap_or_default();
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EvaluationCliError::validation(format!(
            "{field} must be an exact {prefix}<64-lowercase-hex> resource ID; aliases are not supported"
        )));
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<(), EvaluationCliError> {
    validate_exact_id(field, value, "sha256:")
}

async fn validate_live_references(
    target: &str,
    plan: &DomainPlan,
) -> Result<(), EvaluationCliError> {
    let channel = connect_sekai(target)
        .await
        .map_err(|error| transport_error("connect for live validation", error))?;
    let mut chisei = ChiseiServiceClient::new(channel.clone());
    let mut sekai = SekaiServiceClient::new(channel);
    let mut definitions = BTreeMap::new();
    let mut invariants = BTreeMap::new();

    for node in &plan.nodes {
        if !definitions.contains_key(&node.evaluator_definition_id) {
            let record = chisei
                .get_evaluator_definition(GetEvaluatorDefinitionRequest {
                    definition_id: node.evaluator_definition_id.clone(),
                })
                .await
                .map_err(|status| rpc_error("validate evaluator definition", status))?
                .into_inner()
                .record
                .ok_or_else(|| {
                    compatibility_error("evaluator response omitted definition record")
                })?;
            let definition = record.definition.ok_or_else(|| {
                compatibility_error("evaluator record omitted immutable definition")
            })?;
            let availability = record
                .availability
                .ok_or_else(|| compatibility_error("evaluator record omitted availability"))?;
            if definition.namespace != plan.namespace {
                return Err(EvaluationCliError::validation(format!(
                    "node {:?} selects an evaluator from another namespace",
                    node.node_id
                )));
            }
            if availability.state != AVAILABILITY_ENABLED {
                return Err(EvaluationCliError::validation(format!(
                    "node {:?} selects evaluator {} in state {}",
                    node.node_id, node.evaluator_definition_id, availability.state
                )));
            }
            definitions.insert(node.evaluator_definition_id.clone(), definition);
        }
        let definition = definitions
            .get(&node.evaluator_definition_id)
            .expect("definition inserted");
        if node.classification == NODE_REQUIRED
            && definition.execution_class == STOCHASTIC_EXECUTION_CLASS
            && !definition
                .stochastic_policy
                .as_ref()
                .is_some_and(|policy| policy.gate_eligible)
        {
            return Err(EvaluationCliError::validation(format!(
                "node {:?} requires a stochastic evaluator without explicit gate eligibility",
                node.node_id
            )));
        }
        validate_parameters(&definition.parameter_schema_json, &node.parameters_json).map_err(
            |error| {
                EvaluationCliError::validation(format!(
                    "node {:?} parameters do not match evaluator schema: {error}",
                    node.node_id
                ))
            },
        )?;
        for binding in &node.input_bindings {
            if !definition
                .supported_input_schemas
                .contains(&binding.schema_id)
            {
                return Err(EvaluationCliError::validation(format!(
                    "node {:?} binds unsupported input schema {:?}",
                    node.node_id, binding.schema_id
                )));
            }
        }
        for invariant_id in &node.invariant_version_ids {
            if !invariants.contains_key(invariant_id) {
                let fact = sekai
                    .get_governed_fact_version(GetGovernedFactVersionRequest {
                        object_id: invariant_id.clone(),
                    })
                    .await
                    .map_err(|status| rpc_error("validate governed invariant", status))?
                    .into_inner()
                    .fact
                    .ok_or_else(|| {
                        compatibility_error("governed-fact response omitted invariant")
                    })?;
                invariants.insert(invariant_id.clone(), fact);
            }
            let invariant = invariants.get(invariant_id).expect("invariant inserted");
            if invariant.namespace != plan.namespace
                || invariant.fact_type != "invariant"
                || invariant.status != "active"
            {
                return Err(EvaluationCliError::validation(format!(
                    "node {:?} requires an active invariant in namespace {:?}",
                    node.node_id, plan.namespace
                )));
            }
            let applicability = invariant.applicability.as_ref().ok_or_else(|| {
                EvaluationCliError::validation(format!(
                    "invariant {invariant_id} omits applicability"
                ))
            })?;
            if !applicability.subject_refs.is_empty() {
                return Err(EvaluationCliError::validation(format!(
                    "invariant {invariant_id} is subject-specific and cannot be used by a profile-wide v1 plan"
                )));
            }
            if !plan
                .accepted_subject_profiles
                .iter()
                .all(|profile| applicability.subject_profiles.contains(profile))
            {
                return Err(EvaluationCliError::validation(format!(
                    "invariant {invariant_id} does not cover every accepted subject profile"
                )));
            }
            let verification = invariant.verification.as_ref().ok_or_else(|| {
                EvaluationCliError::validation(format!(
                    "invariant {invariant_id} omits its verification contract"
                ))
            })?;
            if !definition
                .supported_predicate_kinds
                .contains(&verification.predicate_kind)
                || !definition
                    .supported_input_schemas
                    .contains(&verification.input_schema)
                || !definition
                    .supported_result_schemas
                    .contains(&verification.result_schema)
            {
                return Err(EvaluationCliError::validation(format!(
                    "node {:?} evaluator is incompatible with invariant {invariant_id}",
                    node.node_id
                )));
            }
            if !node.input_bindings.iter().any(|binding| {
                binding.source_kind == "invariant" && binding.schema_id == verification.input_schema
            }) {
                return Err(EvaluationCliError::validation(format!(
                    "node {:?} lacks an invariant binding for schema {:?}",
                    node.node_id, verification.input_schema
                )));
            }
        }
    }
    Ok(())
}

fn to_proto_plan(plan: &DomainPlan) -> EvaluationPlan {
    EvaluationPlan {
        contract_version: plan.contract_version.clone(),
        plan_version_id: plan.plan_version_id.clone(),
        namespace: plan.namespace.clone(),
        plan_id: plan.plan_id.clone(),
        version: plan.version.clone(),
        accepted_subject_profiles: plan.accepted_subject_profiles.clone(),
        nodes: plan
            .nodes
            .iter()
            .map(|node| EvaluationPlanNode {
                node_id: node.node_id.clone(),
                evaluator_definition_id: node.evaluator_definition_id.clone(),
                depends_on_node_ids: node.depends_on_node_ids.clone(),
                input_bindings: node
                    .input_bindings
                    .iter()
                    .map(|binding| EvaluationInputBinding {
                        name: binding.name.clone(),
                        source_kind: binding.source_kind.clone(),
                        schema_id: binding.schema_id.clone(),
                    })
                    .collect(),
                parameters_json: node.parameters_json.clone(),
                invariant_version_ids: node.invariant_version_ids.clone(),
                classification: node.classification.clone(),
            })
            .collect(),
        reducer: plan.reducer.clone(),
        source_ref: plan.source_ref.clone(),
        content_digest: plan.content_digest.clone(),
        created_by: plan.created_by.clone(),
        created_at_ms: plan.created_at_ms,
    }
}

fn from_proto_plan(plan: EvaluationPlan) -> DomainPlan {
    DomainPlan {
        contract_version: plan.contract_version,
        plan_version_id: plan.plan_version_id,
        namespace: plan.namespace,
        plan_id: plan.plan_id,
        version: plan.version,
        accepted_subject_profiles: plan.accepted_subject_profiles,
        nodes: plan
            .nodes
            .into_iter()
            .map(|node| DomainPlanNode {
                node_id: node.node_id,
                evaluator_definition_id: node.evaluator_definition_id,
                depends_on_node_ids: node.depends_on_node_ids,
                input_bindings: node
                    .input_bindings
                    .into_iter()
                    .map(|binding| DomainInputBinding {
                        name: binding.name,
                        source_kind: binding.source_kind,
                        schema_id: binding.schema_id,
                    })
                    .collect(),
                parameters_json: node.parameters_json,
                invariant_version_ids: node.invariant_version_ids,
                classification: node.classification,
            })
            .collect(),
        reducer: plan.reducer,
        source_ref: plan.source_ref,
        content_digest: plan.content_digest,
        created_by: plan.created_by,
        created_at_ms: plan.created_at_ms,
    }
}

fn to_proto_resolution(resolution: DomainResolution) -> EvaluationResolutionRequest {
    EvaluationResolutionRequest {
        contract_version: resolution.contract_version,
        resolver_version: resolution.resolver_version,
        namespace: resolution.namespace,
        request_id: resolution.request_id,
        plan_version_id: resolution.plan_version_id,
        subject_profile: resolution.subject_profile,
        subject_identity: resolution.subject_identity,
        subject_content_digest: resolution.subject_content_digest,
        evidence_object_ids: resolution.evidence_object_ids,
        evaluation_time_ms: resolution.evaluation_time_ms,
    }
}

fn print_plan_output(
    command: &str,
    status: &str,
    plan: &DomainPlan,
    validation_mode: Option<&str>,
    as_json: bool,
) -> Result<(), EvaluationCliError> {
    if as_json {
        let mut output = json!({
            "schema_version": OUTPUT_SCHEMA,
            "command": command,
            "status": status,
            "plan": plan_summary(plan),
        });
        if let Some(mode) = validation_mode {
            output["validation_mode"] = json!(mode);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(json_error)?
        );
        return Ok(());
    }
    println!("Evaluation plan {status}.");
    if let Some(mode) = validation_mode {
        println!("Validation: {mode}");
    }
    println!("Plan: {}@{}", plan.plan_id, plan.version);
    println!("Plan version: {}", plan.plan_version_id);
    println!("Content digest: {}", plan.content_digest);
    println!(
        "Subject profiles: {}",
        plan.accepted_subject_profiles.join(", ")
    );
    println!("Reducer: {}", plan.reducer);
    println!("Nodes:");
    for node in &plan.nodes {
        println!(
            "  {} [{}] evaluator={} parameters={}",
            node.node_id,
            node.classification,
            node.evaluator_definition_id,
            parameters_digest(&node.parameters_json)?
        );
        println!("    invariants: {}", node.invariant_version_ids.join(", "));
        if !node.depends_on_node_ids.is_empty() {
            println!("    depends on: {}", node.depends_on_node_ids.join(", "));
        }
    }
    Ok(())
}

fn plan_summary(plan: &DomainPlan) -> Value {
    json!({
        "contract_version": plan.contract_version,
        "plan_version_id": plan.plan_version_id,
        "namespace": plan.namespace,
        "plan_id": plan.plan_id,
        "version": plan.version,
        "content_digest": plan.content_digest,
        "accepted_subject_profiles": plan.accepted_subject_profiles,
        "reducer": plan.reducer,
        "nodes": plan.nodes.iter().map(|node| json!({
            "node_id": node.node_id,
            "classification": node.classification,
            "evaluator_definition_id": node.evaluator_definition_id,
            "depends_on_node_ids": node.depends_on_node_ids,
            "input_bindings": node.input_bindings.iter().map(|binding| json!({
                "name": binding.name,
                "source_kind": binding.source_kind,
                "schema_id": binding.schema_id,
            })).collect::<Vec<_>>(),
            "parameters_digest": parameters_digest(&node.parameters_json)
                .unwrap_or_else(|_| "invalid".into()),
            "invariant_version_ids": node.invariant_version_ids,
        })).collect::<Vec<_>>(),
        "invariant_coverage": plan_coverage(plan),
    })
}

fn plan_coverage(plan: &DomainPlan) -> Vec<Value> {
    let mut coverage: BTreeMap<&str, (Vec<&str>, Vec<&str>)> = BTreeMap::new();
    for node in &plan.nodes {
        for invariant in &node.invariant_version_ids {
            let entry = coverage.entry(invariant).or_default();
            if node.classification == "required" {
                entry.0.push(&node.node_id);
            } else {
                entry.1.push(&node.node_id);
            }
        }
    }
    coverage
        .into_iter()
        .map(
            |(invariant_version_id, (required_node_ids, advisory_node_ids))| {
                json!({
                    "invariant_version_id": invariant_version_id,
                    "required_node_ids": required_node_ids,
                    "advisory_node_ids": advisory_node_ids,
                })
            },
        )
        .collect()
}

fn parameters_digest(parameters_json: &str) -> Result<String, EvaluationCliError> {
    let value: Value = serde_json::from_str(parameters_json).map_err(json_error)?;
    let bytes = crate::shomei::canonical_json(&value).map_err(EvaluationCliError::validation)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn print_resolution_output(
    status: &str,
    manifest: Option<&ResolvedEvaluationManifest>,
    findings: &[crate::grpc::pb::chisei::EvaluationResolutionFinding],
    as_json: bool,
) -> Result<(), EvaluationCliError> {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema_version": OUTPUT_SCHEMA,
                "command": "resolve",
                "status": status,
                "manifest": manifest.map(manifest_summary),
                "findings": findings.iter().map(|finding| json!({
                    "code": finding.code,
                    "severity": finding.severity,
                    "node_id": finding.node_id,
                    "invariant_version_id": finding.invariant_version_id,
                })).collect::<Vec<_>>(),
            }))
            .map_err(json_error)?
        );
        return Ok(());
    }
    println!("Resolution: {status}");
    for finding in findings {
        let scope = match (
            finding.node_id.is_empty(),
            finding.invariant_version_id.is_empty(),
        ) {
            (false, false) => format!(
                " node={} invariant={}",
                finding.node_id, finding.invariant_version_id
            ),
            (false, true) => format!(" node={}", finding.node_id),
            _ => String::new(),
        };
        println!("  {} [{}]{}", finding.code, finding.severity, scope);
    }
    if let Some(manifest) = manifest {
        println!("Manifest: {}", manifest.manifest_id);
        println!("Manifest digest: {}", manifest.manifest_digest);
        println!(
            "Plan: {} ({})",
            manifest.plan_version_id, manifest.plan_digest
        );
        println!("Subject profile: {}", manifest.subject_profile);
        println!("Subject identity: [redacted]");
        println!("Evaluators and invariant coverage:");
        for node in &manifest.nodes {
            let evaluator = node.evaluator.as_ref();
            println!(
                "  {} [{}] evaluator={}",
                node.node_id,
                node.classification,
                evaluator
                    .map(|binding| binding.definition_id.as_str())
                    .unwrap_or("[missing]")
            );
            for invariant in &node.invariants {
                println!(
                    "    {} predicate={} waivers={}",
                    invariant.invariant_version_id,
                    invariant.predicate_kind,
                    if invariant.waiver_version_ids.is_empty() {
                        "none"
                    } else {
                        "applied (identifiers redacted)"
                    }
                );
            }
        }
        println!(
            "Evidence: {}",
            if manifest.evidence.is_empty() {
                "none admitted"
            } else {
                "admitted and fresh at evaluation time (details redacted)"
            }
        );
        println!(
            "Waivers: {}",
            if manifest.waivers.is_empty() {
                "none"
            } else {
                "applied (details redacted)"
            }
        );
    }
    Ok(())
}

fn manifest_summary(manifest: &ResolvedEvaluationManifest) -> Value {
    json!({
        "contract_version": manifest.contract_version,
        "resolver_version": manifest.resolver_version,
        "manifest_id": manifest.manifest_id,
        "manifest_digest": manifest.manifest_digest,
        "namespace": manifest.namespace,
        "plan_version_id": manifest.plan_version_id,
        "plan_digest": manifest.plan_digest,
        "subject_profile": manifest.subject_profile,
        "subject_identity": manifest.subject_identity,
        "subject_content_digest": manifest.subject_content_digest,
        "invariant_set_id": manifest.invariant_set_id,
        "invariant_set_digest": manifest.invariant_set_digest,
        "invariant_profile_digest": manifest.invariant_profile_digest,
        "evaluation_time_ms": manifest.evaluation_time_ms,
        "nodes": manifest.nodes.iter().map(|node| {
            let evaluator = node.evaluator.as_ref();
            json!({
                "node_id": node.node_id,
                "classification": node.classification,
                "depends_on_node_ids": node.depends_on_node_ids,
                "parameters_digest": parameters_digest(&node.parameters_json)
                    .unwrap_or_else(|_| "invalid".into()),
                "evaluator": evaluator.map(|binding| json!({
                    "definition_id": binding.definition_id,
                    "definition_digest": binding.definition_digest,
                    "implementation_digest": binding.implementation_digest,
                })),
                "invariants": node.invariants.iter().map(|invariant| json!({
                    "invariant_version_id": invariant.invariant_version_id,
                    "content_digest": invariant.content_digest,
                    "predicate_kind": invariant.predicate_kind,
                    "input_schema": invariant.input_schema,
                    "result_schema": invariant.result_schema,
                    "evidence_types": invariant.evidence_types,
                    "waiver_version_ids": invariant.waiver_version_ids,
                })).collect::<Vec<_>>(),
                "evidence_object_ids": node.evidence_object_ids,
            })
        }).collect::<Vec<_>>(),
        "requirements": manifest.requirements.iter().map(|requirement| json!({
            "requirement_version_id": requirement.requirement_version_id,
            "content_digest": requirement.content_digest,
            "provenance_evidence_object_ids": requirement.provenance_evidence_object_ids,
        })).collect::<Vec<_>>(),
        "evidence": manifest.evidence.iter().map(|evidence| json!({
            "evidence_object_id": evidence.evidence_object_id,
            "submission_id": evidence.submission_id,
            "content_digest": evidence.content_digest,
            "evidence_type": evidence.evidence_type,
            "schema_id": evidence.schema_id,
            "schema_version": evidence.schema_version,
            "classification": evidence.classification,
            "observed_at_ms": evidence.observed_at_ms,
            "expires_at_ms": evidence.expires_at_ms,
            "fresh_at_evaluation_time": evidence.expires_at_ms == 0
                || evidence.expires_at_ms > manifest.evaluation_time_ms,
            "source_identity_digest": evidence.source_identity_digest,
        })).collect::<Vec<_>>(),
        "waivers": manifest.waivers.iter().map(|waiver| json!({
            "waiver_version_id": waiver.waiver_version_id,
            "content_digest": waiver.content_digest,
            "evidence_object_ids": waiver.evidence_object_ids,
            "invariant_version_ids": waiver.invariant_version_ids,
        })).collect::<Vec<_>>(),
    })
}

fn print_execution_output(
    execution: &EvaluationExecutionProjection,
    as_json: bool,
) -> Result<(), EvaluationCliError> {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema_version": OUTPUT_SCHEMA,
                "command": "execute",
                "status": execution.status,
                "execution": execution_summary(execution),
            }))
            .map_err(json_error)?
        );
        return Ok(());
    }
    println!("Execution: {}", execution.status);
    println!("Operation: {}", execution.operation_id);
    println!("Manifest digest: {}", execution.manifest_digest);
    for step in &execution.steps {
        println!(
            "  {} [{}] {} ({}) receipt={}",
            step.node_id,
            step.classification,
            step.status,
            step.reason_code,
            step.step_receipt_digest
        );
    }
    if let Some(decision) = &execution.decision {
        println!(
            "Gate: {} ({}) digest={}",
            decision.verdict, decision.reason_code, decision.decision_digest
        );
    }
    Ok(())
}

fn execution_summary(execution: &EvaluationExecutionProjection) -> Value {
    json!({
        "manifest_digest": execution.manifest_digest,
        "operation_id": execution.operation_id,
        "namespace": execution.namespace,
        "status": execution.status,
        "steps": execution.steps.iter().map(|step| json!({
            "node_id": step.node_id,
            "classification": step.classification,
            "status": step.status,
            "reason_code": step.reason_code,
            "input_digest": step.input_digest,
            "parameters_digest": step.parameters_digest,
            "evaluator_definition_digest": step.evaluator_definition_digest,
            "implementation_digest": step.implementation_digest,
            "evidence_digests": step.evidence_digests,
            "dependency_result_digests": step.dependency_result_digests,
            "result_digest": step.result_digest,
            "step_receipt_digest": step.step_receipt_digest,
        })).collect::<Vec<_>>(),
        "decision": execution.decision.as_ref().map(|decision| json!({
            "verdict": decision.verdict,
            "reason_code": decision.reason_code,
            "reducer": decision.reducer,
            "decision_digest": decision.decision_digest,
            "step_receipt_digests": decision.step_receipt_digests,
            "invariant_coverage": decision.invariant_coverage.iter().map(|coverage| json!({
                "invariant_version_id": coverage.invariant_version_id,
                "covered_by_node_ids": coverage.covered_by_node_ids,
                "waiver_version_ids": coverage.waiver_version_ids,
                "satisfied": coverage.satisfied,
            })).collect::<Vec<_>>(),
        })),
    })
}

fn rpc_error(operation: &str, status: Status) -> EvaluationCliError {
    let safe_message = match status.code() {
        Code::Unauthenticated | Code::PermissionDenied | Code::NotFound => {
            return EvaluationCliError::new(
                ErrorKind::Authorization,
                format!("{operation}: resource not found or not authorized"),
            );
        }
        Code::InvalidArgument
        | Code::AlreadyExists
        | Code::FailedPrecondition
        | Code::OutOfRange => status.message(),
        Code::Unimplemented => {
            return compatibility_error(format!(
                "{operation}: server does not implement the evaluation-plan API"
            ));
        }
        Code::Unavailable
        | Code::DeadlineExceeded
        | Code::ResourceExhausted
        | Code::Aborted
        | Code::Cancelled
        | Code::Internal
        | Code::DataLoss
        | Code::Unknown => {
            return EvaluationCliError::new(
                ErrorKind::Unavailable,
                format!("{operation}: evaluation service unavailable"),
            );
        }
        _ => "evaluation service rejected the request",
    };
    EvaluationCliError::validation(format!("{operation}: {safe_message}"))
}

fn transport_error(
    operation: &str,
    _error: Box<dyn std::error::Error + Send + Sync>,
) -> EvaluationCliError {
    EvaluationCliError::new(
        ErrorKind::Unavailable,
        format!("{operation}: evaluation service unavailable"),
    )
}

fn compatibility_error(message: impl Into<String>) -> EvaluationCliError {
    EvaluationCliError::new(ErrorKind::Compatibility, message)
}

fn json_error(error: impl fmt::Display) -> EvaluationCliError {
    EvaluationCliError::validation(format!("JSON processing failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::evaluation_plan::{
        EVALUATION_PLAN_CONTRACT, FIXED_REDUCER, NODE_ADVISORY, NODE_REQUIRED,
    };

    fn exact(prefix: &str, byte: char) -> String {
        format!("{prefix}{}", byte.to_string().repeat(64))
    }

    fn plan_document(nodes: Vec<PlanNodeDocument>) -> PlanDocument {
        PlanDocument {
            contract_version: EVALUATION_PLAN_CONTRACT.into(),
            namespace: "acme".into(),
            plan_id: "release".into(),
            version: "1.0.0".into(),
            accepted_subject_profiles: vec!["release/v1".into()],
            nodes,
            reducer: FIXED_REDUCER.into(),
            source_ref: "repo://plans/release@1.0.0".into(),
        }
    }

    fn node(id: &str, depends_on_node_ids: Vec<String>, classification: &str) -> PlanNodeDocument {
        PlanNodeDocument {
            node_id: id.into(),
            evaluator_definition_id: exact("evaluator-definition:", 'a'),
            depends_on_node_ids,
            input_bindings: vec![PlanInputBindingDocument {
                name: "invariant".into(),
                source_kind: "invariant".into(),
                schema_id: "schema://release/v1".into(),
            }],
            parameters: Some(json!({"strict": true})),
            parameters_json: None,
            invariant_version_ids: vec![exact("governed-fact-", 'b')],
            classification: classification.into(),
        }
    }

    #[test]
    fn local_authoring_validation_canonicalizes_and_explains_coverage() {
        let plan = prepare_plan(
            plan_document(vec![node("required", vec![], NODE_REQUIRED)])
                .into_domain()
                .unwrap(),
            "cli",
            1,
        )
        .unwrap();
        validate_exact_plan_references(&plan).unwrap();
        let summary = plan_summary(&plan);
        assert_eq!(
            summary["nodes"][0]["parameters_digest"]
                .as_str()
                .unwrap()
                .len(),
            71
        );
        assert_eq!(
            summary["invariant_coverage"][0]["required_node_ids"],
            json!(["required"])
        );
        assert!(summary.get("source_ref").is_none());
        assert!(summary["nodes"][0].get("parameters").is_none());
    }

    #[test]
    fn local_validation_rejects_cycles_and_unversioned_references() {
        let cycle = plan_document(vec![
            node("a", vec!["b".into()], NODE_REQUIRED),
            node("b", vec!["a".into()], NODE_REQUIRED),
        ])
        .into_domain()
        .unwrap();
        assert!(prepare_plan(cycle, "cli", 1).unwrap_err().contains("cycle"));

        let mut alias = plan_document(vec![node("required", vec![], NODE_REQUIRED)])
            .into_domain()
            .unwrap();
        alias.nodes[0].evaluator_definition_id = "schema-check@latest".into();
        let alias = prepare_plan(alias, "cli", 1).unwrap();
        assert!(
            validate_exact_plan_references(&alias)
                .unwrap_err()
                .to_string()
                .contains("aliases are not supported")
        );
    }

    #[test]
    fn advisory_only_coverage_fails_closed() {
        let plan = plan_document(vec![node("advisory", vec![], NODE_ADVISORY)])
            .into_domain()
            .unwrap();
        assert!(
            prepare_plan(plan, "cli", 1)
                .unwrap_err()
                .contains("required node")
        );
    }

    #[test]
    fn parser_separates_confirmation_and_rejects_unknown_options() {
        let parsed = ParsedArgs::parse(&[
            "acme".into(),
            exact("sha256:", 'a'),
            "--yes".into(),
            "--json".into(),
        ])
        .unwrap();
        parsed
            .validate_options(&["--target", "--max-duration-ms"], &["--json", "--yes"])
            .unwrap();
        assert!(parsed.switches.contains("--yes"));
        assert!(ParsedArgs::parse(&["--execute".into()]).is_err());
    }

    #[test]
    fn exit_codes_are_stable_and_server_skew_is_bounded() {
        assert_eq!(
            EvaluationCliError::validation("bad").exit_code(),
            EXIT_VALIDATION
        );
        assert_eq!(
            rpc_error("read", Status::permission_denied("secret")).exit_code(),
            EXIT_AUTHORIZATION
        );
        let skew = rpc_error("read", Status::unimplemented("old server"));
        assert_eq!(skew.exit_code(), EXIT_COMPATIBILITY);
        assert!(!skew.to_string().contains("old server"));
        assert_eq!(
            rpc_error("read", Status::internal("database detail")).exit_code(),
            EXIT_UNAVAILABLE
        );
    }

    #[test]
    fn human_manifest_output_policy_redacts_sensitive_fields() {
        let source = include_str!("evaluation_plan_cli.rs");
        let human_section = source
            .split("fn print_resolution_output")
            .nth(1)
            .unwrap()
            .split("fn manifest_summary")
            .next()
            .unwrap();
        assert!(human_section.contains("Subject identity: [redacted]"));
        assert!(human_section.contains("details redacted"));
        assert!(!human_section.contains("parameters_json"));
        assert!(!human_section.contains("evidence_object_id"));
        assert!(!human_section.contains("source_ref"));
    }

    #[test]
    fn plan_document_rejects_ambiguous_parameter_forms() {
        let mut document = plan_document(vec![node("required", vec![], NODE_REQUIRED)]);
        document.nodes[0].parameters_json = Some(r#"{"strict":true}"#.into());
        assert!(
            document
                .into_domain()
                .unwrap_err()
                .to_string()
                .contains("only one")
        );
    }
}
