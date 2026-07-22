//! Replaceable MCP and SDK projections of the native capability contract.
//!
//! This module deliberately stops at transport adaptation. Discovery remains
//! authorization-filtered by `SekaiService::DiscoverCapabilities`, and every
//! invocation is rebound to the existing native RPC with the same identity,
//! namespace, capability, and operation correlation metadata.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tonic::{Code, Request, Status, metadata::MetadataValue};

use crate::grpc::pb::sekai::{
    ActionParamDef, ActionTypeDef, CapabilityEntry, ObjectType, PropertyDef, StructFieldDef,
};

pub const PROJECTION_VERSION: &str = "sekai.capability-projection/v1";
const JSON_SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionContext {
    pub namespace: String,
    pub principal: String,
    pub contract_version: String,
    pub catalog_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectedCapability {
    pub projection_version: String,
    pub context: ProjectionContext,
    pub name: String,
    pub description: String,
    pub kind: String,
    pub lifecycle_state: String,
    pub contract_version: String,
    pub minimum_compatible_version: String,
    pub maximum_compatible_version: String,
    pub replacement_capability: String,
    pub input_type: String,
    pub output_type: String,
    pub required_scopes: Vec<String>,
    pub policy_decision_points: Vec<String>,
    pub risk_class: String,
    pub approval_behavior: String,
    pub limits: BTreeMap<String, u64>,
    pub evidence_requirements: Vec<String>,
    pub object_schema: Option<Value>,
    pub action_schema: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub title: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(rename = "outputSchema")]
    pub output_schema: Value,
    pub annotations: McpAnnotations,
    #[serde(rename = "_meta")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAnnotations {
    pub read_only_hint: bool,
    pub destructive_hint: bool,
    pub idempotent_hint: bool,
    pub open_world_hint: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SdkInvocation {
    pub projection_version: String,
    pub contract_version: String,
    pub catalog_version: String,
    pub namespace: String,
    pub principal: String,
    pub capability: String,
    pub operation_id: String,
    pub input_type: String,
    pub output_type: String,
    pub input: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectedError {
    pub code: String,
    pub message: String,
    pub capability: String,
    pub operation_id: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    InvalidContext(&'static str),
    ContractDrift,
    CapabilityUnavailable,
    InvalidInvocation(&'static str),
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidContext(field) => write!(formatter, "projection context requires {field}"),
            Self::ContractDrift => write!(formatter, "capability contract version drift"),
            Self::CapabilityUnavailable => write!(formatter, "capability unavailable"),
            Self::InvalidInvocation(field) => write!(formatter, "invocation requires {field}"),
        }
    }
}

impl std::error::Error for ProjectionError {}

impl ProjectedCapability {
    pub fn new(
        entry: &CapabilityEntry,
        context: ProjectionContext,
    ) -> Result<Self, ProjectionError> {
        for (field, value) in [
            ("namespace", context.namespace.as_str()),
            ("principal", context.principal.as_str()),
            ("contract_version", context.contract_version.as_str()),
            ("catalog_version", context.catalog_version.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ProjectionError::InvalidContext(field));
            }
        }
        if entry.contract_version != context.contract_version
            || entry.minimum_compatible_version != context.contract_version
            || entry.maximum_compatible_version != context.contract_version
        {
            return Err(ProjectionError::ContractDrift);
        }
        Ok(Self {
            projection_version: PROJECTION_VERSION.into(),
            context,
            name: entry.name.clone(),
            description: entry.description.clone(),
            kind: entry.kind.clone(),
            lifecycle_state: entry.lifecycle_state.clone(),
            contract_version: entry.contract_version.clone(),
            minimum_compatible_version: entry.minimum_compatible_version.clone(),
            maximum_compatible_version: entry.maximum_compatible_version.clone(),
            replacement_capability: entry.replacement_capability.clone(),
            input_type: entry.input_type.clone(),
            output_type: entry.output_type.clone(),
            required_scopes: entry.required_scopes.clone(),
            policy_decision_points: entry.policy_decision_points.clone(),
            risk_class: entry.risk_class.clone(),
            approval_behavior: entry.approval_behavior.clone(),
            limits: entry
                .limits
                .iter()
                .map(|limit| (limit.name.clone(), limit.value))
                .collect(),
            evidence_requirements: entry.evidence_requirements.clone(),
            object_schema: entry.object_type.as_ref().map(object_schema),
            action_schema: entry.action_type.as_ref().map(action_schema),
        })
    }

    pub fn mcp_tool(&self) -> McpTool {
        let read_only = self.kind != "action";
        McpTool {
            name: self.name.clone(),
            title: self.name.clone(),
            description: self.description.clone(),
            input_schema: json!({
                "$schema": JSON_SCHEMA_DIALECT,
                "type": "object",
                "properties": {
                    "operation_id": {"type": "string", "minLength": 1},
                    "input": invocation_input_schema(self),
                },
                "required": ["operation_id", "input"],
                "additionalProperties": false,
            }),
            output_schema: json!({
                "$schema": JSON_SCHEMA_DIALECT,
                "type": "object",
                "properties": {
                    "operation_id": {"type": "string"},
                    "output_type": {"const": self.output_type},
                    "output": {"type": "object"},
                },
                "required": ["operation_id", "output_type", "output"],
                "additionalProperties": false,
            }),
            annotations: McpAnnotations {
                read_only_hint: read_only,
                destructive_hint: !read_only && self.risk_class == "destructive",
                idempotent_hint: false,
                open_world_hint: false,
            },
            metadata: serde_json::to_value(self).expect("projected capability is serializable"),
        }
    }

    pub fn invocation(
        &self,
        operation_id: &str,
        input: Value,
    ) -> Result<SdkInvocation, ProjectionError> {
        if self.projection_version != PROJECTION_VERSION
            || self.contract_version != self.context.contract_version
            || self.minimum_compatible_version != self.context.contract_version
            || self.maximum_compatible_version != self.context.contract_version
        {
            return Err(ProjectionError::ContractDrift);
        }
        if operation_id.trim().is_empty() {
            return Err(ProjectionError::InvalidInvocation("operation_id"));
        }
        if !input.is_object() {
            return Err(ProjectionError::InvalidInvocation("object input"));
        }
        Ok(SdkInvocation {
            projection_version: PROJECTION_VERSION.into(),
            contract_version: self.contract_version.clone(),
            catalog_version: self.context.catalog_version.clone(),
            namespace: self.context.namespace.clone(),
            principal: self.context.principal.clone(),
            capability: self.name.clone(),
            operation_id: operation_id.into(),
            input_type: self.input_type.clone(),
            output_type: self.output_type.clone(),
            input,
        })
    }
}

impl SdkInvocation {
    /// Bind a decoded native protobuf request without changing its authority.
    pub fn bind<T>(&self, message: T) -> Result<Request<T>, ProjectionError> {
        for (field, value) in [
            ("principal", self.principal.as_str()),
            ("namespace", self.namespace.as_str()),
            ("capability", self.capability.as_str()),
            ("operation_id", self.operation_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ProjectionError::InvalidInvocation(field));
            }
        }
        let mut request = Request::new(message);
        insert_metadata(&mut request, "x-principal", &self.principal)?;
        insert_metadata(&mut request, "x-sekai-namespace", &self.namespace)?;
        insert_metadata(&mut request, "x-sekai-capability", &self.capability)?;
        insert_metadata(&mut request, "x-sekai-operation-id", &self.operation_id)?;
        insert_metadata(&mut request, "x-chisei-work-unit", &self.operation_id)?;
        insert_metadata(
            &mut request,
            "x-sekai-catalog-version",
            &self.catalog_version,
        )?;
        Ok(request)
    }

    pub fn normalize_error(&self, status: &Status) -> ProjectedError {
        ProjectedError {
            code: grpc_code_name(status.code()).into(),
            message: status.message().into(),
            capability: self.capability.clone(),
            operation_id: self.operation_id.clone(),
            retryable: matches!(
                status.code(),
                Code::Aborted | Code::Unavailable | Code::DeadlineExceeded
            ),
        }
    }
}

fn insert_metadata<T>(
    request: &mut Request<T>,
    key: &'static str,
    value: &str,
) -> Result<(), ProjectionError> {
    let value = MetadataValue::try_from(value)
        .map_err(|_| ProjectionError::InvalidInvocation("ASCII metadata"))?;
    request.metadata_mut().insert(key, value);
    Ok(())
}

fn grpc_code_name(code: Code) -> &'static str {
    match code {
        Code::Ok => "ok",
        Code::Cancelled => "cancelled",
        Code::Unknown => "unknown",
        Code::InvalidArgument => "invalid_argument",
        Code::DeadlineExceeded => "deadline_exceeded",
        Code::NotFound => "not_found",
        Code::AlreadyExists => "already_exists",
        Code::PermissionDenied => "permission_denied",
        Code::ResourceExhausted => "resource_exhausted",
        Code::FailedPrecondition => "failed_precondition",
        Code::Aborted => "aborted",
        Code::OutOfRange => "out_of_range",
        Code::Unimplemented => "unimplemented",
        Code::Internal => "internal",
        Code::Unavailable => "unavailable",
        Code::DataLoss => "data_loss",
        Code::Unauthenticated => "unauthenticated",
    }
}

fn invocation_input_schema(capability: &ProjectedCapability) -> Value {
    capability.action_schema.clone().unwrap_or_else(|| {
        json!({
            "type": "object",
            "description": format!("Canonical protobuf JSON for {}", capability.input_type),
        })
    })
}

fn action_schema(action: &ActionTypeDef) -> Value {
    let properties = action
        .params
        .iter()
        .map(|parameter| (parameter.name.clone(), action_parameter_schema(parameter)))
        .collect::<serde_json::Map<_, _>>();
    let required = action
        .params
        .iter()
        .filter(|parameter| parameter.required)
        .map(|parameter| Value::String(parameter.name.clone()))
        .collect::<Vec<_>>();
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
        "x-sekai-action": action.name,
        "x-sekai-target-kind": action.target_kind,
    })
}

fn action_parameter_schema(parameter: &ActionParamDef) -> Value {
    let mut schema = scalar_schema(&parameter.r#type, &parameter.enum_values);
    if let Some(object) = schema.as_object_mut() {
        object.insert("x-sekai-required".into(), Value::Bool(parameter.required));
    }
    schema
}

fn object_schema(object_type: &ObjectType) -> Value {
    json!({
        "kind": object_type.kind,
        "description": object_type.description,
        "is_builtin": object_type.is_builtin,
        "implements": object_type.implements,
        "properties": object_type.properties.iter().map(property_schema).collect::<Vec<_>>(),
    })
}

fn property_schema(property: &PropertyDef) -> Value {
    json!({
        "name": property.name,
        "type": property.r#type,
        "required": property.required,
        "description": property.description,
        "enum_values": property.enum_values,
        "link_kind": property.link_kind,
        "compute_expr": property.compute_expr,
        "classification": property.classification,
        "struct_fields": property.struct_fields.iter().map(struct_field_schema).collect::<Vec<_>>(),
    })
}

fn struct_field_schema(field: &StructFieldDef) -> Value {
    json!({
        "name": field.name,
        "type": field.r#type,
        "required": field.required,
        "description": field.description,
        "enum_values": field.enum_values,
    })
}

fn scalar_schema(kind: &str, enum_values: &[String]) -> Value {
    let json_type = match kind {
        "int" | "integer" => "integer",
        "float" | "double" | "number" => "number",
        "bool" | "boolean" => "boolean",
        "json" | "struct" => "object",
        "list" | "array" => "array",
        _ => "string",
    };
    let mut schema = json!({"type": json_type});
    if !enum_values.is_empty() {
        schema["enum"] = json!(enum_values);
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::pb::sekai::CapabilityLimit;

    #[derive(Deserialize)]
    struct Fixture {
        expected_metadata: BTreeMap<String, String>,
        expected_error: ProjectedError,
    }

    fn entry() -> CapabilityEntry {
        CapabilityEntry {
            name: "sekai.actions.write".into(),
            description: "Write a governed value.".into(),
            kind: "action".into(),
            lifecycle_state: "active".into(),
            contract_version: "1.0".into(),
            minimum_compatible_version: "1.0".into(),
            maximum_compatible_version: "1.0".into(),
            replacement_capability: String::new(),
            input_type: "sekai.ExecuteActionRequest".into(),
            output_type: "sekai.ExecuteActionResponse".into(),
            required_scopes: vec!["namespace:write".into()],
            policy_decision_points: vec!["namespace_access".into(), "action_policy".into()],
            risk_class: "write".into(),
            approval_behavior: "may_require".into(),
            limits: vec![CapabilityLimit {
                name: "max_mutations_per_invocation".into(),
                value: 1,
            }],
            object_type: None,
            action_type: Some(ActionTypeDef {
                name: "write".into(),
                description: "Write a value.".into(),
                params: vec![ActionParamDef {
                    name: "value".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![],
                target_kind: "record".into(),
                created: 0,
            }),
            evidence_requirements: vec!["audit_receipt".into()],
        }
    }

    fn projection() -> ProjectedCapability {
        ProjectedCapability::new(
            &entry(),
            ProjectionContext {
                namespace: "team-a".into(),
                principal: "agent-a".into(),
                contract_version: "1.0".into(),
                catalog_version: "sha256:catalog".into(),
            },
        )
        .unwrap()
    }

    #[test]
    fn mcp_and_sdk_preserve_the_canonical_contract() {
        let projection = projection();
        let tool = projection.mcp_tool();
        let metadata: ProjectedCapability = serde_json::from_value(tool.metadata).unwrap();
        assert_eq!(metadata, projection);
        assert_eq!(tool.name, projection.name);
        assert_eq!(tool.input_schema["additionalProperties"], false);
        assert_eq!(
            tool.input_schema["properties"]["input"]["required"],
            json!(["value"])
        );

        let sdk = projection
            .invocation("operation-1", json!({"value": "safe"}))
            .unwrap();
        assert_eq!(sdk.capability, tool.name);
        assert_eq!(sdk.contract_version, metadata.contract_version);
        assert_eq!(sdk.catalog_version, metadata.context.catalog_version);
        assert_eq!(sdk.operation_id, "operation-1");
    }

    #[test]
    fn every_projection_binds_the_same_identity_authority_and_correlation() {
        let sdk = projection()
            .invocation("operation-1", json!({"value": "safe"}))
            .unwrap();
        let request = sdk.bind("native request").unwrap();
        assert_eq!(request.metadata().get("x-principal").unwrap(), "agent-a");
        assert_eq!(
            request.metadata().get("x-sekai-namespace").unwrap(),
            "team-a"
        );
        assert_eq!(
            request.metadata().get("x-sekai-capability").unwrap(),
            "sekai.actions.write"
        );
        assert_eq!(
            request.metadata().get("x-sekai-operation-id").unwrap(),
            "operation-1"
        );
    }

    #[test]
    fn version_drift_and_missing_correlation_fail_closed() {
        let mut drifted = entry();
        drifted.maximum_compatible_version = "2.0".into();
        assert_eq!(
            ProjectedCapability::new(&drifted, projection().context),
            Err(ProjectionError::ContractDrift)
        );
        assert_eq!(
            projection().invocation("", json!({})),
            Err(ProjectionError::InvalidInvocation("operation_id"))
        );

        let mut cached = projection();
        cached.projection_version = "sekai.capability-projection/v2".into();
        assert_eq!(
            cached.invocation("operation-1", json!({})),
            Err(ProjectionError::ContractDrift)
        );

        let mut cached = projection();
        cached.maximum_compatible_version = "2.0".into();
        assert_eq!(
            cached.invocation("operation-1", json!({})),
            Err(ProjectionError::ContractDrift)
        );
    }

    #[test]
    fn errors_keep_native_semantics_and_correlation() {
        let sdk = projection()
            .invocation("operation-1", json!({"value": "safe"}))
            .unwrap();
        let denied = sdk.normalize_error(&Status::permission_denied("write denied"));
        assert_eq!(denied.code, "permission_denied");
        assert_eq!(denied.capability, "sekai.actions.write");
        assert_eq!(denied.operation_id, "operation-1");
        assert!(!denied.retryable);
    }

    #[test]
    fn rust_matches_the_shared_cross_sdk_fixture() {
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../tests/fixtures/capability_projection/v1.json"
        ))
        .unwrap();
        let sdk = projection()
            .invocation("operation-1", json!({"value": "safe"}))
            .unwrap();
        let request = sdk.bind(()).unwrap();
        let actual: BTreeMap<String, String> = [
            "x-principal",
            "x-sekai-namespace",
            "x-sekai-capability",
            "x-sekai-operation-id",
            "x-chisei-work-unit",
            "x-sekai-catalog-version",
        ]
        .into_iter()
        .map(|key| {
            (
                key.to_string(),
                request
                    .metadata()
                    .get(key)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect();
        assert_eq!(actual, fixture.expected_metadata);
        assert_eq!(
            sdk.normalize_error(&Status::permission_denied("write denied")),
            fixture.expected_error
        );
    }
}
