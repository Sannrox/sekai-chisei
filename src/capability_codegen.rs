//! Namespace-scoped capability client codegen (#299).
//!
//! Generates a typed TypeScript client from a **selected** subset of projected
//! capabilities, pins the catalog version, and emits a scope manifest that
//! credentials must not exceed. Runtime authorization still re-checks live
//! catalog visibility; codegen never treats discovery as a grant.

use crate::capability_projection::{ProjectedCapability, ProjectionContext};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodegenSelection {
    pub context: ProjectionContext,
    /// Capability names to include. Empty means reject (must select explicitly).
    pub capability_names: BTreeSet<String>,
    /// Optional pin; when set must equal context.catalog_version.
    pub catalog_version_pin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityScopeManifest {
    pub namespace: String,
    pub principal: String,
    pub catalog_version: String,
    pub allowed_capabilities: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedClient {
    pub typescript: String,
    pub scope: CapabilityScopeManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodegenError {
    EmptySelection,
    CatalogPinMismatch { expected: String, actual: String },
    MissingCapability(String),
    InvalidContext(&'static str),
}

impl std::fmt::Display for CodegenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySelection => write!(f, "capability selection is empty"),
            Self::CatalogPinMismatch { expected, actual } => write!(
                f,
                "catalog version pin mismatch: expected {expected}, got {actual}"
            ),
            Self::MissingCapability(name) => {
                write!(f, "selected capability not in catalog: {name}")
            }
            Self::InvalidContext(field) => write!(f, "codegen context requires {field}"),
        }
    }
}

impl std::error::Error for CodegenError {}

/// Validate that a scoped credential selection cannot exceed the generated
/// allow-list. Runtime still re-checks live catalog; this is a client-side
/// fail-closed guard for non-selected names.
pub fn scope_allows(scope: &CapabilityScopeManifest, capability: &str) -> bool {
    scope.allowed_capabilities.contains(capability)
}

/// Generate a TypeScript client from projected capabilities and an explicit
/// selection. Fails closed on empty selection, pin mismatch, or missing names.
pub fn generate_typescript_client(
    catalog: &[ProjectedCapability],
    selection: &CodegenSelection,
) -> Result<GeneratedClient, CodegenError> {
    for (field, value) in [
        ("namespace", selection.context.namespace.as_str()),
        ("principal", selection.context.principal.as_str()),
        (
            "catalog_version",
            selection.context.catalog_version.as_str(),
        ),
    ] {
        if value.trim().is_empty()
            || value
                .chars()
                .any(|ch| ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}'))
        {
            return Err(CodegenError::InvalidContext(field));
        }
    }
    if selection.capability_names.is_empty() {
        return Err(CodegenError::EmptySelection);
    }
    if let Some(pin) = &selection.catalog_version_pin
        && pin != &selection.context.catalog_version
    {
        return Err(CodegenError::CatalogPinMismatch {
            expected: pin.clone(),
            actual: selection.context.catalog_version.clone(),
        });
    }

    let by_name: BTreeMap<&str, &ProjectedCapability> = catalog
        .iter()
        .map(|capability| (capability.name.as_str(), capability))
        .collect();
    let mut selected = Vec::new();
    let mut method_names = BTreeSet::new();
    for name in &selection.capability_names {
        let capability = by_name
            .get(name.as_str())
            .copied()
            .ok_or_else(|| CodegenError::MissingCapability(name.clone()))?;
        // Reject capabilities from a different authorization context or with
        // contract/projection drift (same boundary as ProjectedCapability::invocation).
        if capability.projection_version != crate::capability_projection::PROJECTION_VERSION
            || capability.context.catalog_version != selection.context.catalog_version
            || capability.context.namespace != selection.context.namespace
            || capability.context.principal != selection.context.principal
            || capability.context.contract_version != selection.context.contract_version
            || capability.contract_version != selection.context.contract_version
            || capability.minimum_compatible_version != selection.context.contract_version
            || capability.maximum_compatible_version != selection.context.contract_version
        {
            return Err(CodegenError::CatalogPinMismatch {
                expected: selection.context.catalog_version.clone(),
                actual: capability.context.catalog_version.clone(),
            });
        }
        let method = sanitize_method_name(&capability.name);
        if !method_names.insert(method) {
            return Err(CodegenError::MissingCapability(format!(
                "method name collision for {name}"
            )));
        }
        selected.push(capability);
    }
    selected.sort_by(|a, b| a.name.cmp(&b.name));

    let scope = CapabilityScopeManifest {
        namespace: selection.context.namespace.clone(),
        principal: selection.context.principal.clone(),
        catalog_version: selection.context.catalog_version.clone(),
        allowed_capabilities: selection.capability_names.clone(),
    };

    let typescript = render_typescript(&selected, &scope);
    Ok(GeneratedClient { typescript, scope })
}

fn render_typescript(selected: &[&ProjectedCapability], scope: &CapabilityScopeManifest) -> String {
    let mut methods = String::new();
    for capability in selected {
        let method = sanitize_method_name(&capability.name);
        methods.push_str(&format!(
            r#"
  // {description}
  {method}(operationId: string, input: Record<string, unknown>): SdkInvocation {{
    return invoke(CAPABILITIES[{name}]!, operationId, input);
  }}
"#,
            description = escape_ts_comment(&capability.description),
            method = method,
            name = js_string(&capability.name),
        ));
    }

    let capability_literals: String = selected
        .iter()
        .map(|capability| {
            format!(
                "  {name}: {{\n    name: {name},\n    input_type: {input},\n    output_type: {output},\n    kind: {kind},\n  }},\n",
                name = js_string(&capability.name),
                input = js_string(&capability.input_type),
                output = js_string(&capability.output_type),
                kind = js_string(&capability.kind),
            )
        })
        .collect();

    let allowed_js = selected
        .iter()
        .map(|capability| js_string(&capability.name))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"// Generated by sekai-chisei capability codegen. DO NOT EDIT.
// catalog_version={catalog_version}
// namespace={namespace}
// principal={principal}

export const GENERATED_CATALOG_VERSION = {catalog_version};
export const GENERATED_NAMESPACE = {namespace};
export const GENERATED_PRINCIPAL = {principal};
export const ALLOWED_CAPABILITIES = [{allowed}] as const;

export interface SdkInvocation {{
  catalog_version: string;
  namespace: string;
  principal: string;
  capability: string;
  operation_id: string;
  input_type: string;
  output_type: string;
  input: Record<string, unknown>;
}}

const CAPABILITIES = {{
{capability_literals}}} as const;

function invoke(
  capability: {{ name: string; input_type: string; output_type: string }},
  operationId: string,
  input: Record<string, unknown>,
): SdkInvocation {{
  if (!(ALLOWED_CAPABILITIES as readonly string[]).includes(capability.name)) {{
    throw new Error(`capability not in generated scope: ${{capability.name}}`);
  }}
  if (!operationId.trim()) throw new Error("operation_id required");
  return {{
    catalog_version: GENERATED_CATALOG_VERSION,
    namespace: GENERATED_NAMESPACE,
    principal: GENERATED_PRINCIPAL,
    capability: capability.name,
    operation_id: operationId,
    input_type: capability.input_type,
    output_type: capability.output_type,
    input,
  }};
}}

export function nativeMetadata(call: SdkInvocation): Record<string, string> {{
  if (!(ALLOWED_CAPABILITIES as readonly string[]).includes(call.capability)) {{
    throw new Error(`capability not in generated scope: ${{call.capability}}`);
  }}
  if (call.namespace !== GENERATED_NAMESPACE || call.principal !== GENERATED_PRINCIPAL
      || call.catalog_version !== GENERATED_CATALOG_VERSION) {{
    throw new Error("invocation context does not match generated scope");
  }}
  if (!call.operation_id.trim()) throw new Error("operation_id required");
  return {{
    "x-principal": call.principal,
    "x-sekai-namespace": call.namespace,
    "x-sekai-capability": call.capability,
    "x-sekai-operation-id": call.operation_id,
    "x-chisei-work-unit": call.operation_id,
    "x-sekai-catalog-version": call.catalog_version,
  }};
}}

export function scopeAllows(capability: string): boolean {{
  return (ALLOWED_CAPABILITIES as readonly string[]).includes(capability);
}}

export class ScopedCapabilityClient {{
{methods}}}
"#,
        catalog_version = js_string(&scope.catalog_version),
        namespace = js_string(&scope.namespace),
        principal = js_string(&scope.principal),
        allowed = allowed_js,
        capability_literals = capability_literals,
        methods = methods,
    )
}

fn js_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into())
}

fn sanitize_method_name(name: &str) -> String {
    let mut out = String::new();
    let mut capitalize = false;
    for (index, ch) in name.chars().enumerate() {
        if ch.is_ascii_alphanumeric() {
            if capitalize {
                out.extend(ch.to_uppercase());
                capitalize = false;
            } else if index == 0 {
                out.extend(ch.to_lowercase());
            } else {
                out.push(ch);
            }
        } else {
            capitalize = true;
        }
    }
    if out.is_empty() {
        return "capability".into();
    }
    if out.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        out = format!("c{out}");
    }
    // Avoid TypeScript reserved class member names.
    if matches!(out.as_str(), "constructor" | "prototype") {
        out = format!("capability{out}");
    }
    out
}

fn escape_ts_comment(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            // Include ECMAScript line terminators U+2028/U+2029 (not Rust controls).
            '\n' | '\r' | '\u{2028}' | '\u{2029}' => ' ',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect::<String>()
        .replace("*/", "* /")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_projection::{
        PROJECTION_VERSION, ProjectedCapability, ProjectionContext,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn fixture_capability(name: &str) -> ProjectedCapability {
        ProjectedCapability {
            projection_version: PROJECTION_VERSION.into(),
            context: ProjectionContext {
                namespace: "demo".into(),
                principal: "alice".into(),
                contract_version: "1.0".into(),
                catalog_version: "sha256:fixture-catalog".into(),
            },
            name: name.into(),
            description: format!("Invoke {name}"),
            kind: "action".into(),
            lifecycle_state: "active".into(),
            contract_version: "1.0".into(),
            minimum_compatible_version: "1.0".into(),
            maximum_compatible_version: "1.0".into(),
            replacement_capability: String::new(),
            input_type: "sekai.ExecuteActionRequest".into(),
            output_type: "sekai.ExecuteActionResponse".into(),
            required_scopes: vec!["namespace:write".into()],
            policy_decision_points: vec!["action_policy".into()],
            risk_class: "write".into(),
            approval_behavior: "none".into(),
            limits: BTreeMap::new(),
            evidence_requirements: Vec::new(),
            object_schema: None,
            action_schema: None,
        }
    }

    #[test]
    fn generates_stable_typescript_for_selection() {
        let catalog = vec![
            fixture_capability("sekai.action.assign_color"),
            fixture_capability("sekai.action.hidden"),
        ];
        let selection = CodegenSelection {
            context: catalog[0].context.clone(),
            capability_names: BTreeSet::from(["sekai.action.assign_color".into()]),
            catalog_version_pin: Some("sha256:fixture-catalog".into()),
        };
        let generated = generate_typescript_client(&catalog, &selection).unwrap();
        assert!(scope_allows(&generated.scope, "sekai.action.assign_color"));
        assert!(!scope_allows(&generated.scope, "sekai.action.hidden"));
        assert!(generated.typescript.contains("sekaiActionAssignColor"));
        assert!(generated.typescript.contains("ALLOWED_CAPABILITIES"));
        assert!(!generated.typescript.contains("sekai.action.hidden"));

        let golden = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/capability_codegen/scoped_client.v1.ts");
        let expected = std::fs::read_to_string(&golden).expect("golden typescript fixture");
        assert_eq!(
            generated.typescript, expected,
            "generated client drifted from golden fixture"
        );
    }

    #[test]
    fn pin_mismatch_fails_closed() {
        let catalog = vec![fixture_capability("sekai.action.assign_color")];
        let selection = CodegenSelection {
            context: catalog[0].context.clone(),
            capability_names: BTreeSet::from(["sekai.action.assign_color".into()]),
            catalog_version_pin: Some("sha256:other".into()),
        };
        let err = generate_typescript_client(&catalog, &selection).unwrap_err();
        assert!(matches!(err, CodegenError::CatalogPinMismatch { .. }));
    }

    #[test]
    fn empty_selection_fails_closed() {
        let catalog = vec![fixture_capability("sekai.action.assign_color")];
        let selection = CodegenSelection {
            context: catalog[0].context.clone(),
            capability_names: BTreeSet::new(),
            catalog_version_pin: None,
        };
        assert!(matches!(
            generate_typescript_client(&catalog, &selection),
            Err(CodegenError::EmptySelection)
        ));
    }

    #[test]
    fn projection_contract_drift_fails_closed() {
        let mut capability = fixture_capability("sekai.action.assign_color");
        capability.projection_version = "sekai.capability-projection/v0".into();
        let selection = CodegenSelection {
            context: capability.context.clone(),
            capability_names: BTreeSet::from(["sekai.action.assign_color".into()]),
            catalog_version_pin: None,
        };
        assert!(matches!(
            generate_typescript_client(&[capability], &selection),
            Err(CodegenError::CatalogPinMismatch { .. })
        ));
    }
}
