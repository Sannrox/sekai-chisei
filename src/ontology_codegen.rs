//! Revision-pinned TypeScript ontology client codegen (#694).
//!
//! Generates a typed TypeScript package from a **selected** subset of one
//! published definition revision. The package embeds the revision digest and
//! selected member identities. It never embeds credentials. Live gRPC
//! invocation reauthorizes; discovery and generation are not grants.

use crate::sekai::definition_branch::{DefinitionMember, DefinitionRevision};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const GENERATOR_CONTRACT_VERSION: &str = "sekai.ontology-client/v1";

const SELECTABLE_MEMBER_KINDS: &[&str] = &["action_type", "function", "link_type", "object_type"];

const RESERVED_TS_NAMES: &[&str] = &[
    "ALLOWED_MEMBERS",
    "GENERATED_CONTRACT_VERSION",
    "GENERATED_NAMESPACE",
    "GENERATED_REVISION_DIGEST",
    "OntologyInvocation",
    "OntologyType",
    "ScopedOntologyClient",
    "bindLiveRevision",
    "invoke",
    "nativeMetadata",
    "scopeAllows",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OntologyClientMemberRef {
    pub member_kind: String,
    pub member_id: String,
}

impl OntologyClientMemberRef {
    pub fn new(member_kind: impl Into<String>, member_id: impl Into<String>) -> Self {
        Self {
            member_kind: member_kind.into(),
            member_id: member_id.into(),
        }
    }

    fn key(&self) -> (&str, &str) {
        (&self.member_kind, &self.member_id)
    }

    fn scope_token(&self) -> String {
        format!("{}:{}", self.member_kind, self.member_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OntologyClientSelection {
    pub namespace: String,
    pub revision_digest_pin: String,
    pub members: BTreeSet<OntologyClientMemberRef>,
    /// Optional envelope. The selection must be a subset; failures do not name
    /// the envelope or the unpublished catalog.
    pub max_scope: Option<BTreeSet<OntologyClientMemberRef>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OntologyClientScope {
    pub contract_version: String,
    pub namespace: String,
    pub revision_digest: String,
    pub selected_members: BTreeSet<OntologyClientMemberRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedOntologyClient {
    pub typescript: String,
    pub scope: OntologyClientScope,
    pub package_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OntologyCodegenError {
    EmptySelection,
    UnpublishedRevision,
    RevisionPinMismatch,
    NamespaceMismatch,
    UnknownMember,
    UnsupportedMemberKind,
    UnsupportedProtocol,
    InvalidDefinition,
    ExcessiveScope,
    TamperedPackage,
    InvalidContext(&'static str),
}

impl std::fmt::Display for OntologyCodegenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySelection => write!(f, "ontology client selection is empty"),
            Self::UnpublishedRevision => write!(f, "ontology client requires a published revision"),
            Self::RevisionPinMismatch => write!(f, "ontology client revision pin is stale"),
            Self::NamespaceMismatch => {
                write!(f, "ontology client namespace does not match the revision")
            }
            Self::UnknownMember => write!(f, "selected member is unavailable"),
            Self::UnsupportedMemberKind => write!(f, "selected member kind is unsupported"),
            Self::UnsupportedProtocol => write!(f, "ontology client protocol is unsupported"),
            Self::InvalidDefinition => write!(f, "selected member definition is invalid"),
            Self::ExcessiveScope => {
                write!(f, "ontology client selection exceeds the allowed scope")
            }
            Self::TamperedPackage => write!(f, "ontology client package identity is invalid"),
            Self::InvalidContext(field) => write!(f, "ontology client requires {field}"),
        }
    }
}

impl std::error::Error for OntologyCodegenError {}

pub fn scope_allows(scope: &OntologyClientScope, member_kind: &str, member_id: &str) -> bool {
    scope
        .selected_members
        .contains(&OntologyClientMemberRef::new(member_kind, member_id))
}

pub fn bind_live_revision(
    scope: &OntologyClientScope,
    live_revision_digest: &str,
) -> Result<(), OntologyCodegenError> {
    if live_revision_digest != scope.revision_digest {
        return Err(OntologyCodegenError::RevisionPinMismatch);
    }
    Ok(())
}

pub fn verify_ontology_client_package(
    package: &GeneratedOntologyClient,
    expected_digest: &str,
) -> Result<(), OntologyCodegenError> {
    let computed = package_digest(&package.typescript, &package.scope)?;
    if computed != expected_digest || package.package_digest != expected_digest {
        return Err(OntologyCodegenError::TamperedPackage);
    }
    Ok(())
}

/// Generate a TypeScript ontology client from one published revision and an
/// explicit member selection. Failures do not disclose other catalog members.
pub fn generate_ontology_typescript_client(
    revision: &DefinitionRevision,
    members: &[DefinitionMember],
    selection: &OntologyClientSelection,
) -> Result<GeneratedOntologyClient, OntologyCodegenError> {
    validate_context(selection)?;
    if selection.members.is_empty() {
        return Err(OntologyCodegenError::EmptySelection);
    }
    if !revision.published {
        return Err(OntologyCodegenError::UnpublishedRevision);
    }
    if revision.namespace != selection.namespace {
        return Err(OntologyCodegenError::NamespaceMismatch);
    }
    if revision.revision_digest != selection.revision_digest_pin {
        return Err(OntologyCodegenError::RevisionPinMismatch);
    }
    revision
        .verify()
        .map_err(|_| OntologyCodegenError::UnsupportedProtocol)?;

    if let Some(max_scope) = &selection.max_scope
        && !selection.members.is_subset(max_scope)
    {
        return Err(OntologyCodegenError::ExcessiveScope);
    }

    let revision_digests = revision
        .members
        .iter()
        .map(|member| {
            (
                (member.member_kind.as_str(), member.member_id.as_str()),
                member.member_digest.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let by_identity = members
        .iter()
        .map(|member| {
            (
                (member.member_kind.as_str(), member.member_id.as_str()),
                member,
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut selected = Vec::new();
    let mut type_names = BTreeSet::new();
    let mut method_names = BTreeSet::new();
    for selected_ref in &selection.members {
        if !SELECTABLE_MEMBER_KINDS.contains(&selected_ref.member_kind.as_str()) {
            return Err(OntologyCodegenError::UnsupportedMemberKind);
        }
        let expected_digest = *revision_digests
            .get(&selected_ref.key())
            .ok_or(OntologyCodegenError::UnknownMember)?;
        let member = by_identity
            .get(&selected_ref.key())
            .copied()
            .ok_or(OntologyCodegenError::UnknownMember)?;
        member
            .verify()
            .map_err(|_| OntologyCodegenError::InvalidDefinition)?;
        if member.namespace != selection.namespace {
            return Err(OntologyCodegenError::NamespaceMismatch);
        }
        if member.member_digest != expected_digest {
            return Err(OntologyCodegenError::UnsupportedProtocol);
        }
        if !is_metadata_safe(&member.member_kind) || !is_metadata_safe(&member.member_id) {
            return Err(OntologyCodegenError::UnsupportedProtocol);
        }
        let rendered = render_member_types(member)?;
        if RESERVED_TS_NAMES.contains(&rendered.type_name.as_str())
            || RESERVED_TS_NAMES.contains(&rendered.method_name.as_str())
            || !type_names.insert(rendered.type_name.clone())
            || !method_names.insert(rendered.method_name.clone())
        {
            return Err(OntologyCodegenError::InvalidDefinition);
        }
        selected.push(rendered);
    }

    let scope = OntologyClientScope {
        contract_version: GENERATOR_CONTRACT_VERSION.into(),
        namespace: selection.namespace.clone(),
        revision_digest: revision.revision_digest.clone(),
        selected_members: selection.members.clone(),
    };
    let typescript = render_typescript(&selected, &scope);
    let digest = package_digest(&typescript, &scope)?;
    Ok(GeneratedOntologyClient {
        typescript,
        scope,
        package_digest: digest,
    })
}

fn validate_context(selection: &OntologyClientSelection) -> Result<(), OntologyCodegenError> {
    for (field, value) in [
        ("namespace", selection.namespace.as_str()),
        (
            "revision_digest_pin",
            selection.revision_digest_pin.as_str(),
        ),
    ] {
        if !is_metadata_safe(value) {
            return Err(OntologyCodegenError::InvalidContext(field));
        }
    }
    for member in &selection.members {
        if !is_metadata_safe(&member.member_kind) || !is_metadata_safe(&member.member_id) {
            return Err(OntologyCodegenError::InvalidContext("member"));
        }
    }
    Ok(())
}

struct RenderedMember {
    member_kind: String,
    member_id: String,
    type_name: String,
    method_name: String,
    fields: Vec<RenderedField>,
}

struct RenderedField {
    name: String,
    ts_type: String,
    required: bool,
}

fn render_member_types(member: &DefinitionMember) -> Result<RenderedMember, OntologyCodegenError> {
    let value: serde_json::Value = serde_json::from_str(&member.definition_json)
        .map_err(|_| OntologyCodegenError::InvalidDefinition)?;
    let object = value
        .as_object()
        .ok_or(OntologyCodegenError::InvalidDefinition)?;
    if object.contains_key("$schema") {
        return Err(OntologyCodegenError::UnsupportedProtocol);
    }
    let fields = properties_from_definition(object)?;
    Ok(RenderedMember {
        member_kind: member.member_kind.clone(),
        member_id: member.member_id.clone(),
        type_name: sanitize_type_name(&member.member_id),
        method_name: sanitize_method_name(&member.member_id),
        fields,
    })
}

fn properties_from_definition(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<RenderedField>, OntologyCodegenError> {
    let required = named_string_set(object.get("required"))?;
    let mut fields = match object.get("properties") {
        None => Vec::new(),
        Some(serde_json::Value::Array(items)) => {
            let mut fields = Vec::new();
            let mut seen = BTreeSet::new();
            for item in items {
                let name = item
                    .as_str()
                    .ok_or(OntologyCodegenError::InvalidDefinition)?;
                if !seen.insert(name.to_string()) {
                    return Err(OntologyCodegenError::InvalidDefinition);
                }
                fields.push(RenderedField {
                    name: name.to_string(),
                    ts_type: "unknown".into(),
                    required: required.contains(name),
                });
            }
            fields
        }
        Some(serde_json::Value::Object(map)) => {
            let mut fields = Vec::new();
            for (name, spec) in map {
                let ts_type = spec
                    .as_object()
                    .and_then(|item| item.get("type"))
                    .and_then(serde_json::Value::as_str)
                    .map(map_json_schema_type)
                    .transpose()?
                    .unwrap_or_else(|| "unknown".into());
                fields.push(RenderedField {
                    name: name.clone(),
                    ts_type,
                    required: required.contains(name),
                });
            }
            fields
        }
        Some(_) => return Err(OntologyCodegenError::InvalidDefinition),
    };
    let present = fields
        .iter()
        .map(|field| field.name.clone())
        .collect::<BTreeSet<_>>();
    for name in &required {
        if !present.contains(name) {
            fields.push(RenderedField {
                name: name.clone(),
                ts_type: "unknown".into(),
                required: true,
            });
        }
    }
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(fields)
}

fn named_string_set(
    value: Option<&serde_json::Value>,
) -> Result<BTreeSet<String>, OntologyCodegenError> {
    let Some(value) = value else {
        return Ok(BTreeSet::new());
    };
    let items = value
        .as_array()
        .ok_or(OntologyCodegenError::InvalidDefinition)?;
    let mut names = BTreeSet::new();
    for item in items {
        let name = item
            .as_str()
            .ok_or(OntologyCodegenError::InvalidDefinition)?;
        if !names.insert(name.to_string()) {
            return Err(OntologyCodegenError::InvalidDefinition);
        }
    }
    Ok(names)
}

fn map_json_schema_type(value: &str) -> Result<String, OntologyCodegenError> {
    Ok(match value {
        "string" | "timestamp" => "string".into(),
        "integer" | "int" | "number" | "float" => "number".into(),
        "boolean" | "bool" => "boolean".into(),
        "array" => "unknown[]".into(),
        "object" | "struct" => "Record<string, unknown>".into(),
        "link" | "computed" | "enum" => "unknown".into(),
        _ => return Err(OntologyCodegenError::UnsupportedProtocol),
    })
}

fn render_typescript(selected: &[RenderedMember], scope: &OntologyClientScope) -> String {
    let mut interfaces = String::new();
    let mut methods = String::new();
    for member in selected {
        interfaces.push_str(&render_interface(member));
        methods.push_str(&format!(
            r#"
  {method}(operationId: string, input: {type_name}): OntologyInvocation {{
    return invoke({kind}, {id}, operationId, input);
  }}
"#,
            method = member.method_name,
            type_name = member.type_name,
            kind = js_string(&member.member_kind),
            id = js_string(&member.member_id),
        ));
    }

    let allowed = selected
        .iter()
        .map(|member| {
            js_string(
                &OntologyClientMemberRef::new(&member.member_kind, &member.member_id).scope_token(),
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"// Generated by sekai-chisei ontology codegen. DO NOT EDIT.
// contract_version={contract_version}
// namespace={namespace}
// revision_digest={revision_digest}

export const GENERATED_CONTRACT_VERSION = {contract_version};
export const GENERATED_NAMESPACE = {namespace};
export const GENERATED_REVISION_DIGEST = {revision_digest};
export const ALLOWED_MEMBERS = [{allowed}] as const;

{interfaces}export interface OntologyInvocation {{
  contract_version: string;
  namespace: string;
  revision_digest: string;
  member_kind: string;
  member_id: string;
  operation_id: string;
  input: Record<string, unknown>;
}}

export function scopeAllows(memberKind: string, memberId: string): boolean {{
  return (ALLOWED_MEMBERS as readonly string[]).includes(`${{memberKind}}:${{memberId}}`);
}}

export function bindLiveRevision(liveRevisionDigest: string): void {{
  if (liveRevisionDigest !== GENERATED_REVISION_DIGEST) {{
    throw new Error("ontology client revision pin is stale");
  }}
}}

export function invoke<T extends object>(
  memberKind: string,
  memberId: string,
  operationId: string,
  input: T,
): OntologyInvocation {{
  if (!scopeAllows(memberKind, memberId)) {{
    throw new Error("member is not in generated scope");
  }}
  if (!operationId.trim()) throw new Error("operation_id required");
  return {{
    contract_version: GENERATED_CONTRACT_VERSION,
    namespace: GENERATED_NAMESPACE,
    revision_digest: GENERATED_REVISION_DIGEST,
    member_kind: memberKind,
    member_id: memberId,
    operation_id: operationId,
    input: {{ ...input }} as Record<string, unknown>,
  }};
}}

export function nativeMetadata(call: OntologyInvocation): Record<string, string> {{
  if (!scopeAllows(call.member_kind, call.member_id)) {{
    throw new Error("member is not in generated scope");
  }}
  if (call.namespace !== GENERATED_NAMESPACE
      || call.revision_digest !== GENERATED_REVISION_DIGEST
      || call.contract_version !== GENERATED_CONTRACT_VERSION) {{
    throw new Error("invocation context does not match generated scope");
  }}
  if (!call.operation_id.trim()) throw new Error("operation_id required");
  return {{
    "x-sekai-namespace": call.namespace,
    "x-sekai-definition-revision": call.revision_digest,
    "x-sekai-member-kind": call.member_kind,
    "x-sekai-member-id": call.member_id,
    "x-sekai-operation-id": call.operation_id,
  }};
}}

export class ScopedOntologyClient {{
{methods}}}
"#,
        contract_version = js_string(&scope.contract_version),
        namespace = js_string(&scope.namespace),
        revision_digest = js_string(&scope.revision_digest),
        allowed = allowed,
        interfaces = interfaces,
        methods = methods,
    )
}

fn render_interface(member: &RenderedMember) -> String {
    if member.fields.is_empty() {
        return format!("export interface {} {{}}\n\n", member.type_name);
    }
    let mut body = String::new();
    for field in &member.fields {
        let optional = if field.required { "" } else { "?" };
        body.push_str(&format!(
            "  {}{}: {};\n",
            render_ts_property_name(&field.name),
            optional,
            field.ts_type
        ));
    }
    format!("export interface {} {{\n{}}}\n\n", member.type_name, body)
}

fn package_digest(
    typescript: &str,
    scope: &OntologyClientScope,
) -> Result<String, OntologyCodegenError> {
    #[derive(Serialize)]
    struct PackageIdentity<'a> {
        contract_version: &'a str,
        typescript: &'a str,
        scope: &'a OntologyClientScope,
    }
    let canonical = crate::shomei::canonical_json_with_finite_numbers(&PackageIdentity {
        contract_version: GENERATOR_CONTRACT_VERSION,
        typescript,
        scope,
    })
    .map_err(|_| OntologyCodegenError::UnsupportedProtocol)?;
    let mut hasher = Sha256::new();
    hasher.update(GENERATOR_CONTRACT_VERSION.as_bytes());
    hasher.update(b"\n");
    hasher.update(b"ontology_client_package\n");
    hasher.update(canonical);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn js_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into())
}

fn sanitize_type_name(name: &str) -> String {
    let camel = sanitize_identifier(name, true);
    if camel.is_empty() {
        "OntologyType".into()
    } else {
        camel
    }
}

fn sanitize_method_name(name: &str) -> String {
    let mut out = sanitize_identifier(name, false);
    if out.is_empty() {
        out = "member".into();
    }
    if matches!(out.as_str(), "constructor" | "prototype") {
        out = format!("member{out}");
    }
    out
}

fn render_ts_property_name(name: &str) -> String {
    if is_safe_ts_identifier(name) {
        name.to_string()
    } else {
        js_string(name)
    }
}

pub(crate) fn is_metadata_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii() && !ch.is_ascii_control())
}

fn is_safe_ts_identifier(name: &str) -> bool {
    if matches!(
        name,
        "break"
            | "case"
            | "catch"
            | "class"
            | "const"
            | "continue"
            | "debugger"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "enum"
            | "export"
            | "extends"
            | "false"
            | "finally"
            | "for"
            | "function"
            | "if"
            | "import"
            | "in"
            | "instanceof"
            | "new"
            | "null"
            | "return"
            | "super"
            | "switch"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typeof"
            | "var"
            | "void"
            | "while"
            | "with"
            | "yield"
            | "let"
            | "static"
            | "implements"
            | "interface"
            | "package"
            | "private"
            | "protected"
            | "public"
            | "await"
            | "constructor"
            | "prototype"
    ) {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
}

fn sanitize_identifier(name: &str, pascal: bool) -> String {
    let mut out = String::new();
    let mut capitalize = pascal;
    for (index, ch) in name.chars().enumerate() {
        if ch.is_ascii_alphanumeric() {
            if capitalize {
                out.extend(ch.to_uppercase());
                capitalize = false;
            } else if index == 0 && !pascal {
                out.extend(ch.to_lowercase());
            } else {
                out.push(ch);
            }
        } else {
            capitalize = true;
        }
    }
    if out.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        out = format!("n{out}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::definition_branch::{
        DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };
    use std::path::PathBuf;
    use std::process::Command;

    fn member(kind: &str, id: &str, json: &str) -> DefinitionMember {
        DefinitionMemberInput {
            member_kind: kind.into(),
            member_id: id.into(),
            definition_json: json.into(),
            member_digest: String::new(),
        }
        .prepare("demo")
        .unwrap()
    }

    fn published(members: &[DefinitionMember]) -> (DefinitionRevision, Vec<DefinitionMember>) {
        let refs = members.iter().map(|item| DefinitionRevisionMember {
            member_kind: item.member_kind.clone(),
            member_id: item.member_id.clone(),
            member_digest: item.member_digest.clone(),
        });
        let revision = prepare_revision("demo", "", refs, true, "author", 1).unwrap();
        (revision, members.to_vec())
    }

    fn fixture_catalog() -> (DefinitionRevision, Vec<DefinitionMember>) {
        published(&[
            member(
                "object_type",
                "Ticket",
                r#"{"name":"Ticket","properties":{"title":{"type":"string"}},"required":["title"]}"#,
            ),
            member("link_type", "AssignedTo", r#"{"name":"AssignedTo"}"#),
            member(
                "action_type",
                "Assign",
                r#"{"name":"Assign","properties":{"assignee":{"type":"string"}}}"#,
            ),
            member(
                "function",
                "CountOpen",
                r#"{"name":"CountOpen","properties":{"status":{"type":"string"}},"required":["status"]}"#,
            ),
            member("object_type", "Hidden", r#"{"name":"Hidden"}"#),
        ])
    }

    fn selected(
        revision: &DefinitionRevision,
        members: impl IntoIterator<Item = OntologyClientMemberRef>,
    ) -> OntologyClientSelection {
        OntologyClientSelection {
            namespace: "demo".into(),
            revision_digest_pin: revision.revision_digest.clone(),
            members: members.into_iter().collect(),
            max_scope: None,
        }
    }

    #[test]
    fn generates_stable_typescript_for_selection() {
        let (revision, members) = fixture_catalog();
        let selection = selected(
            &revision,
            [
                OntologyClientMemberRef::new("object_type", "Ticket"),
                OntologyClientMemberRef::new("link_type", "AssignedTo"),
                OntologyClientMemberRef::new("action_type", "Assign"),
                OntologyClientMemberRef::new("function", "CountOpen"),
            ],
        );
        let generated =
            generate_ontology_typescript_client(&revision, &members, &selection).unwrap();
        verify_ontology_client_package(&generated, &generated.package_digest).unwrap();
        assert!(scope_allows(&generated.scope, "object_type", "Ticket"));
        assert!(!scope_allows(&generated.scope, "object_type", "Hidden"));
        assert!(generated.typescript.contains("export interface Ticket"));
        assert!(generated.typescript.contains("countOpen("));
        assert!(!generated.typescript.contains("Hidden"));
        assert!(!generated.typescript.contains("credential"));
        assert!(!generated.typescript.contains("token"));

        let golden = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ontology_codegen/scoped_client.v1.ts");
        let expected = std::fs::read_to_string(&golden).expect("golden typescript fixture");
        assert_eq!(
            generated.typescript, expected,
            "generated client drifted from golden fixture"
        );
    }

    #[test]
    fn golden_package_typechecks_when_tsc_is_available() {
        let fixture_dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ontology_codegen");
        let tsc = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("sdk/typescript/node_modules/typescript/bin/tsc");
        if !tsc.is_file() {
            return;
        }
        let checked = Command::new(&tsc)
            .arg("-p")
            .arg(fixture_dir.join("tsconfig.json"))
            .output()
            .expect("tsc --noEmit");
        assert!(
            checked.status.success(),
            "golden TypeScript package failed to typecheck: {}\n{}",
            String::from_utf8_lossy(&checked.stdout),
            String::from_utf8_lossy(&checked.stderr)
        );
    }

    #[test]
    fn stale_revision_pin_fails_closed() {
        let (revision, members) = fixture_catalog();
        let mut selection = selected(
            &revision,
            [OntologyClientMemberRef::new("object_type", "Ticket")],
        );
        selection.revision_digest_pin =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        assert!(matches!(
            generate_ontology_typescript_client(&revision, &members, &selection),
            Err(OntologyCodegenError::RevisionPinMismatch)
        ));
        assert!(matches!(
            bind_live_revision(
                &OntologyClientScope {
                    contract_version: GENERATOR_CONTRACT_VERSION.into(),
                    namespace: "demo".into(),
                    revision_digest: revision.revision_digest,
                    selected_members: BTreeSet::new(),
                },
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ),
            Err(OntologyCodegenError::RevisionPinMismatch)
        ));
    }

    #[test]
    fn unknown_and_hidden_members_fail_without_catalog_disclosure() {
        let (revision, members) = fixture_catalog();
        let err = generate_ontology_typescript_client(
            &revision,
            &members,
            &selected(
                &revision,
                [OntologyClientMemberRef::new("object_type", "Missing")],
            ),
        )
        .unwrap_err();
        assert!(matches!(err, OntologyCodegenError::UnknownMember));
        let message = err.to_string();
        assert!(!message.contains("Hidden"));
        assert!(!message.contains("Ticket"));
        assert!(!message.contains(&revision.members[0].member_id));
    }

    #[test]
    fn excessive_scope_fails_closed() {
        let (revision, members) = fixture_catalog();
        let mut selection = selected(
            &revision,
            [
                OntologyClientMemberRef::new("object_type", "Ticket"),
                OntologyClientMemberRef::new("object_type", "Hidden"),
            ],
        );
        selection.max_scope = Some(BTreeSet::from([OntologyClientMemberRef::new(
            "object_type",
            "Ticket",
        )]));
        let err = generate_ontology_typescript_client(&revision, &members, &selection).unwrap_err();
        assert!(matches!(err, OntologyCodegenError::ExcessiveScope));
        assert!(!err.to_string().contains("Hidden"));
    }

    #[test]
    fn unpublished_revision_fails_closed() {
        let (mut revision, members) = fixture_catalog();
        revision.published = false;
        assert!(matches!(
            generate_ontology_typescript_client(
                &revision,
                &members,
                &selected(
                    &revision,
                    [OntologyClientMemberRef::new("object_type", "Ticket")]
                )
            ),
            Err(OntologyCodegenError::UnpublishedRevision)
        ));
    }

    #[test]
    fn tampered_package_fails_closed() {
        let (revision, members) = fixture_catalog();
        let mut generated = generate_ontology_typescript_client(
            &revision,
            &members,
            &selected(
                &revision,
                [OntologyClientMemberRef::new("object_type", "Ticket")],
            ),
        )
        .unwrap();
        let expected = generated.package_digest.clone();
        generated
            .typescript
            .push_str("\nexport const leaked = true;\n");
        assert!(matches!(
            verify_ontology_client_package(&generated, &expected),
            Err(OntologyCodegenError::TamperedPackage)
        ));
        generated.package_digest = package_digest(&generated.typescript, &generated.scope).unwrap();
        assert!(matches!(
            verify_ontology_client_package(&generated, &expected),
            Err(OntologyCodegenError::TamperedPackage)
        ));
    }

    #[test]
    fn empty_selection_fails_closed() {
        let (revision, members) = fixture_catalog();
        assert!(matches!(
            generate_ontology_typescript_client(&revision, &members, &selected(&revision, [])),
            Err(OntologyCodegenError::EmptySelection)
        ));
    }

    #[test]
    fn selected_bodies_do_not_require_the_full_catalog() {
        let (revision, members) = fixture_catalog();
        let selected_only = members
            .into_iter()
            .filter(|member| member.member_id == "Ticket")
            .collect::<Vec<_>>();
        let generated = generate_ontology_typescript_client(
            &revision,
            &selected_only,
            &selected(
                &revision,
                [OntologyClientMemberRef::new("object_type", "Ticket")],
            ),
        )
        .unwrap();
        assert!(generated.typescript.contains("export interface Ticket"));
        assert!(!generated.typescript.contains("Hidden"));
    }

    #[test]
    fn required_fields_without_properties_remain_required() {
        let (revision, members) = published(&[member(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","required":["title"]}"#,
        )]);
        let generated = generate_ontology_typescript_client(
            &revision,
            &members,
            &selected(
                &revision,
                [OntologyClientMemberRef::new("object_type", "Ticket")],
            ),
        )
        .unwrap();
        assert!(generated.typescript.contains("  title: unknown;"));
        assert!(!generated.typescript.contains("title?:"));
    }

    #[test]
    fn original_property_keys_are_preserved() {
        let (revision, members) = published(&[member(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":{"foo-bar":{"type":"string"},"URL":{"type":"string"}},"required":["foo-bar"]}"#,
        )]);
        let generated = generate_ontology_typescript_client(
            &revision,
            &members,
            &selected(
                &revision,
                [OntologyClientMemberRef::new("object_type", "Ticket")],
            ),
        )
        .unwrap();
        assert!(generated.typescript.contains("\"foo-bar\": string"));
        assert!(generated.typescript.contains("  URL?: string;"));
        assert!(!generated.typescript.contains("fooBar"));
        assert!(!generated.typescript.contains("uRL"));
    }

    #[test]
    fn non_ascii_identities_fail_closed() {
        let cafe = member("object_type", "Café", r#"{"name":"Cafe"}"#);
        let (revision, members) = published(&[cafe]);
        assert!(matches!(
            generate_ontology_typescript_client(
                &revision,
                &members,
                &selected(
                    &revision,
                    [OntologyClientMemberRef::new("object_type", "Café")]
                )
            ),
            Err(OntologyCodegenError::InvalidContext(_))
                | Err(OntologyCodegenError::UnsupportedProtocol)
        ));
    }

    #[test]
    fn reserved_generated_names_fail_closed() {
        let (revision, members) = published(&[member(
            "object_type",
            "OntologyInvocation",
            r#"{"name":"OntologyInvocation"}"#,
        )]);
        assert!(matches!(
            generate_ontology_typescript_client(
                &revision,
                &members,
                &selected(
                    &revision,
                    [OntologyClientMemberRef::new(
                        "object_type",
                        "OntologyInvocation"
                    )]
                )
            ),
            Err(OntologyCodegenError::InvalidDefinition)
        ));
    }

    #[test]
    fn control_members_are_not_selectable() {
        let control = member(
            "control",
            "retention",
            r#"{"name":"retention","mode":"strict"}"#,
        );
        let (revision, members) = published(&[control]);
        assert!(matches!(
            generate_ontology_typescript_client(
                &revision,
                &members,
                &selected(
                    &revision,
                    [OntologyClientMemberRef::new("control", "retention")]
                )
            ),
            Err(OntologyCodegenError::UnsupportedMemberKind)
        ));
    }
}
