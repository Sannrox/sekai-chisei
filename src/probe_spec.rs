//! Declarative isolation probe specs (#1680).
//!
//! A spec says which read-only RPC to call, as which of the run's
//! principals, with which request options, and how the call must be denied.
//! It names no endpoint, credential, tenant or object: every RPC here is
//! object-scoped and is called on the run's foreign object, which the target
//! guard has already verified lives in a synthetic tenant on an allow-listed
//! endpoint, as the run's own synthetic tenant or with no credential. A spec
//! that tries to say more fails to parse, so it is refused before any call.
//!
//! An agent proposing probes emits specs; it never calls an RPC itself. The
//! guarded runner (`crate::probe_runner`) executes them behind the same guard
//! and ledger as its built-in probes.

use serde::{Deserialize, Serialize};

pub const PROBE_SPEC_VERSION: &str = "sekai.probe-spec/v1";
const MAX_SPEC_ID: usize = 64;
const MAX_REASON: usize = 200;
const MAX_LINEAGE_NODES: i32 = 100;

/// Who a spec calls as. The probing tenant's own credential, or none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecPrincipal {
    Tenant,
    Anonymous,
}

/// The read-only, object-scoped RPC a spec calls, with its options. The
/// object is always the run's foreign object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rpc", rename_all = "PascalCase", deny_unknown_fields)]
pub enum SpecCall {
    // A struct variant, not a unit one, so unknown fields are refused.
    GetObject {},
    GetLinks {
        #[serde(default)]
        relation: String,
        #[serde(default)]
        direction: String,
    },
    GetLinkedObjects {
        #[serde(default)]
        relation: String,
        #[serde(default)]
        direction: String,
    },
    ListObjectComments {
        #[serde(default)]
        include_resolved: bool,
    },
    GetLineage {
        #[serde(default = "default_lineage_nodes")]
        max_nodes: i32,
    },
}

fn default_lineage_nodes() -> i32 {
    10
}

impl SpecCall {
    pub fn rpc(&self) -> &'static str {
        match self {
            Self::GetObject {} => "SekaiService.GetObject",
            Self::GetLinks { .. } => "SekaiService.GetLinks",
            Self::GetLinkedObjects { .. } => "SekaiService.GetLinkedObjects",
            Self::ListObjectComments { .. } => "SekaiService.ListObjectComments",
            Self::GetLineage { .. } => "SekaiService.GetLineage",
        }
    }
}

/// How the call must be denied: one of `codes`, and when given, a status
/// message containing `reason`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedDenial {
    pub codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeSpec {
    pub schema: String,
    /// Names the spec in the ledger and in findings.
    pub id: String,
    #[serde(rename = "as")]
    pub principal: SpecPrincipal,
    pub call: SpecCall,
    pub expect: ExpectedDenial,
}

/// gRPC codes a spec may expect. `Ok` is not a denial; codes that mean the
/// target is unwell (`Unavailable`, `DeadlineExceeded`) never decide one.
const DENIAL_CODES: [(&str, tonic::Code); 5] = [
    ("Unauthenticated", tonic::Code::Unauthenticated),
    ("PermissionDenied", tonic::Code::PermissionDenied),
    ("NotFound", tonic::Code::NotFound),
    ("FailedPrecondition", tonic::Code::FailedPrecondition),
    ("InvalidArgument", tonic::Code::InvalidArgument),
];

/// What one call of a spec proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecVerdict {
    /// Denied as the spec expects.
    Denied,
    /// The call succeeded: a finding.
    NotDenied,
    /// Denied, but not as expected: a finding to inspect.
    Mismatch(String),
}

impl ProbeSpec {
    /// Parse and validate one spec. Unknown fields, including any attempt to
    /// name an endpoint, credential, tenant or object, are refused.
    pub fn parse(json: &str) -> Result<Self, String> {
        let spec: Self =
            serde_json::from_str(json).map_err(|error| format!("invalid probe spec: {error}"))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != PROBE_SPEC_VERSION {
            return Err(format!("probe spec schema must be {PROBE_SPEC_VERSION}"));
        }
        if self.id.is_empty()
            || self.id.len() > MAX_SPEC_ID
            || !self
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "probe spec id must be 1 to {MAX_SPEC_ID} of [A-Za-z0-9_-]"
            ));
        }
        if self.expect.codes.is_empty() {
            return Err(format!("probe spec {} expects no denial code", self.id));
        }
        if let Some(code) = self
            .expect
            .codes
            .iter()
            .find(|code| !DENIAL_CODES.iter().any(|(name, _)| name == code))
        {
            return Err(format!(
                "probe spec {} expects {code}, which is not a denial code",
                self.id
            ));
        }
        if self
            .expect
            .reason
            .as_ref()
            .is_some_and(|reason| reason.is_empty() || reason.len() > MAX_REASON)
        {
            return Err(format!(
                "probe spec {} reason must be 1 to {MAX_REASON} bytes",
                self.id
            ));
        }
        let names = |value: &str| {
            value.len() <= 64
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        };
        match &self.call {
            SpecCall::GetLinks {
                relation,
                direction,
            }
            | SpecCall::GetLinkedObjects {
                relation,
                direction,
            } if !names(relation)
                || !["", "outgoing", "incoming"].contains(&direction.as_str()) =>
            {
                Err(format!(
                    "probe spec {} link options must be a relation name and outgoing or incoming",
                    self.id
                ))
            }
            // Zero would mean the server's own, larger, default.
            SpecCall::GetLineage { max_nodes } if !(1..=MAX_LINEAGE_NODES).contains(max_nodes) => {
                Err(format!(
                    "probe spec {} max_nodes must be 1 to {MAX_LINEAGE_NODES}",
                    self.id
                ))
            }
            _ => Ok(()),
        }
    }

    /// The verdict for one call's result.
    pub fn judge<T>(&self, result: &Result<T, tonic::Status>) -> SpecVerdict {
        let Err(status) = result else {
            return SpecVerdict::NotDenied;
        };
        let code_expected = self.expect.codes.iter().any(|name| {
            DENIAL_CODES
                .iter()
                .any(|(known, code)| known == name && *code == status.code())
        });
        let reason_expected = self
            .expect
            .reason
            .as_ref()
            .is_none_or(|reason| status.message().contains(reason.as_str()));
        if code_expected && reason_expected {
            SpecVerdict::Denied
        } else {
            SpecVerdict::Mismatch(format!(
                "denied with {:?}, the spec expects {}{}",
                status.code(),
                self.expect.codes.join(" or "),
                self.expect
                    .reason
                    .as_ref()
                    .map(|reason| format!(" containing {reason:?}"))
                    .unwrap_or_default()
            ))
        }
    }
}

/// Every `*.json` spec in `dir`, all validated before any is run, in name
/// order. One invalid spec refuses the set.
pub fn load_dir(dir: &std::path::Path) -> Result<Vec<ProbeSpec>, String> {
    let mut paths = std::fs::read_dir(dir)
        .map_err(|error| format!("probe specs {}: {error}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect::<Vec<_>>();
    paths.sort();
    let mut specs = Vec::with_capacity(paths.len());
    for path in paths {
        let json = std::fs::read_to_string(&path)
            .map_err(|error| format!("probe spec {}: {error}", path.display()))?;
        specs
            .push(ProbeSpec::parse(&json).map_err(|error| format!("{}: {error}", path.display()))?);
    }
    validate_set(&specs)?;
    Ok(specs)
}

/// Every spec valid, and no id used twice, so each names one ledger line.
pub fn validate_set(specs: &[ProbeSpec]) -> Result<(), String> {
    let mut ids = std::collections::HashSet::new();
    for spec in specs {
        spec.validate()?;
        if !ids.insert(spec.id.as_str()) {
            return Err(format!("probe spec id {} is used twice", spec.id));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CROSS_TENANT: &str = r#"{
        "schema": "sekai.probe-spec/v1",
        "id": "links-cross-tenant",
        "as": "tenant",
        "call": {"rpc": "GetLinks", "direction": "outgoing"},
        "expect": {"codes": ["PermissionDenied", "NotFound"]}
    }"#;

    #[test]
    fn a_spec_names_only_an_rpc_a_principal_options_and_a_denial() {
        let spec = ProbeSpec::parse(CROSS_TENANT).unwrap();
        assert_eq!(spec.call.rpc(), "SekaiService.GetLinks");
        assert_eq!(spec.principal, SpecPrincipal::Tenant);
        // Anything that could point the call elsewhere is refused.
        for (field, value) in [
            ("target", r#""https://prod.example.test""#),
            ("tenant", r#""acme""#),
            ("token", r#""secret""#),
            ("object_id", r#""obj-1""#),
        ] {
            let json = CROSS_TENANT.replacen('{', &format!("{{\"{field}\": {value},"), 1);
            assert!(ProbeSpec::parse(&json).is_err(), "{field}");
        }
        let in_call = CROSS_TENANT.replace(
            r#""direction": "outgoing""#,
            r#""direction": "outgoing", "object_id": "obj-1""#,
        );
        assert!(ProbeSpec::parse(&in_call).is_err());
        let get_object = CROSS_TENANT.replace(
            r#"{"rpc": "GetLinks", "direction": "outgoing"}"#,
            r#"{"rpc": "GetObject", "object_id": "obj-1"}"#,
        );
        assert!(ProbeSpec::parse(&get_object).is_err());
        let plain = CROSS_TENANT.replace(
            r#"{"rpc": "GetLinks", "direction": "outgoing"}"#,
            r#"{"rpc": "GetObject"}"#,
        );
        assert_eq!(
            ProbeSpec::parse(&plain).unwrap().call,
            SpecCall::GetObject {}
        );
        let lineage = |nodes: &str| {
            ProbeSpec::parse(&CROSS_TENANT.replace(
                r#"{"rpc": "GetLinks", "direction": "outgoing"}"#,
                &format!(r#"{{"rpc": "GetLineage"{nodes}}}"#),
            ))
        };
        assert_eq!(
            lineage("").unwrap().call,
            SpecCall::GetLineage { max_nodes: 10 }
        );
        assert!(lineage(r#", "max_nodes": 0"#).is_err());
        assert!(lineage(r#", "max_nodes": 101"#).is_err());
    }

    #[test]
    fn malformed_specs_are_refused_with_a_validation_error() {
        for (from, to) in [
            (r#""sekai.probe-spec/v1""#, r#""sekai.probe-spec/v2""#),
            (r#""links-cross-tenant""#, r#""spaces are bad""#),
            (r#"["PermissionDenied", "NotFound"]"#, "[]"),
            (r#"["PermissionDenied", "NotFound"]"#, r#"["Ok"]"#),
            (r#"["PermissionDenied", "NotFound"]"#, r#"["Unavailable"]"#),
            (r#""direction": "outgoing""#, r#""direction": "sideways""#),
            (r#""rpc": "GetLinks""#, r#""rpc": "DeleteObject""#),
            (r#""as": "tenant""#, r#""as": "root""#),
        ] {
            let json = CROSS_TENANT.replace(from, to);
            assert!(ProbeSpec::parse(&json).is_err(), "{to}");
        }
        assert!(ProbeSpec::parse("not json").is_err());
    }

    #[test]
    fn a_spec_id_is_used_once_in_a_set() {
        let spec = ProbeSpec::parse(CROSS_TENANT).unwrap();
        let other = ProbeSpec {
            id: "other".into(),
            ..spec.clone()
        };
        assert!(validate_set(&[spec.clone(), other.clone()]).is_ok());
        assert!(validate_set(&[spec.clone(), other, spec]).is_err());
    }

    #[test]
    fn only_the_expected_denial_passes() {
        let mut spec = ProbeSpec::parse(CROSS_TENANT).unwrap();
        let denied: Result<(), _> = Err(tonic::Status::permission_denied("access denied"));
        assert_eq!(spec.judge(&denied), SpecVerdict::Denied);
        assert_eq!(spec.judge(&Ok(())), SpecVerdict::NotDenied);
        let wrong: Result<(), _> = Err(tonic::Status::invalid_argument("bad"));
        assert!(matches!(spec.judge(&wrong), SpecVerdict::Mismatch(_)));
        let down: Result<(), _> = Err(tonic::Status::unavailable("restarting"));
        assert!(matches!(spec.judge(&down), SpecVerdict::Mismatch(_)));
        spec.expect.reason = Some("tenant boundary".into());
        assert!(matches!(spec.judge(&denied), SpecVerdict::Mismatch(_)));
    }
}
