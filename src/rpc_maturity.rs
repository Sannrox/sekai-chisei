//! Public RPC maturity projection (#871).
//!
//! Classification is derived from proto services, dual-backend inventories,
//! and known SDK / host / example consumers. It does not invent invocation
//! authority. Experimental and remove RPCs stay on the wire but are rejected
//! in the default build unless an explicit runtime flag or Cargo feature is on.

use crate::db::chisei_rpc_inventory::{
    CHISEI_SERVICE_PROTO, parse_service_rpcs as parse_named_service_rpcs,
};
use crate::db::sekai_rpc_inventory::{SEKAI_SERVICE_PROTO, parse_sekai_service_rpcs};
use futures_util::future::BoxFuture;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::task::{Context, Poll};
use tonic::Status;
use tonic::server::NamedService;
use tower::{Layer, Service};

pub const MATURITY_CONTRACT: &str = "sekai.rpc-maturity/v1";
pub const MATURITY_JSON: &str = include_str!("../tests/fixtures/rpc_maturity/v1.json");
pub const MATURITY_DOCS: &str = include_str!("../docs/rpc-maturity.md");
pub const EXPERIMENTAL_ENV: &str = "SEKAI_EXPERIMENTAL_RPCS";
pub const EXPERIMENTAL_FEATURE: &str = "experimental-rpcs";
pub const EXPERIMENTAL_CAPABILITY: &str = "sekai.rpc.experimental";
pub const STABLE_LIMIT: usize = 66;

const EXPERIMENTAL_MESSAGE: &str =
    "rpc is experimental; enable SEKAI_EXPERIMENTAL_RPCS=1 or the experimental-rpcs build feature";
const REMOVE_MESSAGE: &str = "rpc is classified for removal; enable SEKAI_EXPERIMENTAL_RPCS=1 to invoke during the deprecation window";
const UNKNOWN_MESSAGE: &str = "rpc has no maturity classification";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcClassification {
    Stable,
    Experimental,
    Remove,
}

impl RpcClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Experimental => "experimental",
            Self::Remove => "remove",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RpcMaturityEntry {
    pub service: String,
    pub rpc: String,
    pub storage_path: String,
    pub real_backend: String,
    pub consumer: String,
    pub classification: RpcClassification,
    #[serde(default)]
    pub product_tier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RpcMaturityTable {
    pub version: String,
    pub issue: u64,
    pub stable_limit: usize,
    pub experimental_env: String,
    pub experimental_feature: String,
    pub entries: Vec<RpcMaturityEntry>,
}

impl RpcMaturityTable {
    pub fn load() -> Result<Self, String> {
        let table: Self = serde_json::from_str(MATURITY_JSON)
            .map_err(|error| format!("parse rpc maturity table: {error}"))?;
        table.validate()?;
        Ok(table)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != MATURITY_CONTRACT {
            return Err(format!(
                "unsupported maturity version {:?}; expected {MATURITY_CONTRACT:?}",
                self.version
            ));
        }
        if self.issue != 871 {
            return Err(format!(
                "maturity table issue must be 871, got {}",
                self.issue
            ));
        }
        if self.stable_limit != STABLE_LIMIT {
            return Err(format!(
                "stable_limit must be {STABLE_LIMIT}, got {}",
                self.stable_limit
            ));
        }
        if self.experimental_env != EXPERIMENTAL_ENV {
            return Err(format!(
                "experimental_env must be {EXPERIMENTAL_ENV}, got {}",
                self.experimental_env
            ));
        }
        if self.experimental_feature != EXPERIMENTAL_FEATURE {
            return Err(format!(
                "experimental_feature must be {EXPERIMENTAL_FEATURE}, got {}",
                self.experimental_feature
            ));
        }
        let proto = proto_rpc_keys()?;
        let mut seen = BTreeSet::new();
        let mut stable = 0usize;
        for entry in &self.entries {
            if entry.rpc.trim().is_empty() || entry.rpc != entry.rpc.trim() {
                return Err("maturity table contains an empty or padded rpc name".into());
            }
            if !matches!(entry.service.as_str(), "SekaiService" | "ChiseiService") {
                return Err(format!("unknown maturity service {}", entry.service));
            }
            if !matches!(
                entry.real_backend.as_str(),
                "yes" | "sqlite only" | "fixture only"
            ) {
                return Err(format!(
                    "rpc {} real_backend must be yes, sqlite only, or fixture only",
                    entry.rpc
                ));
            }
            if entry.storage_path.trim().is_empty() {
                return Err(format!("rpc {} is missing a storage path", entry.rpc));
            }
            if entry.consumer.trim().is_empty() {
                return Err(format!("rpc {} is missing a consumer label", entry.rpc));
            }
            let key = rpc_key(&entry.service, &entry.rpc);
            if !seen.insert(key.clone()) {
                return Err(format!("duplicate maturity rpc {key}"));
            }
            if !proto.contains(&key) {
                return Err(format!("maturity rpc {key} is not in proto"));
            }
            if entry.classification == RpcClassification::Stable {
                stable += 1;
                if entry.real_backend != "yes" {
                    return Err(format!(
                        "stable rpc {} needs a real backend on every community runtime",
                        entry.rpc
                    ));
                }
            }
            if entry.real_backend == "fixture only"
                && entry.classification == RpcClassification::Stable
            {
                return Err(format!("fixture-only rpc {} cannot be stable", entry.rpc));
            }
        }
        if seen != proto {
            let missing: Vec<_> = proto.difference(&seen).cloned().collect();
            return Err(format!(
                "maturity table is missing proto RPCs: {}",
                missing.join(", ")
            ));
        }
        if stable > STABLE_LIMIT {
            return Err(format!(
                "stable RPC count {stable} exceeds the {STABLE_LIMIT} target"
            ));
        }
        Ok(())
    }

    pub fn entry(&self, service: &str, rpc: &str) -> Option<&RpcMaturityEntry> {
        self.entries
            .iter()
            .find(|entry| entry.service == service && entry.rpc == rpc)
    }

    pub fn by_rpc(&self) -> BTreeMap<String, &RpcMaturityEntry> {
        self.entries
            .iter()
            .map(|entry| (entry.rpc.clone(), entry))
            .collect()
    }

    pub fn classification_of(&self, rpc: &str) -> Option<RpcClassification> {
        self.entries
            .iter()
            .find(|entry| entry.rpc == rpc)
            .map(|entry| entry.classification)
    }

    pub fn stable_rpcs(&self) -> BTreeSet<&str> {
        self.entries
            .iter()
            .filter(|entry| entry.classification == RpcClassification::Stable)
            .map(|entry| entry.rpc.as_str())
            .collect()
    }
}

/// Public RPCs `sekaictl ontology apply|seed|run|first-run` actually invokes.
/// This is the advertised define → seed → plan → receipt loop, not the full
/// stable wire set.
pub const ADVERTISED_PRODUCT_LOOP_RPCS: &[&str] = &[
    "CreateSchemaType",
    "CreateOntologyClass",
    "CreateOntologyRelation",
    "CreateObject",
    "CreateLink",
    "PlanExecution",
    "ExecutePlanStream",
    "GetOperationReceipt",
    "RetrieveContext",
    "ExpandRelations",
    "ExplainDerivation",
];

/// Additional typed SDK helpers that are not part of `sekaictl ontology` but
/// are called by `sdk/` facades.
pub const ADVERTISED_SDK_TYPED_RPCS: &[&str] = &["GetQualityTrend"];

pub fn advertised_product_loop_rpcs() -> &'static [&'static str] {
    ADVERTISED_PRODUCT_LOOP_RPCS
}

pub fn advertised_sdk_typed_rpcs() -> &'static [&'static str] {
    ADVERTISED_SDK_TYPED_RPCS
}

fn rpc_key(service: &str, rpc: &str) -> String {
    format!("{service}.{rpc}")
}

fn proto_rpc_keys() -> Result<BTreeSet<String>, String> {
    let mut keys = BTreeSet::new();
    for rpc in parse_sekai_service_rpcs(SEKAI_SERVICE_PROTO)? {
        keys.insert(rpc_key("SekaiService", rpc));
    }
    for rpc in parse_named_service_rpcs(CHISEI_SERVICE_PROTO, "ChiseiService")? {
        keys.insert(rpc_key("ChiseiService", rpc));
    }
    Ok(keys)
}

/// Runtime or compile-time permission to invoke experimental and remove RPCs.
pub fn experimental_rpcs_enabled() -> bool {
    cfg!(feature = "experimental-rpcs") || env_flag(EXPERIMENTAL_ENV)
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1" | "true" | "yes" | "on")
    )
}

pub fn require_invokable(rpc: &str, experimental_enabled: bool) -> Result<(), Status> {
    match loaded_classification(rpc) {
        Some(RpcClassification::Stable) => Ok(()),
        Some(RpcClassification::Experimental) if experimental_enabled => Ok(()),
        Some(RpcClassification::Experimental) => {
            Err(Status::failed_precondition(EXPERIMENTAL_MESSAGE))
        }
        Some(RpcClassification::Remove) if experimental_enabled => Ok(()),
        Some(RpcClassification::Remove) => Err(Status::failed_precondition(REMOVE_MESSAGE)),
        None => Err(Status::failed_precondition(UNKNOWN_MESSAGE)),
    }
}

fn embedded_table() -> &'static RpcMaturityTable {
    static TABLE: OnceLock<RpcMaturityTable> = OnceLock::new();
    TABLE.get_or_init(|| RpcMaturityTable::load().expect("embedded rpc maturity table"))
}

fn loaded_classification(rpc: &str) -> Option<RpcClassification> {
    embedded_table().classification_of(rpc)
}

pub fn require_path(path: &str, experimental_enabled: bool) -> Result<(), Status> {
    let trimmed = path.trim_start_matches('/');
    let mut parts = trimmed.splitn(2, '/');
    let service = parts.next().unwrap_or_default();
    let method = parts.next().unwrap_or_default();
    if service.is_empty() || method.is_empty() {
        return Err(Status::failed_precondition(UNKNOWN_MESSAGE));
    }
    if service == "grpc.health.v1.Health" {
        return Ok(());
    }
    require_invokable(method, experimental_enabled)
}

/// Map a discovered capability name onto its backing public RPC, when one exists.
pub fn capability_backing_rpc(name: &str) -> Option<&'static str> {
    match name {
        EXPERIMENTAL_CAPABILITY => None,
        "sekai.objects.evaluate_set" => Some("EvaluateObjectSet"),
        "sekai.objects.read_change_subscription" => Some("ReadObjectChangeSubscription"),
        "sekai.relations.traverse" => Some("Traverse"),
        "sekai.semantic.expand_relations" => Some("ExpandRelations"),
        "sekai.context.retrieve" => Some("RetrieveContext"),
        "sekai.semantic.explain_derivation" => Some("ExplainDerivation"),
        "chisei.kioku.candidates.list" => Some("ListKiokuCandidates"),
        other if other.starts_with("sekai.objects.query.") => Some("ListObjects"),
        other if other.starts_with("sekai.actions.") || other.starts_with("sekai.action.") => {
            Some("SubmitActionInstance")
        }
        _ => None,
    }
}

pub fn capability_is_stable(name: &str) -> bool {
    capability_backing_rpc(name)
        .and_then(loaded_classification)
        .is_some_and(|class| class == RpcClassification::Stable)
}

pub fn parse_docs_rpcs(docs: &str) -> Result<BTreeSet<String>, String> {
    let start = docs
        .find("<!-- rpc-maturity-rows -->")
        .ok_or_else(|| "docs/rpc-maturity.md is missing the row marker".to_string())?;
    let table = docs[start..]
        .split("<!-- /rpc-maturity-rows -->")
        .next()
        .ok_or_else(|| "docs/rpc-maturity.md is missing the closing row marker".to_string())?;
    let mut rpcs = BTreeSet::new();
    for line in table.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("| `")
            || trimmed.starts_with("| RPC")
            || trimmed.starts_with("| ---")
        {
            continue;
        }
        let Some(cell) = trimmed.strip_prefix("| `") else {
            continue;
        };
        let name = cell.split('`').next().unwrap_or_default();
        if name.contains('.') {
            rpcs.insert(name.to_string());
        }
    }
    if rpcs.is_empty() {
        return Err("docs/rpc-maturity.md has no RPC rows".into());
    }
    Ok(rpcs)
}

#[derive(Clone, Debug)]
pub struct RpcMaturityLayer {
    /// `None` re-reads the env/feature flag on each request so discovery and
    /// the wire gate stay aligned without a restart.
    experimental_enabled: Option<bool>,
}

impl RpcMaturityLayer {
    pub fn from_env() -> Self {
        Self {
            experimental_enabled: None,
        }
    }

    pub fn new(experimental_enabled: bool) -> Self {
        Self {
            experimental_enabled: Some(experimental_enabled),
        }
    }
}

impl Default for RpcMaturityLayer {
    fn default() -> Self {
        Self::new(false)
    }
}

impl<S> Layer<S> for RpcMaturityLayer {
    type Service = RpcMaturityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcMaturityService {
            inner,
            experimental_enabled: self.experimental_enabled,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RpcMaturityService<S> {
    inner: S,
    experimental_enabled: Option<bool>,
}

impl<S> NamedService for RpcMaturityService<S>
where
    S: NamedService,
{
    const NAME: &'static str = S::NAME;
}

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for RpcMaturityService<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = http::Response<ResBody>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        let enabled = self
            .experimental_enabled
            .unwrap_or_else(experimental_rpcs_enabled);
        match require_path(req.uri().path(), enabled) {
            Ok(()) => {
                let mut inner = self.inner.clone();
                Box::pin(async move { inner.call(req).await })
            }
            Err(status) => Box::pin(async move { Ok(status.into_http()) }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use tower::ServiceExt;

    #[test]
    fn table_matches_proto_and_stays_within_the_stable_limit() {
        let table = RpcMaturityTable::load().expect("maturity table");
        assert_eq!(table.entries.len(), 174);
        assert_eq!(table.stable_rpcs().len(), 66);
        assert!(
            table
                .entries
                .iter()
                .filter(|entry| entry.real_backend == "fixture only")
                .all(|entry| entry.classification != RpcClassification::Stable)
        );
        for rpc in [
            "CreateDataset",
            "UpdateDataset",
            "AppendRows",
            "QueryRows",
            "DecideGatewayExecution",
            "RecordUsage",
            "ClaimGatewayDispatch",
        ] {
            assert_eq!(
                table.classification_of(rpc),
                Some(RpcClassification::Stable),
                "{rpc} is used by the gateway host"
            );
        }
        for rpc in [
            "CreateDataset",
            "UpdateDataset",
            "AppendRows",
            "QueryRows",
            "DecideGatewayExecution",
            "RecordUsage",
            "ClaimGatewayDispatch",
        ] {
            assert_eq!(
                table.classification_of(rpc),
                Some(RpcClassification::Stable),
                "{rpc} is used by the gateway host"
            );
        }
    }

    #[test]
    fn docs_table_matches_fixture_and_proto() {
        let table = RpcMaturityTable::load().expect("maturity table");
        let docs = parse_docs_rpcs(MATURITY_DOCS).expect("docs rows");
        let fixture: BTreeSet<_> = table
            .entries
            .iter()
            .map(|entry| rpc_key(&entry.service, &entry.rpc))
            .collect();
        assert_eq!(docs, fixture);
        assert_eq!(docs, proto_rpc_keys().expect("proto keys"));
    }

    #[test]
    fn advertised_product_loop_rpcs_are_stable() {
        let table = RpcMaturityTable::load().expect("maturity table");
        for rpc in advertised_product_loop_rpcs()
            .iter()
            .chain(advertised_sdk_typed_rpcs())
        {
            assert_eq!(
                table.classification_of(rpc),
                Some(RpcClassification::Stable),
                "advertised loop rpc {rpc} must stay invokable on the default build"
            );
        }
    }

    #[test]
    fn default_gate_rejects_experimental_and_remove() {
        assert!(require_invokable("CreateObject", false).is_ok());
        assert_eq!(
            require_invokable("CreateFunction", false)
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            require_invokable("ListKiokuCandidates", false)
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        assert!(require_invokable("CreateFunction", true).is_ok());
        assert!(require_invokable("ListKiokuCandidates", true).is_ok());
    }

    #[test]
    fn stable_capabilities_need_no_denylist() {
        assert!(capability_is_stable("sekai.objects.query.Widget"));
        assert!(capability_is_stable("sekai.action.assign_color"));
        assert!(capability_is_stable("sekai.semantic.expand_relations"));
        assert!(!capability_is_stable("chisei.kioku.candidates.list"));
        assert!(!capability_is_stable(EXPERIMENTAL_CAPABILITY));
    }

    #[tokio::test]
    async fn default_layer_cannot_reach_experimental_rpcs() {
        let inner = tower::service_fn(|_req: http::Request<tonic::body::Body>| async {
            Ok::<_, Infallible>(http::Response::new(tonic::body::Body::default()))
        });
        let mut denied = RpcMaturityLayer::default().layer(inner);
        let experimental = http::Request::builder()
            .uri("/sekai.SekaiService/CreateFunction")
            .body(tonic::body::Body::default())
            .unwrap();
        let response = denied
            .ready()
            .await
            .unwrap()
            .call(experimental)
            .await
            .unwrap();
        assert_eq!(
            response.headers().get("grpc-status").unwrap(),
            "9",
            "experimental RPCs must fail closed in the default build"
        );

        let mut allowed = RpcMaturityLayer::default().layer(inner);
        let stable = http::Request::builder()
            .uri("/sekai.SekaiService/CreateObject")
            .body(tonic::body::Body::default())
            .unwrap();
        let response = allowed.ready().await.unwrap().call(stable).await.unwrap();
        assert!(
            response.headers().get("grpc-status").is_none(),
            "stable RPCs remain reachable"
        );
    }

    #[tokio::test]
    async fn enabled_layer_reaches_experimental_rpcs() {
        let inner = tower::service_fn(|_req: http::Request<tonic::body::Body>| async {
            Ok::<_, Infallible>(http::Response::new(tonic::body::Body::default()))
        });
        let mut svc = RpcMaturityLayer::new(true).layer(inner);
        let experimental = http::Request::builder()
            .uri("/sekai.SekaiService/CreateFunction")
            .body(tonic::body::Body::default())
            .unwrap();
        let response = svc.ready().await.unwrap().call(experimental).await.unwrap();
        assert!(response.headers().get("grpc-status").is_none());
    }
}
