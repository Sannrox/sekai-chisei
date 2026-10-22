//! Guarded runner for isolation probes against a deployment (#1621).
//!
//! The runner checks the remote object-read surface of one deployment, as
//! principals of two synthetic tenants: a read without a credential and a
//! read of the other tenant's object must both be denied. These are generic
//! checks; the specific regressions in the isolation probe catalogue (#1620)
//! stay covered in-process by the test suite. A target guard is the safety boundary and fails closed: the
//! endpoint must be on the allow-list in `SEKAI_PROBE_TARGET_ALLOWLIST`, and
//! both tenants' namespace boundaries must carry the synthetic marker, read
//! with each tenant's own credential. A missing allow-list refuses every
//! target.
//!
//! Every attempt, including a refused one, is appended to a JSON Lines
//! ledger (fsynced) that the weekly summary is computed from. A bypass
//! produces a private security advisory draft with reproduction steps,
//! written owner-only to a local file for the repository's private reporting
//! flow (SECURITY.md); the runner never opens an issue or posts anything. The
//! probed object must exist in the foreign tenant, read as that tenant, so a
//! stale id cannot pass for a denial.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tonic::{Code, Request};

use crate::grpc::pb::sekai::GetObjectRequest;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;

pub const PROBE_LEDGER_VERSION: &str = "sekai.probe-ledger/v1";
pub const ALLOWLIST_ENV: &str = "SEKAI_PROBE_TARGET_ALLOWLIST";

const WEEK_MS: i64 = 7 * 86_400_000;
/// Bound on connecting and on each call, so a hung target becomes a
/// recorded failure instead of a hung scheduled run.
const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// One deployment and the two synthetic tenants the probes act as.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub endpoint: String,
    /// The probing tenant's namespace and a principal credential in it.
    pub tenant: String,
    pub tenant_token: String,
    /// The other tenant, whose object the probing tenant must not read.
    pub foreign_tenant: String,
    pub foreign_token: String,
    pub foreign_object_id: String,
}

/// Endpoints probes may reach. Built only from the environment, so a
/// target cannot vouch for itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetGuard {
    allowed: Vec<String>,
}

impl TargetGuard {
    /// The allow-list from `SEKAI_PROBE_TARGET_ALLOWLIST` (comma-separated
    /// endpoints). Missing or empty refuses.
    pub fn from_env() -> Result<Self, String> {
        Self::parse(std::env::var(ALLOWLIST_ENV).ok().as_deref())
    }

    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        let allowed: Vec<String> = raw
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|endpoint| !endpoint.is_empty())
            .map(str::to_string)
            .collect();
        if allowed.is_empty() {
            return Err(format!(
                "{ALLOWLIST_ENV} is not set; refusing every probe target"
            ));
        }
        Ok(Self { allowed })
    }

    /// The endpoint must match an allow-listed endpoint exactly.
    pub fn admit_endpoint(&self, endpoint: &str) -> Result<(), String> {
        if self.allowed.iter().any(|allowed| allowed == endpoint) {
            Ok(())
        } else {
            Err(format!("probe target {endpoint} is not on the allow-list"))
        }
    }
}

/// Whether a namespace boundary's properties carry the synthetic marker.
pub fn boundary_is_synthetic(properties: &std::collections::HashMap<String, String>) -> bool {
    properties.get("synthetic").map(String::as_str) == Some("true")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    /// A read without a credential.
    UnauthenticatedRead,
    /// The probing tenant reads the other tenant's object.
    CrossTenantRead,
}

impl ProbeKind {
    pub const ALL: [ProbeKind; 2] = [ProbeKind::UnauthenticatedRead, ProbeKind::CrossTenantRead];

    pub fn expected_denial(self) -> &'static str {
        match self {
            Self::UnauthenticatedRead => "Unauthenticated or PermissionDenied",
            Self::CrossTenantRead => "PermissionDenied or NotFound",
        }
    }

    fn reproduction(self, target: &ProbeTarget) -> Vec<String> {
        match self {
            Self::UnauthenticatedRead => vec![
                format!(
                    "Call SekaiService.GetObject on the deployment for object `{}` with no credential.",
                    target.foreign_object_id
                ),
                "Observe that the object is returned instead of Unauthenticated.".into(),
            ],
            Self::CrossTenantRead => vec![
                format!(
                    "Authenticate as a principal of tenant namespace `{}`.",
                    target.tenant
                ),
                format!(
                    "Call SekaiService.GetObject for object `{}` of tenant namespace `{}`.",
                    target.foreign_object_id, target.foreign_tenant
                ),
                "Observe that the object is returned instead of PermissionDenied or NotFound."
                    .into(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "detail")]
pub enum ProbeOutcome {
    /// The expected denial was observed.
    Denied,
    /// The read succeeded: an isolation bypass.
    Bypass,
    /// Neither: the probe could not decide (transport error, other status).
    Error(String),
    /// The target guard refused the run before any probe.
    Refused(String),
}

/// One ledger line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub schema: String,
    pub attempt_id: String,
    pub at_ms: i64,
    pub endpoint: String,
    pub tenant: String,
    /// `None` for a refused run.
    pub probe: Option<ProbeKind>,
    #[serde(flatten)]
    pub outcome: ProbeOutcome,
}

/// A private security advisory draft: the request body of a repository
/// security advisory, kept as a local file for maintainers to submit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryDraft {
    pub summary: String,
    pub description: String,
    pub severity: String,
    pub vulnerabilities: Vec<serde_json::Value>,
}

fn advisory(probe: ProbeKind, target: &ProbeTarget, attempt: &Attempt) -> AdvisoryDraft {
    let steps = probe
        .reproduction(target)
        .iter()
        .enumerate()
        .map(|(index, step)| format!("{}. {step}", index + 1))
        .collect::<Vec<_>>()
        .join("\n");
    AdvisoryDraft {
        summary: format!("Isolation bypass: {probe:?} probe was not denied"),
        description: format!(
            "The `{probe:?}` isolation probe expected {} \
             but the read succeeded.\n\n### Reproduction\n\n{steps}\n\n\
             Probe attempt `{}` at {} ms, recorded in the probe ledger.",
            probe.expected_denial(),
            attempt.attempt_id,
            attempt.at_ms
        ),
        severity: "high".into(),
        vulnerabilities: vec![serde_json::json!({
            "package": {"ecosystem": "other", "name": "sekai-chisei"},
        })],
    }
}

/// The outcome of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub attempts: Vec<Attempt>,
    /// Advisory draft files written for bypasses.
    pub advisories: Vec<PathBuf>,
    /// Bypasses recorded whose draft could not be written; retry by hand.
    pub advisory_failures: Vec<String>,
}

fn append(ledger: &Path, attempt: &Attempt) -> Result<(), String> {
    use std::io::{Read, Seek, SeekFrom};
    if let Some(parent) = ledger.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(ledger)
        .map_err(|error| format!("probe ledger: {error}"))?;
    // Overlapping runs serialize the whole repair-and-append on the ledger.
    file.lock()
        .map_err(|error| format!("probe ledger lock: {error}"))?;
    // A crash mid-append leaves a torn last line; drop it so every line
    // stays a whole record.
    let mut text = Vec::new();
    file.read_to_end(&mut text)
        .map_err(|error| format!("probe ledger: {error}"))?;
    if text.last().is_some_and(|byte| *byte != b'\n') {
        let keep = text
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |at| at + 1);
        file.set_len(keep as u64)
            .map_err(|error| format!("probe ledger: {error}"))?;
    }
    file.seek(SeekFrom::End(0))
        .map_err(|error| format!("probe ledger: {error}"))?;
    let mut line = serde_json::to_string(attempt).map_err(|error| error.to_string())?;
    line.push('\n');
    file.write_all(line.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("probe ledger: {error}"))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

type Client = SekaiServiceClient<crate::grpc::client::GatewayClient>;

async fn client(endpoint: &str, token: Option<&str>) -> Result<Client, String> {
    crate::grpc::client::connect_sekai_with_token(
        endpoint,
        token.map(str::to_string),
        Some(CALL_TIMEOUT),
    )
    .await
    .map(SekaiServiceClient::new)
    .map_err(|error| format!("cannot reach the probe target: {error}"))
}

/// `GetObject` bounded end to end; the transport timeout stops at response
/// headers, so a target that stalls after them would hang the run.
async fn get_object(
    mut client: Client,
    id: String,
) -> Result<crate::grpc::pb::sekai::GetObjectResponse, tonic::Status> {
    match tokio::time::timeout(
        CALL_TIMEOUT,
        client.get_object(Request::new(GetObjectRequest { id })),
    )
    .await
    {
        Ok(response) => response.map(tonic::Response::into_inner),
        Err(_) => Err(tonic::Status::deadline_exceeded("probe call timed out")),
    }
}

/// Read `namespace:<namespace>` as that tenant and require the marker.
async fn require_synthetic(endpoint: &str, namespace: &str, token: &str) -> Result<(), String> {
    let boundary = get_object(
        client(endpoint, Some(token)).await?,
        format!("namespace:{namespace}"),
    )
    .await
    .map_err(|status| {
        format!(
            "tenant {namespace} boundary is unreadable: {}",
            status.code()
        )
    })?
    .object;
    match boundary {
        Some(object)
            if object.namespace == namespace && boundary_is_synthetic(&object.properties) =>
        {
            Ok(())
        }
        _ => Err(format!("tenant {namespace} is not synthetic")),
    }
}

/// The probed object, read as its own tenant, exists in that tenant.
async fn require_foreign_object(target: &ProbeTarget) -> Result<(), String> {
    let object = get_object(
        client(&target.endpoint, Some(&target.foreign_token)).await?,
        target.foreign_object_id.clone(),
    )
    .await
    .map_err(|status| {
        format!(
            "probe object is unreadable by its own tenant: {}",
            status.code()
        )
    })?
    .object;
    match object {
        Some(object) if object.namespace == target.foreign_tenant => Ok(()),
        _ => Err(format!(
            "probe object is not in tenant {}",
            target.foreign_tenant
        )),
    }
}

/// Create the advisory directory owner-only, or refuse an existing one that
/// others can reach.
fn prepare_advisory_dir(dir: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir)
            .map_err(|error| error.to_string())?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "advisory directory {} must be owner-only (0700)",
                dir.display()
            ));
        }
    }
    Ok(())
}

/// Write one advisory draft readable by the owner only, durably.
fn write_private(dir: &Path, name: &str, body: &[u8]) -> Result<PathBuf, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let path = dir.join(name);
    let mut file = options.open(&path).map_err(|error| error.to_string())?;
    file.write_all(body)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::File::open(dir)?.sync_all())
        .map_err(|error| error.to_string())?;
    Ok(path)
}

async fn run_probe(probe: ProbeKind, target: &ProbeTarget) -> ProbeOutcome {
    let token = match probe {
        ProbeKind::UnauthenticatedRead => None,
        ProbeKind::CrossTenantRead => Some(target.tenant_token.as_str()),
    };
    let client = match client(&target.endpoint, token).await {
        Ok(client) => client,
        Err(error) => return ProbeOutcome::Error(error),
    };
    let read = get_object(client, target.foreign_object_id.clone()).await;
    match (probe, read) {
        (_, Ok(_)) => ProbeOutcome::Bypass,
        (ProbeKind::UnauthenticatedRead, Err(status))
            if matches!(
                status.code(),
                Code::Unauthenticated | Code::PermissionDenied
            ) =>
        {
            ProbeOutcome::Denied
        }
        (ProbeKind::CrossTenantRead, Err(status))
            if matches!(status.code(), Code::PermissionDenied | Code::NotFound) =>
        {
            ProbeOutcome::Denied
        }
        (_, Err(status)) => ProbeOutcome::Error(format!("unexpected status {}", status.code())),
    }
}

/// Run every probe against `target` once. The guard runs first and a
/// refusal is recorded as the run's only attempt. Bypasses write advisory
/// drafts under `advisory_dir`.
pub async fn run(
    guard: Result<TargetGuard, String>,
    target: &ProbeTarget,
    ledger: &Path,
    advisory_dir: &Path,
) -> Result<RunReport, String> {
    let attempt = |probe, outcome| Attempt {
        schema: PROBE_LEDGER_VERSION.into(),
        attempt_id: uuid::Uuid::new_v4().to_string(),
        at_ms: now_ms(),
        endpoint: target.endpoint.clone(),
        tenant: target.tenant.clone(),
        probe,
        outcome,
    };
    let admitted = async {
        let guard = guard?;
        guard.admit_endpoint(&target.endpoint)?;
        if target.tenant == target.foreign_tenant {
            return Err("the two probe tenants must differ".to_string());
        }
        require_synthetic(&target.endpoint, &target.tenant, &target.tenant_token).await?;
        require_synthetic(
            &target.endpoint,
            &target.foreign_tenant,
            &target.foreign_token,
        )
        .await?;
        // The probed object must exist in the foreign tenant, or a NotFound
        // would pass for a denial.
        require_foreign_object(target).await?;
        // Findings need somewhere private to go before any probe runs.
        prepare_advisory_dir(advisory_dir)
    }
    .await;
    if let Err(reason) = admitted {
        let refused = attempt(None, ProbeOutcome::Refused(reason.clone()));
        append(ledger, &refused)?;
        return Err(reason);
    }
    let mut report = RunReport {
        attempts: Vec::new(),
        advisories: Vec::new(),
        advisory_failures: Vec::new(),
    };
    for probe in ProbeKind::ALL {
        let outcome = run_probe(probe, target).await;
        let recorded = attempt(Some(probe), outcome);
        // The draft is written before the ledger records the bypass; a crash
        // in between only leaves a draft, and the next run detects the bypass
        // again. A draft that cannot be written never hides the finding.
        if recorded.outcome == ProbeOutcome::Bypass {
            let name = format!("advisory-{}.json", recorded.attempt_id);
            let written = serde_json::to_vec_pretty(&advisory(probe, target, &recorded))
                .map_err(|error| error.to_string())
                .and_then(|draft| write_private(advisory_dir, &name, &draft));
            match written {
                Ok(path) => report.advisories.push(path),
                Err(error) => report.advisory_failures.push(format!(
                    "attempt {}: advisory draft not written: {error}",
                    recorded.attempt_id
                )),
            }
        }
        append(ledger, &recorded)?;
        report.attempts.push(recorded);
    }
    Ok(report)
}

/// Attempts per probe and outcome over one week.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WeeklySummary {
    pub from_ms: i64,
    pub to_ms: i64,
    pub attempts: usize,
    pub refused_runs: usize,
    /// `probe -> outcome -> count`.
    pub by_probe: BTreeMap<String, BTreeMap<String, usize>>,
    pub bypass_attempts: Vec<String>,
}

/// The week starting at `from_ms`, computed from the ledger alone.
pub fn weekly_summary(ledger: &Path, from_ms: i64) -> Result<WeeklySummary, String> {
    use std::io::Read;
    // Shared with readers, exclusive with appends, so no half-written line
    // is read; a torn final line from a crash is ignored, as append drops it.
    let mut file = fs::File::open(ledger).map_err(|error| format!("probe ledger: {error}"))?;
    file.lock_shared()
        .map_err(|error| format!("probe ledger lock: {error}"))?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| format!("probe ledger: {error}"))?;
    if !text.ends_with('\n') {
        text.truncate(text.rfind('\n').map_or(0, |at| at + 1));
    }
    let mut summary = WeeklySummary {
        from_ms,
        to_ms: from_ms + WEEK_MS,
        ..Default::default()
    };
    for (number, line) in text.lines().enumerate() {
        let attempt: Attempt = serde_json::from_str(line)
            .map_err(|_| format!("probe ledger line {} is unreadable", number + 1))?;
        if attempt.schema != PROBE_LEDGER_VERSION
            || attempt.at_ms < summary.from_ms
            || attempt.at_ms >= summary.to_ms
        {
            continue;
        }
        summary.attempts += 1;
        let outcome = match &attempt.outcome {
            ProbeOutcome::Denied => "denied",
            ProbeOutcome::Bypass => {
                summary.bypass_attempts.push(attempt.attempt_id.clone());
                "bypass"
            }
            ProbeOutcome::Error(_) => "error",
            ProbeOutcome::Refused(_) => {
                summary.refused_runs += 1;
                "refused"
            }
        };
        let probe = attempt
            .probe
            .map_or_else(|| "guard".to_string(), |probe| format!("{probe:?}"));
        *summary
            .by_probe
            .entry(probe)
            .or_default()
            .entry(outcome.into())
            .or_insert(0) += 1;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_guard_fails_closed_without_an_allow_list() {
        assert!(TargetGuard::parse(None).is_err());
        assert!(TargetGuard::parse(Some(" , ")).is_err());
        let guard = TargetGuard::parse(Some("https://probe.example.test:443")).unwrap();
        assert!(
            guard
                .admit_endpoint("https://probe.example.test:443")
                .is_ok()
        );
        for other in [
            "https://probe.example.test",
            "https://probe.example.test:443/",
            "http://probe.example.test:443",
        ] {
            assert!(guard.admit_endpoint(other).is_err(), "{other}");
        }
    }

    #[test]
    fn only_a_boundary_marked_synthetic_admits_a_tenant() {
        let mut properties = std::collections::HashMap::new();
        assert!(!boundary_is_synthetic(&properties));
        properties.insert("synthetic".into(), "yes".into());
        assert!(!boundary_is_synthetic(&properties));
        properties.insert("synthetic".into(), "true".into());
        assert!(boundary_is_synthetic(&properties));
    }

    use std::sync::Arc;

    use crate::db::runtime_db::RuntimeDb;
    use crate::gateway_keys::hash_gateway_key;
    use crate::grpc::TokenAuthInterceptor;
    use crate::grpc::pb::sekai::sekai_service_server::SekaiServiceServer;
    use crate::sekai::credentials::PrincipalCredentialStore;
    use crate::sekai::security::{Grant, Role};
    use crate::sekai::synthetic::{SizePreset, Spec, SupplyChain, SyntheticPlan, apply, generate};

    /// A deployment-like target: the real service behind token
    /// authentication on an ephemeral port, with two synthetic tenants.
    struct Deployment {
        endpoint: String,
        db: Arc<RuntimeDb>,
        north: SyntheticPlan,
        south: SyntheticPlan,
        _stop: tokio::sync::oneshot::Sender<()>,
    }

    fn viewer(plan: &SyntheticPlan) -> String {
        plan.principals
            .iter()
            .find(|principal| principal.role == "viewer")
            .unwrap()
            .id
            .clone()
    }

    async fn deployment(
        extra: impl FnOnce(&RuntimeDb, &SyntheticPlan, &SyntheticPlan),
    ) -> Deployment {
        let db = Arc::new(RuntimeDb::memory());
        let tenant = |namespace: &str, seed| {
            generate(
                &SupplyChain,
                &Spec {
                    namespace: namespace.into(),
                    seed,
                    preset: SizePreset::Demo,
                },
            )
            .unwrap()
        };
        let north = tenant("probe-north", 21);
        let south = tenant("probe-south", 22);
        apply(&db, &north).unwrap();
        apply(&db, &south).unwrap();
        db.create_principal_credential(&viewer(&north), &hash_gateway_key("north-token"), 1)
            .unwrap();
        db.create_principal_credential(&viewer(&south), &hash_gateway_key("south-token"), 1)
            .unwrap();
        extra(&db, &north, &south);
        let credentials = PrincipalCredentialStore::new();
        credentials.load(&db.list_active_credentials().unwrap());
        let store = crate::db::store::SekaiStore::from_shared_runtime(db.clone());
        let service = SekaiServiceServer::with_interceptor(
            crate::grpc::sekai_service::SekaiServiceImpl::new(store.clone()),
            TokenAuthInterceptor::new(Arc::new(credentials), store),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = stopped.await;
                    },
                )
                .await
                .unwrap()
        });
        Deployment {
            endpoint,
            db,
            north,
            south,
            _stop: stop,
        }
    }

    fn target(deployment: &Deployment) -> ProbeTarget {
        ProbeTarget {
            endpoint: deployment.endpoint.clone(),
            tenant: deployment.north.namespace.clone(),
            tenant_token: "north-token".into(),
            foreign_tenant: deployment.south.namespace.clone(),
            foreign_token: "south-token".into(),
            foreign_object_id: deployment.south.objects[0].id.clone(),
        }
    }

    fn ledger_lines(ledger: &Path) -> Vec<Attempt> {
        fs::read_to_string(ledger)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn an_isolating_target_denies_every_probe_and_the_ledger_records_it() {
        let deployment = deployment(|_, _, _| {}).await;
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("ledger.jsonl");
        let guard = TargetGuard::parse(Some(&deployment.endpoint));
        let report = run(
            guard,
            &target(&deployment),
            &ledger,
            &dir.path().join("advisories"),
        )
        .await
        .unwrap();
        let outcomes: Vec<_> = report
            .attempts
            .iter()
            .map(|attempt| attempt.outcome.clone())
            .collect();
        assert_eq!(outcomes, [ProbeOutcome::Denied, ProbeOutcome::Denied]);
        assert!(report.advisories.is_empty());
        assert_eq!(ledger_lines(&ledger), report.attempts);
        // A torn last line from a crash is dropped before the next append.
        let mut torn = fs::OpenOptions::new().append(true).open(&ledger).unwrap();
        torn.write_all(b"{\"schema\":\"sekai.probe-led").unwrap();
        drop(torn);
        run(
            TargetGuard::parse(Some(&deployment.endpoint)),
            &target(&deployment),
            &ledger,
            &dir.path().join("advisories"),
        )
        .await
        .unwrap();
        assert_eq!(ledger_lines(&ledger).len(), 4);
    }

    #[tokio::test]
    async fn the_guard_refuses_a_target_off_the_allow_list_or_a_real_tenant() {
        let deployment = deployment(|db, north, _| {
            // A tenant that exists but is not synthetic, with a credential.
            db.create_object(&crate::domain::Object {
                id: "namespace:real-tenant".into(),
                kind: "namespace".into(),
                name: "real-tenant".into(),
                namespace: "real-tenant".into(),
                external_id: "namespace:real-tenant".into(),
                properties: Default::default(),
                created: 1,
                updated: 1,
            })
            .unwrap();
            db.create_grant(&Grant {
                id: "real-grant".into(),
                object_id: "namespace:real-tenant".into(),
                principal: viewer(north),
                role: Role::Viewer,
                created: 1,
                ..Default::default()
            })
            .unwrap();
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("ledger.jsonl");
        let advisories = dir.path().join("advisories");

        let elsewhere = TargetGuard::parse(Some("https://elsewhere.example.test:443"));
        let refused = run(elsewhere, &target(&deployment), &ledger, &advisories)
            .await
            .unwrap_err();
        assert!(refused.contains("not on the allow-list"), "{refused}");
        let missing = run(
            TargetGuard::parse(None),
            &target(&deployment),
            &ledger,
            &advisories,
        )
        .await
        .unwrap_err();
        assert!(missing.contains(ALLOWLIST_ENV), "{missing}");

        let mut real = target(&deployment);
        real.foreign_tenant = "real-tenant".into();
        real.foreign_token = "north-token".into();
        let refused = run(
            TargetGuard::parse(Some(&deployment.endpoint)),
            &real,
            &ledger,
            &advisories,
        )
        .await
        .unwrap_err();
        assert!(refused.contains("not synthetic"), "{refused}");

        let mut stale = target(&deployment);
        stale.foreign_object_id = "no-such-object".into();
        let refused = run(
            TargetGuard::parse(Some(&deployment.endpoint)),
            &stale,
            &ledger,
            &advisories,
        )
        .await
        .unwrap_err();
        assert!(refused.contains("probe object"), "{refused}");

        // Refusals are attempts too; no probe ran.
        let lines = ledger_lines(&ledger);
        assert_eq!(lines.len(), 4);
        assert!(lines.iter().all(|attempt| attempt.probe.is_none()
            && matches!(attempt.outcome, ProbeOutcome::Refused(_))));
        assert!(!advisories.exists());
    }

    #[tokio::test]
    async fn a_seeded_bypass_produces_a_private_advisory_draft_and_the_summary_counts_it() {
        // A staging-like target with an isolation bug: the north viewer was
        // granted the south tenant's object.
        let deployment = deployment(|db, north, south| {
            db.create_grant(&Grant {
                id: "seeded-bypass".into(),
                object_id: south.objects[0].id.clone(),
                principal: viewer(north),
                role: Role::Viewer,
                created: 1,
                ..Default::default()
            })
            .unwrap();
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("ledger.jsonl");
        let advisories = dir.path().join("advisories");
        let target = target(&deployment);
        let report = run(
            TargetGuard::parse(Some(&deployment.endpoint)),
            &target,
            &ledger,
            &advisories,
        )
        .await
        .unwrap();
        assert_eq!(report.attempts[1].probe, Some(ProbeKind::CrossTenantRead));
        assert_eq!(report.attempts[1].outcome, ProbeOutcome::Bypass);
        assert_eq!(report.advisories.len(), 1);
        let draft: AdvisoryDraft =
            serde_json::from_slice(&fs::read(&report.advisories[0]).unwrap()).unwrap();
        assert_eq!(draft.severity, "high");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&report.advisories[0]), 0o600);
            assert_eq!(mode(&advisories), 0o700);
            // A directory others can reach is refused, even when it exists.
            let shared = dir.path().join("shared");
            fs::create_dir(&shared).unwrap();
            fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
            let refused = run(
                TargetGuard::parse(Some(&deployment.endpoint)),
                &target,
                &dir.path().join("ledger-2.jsonl"),
                &shared,
            )
            .await
            .unwrap_err();
            assert!(refused.contains("owner-only"), "{refused}");
        }
        assert!(draft.description.contains("### Reproduction"));
        assert!(draft.description.contains(&target.foreign_object_id));
        assert!(draft.description.contains(&report.attempts[1].attempt_id));
        // Nothing in the draft names the endpoint or a credential.
        for private in [target.endpoint.as_str(), "north-token", "south-token"] {
            assert!(!draft.description.contains(private), "{private}");
        }

        let summary = weekly_summary(&ledger, report.attempts[0].at_ms - 1_000).unwrap();
        assert_eq!(summary.attempts, 2);
        assert_eq!(summary.by_probe["CrossTenantRead"]["bypass"], 1);
        assert_eq!(summary.by_probe["UnauthenticatedRead"]["denied"], 1);
        assert_eq!(
            summary.bypass_attempts,
            [report.attempts[1].attempt_id.clone()]
        );
        // A torn final line is ignored; a corrupt complete line is not.
        let mut torn = fs::OpenOptions::new().append(true).open(&ledger).unwrap();
        torn.write_all(b"{\"schema\":").unwrap();
        drop(torn);
        assert_eq!(
            weekly_summary(&ledger, report.attempts[0].at_ms - 1_000)
                .unwrap()
                .attempts,
            2
        );
        let mut corrupt = fs::OpenOptions::new().append(true).open(&ledger).unwrap();
        corrupt.write_all(b"\n").unwrap();
        drop(corrupt);
        assert!(weekly_summary(&ledger, report.attempts[0].at_ms - 1_000).is_err());
        let next_week = weekly_summary(&ledger, report.attempts[0].at_ms + WEEK_MS);
        assert!(next_week.is_err());
        let next_week = weekly_summary(&dir.path().join("ledger-2.jsonl"), 0);
        assert_eq!(next_week.unwrap().attempts, 0);
        drop(deployment.db);
    }
}
