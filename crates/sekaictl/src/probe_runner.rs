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
//!
//! Declarative probe specs (`crate::probe_spec`, #1680) run after the
//! built-in probes, behind the same guard and into the same ledger. A spec
//! call that succeeds is a bypass with the spec as its reproduction; one
//! denied otherwise than the spec expects is a mismatch.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tonic::{Code, Request};

use crate::probe_spec::{ProbeSpec, SpecCall, SpecPrincipal, SpecVerdict};
use sekai_proto::sekai::GetObjectRequest;
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;

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
#[non_exhaustive]
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
#[non_exhaustive]
pub enum ProbeOutcome {
    /// The expected denial was observed.
    Denied,
    /// The read succeeded: an isolation bypass.
    Bypass,
    /// Neither: the probe could not decide (transport error, other status).
    Error(String),
    /// A spec's call was denied, but not as the spec expects: a finding.
    Mismatch(String),
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
    /// `None` for a refused run and for a spec.
    pub probe: Option<ProbeKind>,
    /// The spec id, for a spec's attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
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

fn spec_advisory(spec: &ProbeSpec, target: &ProbeTarget, attempt: &Attempt) -> AdvisoryDraft {
    let caller = match spec.principal {
        SpecPrincipal::Tenant => format!(
            "Authenticate as a principal of tenant namespace `{}`.",
            target.tenant
        ),
        SpecPrincipal::Anonymous => "Call with no credential.".to_string(),
    };
    let spec_json = serde_json::to_string_pretty(spec).unwrap_or_default();
    AdvisoryDraft {
        summary: format!("Isolation bypass: probe spec {} was not denied", spec.id),
        description: format!(
            "Probe spec `{}` expected {} but the call succeeded.\n\n### Reproduction\n\n\
             1. {caller}\n2. Call {} for object `{}` of tenant namespace `{}`.\n\
             3. Observe that it succeeds.\n\n### Probe spec\n\n\
             Promote it into the regression catalogue as a failing probe by adding it to \
             `tests/fixtures/probe_specs/`.\n\n```json\n{spec_json}\n```\n\n\
             Probe attempt `{}` at {} ms, recorded in the probe ledger.",
            spec.id,
            spec.expect.codes.join(" or "),
            spec.call.rpc(),
            target.foreign_object_id,
            target.foreign_tenant,
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
    use std::io::{Seek, SeekFrom};
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
    let len = file
        .seek(SeekFrom::End(0))
        .map_err(|error| format!("probe ledger: {error}"))?;
    let keep =
        whole_records_len(&mut file, len).map_err(|error| format!("probe ledger: {error}"))?;
    if keep != len {
        file.set_len(keep)
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

/// Length of `ledger`'s leading whole lines, given its total `len`. An intact
/// ledger costs one byte read; a torn last line is scanned back in chunks
/// only as far as the previous newline.
fn whole_records_len<R: std::io::Read + std::io::Seek>(
    ledger: &mut R,
    len: u64,
) -> std::io::Result<u64> {
    use std::io::SeekFrom;
    const CHUNK: u64 = 4096;
    let mut last = [0u8; 1];
    if len == 0 {
        return Ok(0);
    }
    ledger.seek(SeekFrom::Start(len - 1))?;
    ledger.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(len);
    }
    let mut end = len - 1;
    let mut buf = vec![0u8; CHUNK as usize];
    while end > 0 {
        let start = end.saturating_sub(CHUNK);
        let chunk = &mut buf[..(end - start) as usize];
        ledger.seek(SeekFrom::Start(start))?;
        ledger.read_exact(chunk)?;
        if let Some(at) = chunk.iter().rposition(|byte| *byte == b'\n') {
            return Ok(start + at as u64 + 1);
        }
        end = start;
    }
    Ok(0)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

type Client = SekaiServiceClient<sekai_admin_client::client::GatewayClient>;

async fn client(endpoint: &str, token: Option<&str>) -> Result<Client, String> {
    sekai_admin_client::client::connect_sekai_with_token(
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
) -> Result<sekai_proto::sekai::GetObjectResponse, tonic::Status> {
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

/// Call `spec` on the run's foreign object, bounded end to end.
pub(crate) async fn call_spec(
    mut client: Client,
    spec: &ProbeSpec,
    object_id: String,
) -> Result<(), tonic::Status> {
    use sekai_proto::sekai::{
        GetLineageRequest, GetLinkedObjectsRequest, GetLinksRequest, ListObjectCommentsRequest,
    };
    let call = async {
        match &spec.call {
            SpecCall::GetObject {} => client
                .get_object(Request::new(GetObjectRequest { id: object_id }))
                .await
                .map(drop),
            SpecCall::GetLinks {
                relation,
                direction,
            } => client
                .get_links(Request::new(GetLinksRequest {
                    object_id,
                    relation: relation.clone(),
                    direction: direction.clone(),
                }))
                .await
                .map(drop),
            SpecCall::GetLinkedObjects {
                relation,
                direction,
            } => client
                .get_linked_objects(Request::new(GetLinkedObjectsRequest {
                    object_id,
                    relation: relation.clone(),
                    direction: direction.clone(),
                }))
                .await
                .map(drop),
            SpecCall::ListObjectComments { include_resolved } => client
                .list_object_comments(Request::new(ListObjectCommentsRequest {
                    object_id,
                    include_resolved: *include_resolved,
                }))
                .await
                .map(drop),
            SpecCall::GetLineage { max_nodes } => client
                .get_lineage(Request::new(GetLineageRequest {
                    object_id,
                    max_nodes: *max_nodes,
                }))
                .await
                .map(drop),
        }
    };
    match tokio::time::timeout(CALL_TIMEOUT, call).await {
        Ok(result) => result,
        Err(_) => Err(tonic::Status::deadline_exceeded("probe call timed out")),
    }
}

async fn run_spec(spec: &ProbeSpec, target: &ProbeTarget) -> ProbeOutcome {
    let token = match spec.principal {
        SpecPrincipal::Tenant => Some(target.tenant_token.as_str()),
        SpecPrincipal::Anonymous => None,
    };
    let client = match client(&target.endpoint, token).await {
        Ok(client) => client,
        Err(error) => return ProbeOutcome::Error(error),
    };
    let result = call_spec(client, spec, target.foreign_object_id.clone()).await;
    // A target that is unwell proves nothing either way.
    if let Err(status) = &result
        && matches!(
            status.code(),
            Code::Unavailable
                | Code::DeadlineExceeded
                | Code::Unknown
                | Code::Cancelled
                | Code::ResourceExhausted
                | Code::Internal
        )
    {
        return ProbeOutcome::Error(format!("unexpected status {}", status.code()));
    }
    match spec.judge(&result) {
        SpecVerdict::Denied => ProbeOutcome::Denied,
        SpecVerdict::NotDenied => ProbeOutcome::Bypass,
        SpecVerdict::Mismatch(detail) => ProbeOutcome::Mismatch(detail),
    }
}

/// Run every built-in probe, then every spec in `specs`, against `target`
/// once. The specs and the guard are checked first, and a refusal (a spec
/// set that failed to load or validate, or a guard refusal) is recorded as
/// the run's only attempt. Bypasses write advisory drafts under
/// `advisory_dir`.
pub async fn run(
    guard: Result<TargetGuard, String>,
    target: &ProbeTarget,
    specs: Result<Vec<ProbeSpec>, String>,
    ledger: &Path,
    advisory_dir: &Path,
) -> Result<RunReport, String> {
    let attempt = |probe, spec: Option<&ProbeSpec>, outcome| Attempt {
        schema: PROBE_LEDGER_VERSION.into(),
        attempt_id: uuid::Uuid::new_v4().to_string(),
        at_ms: now_ms(),
        endpoint: target.endpoint.clone(),
        tenant: target.tenant.clone(),
        probe,
        spec: spec.map(|spec| spec.id.clone()),
        outcome,
    };
    let admitted = async {
        // Specs are validated before the guard admits anything, so a bad one
        // refuses the run before any call.
        let specs = specs?;
        crate::probe_spec::validate_set(&specs)?;
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
        prepare_advisory_dir(advisory_dir)?;
        Ok(specs)
    }
    .await;
    let specs = match admitted {
        Ok(specs) => specs,
        Err(reason) => {
            let refused = attempt(None, None, ProbeOutcome::Refused(reason.clone()));
            append(ledger, &refused)?;
            return Err(reason);
        }
    };
    let mut report = RunReport {
        attempts: Vec::new(),
        advisories: Vec::new(),
        advisory_failures: Vec::new(),
    };
    for probe in ProbeKind::ALL {
        let outcome = run_probe(probe, target).await;
        let recorded = attempt(Some(probe), None, outcome);
        let draft = || advisory(probe, target, &recorded);
        record(&mut report, recorded.clone(), draft, ledger, advisory_dir)?;
    }
    for spec in &specs {
        let outcome = run_spec(spec, target).await;
        let recorded = attempt(None, Some(spec), outcome);
        let draft = || spec_advisory(spec, target, &recorded);
        record(&mut report, recorded.clone(), draft, ledger, advisory_dir)?;
    }
    Ok(report)
}

/// Ledger one attempt. A bypass writes its advisory draft first; a crash in
/// between only leaves a draft, and the next run detects the bypass again.
/// A draft that cannot be written never hides the finding.
fn record(
    report: &mut RunReport,
    recorded: Attempt,
    draft: impl FnOnce() -> AdvisoryDraft,
    ledger: &Path,
    advisory_dir: &Path,
) -> Result<(), String> {
    if recorded.outcome == ProbeOutcome::Bypass {
        let name = format!("advisory-{}.json", recorded.attempt_id);
        let written = serde_json::to_vec_pretty(&draft())
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
    Ok(())
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
            ProbeOutcome::Mismatch(_) => "mismatch",
            ProbeOutcome::Refused(_) => {
                summary.refused_runs += 1;
                "refused"
            }
        };
        let probe = match (&attempt.probe, &attempt.spec) {
            (Some(probe), _) => format!("{probe:?}"),
            (None, Some(spec)) => format!("spec:{spec}"),
            (None, None) => "guard".to_string(),
        };
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

    /// Counts bytes read so a test can bound the repair scan.
    struct Counted(std::io::Cursor<Vec<u8>>, usize);

    impl std::io::Read for Counted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let read = self.0.read(buf)?;
            self.1 += read;
            Ok(read)
        }
    }

    impl std::io::Seek for Counted {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.0.seek(pos)
        }
    }

    fn keep(bytes: &[u8]) -> (u64, usize) {
        let mut ledger = Counted(std::io::Cursor::new(bytes.to_vec()), 0);
        let kept = whole_records_len(&mut ledger, bytes.len() as u64).unwrap();
        (kept, ledger.1)
    }

    #[test]
    fn ledger_repair_reads_only_the_tail() {
        let mut intact = b"{\"a\":1}\n".repeat(10_000);
        assert_eq!(keep(&intact), (intact.len() as u64, 1));
        let whole = intact.len() as u64;
        intact.extend_from_slice(b"{\"torn\":");
        let (kept, read) = keep(&intact);
        assert_eq!(kept, whole);
        assert!(read <= 1 + 4096, "{read}");
        // A torn line longer than one chunk still finds the last newline.
        let mut long = b"{\"a\":1}\n".to_vec();
        long.extend(std::iter::repeat_n(b'x', 10_000));
        assert_eq!(keep(&long).0, 8);
        assert_eq!(keep(b"").0, 0);
        assert_eq!(keep(b"no newline at all").0, 0);
    }

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
}
