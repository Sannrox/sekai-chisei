//! Reusable conformance contracts for enterprise tenant-isolation extensions.

use std::collections::BTreeSet;

pub const TENANT_ISOLATION_CONFORMANCE_VERSION: &str = "sekai.tenant-isolation-conformance/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Transport {
    Grpc,
    Gateway,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SurfaceKind {
    Read,
    Write,
    List,
    Report,
    Receipt,
    Credential,
    Namespace,
    Session,
    Authorization,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Surface {
    pub transport: Transport,
    pub name: String,
    pub kind: SurfaceKind,
    pub valid_human_outcome: ExpectedOutcome,
    pub valid_machine_outcome: ExpectedOutcome,
    pub cross_tenant_identifier_outcome: Option<ExpectedOutcome>,
}

impl Surface {
    pub fn new(
        transport: Transport,
        name: impl Into<String>,
        kind: SurfaceKind,
        valid_human_outcome: ExpectedOutcome,
        valid_machine_outcome: ExpectedOutcome,
    ) -> Self {
        Self {
            transport,
            name: name.into(),
            kind,
            valid_human_outcome,
            valid_machine_outcome,
            cross_tenant_identifier_outcome: None,
        }
    }

    pub fn with_cross_tenant_identifier(mut self, outcome: ExpectedOutcome) -> Self {
        self.cross_tenant_identifier_outcome = Some(outcome);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CallerProfile {
    ValidHuman,
    ValidMachine,
    MissingCredential,
    ExpiredCredential,
    RevokedCredential,
    ForgedCredential,
    MembershipRevoked,
    TenantSuspended,
    CallerForgedTenantMetadataHuman,
    CallerForgedTenantMetadataMachine,
    CrossTenantContext,
    CrossTenantIdentifier,
}

impl CallerProfile {
    pub const ALL: [Self; 12] = [
        Self::ValidHuman,
        Self::ValidMachine,
        Self::MissingCredential,
        Self::ExpiredCredential,
        Self::RevokedCredential,
        Self::ForgedCredential,
        Self::MembershipRevoked,
        Self::TenantSuspended,
        Self::CallerForgedTenantMetadataHuman,
        Self::CallerForgedTenantMetadataMachine,
        Self::CrossTenantContext,
        Self::CrossTenantIdentifier,
    ];

    fn expected(self, surface: &Surface) -> Option<ExpectedOutcome> {
        Some(match self {
            Self::ValidHuman | Self::CallerForgedTenantMetadataHuman => surface.valid_human_outcome,
            Self::ValidMachine | Self::CallerForgedTenantMetadataMachine => {
                surface.valid_machine_outcome
            }
            Self::MissingCredential | Self::ForgedCredential => ExpectedOutcome::Unauthenticated,
            Self::CrossTenantContext => ExpectedOutcome::PermissionDenied,
            Self::CrossTenantIdentifier => return surface.cross_tenant_identifier_outcome,
            Self::ExpiredCredential | Self::RevokedCredential => ExpectedOutcome::Unauthenticated,
            Self::MembershipRevoked | Self::TenantSuspended => ExpectedOutcome::PermissionDenied,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExpectedOutcome {
    Success,
    Unauthenticated,
    PermissionDenied,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantFixture {
    pub tenant_a: String,
    pub tenant_b: String,
    pub namespace_a: String,
    pub namespace_b: String,
    pub identifier_a: String,
    pub identifier_b: String,
    pub value_a: String,
    pub value_b: String,
}

impl TenantFixture {
    pub fn deterministic() -> Self {
        Self {
            tenant_a: "tenant-conformance-a".into(),
            tenant_b: "tenant-conformance-b".into(),
            namespace_a: "namespace-conformance-a".into(),
            namespace_b: "namespace-conformance-b".into(),
            identifier_a: "identifier-conformance-a".into(),
            identifier_b: "identifier-conformance-b".into(),
            value_a: "value-conformance-a".into(),
            value_b: "value-conformance-b".into(),
        }
    }

    fn forbidden_foreign_values(&self) -> [&str; 4] {
        [
            &self.tenant_b,
            &self.namespace_b,
            &self.identifier_b,
            &self.value_b,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceCase {
    pub id: String,
    pub surface: Surface,
    pub profile: CallerProfile,
    pub expected: ExpectedOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    UnsupportedVersion(String),
    EmptySurfaceName,
    DuplicateSurface(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageMismatchKind {
    MissingDeclaration,
    StaleDeclaration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageMismatch {
    pub kind: CoverageMismatchKind,
    pub transport: Transport,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseRegistry {
    version: String,
    surfaces: Vec<Surface>,
}

impl CaseRegistry {
    pub fn new(surfaces: impl IntoIterator<Item = Surface>) -> Result<Self, RegistryError> {
        Self::with_version(TENANT_ISOLATION_CONFORMANCE_VERSION, surfaces)
    }

    pub fn with_version(
        version: impl Into<String>,
        surfaces: impl IntoIterator<Item = Surface>,
    ) -> Result<Self, RegistryError> {
        let version = version.into();
        if version != TENANT_ISOLATION_CONFORMANCE_VERSION {
            return Err(RegistryError::UnsupportedVersion(version));
        }
        let mut seen = BTreeSet::new();
        let mut surfaces = surfaces.into_iter().collect::<Vec<_>>();
        for surface in &surfaces {
            if surface.name.trim().is_empty() {
                return Err(RegistryError::EmptySurfaceName);
            }
            if !seen.insert((surface.transport, surface.name.clone())) {
                return Err(RegistryError::DuplicateSurface(surface.name.clone()));
            }
        }
        surfaces.sort();
        Ok(Self { version, surfaces })
    }

    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn surfaces(&self) -> &[Surface] {
        &self.surfaces
    }
    pub fn cases(&self) -> Vec<ConformanceCase> {
        self.surfaces
            .iter()
            .flat_map(|surface| {
                CallerProfile::ALL.into_iter().filter_map(move |profile| {
                    profile.expected(surface).map(|expected| ConformanceCase {
                        id: format!("{}::{:?}::{:?}", surface.name, surface.transport, profile),
                        surface: surface.clone(),
                        profile,
                        expected,
                    })
                })
            })
            .collect()
    }

    /// Compare the registry with the tenant-aware routes installed by the
    /// enterprise composition. CI must supply the independently discovered
    /// inventory so adding a route without a declaration fails closed.
    pub fn validate_coverage(
        &self,
        installed: impl IntoIterator<Item = (Transport, String)>,
    ) -> Result<(), Vec<CoverageMismatch>> {
        let registered = self
            .surfaces
            .iter()
            .map(|surface| (surface.transport, surface.name.clone()))
            .collect::<BTreeSet<_>>();
        let installed = installed.into_iter().collect::<BTreeSet<_>>();
        let mut mismatches = installed
            .difference(&registered)
            .map(|(transport, name)| CoverageMismatch {
                kind: CoverageMismatchKind::MissingDeclaration,
                transport: *transport,
                name: name.clone(),
            })
            .collect::<Vec<_>>();
        mismatches.extend(registered.difference(&installed).map(|(transport, name)| {
            CoverageMismatch {
                kind: CoverageMismatchKind::StaleDeclaration,
                transport: *transport,
                name: name.clone(),
            }
        }));
        if mismatches.is_empty() {
            Ok(())
        } else {
            Err(mismatches)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedOutcome {
    Success,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    OtherFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationChannel {
    Body,
    ListItem,
    Count,
    Report,
    Receipt,
    MetricLabel,
    CacheKey,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservableValue {
    pub channel: ObservationChannel,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakageSignal {
    ForeignRecord,
    ForeignAggregateContribution,
    ForeignReportValue,
    ForeignReceiptValue,
    ForeignMetricLabel,
    CrossTenantCacheReuse,
    ForeignErrorDetail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub outcome: ObservedOutcome,
    pub values: Vec<ObservableValue>,
    /// Semantic leaks that cannot be found through marker matching, such as a
    /// count inflated by foreign rows or a cross-tenant cache hit.
    pub leakage_signals: Vec<LeakageSignal>,
}

/// Opaque digests of protected tenant state, read through an administrative
/// fixture path independent of the request surface under test. Audit and
/// telemetry records are intentionally excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationSnapshot {
    pub tenant_a_state: String,
    pub tenant_b_state: String,
}

impl Observation {
    pub fn outcome(outcome: ObservedOutcome) -> Self {
        Self {
            outcome,
            values: Vec::new(),
            leakage_signals: Vec::new(),
        }
    }
}

pub trait ConformanceTarget {
    type Error: std::fmt::Display;
    fn isolation_snapshot(
        &mut self,
        fixture: &TenantFixture,
    ) -> Result<IsolationSnapshot, Self::Error>;
    fn execute(
        &mut self,
        fixture: &TenantFixture,
        case: &ConformanceCase,
    ) -> Result<Observation, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseFailure {
    pub case_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    pub version: String,
    pub total: usize,
    pub failures: Vec<CaseFailure>,
}

impl ConformanceReport {
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

pub fn run<T: ConformanceTarget>(
    registry: &CaseRegistry,
    fixture: &TenantFixture,
    target: &mut T,
) -> ConformanceReport {
    let cases = registry.cases();
    let mut failures = Vec::new();
    for case in &cases {
        let before = match target.isolation_snapshot(fixture) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                failures.push(CaseFailure {
                    case_id: case.id.clone(),
                    reason: format!("precondition snapshot error: {error}"),
                });
                continue;
            }
        };
        match target.execute(fixture, case) {
            Ok(observation) => {
                validate_observation(case, fixture, &observation, &mut failures);
            }
            Err(error) => failures.push(CaseFailure {
                case_id: case.id.clone(),
                reason: format!("runner error: {error}"),
            }),
        }
        match target.isolation_snapshot(fixture) {
            Ok(after) => validate_isolation_state(case, &before, &after, &mut failures),
            Err(error) => failures.push(CaseFailure {
                case_id: case.id.clone(),
                reason: format!("postcondition snapshot error: {error}"),
            }),
        }
    }
    ConformanceReport {
        version: registry.version().to_string(),
        total: cases.len(),
        failures,
    }
}

fn validate_isolation_state(
    case: &ConformanceCase,
    before: &IsolationSnapshot,
    after: &IsolationSnapshot,
    failures: &mut Vec<CaseFailure>,
) {
    if before.tenant_b_state != after.tenant_b_state {
        failures.push(CaseFailure {
            case_id: case.id.clone(),
            reason: "foreign tenant state changed".into(),
        });
    }
    if case.expected != ExpectedOutcome::Success && before.tenant_a_state != after.tenant_a_state {
        failures.push(CaseFailure {
            case_id: case.id.clone(),
            reason: "refused request changed caller tenant state".into(),
        });
    }
}

fn validate_observation(
    case: &ConformanceCase,
    fixture: &TenantFixture,
    observation: &Observation,
    failures: &mut Vec<CaseFailure>,
) {
    let expected = match case.expected {
        ExpectedOutcome::Success => ObservedOutcome::Success,
        ExpectedOutcome::Unauthenticated => ObservedOutcome::Unauthenticated,
        ExpectedOutcome::PermissionDenied => ObservedOutcome::PermissionDenied,
        ExpectedOutcome::NotFound => ObservedOutcome::NotFound,
    };
    if observation.outcome != expected {
        failures.push(CaseFailure {
            case_id: case.id.clone(),
            reason: format!(
                "expected outcome {expected:?}, observed {:?}",
                observation.outcome
            ),
        });
    }
    for observable in &observation.values {
        for forbidden in fixture.forbidden_foreign_values() {
            if observable.value.contains(forbidden) {
                failures.push(CaseFailure {
                    case_id: case.id.clone(),
                    reason: format!("foreign tenant value appeared in {:?}", observable.channel),
                });
            }
        }
    }
    for signal in &observation.leakage_signals {
        failures.push(CaseFailure {
            case_id: case.id.clone(),
            reason: format!("semantic tenant leak observed: {signal:?}"),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunitySurfaceManifest<'a> {
    pub grpc_methods: &'a [&'a str],
    pub gateway_routes: &'a [&'a str],
    pub configuration_keys: &'a [&'a str],
    pub accepted_authority_metadata: &'a [&'a str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunitySurfaceViolation {
    pub surface: &'static str,
    pub value: String,
}

pub fn validate_community_surface(
    manifest: &CommunitySurfaceManifest<'_>,
) -> Result<(), Vec<CommunitySurfaceViolation>> {
    const FORBIDDEN: [&str; 12] = [
        "tenant",
        "membership",
        "namespaceownership",
        "oidc",
        "oauth",
        "authorizationendpoint",
        "tokenendpoint",
        "revocationendpoint",
        "createsession",
        "beginsession",
        "authorizationcode",
        "xsekaitenantid",
    ];
    let mut violations = Vec::new();
    for (surface, values) in [
        ("grpc", manifest.grpc_methods),
        ("gateway", manifest.gateway_routes),
        ("configuration", manifest.configuration_keys),
        ("metadata", manifest.accepted_authority_metadata),
    ] {
        for value in values {
            let normalized = value
                .chars()
                .filter(|character| character.is_ascii_alphanumeric())
                .flat_map(char::to_lowercase)
                .collect::<String>();
            let words = surface_words(value);
            let generic_identity_surface = words
                .windows(2)
                .any(|words| words[0] == "sign" && matches!(words[1].as_str(), "in" | "out"))
                || words.iter().any(|word| {
                    matches!(
                        word.as_str(),
                        "session"
                            | "sessions"
                            | "login"
                            | "logout"
                            | "signin"
                            | "signout"
                            | "revocation"
                            | "revocations"
                    ) || (matches!(word.as_str(), "token" | "tokens") && surface != "configuration")
                });
            let authorization_surface = match surface {
                "gateway" => words.iter().any(|word| {
                    matches!(
                        word.as_str(),
                        "auth" | "authorize" | "authorization" | "callback"
                    )
                }),
                "grpc" => {
                    surface_words(value.split_once('/').map_or(*value, |(service, _)| service))
                        .iter()
                        .any(|word| matches!(word.as_str(), "auth" | "authorization"))
                }
                _ => false,
            };
            if generic_identity_surface
                || authorization_surface
                || FORBIDDEN.iter().any(|term| normalized.contains(term))
            {
                violations.push(CommunitySurfaceViolation {
                    surface,
                    value: (*value).to_string(),
                });
            }
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn surface_words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_lowercase = false;
    for character in value.chars() {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            previous_lowercase = false;
            continue;
        }
        if character.is_ascii_uppercase() && previous_lowercase && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(character.to_ascii_lowercase());
        previous_lowercase = character.is_ascii_lowercase();
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_generates_every_profile_for_every_surface() {
        let registry = CaseRegistry::new([
            Surface::new(
                Transport::Grpc,
                "service/Get",
                SurfaceKind::Read,
                ExpectedOutcome::Success,
                ExpectedOutcome::Success,
            ),
            Surface::new(
                Transport::Gateway,
                "GET /items",
                SurfaceKind::List,
                ExpectedOutcome::Success,
                ExpectedOutcome::Success,
            ),
        ])
        .unwrap();
        assert_eq!(registry.cases().len(), 2 * (CallerProfile::ALL.len() - 1));
    }

    #[test]
    fn registry_rejects_duplicate_transport_names() {
        let result = CaseRegistry::new([
            Surface::new(
                Transport::Grpc,
                "service/Get",
                SurfaceKind::Read,
                ExpectedOutcome::Success,
                ExpectedOutcome::Success,
            ),
            Surface::new(
                Transport::Grpc,
                "service/Get",
                SurfaceKind::Write,
                ExpectedOutcome::PermissionDenied,
                ExpectedOutcome::Success,
            ),
        ]);
        assert_eq!(
            result,
            Err(RegistryError::DuplicateSurface("service/Get".into()))
        );
    }

    #[test]
    fn coverage_rejects_an_installed_but_unregistered_route() {
        let registry = CaseRegistry::new([Surface::new(
            Transport::Grpc,
            "service/Get",
            SurfaceKind::Read,
            ExpectedOutcome::Success,
            ExpectedOutcome::Success,
        )])
        .unwrap();
        let result = registry.validate_coverage([
            (Transport::Grpc, "service/Get".to_string()),
            (Transport::Gateway, "GET /new-route".to_string()),
        ]);
        assert_eq!(
            result,
            Err(vec![CoverageMismatch {
                kind: CoverageMismatchKind::MissingDeclaration,
                transport: Transport::Gateway,
                name: "GET /new-route".into(),
            }])
        );
    }

    #[test]
    fn community_manifest_rejects_identity_runtime_surface() {
        let result = validate_community_surface(&CommunitySurfaceManifest {
            grpc_methods: &["sekai.v1.SekaiService/CreateTenant"],
            gateway_routes: &[],
            configuration_keys: &[],
            accepted_authority_metadata: &[],
        });
        assert!(result.is_err());
    }

    #[test]
    fn community_manifest_rejects_generic_identity_route_spellings() {
        let result = validate_community_surface(&CommunitySurfaceManifest {
            grpc_methods: &["TokenService/Issue"],
            gateway_routes: &["/session", "/token-endpoint", "/revocation"],
            configuration_keys: &["OIDC_TOKEN_ENDPOINT"],
            accepted_authority_metadata: &[],
        });
        assert_eq!(result.unwrap_err().len(), 5);
    }

    #[test]
    fn community_manifest_rejects_plural_identity_aliases() {
        let result = validate_community_surface(&CommunitySurfaceManifest {
            grpc_methods: &["SessionsService/List", "TokensService/Issue"],
            gateway_routes: &["/sessions", "/tokens", "/revocations"],
            configuration_keys: &[],
            accepted_authority_metadata: &[],
        });
        assert_eq!(result.unwrap_err().len(), 5);
    }

    #[test]
    fn community_manifest_rejects_login_aliases() {
        let result = validate_community_surface(&CommunitySurfaceManifest {
            grpc_methods: &["LoginService/Begin"],
            gateway_routes: &["/login", "/logout", "/sign-in", "/sign-out"],
            configuration_keys: &["LOGIN_ENABLED"],
            accepted_authority_metadata: &[],
        });
        assert_eq!(result.unwrap_err().len(), 6);
    }

    #[test]
    fn community_manifest_rejects_authorization_aliases() {
        let result = validate_community_surface(&CommunitySurfaceManifest {
            grpc_methods: &["AuthorizationService/Begin"],
            gateway_routes: &["/authorize", "/auth/callback"],
            configuration_keys: &[],
            accepted_authority_metadata: &[],
        });
        assert_eq!(result.unwrap_err().len(), 3);
    }

    #[test]
    fn community_manifest_rejects_tenant_authority_metadata() {
        let result = validate_community_surface(&CommunitySurfaceManifest {
            grpc_methods: &[],
            gateway_routes: &[],
            configuration_keys: &[],
            accepted_authority_metadata: &["x-sekai-tenant-id"],
        });
        assert_eq!(result.unwrap_err().len(), 1);
    }
}
