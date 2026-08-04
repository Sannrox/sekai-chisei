use sekai_chisei::enterprise_conformance::*;

struct DeterministicEnterpriseFake;

impl ConformanceTarget for DeterministicEnterpriseFake {
    type Error = &'static str;

    fn isolation_snapshot(
        &mut self,
        _fixture: &TenantFixture,
    ) -> Result<IsolationSnapshot, Self::Error> {
        Ok(IsolationSnapshot {
            tenant_a_state: "tenant-a-state".into(),
            tenant_b_state: "tenant-b-state".into(),
        })
    }

    fn execute(
        &mut self,
        fixture: &TenantFixture,
        case: &ConformanceCase,
    ) -> Result<Observation, Self::Error> {
        let outcome = match case.expected {
            ExpectedOutcome::Success => ObservedOutcome::Success,
            ExpectedOutcome::Unauthenticated => ObservedOutcome::Unauthenticated,
            ExpectedOutcome::PermissionDenied => ObservedOutcome::PermissionDenied,
            ExpectedOutcome::NotFound => ObservedOutcome::NotFound,
        };
        let values = if outcome == ObservedOutcome::Success {
            vec![
                ObservableValue {
                    channel: ObservationChannel::Body,
                    value: fixture.identifier_a.clone(),
                },
                ObservableValue {
                    channel: ObservationChannel::MetricLabel,
                    value: fixture.tenant_a.clone(),
                },
                ObservableValue {
                    channel: ObservationChannel::CacheKey,
                    value: format!("{}:result", fixture.tenant_a),
                },
            ]
        } else {
            vec![ObservableValue {
                channel: ObservationChannel::Error,
                value: "request unavailable".into(),
            }]
        };
        Ok(Observation {
            outcome,
            values,
            leakage_signals: Vec::new(),
        })
    }
}

fn enterprise_registry() -> CaseRegistry {
    fn surface(transport: Transport, name: &str, kind: SurfaceKind) -> Surface {
        let surface = Surface::new(
            transport,
            name,
            kind,
            ExpectedOutcome::Success,
            ExpectedOutcome::Success,
        );
        match kind {
            SurfaceKind::Read
            | SurfaceKind::Write
            | SurfaceKind::Report
            | SurfaceKind::Receipt
            | SurfaceKind::Credential
            | SurfaceKind::Namespace => {
                surface.with_cross_tenant_identifier(ExpectedOutcome::NotFound)
            }
            _ => surface,
        }
    }
    CaseRegistry::new([
        surface(
            Transport::Grpc,
            "enterprise.v1.Objects/Get",
            SurfaceKind::Read,
        ),
        surface(
            Transport::Grpc,
            "enterprise.v1.Objects/Create",
            SurfaceKind::Write,
        ),
        surface(
            Transport::Grpc,
            "enterprise.v1.Objects/List",
            SurfaceKind::List,
        ),
        surface(
            Transport::Grpc,
            "enterprise.v1.Reports/Get",
            SurfaceKind::Report,
        ),
        surface(
            Transport::Grpc,
            "enterprise.v1.Receipts/Get",
            SurfaceKind::Receipt,
        ),
        surface(
            Transport::Grpc,
            "enterprise.v1.Credentials/Revoke",
            SurfaceKind::Credential,
        ),
        surface(
            Transport::Grpc,
            "enterprise.v1.Namespaces/Get",
            SurfaceKind::Namespace,
        ),
        surface(
            Transport::Gateway,
            "POST /oauth/session",
            SurfaceKind::Session,
        ),
        surface(
            Transport::Gateway,
            "POST /oauth/authorize",
            SurfaceKind::Authorization,
        ),
        surface(
            Transport::Gateway,
            "GET /v1/objects/{id}",
            SurfaceKind::Read,
        ),
        surface(Transport::Gateway, "GET /v1/objects", SurfaceKind::List),
    ])
    .unwrap()
}

#[test]
fn deterministic_fake_passes_identical_generated_cases() {
    let registry = enterprise_registry();
    let report = run(
        &registry,
        &TenantFixture::deterministic(),
        &mut DeterministicEnterpriseFake,
    );
    assert!(report.passed(), "{:#?}", report.failures);
    assert_eq!(report.total, registry.cases().len());
}

#[test]
fn runner_detects_foreign_values_in_all_observation_channels() {
    struct LeakingFake {
        mutated_foreign_state: bool,
    }
    impl ConformanceTarget for LeakingFake {
        type Error = &'static str;
        fn isolation_snapshot(
            &mut self,
            _fixture: &TenantFixture,
        ) -> Result<IsolationSnapshot, Self::Error> {
            Ok(IsolationSnapshot {
                tenant_a_state: "tenant-a-state".into(),
                tenant_b_state: if self.mutated_foreign_state {
                    "tenant-b-state-mutated".into()
                } else {
                    "tenant-b-state".into()
                },
            })
        }
        fn execute(
            &mut self,
            fixture: &TenantFixture,
            case: &ConformanceCase,
        ) -> Result<Observation, Self::Error> {
            self.mutated_foreign_state = true;
            let outcome = match case.expected {
                ExpectedOutcome::Success => ObservedOutcome::Success,
                ExpectedOutcome::Unauthenticated => ObservedOutcome::Unauthenticated,
                ExpectedOutcome::PermissionDenied => ObservedOutcome::PermissionDenied,
                ExpectedOutcome::NotFound => ObservedOutcome::NotFound,
            };
            Ok(Observation {
                outcome,
                values: vec![ObservableValue {
                    channel: ObservationChannel::Count,
                    value: format!("{}:1", fixture.tenant_b),
                }],
                leakage_signals: vec![LeakageSignal::ForeignAggregateContribution],
            })
        }
    }

    let registry = CaseRegistry::new([Surface::new(
        Transport::Grpc,
        "enterprise.v1.Objects/List",
        SurfaceKind::List,
        ExpectedOutcome::Success,
        ExpectedOutcome::Success,
    )])
    .unwrap();
    let report = run(
        &registry,
        &TenantFixture::deterministic(),
        &mut LeakingFake {
            mutated_foreign_state: false,
        },
    );
    assert_eq!(
        report.failures.len(),
        2 * (CallerProfile::ALL.len() - 1) + 1
    );
}

#[test]
fn community_profile_exposes_no_tenant_or_identity_runtime_surface() {
    fn rpc_methods(protocol: &str) -> Vec<String> {
        let mut service = None;
        let mut methods = Vec::new();
        for line in protocol.lines().map(str::trim) {
            if let Some(name) = line.strip_prefix("service ") {
                service = name.split_whitespace().next();
            } else if line == "}" {
                service = None;
            } else if let (Some(service), Some(method)) = (service, line.strip_prefix("rpc "))
                && let Some((method, _)) = method.split_once('(')
            {
                methods.push(format!("{service}/{method}"));
            }
        }
        methods
    }
    let protocols = [
        include_str!("../proto/sekai.proto"),
        include_str!("../proto/chisei.proto"),
    ];
    let methods = protocols
        .iter()
        .flat_map(|protocol| rpc_methods(protocol))
        .collect::<Vec<String>>();
    let method_refs = methods.iter().map(String::as_str).collect::<Vec<_>>();
    fn quoted_strings(source: &str) -> impl Iterator<Item = &str> {
        source.split('"').skip(1).step_by(2)
    }
    let gateway = include_str!("../crates/chisei-gateway/src/gateway.rs");
    let configuration_sources = [
        include_str!("../src/config.rs"),
        gateway,
        include_str!("../crates/chisei-gateway/src/main.rs"),
    ];
    let configuration_keys = configuration_sources
        .iter()
        .flat_map(|source| quoted_strings(source))
        .filter(|value| {
            value.contains('_')
                && value.chars().all(|character| {
                    character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
                })
        })
        .collect::<Vec<_>>();
    let manifest = CommunitySurfaceManifest {
        grpc_methods: &method_refs,
        gateway_routes: chisei_gateway::gateway::COMMUNITY_GATEWAY_ROUTES,
        configuration_keys: &configuration_keys,
        accepted_authority_metadata: sekai_chisei::grpc::COMMUNITY_ACCEPTED_AUTHORITY_METADATA_KEYS,
    };
    assert_eq!(validate_community_surface(&manifest), Ok(()));
}
