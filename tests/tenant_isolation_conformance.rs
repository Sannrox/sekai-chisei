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
        let outcome = expected_outcome(case);
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

/// Every observation channel. The exhaustive match makes a new channel a
/// compile error here until it is listed, so it cannot skip the detection test.
fn every_observation_channel() -> Vec<ObservationChannel> {
    use ObservationChannel::*;
    let all = vec![
        Body,
        ListItem,
        Count,
        Report,
        Receipt,
        MetricLabel,
        CacheKey,
        Error,
    ];
    for channel in &all {
        match channel {
            Body | ListItem | Count | Report | Receipt | MetricLabel | CacheKey | Error => {}
        }
    }
    all
}

fn expected_outcome(case: &ConformanceCase) -> ObservedOutcome {
    match case.expected {
        ExpectedOutcome::Success => ObservedOutcome::Success,
        ExpectedOutcome::Unauthenticated => ObservedOutcome::Unauthenticated,
        ExpectedOutcome::PermissionDenied => ObservedOutcome::PermissionDenied,
        ExpectedOutcome::NotFound => ObservedOutcome::NotFound,
    }
}

fn list_registry() -> CaseRegistry {
    CaseRegistry::new([Surface::new(
        Transport::Grpc,
        "enterprise.v1.Objects/List",
        SurfaceKind::List,
        ExpectedOutcome::Success,
        ExpectedOutcome::Success,
    )])
    .unwrap()
}

#[test]
fn runner_detects_foreign_values_in_all_observation_channels() {
    /// Answers every case correctly except for one foreign value in `channel`.
    struct ChannelLeak {
        channel: ObservationChannel,
    }
    impl ConformanceTarget for ChannelLeak {
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
            Ok(Observation {
                outcome: expected_outcome(case),
                values: vec![ObservableValue {
                    channel: self.channel,
                    value: fixture.tenant_b.clone(),
                }],
                leakage_signals: Vec::new(),
            })
        }
    }

    let registry = list_registry();
    let fixture = TenantFixture::deterministic();
    for channel in every_observation_channel() {
        let report = run(&registry, &fixture, &mut ChannelLeak { channel });
        let reason = format!("foreign tenant value appeared in {channel:?}");
        let mut flagged: Vec<&str> = report
            .failures
            .iter()
            .map(|failure| {
                assert_eq!(failure.reason, reason, "{channel:?}");
                failure.case_id.as_str()
            })
            .collect();
        flagged.sort_unstable();
        let mut cases: Vec<String> = registry.cases().into_iter().map(|case| case.id).collect();
        cases.sort_unstable();
        assert_eq!(flagged, cases, "{channel:?}");
    }
}

#[test]
fn runner_reports_semantic_leaks_and_foreign_state_changes_by_kind() {
    /// Answers every case correctly, raises a semantic leak signal, and
    /// changes the foreign tenant's state on its first call.
    struct SemanticLeak {
        mutated_foreign_state: bool,
    }
    impl ConformanceTarget for SemanticLeak {
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
            _fixture: &TenantFixture,
            case: &ConformanceCase,
        ) -> Result<Observation, Self::Error> {
            self.mutated_foreign_state = true;
            Ok(Observation {
                outcome: expected_outcome(case),
                values: Vec::new(),
                leakage_signals: vec![LeakageSignal::ForeignAggregateContribution],
            })
        }
    }

    let registry = list_registry();
    let cases = registry.cases();
    let report = run(
        &registry,
        &TenantFixture::deterministic(),
        &mut SemanticLeak {
            mutated_foreign_state: false,
        },
    );
    let reasons_for = |id: &str| -> Vec<&str> {
        report
            .failures
            .iter()
            .filter(|failure| failure.case_id == id)
            .map(|failure| failure.reason.as_str())
            .collect()
    };
    let signal = "semantic tenant leak observed: ForeignAggregateContribution";
    // Only the first case sees the foreign state change; later cases start
    // from the already-mutated state.
    assert_eq!(
        reasons_for(&cases[0].id),
        [signal, "foreign tenant state changed"]
    );
    for case in &cases[1..] {
        assert_eq!(reasons_for(&case.id), [signal], "{}", case.id);
    }
    assert_eq!(report.failures.len(), cases.len() + 1);
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
        // Client-credentials issuance (#1510) is an experimental enterprise RPC.
        // Community builds reject experimental RPCs and do not install an
        // identity extension, so this method is not a community identity-runtime
        // surface. The lexical scanner still treats "token" as identity
        // vocabulary; this named exclusion is the enterprise exception.
        .filter(|method| method != "SekaiService/IssueServicePrincipalToken")
        .collect::<Vec<String>>();
    let method_refs = methods.iter().map(String::as_str).collect::<Vec<_>>();
    fn quoted_strings(source: &str) -> impl Iterator<Item = &str> {
        source.split('"').skip(1).step_by(2)
    }
    let gateway = include_str!("../crates/chisei-gateway/src/gateway.rs");
    let configuration_sources = [
        include_str!("../crates/chisei-core/src/config.rs"),
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
