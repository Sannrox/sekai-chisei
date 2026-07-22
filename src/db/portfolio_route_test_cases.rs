use crate::chisei::portfolio::RouteSelection;

const COOLDOWN_MS: i64 = 15 * 60 * 1000;

struct RouteStep {
    proposed_model: &'static str,
    now_ms: i64,
    force: bool,
    expected: RouteSelection,
}

struct RouteCase {
    name: &'static str,
    steps: Vec<RouteStep>,
}

pub(super) fn assert_route_contract(
    mut route: impl FnMut(&str, &str, &str, i64, bool) -> Result<RouteSelection, String>,
) {
    for case in route_cases() {
        for (step_index, step) in case.steps.into_iter().enumerate() {
            let actual = route(
                case.name,
                "primary",
                step.proposed_model,
                step.now_ms,
                step.force,
            )
            .unwrap_or_else(|error| {
                panic!("route case {} step {step_index} failed: {error}", case.name)
            });
            assert_eq!(
                actual, step.expected,
                "route case {} step {step_index}",
                case.name
            );
        }
    }
}

fn selection(model: &str, previous_model: &str, shifted: bool, reason: &str) -> RouteSelection {
    RouteSelection {
        model: model.into(),
        prompt_variant: crate::chisei::portfolio::LEGACY_PROMPT_VARIANT.into(),
        previous_model: previous_model.into(),
        previous_prompt_variant: if previous_model.is_empty() {
            String::new()
        } else {
            crate::chisei::portfolio::LEGACY_PROMPT_VARIANT.into()
        },
        shifted,
        reason: reason.into(),
    }
}

fn route_cases() -> Vec<RouteCase> {
    vec![
        RouteCase {
            name: "initial-allocation",
            steps: vec![RouteStep {
                proposed_model: "small",
                now_ms: 0,
                force: false,
                expected: selection("small", "", true, "initial allocation"),
            }],
        },
        RouteCase {
            name: "forced-initial-allocation",
            steps: vec![RouteStep {
                proposed_model: "safe",
                now_ms: 0,
                force: true,
                expected: selection("safe", "", false, "initialized on regression-safe model"),
            }],
        },
        RouteCase {
            name: "cooldown-confirmation-and-reset",
            steps: vec![
                RouteStep {
                    proposed_model: "small",
                    now_ms: 0,
                    force: false,
                    expected: selection("small", "", true, "initial allocation"),
                },
                RouteStep {
                    proposed_model: "large",
                    now_ms: 1,
                    force: false,
                    expected: selection("small", "small", false, "allocation held during cooldown"),
                },
                RouteStep {
                    proposed_model: "large",
                    now_ms: 2,
                    force: false,
                    expected: selection("small", "small", false, "allocation held during cooldown"),
                },
                RouteStep {
                    proposed_model: "small",
                    now_ms: 3,
                    force: false,
                    expected: selection("small", "small", false, "allocation unchanged"),
                },
                RouteStep {
                    proposed_model: "large",
                    now_ms: COOLDOWN_MS,
                    force: false,
                    expected: selection(
                        "small",
                        "small",
                        false,
                        "waiting for allocation confirmation 1/3",
                    ),
                },
                RouteStep {
                    proposed_model: "large",
                    now_ms: COOLDOWN_MS + 1,
                    force: false,
                    expected: selection(
                        "small",
                        "small",
                        false,
                        "waiting for allocation confirmation 2/3",
                    ),
                },
                RouteStep {
                    proposed_model: "large",
                    now_ms: COOLDOWN_MS + 2,
                    force: false,
                    expected: selection(
                        "large",
                        "small",
                        true,
                        "allocation confirmed 3 times after cooldown",
                    ),
                },
            ],
        },
        RouteCase {
            name: "forced-revert-restarts-cooldown",
            steps: vec![
                RouteStep {
                    proposed_model: "small",
                    now_ms: 0,
                    force: false,
                    expected: selection("small", "", true, "initial allocation"),
                },
                RouteStep {
                    proposed_model: "safe",
                    now_ms: 100,
                    force: true,
                    expected: selection("safe", "small", true, "forced regression reversion"),
                },
                RouteStep {
                    proposed_model: "large",
                    now_ms: COOLDOWN_MS,
                    force: false,
                    expected: selection("safe", "safe", false, "allocation held during cooldown"),
                },
                RouteStep {
                    proposed_model: "large",
                    now_ms: COOLDOWN_MS + 50,
                    force: false,
                    expected: selection("safe", "safe", false, "allocation held during cooldown"),
                },
                // A forced revert is a shift: it rewrites shifted_at, so the full
                // cooldown is measured from the revert rather than the initial route.
                RouteStep {
                    proposed_model: "large",
                    now_ms: COOLDOWN_MS + 100,
                    force: false,
                    expected: selection(
                        "large",
                        "safe",
                        true,
                        "allocation confirmed 3 times after cooldown",
                    ),
                },
            ],
        },
    ]
}
