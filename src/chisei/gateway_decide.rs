//! Fat gateway decide contract (Issue #163 research freeze).
//!
//! Pure types and validation for the single control-plane decision the HTTP
//! gateway should call once per request. Wire transport (proto/RPC) and gateway
//! dual-path land in follow-up implementation PRs under
//! `docs/research/163-gateway-pep-fat-decide.md`.

use serde::{Deserialize, Serialize};

pub const GATEWAY_DECIDE_CONTRACT_VERSION: &str = "gateway.decide/v1";

/// Stable deny reasons the edge maps to HTTP/provider errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayDecideDenyReason {
    Unauthorized,
    CapabilityUnsupported,
    PolicyDenied,
    BudgetDenied,
    ResidencyDenied,
    InvalidRequest,
}

impl GatewayDecideDenyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::CapabilityUnsupported => "capability_unsupported",
            Self::PolicyDenied => "policy_denied",
            Self::BudgetDenied => "budget_denied",
            Self::ResidencyDenied => "residency_denied",
            Self::InvalidRequest => "invalid_request",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayDecideRequest {
    pub contract_version: String,
    pub namespace: String,
    pub principal: String,
    pub requested_model: String,
    pub operation_class: String,
    /// Estimated cost dimensions already used by budget checks (micros).
    pub estimated_cost_usd_micros: i64,
    pub correlation_operation_id: String,
    pub correlation_attempt: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayDecideAdmit {
    pub resolved_runtime: String,
    pub resolved_model: String,
    pub policy_version: String,
    pub budget_scope: String,
    pub budget_grant_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayDecideDeny {
    pub reason: GatewayDecideDenyReason,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum GatewayDecideOutcome {
    Admit(GatewayDecideAdmit),
    Deny(GatewayDecideDeny),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayDecideResponse {
    pub contract_version: String,
    pub outcome: GatewayDecideOutcome,
}

impl GatewayDecideRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != GATEWAY_DECIDE_CONTRACT_VERSION {
            return Err(format!(
                "unsupported gateway decide contract {}",
                self.contract_version
            ));
        }
        for (name, value) in [
            ("namespace", self.namespace.as_str()),
            ("principal", self.principal.as_str()),
            ("requested_model", self.requested_model.as_str()),
            ("operation_class", self.operation_class.as_str()),
            (
                "correlation_operation_id",
                self.correlation_operation_id.as_str(),
            ),
        ] {
            if value.trim().is_empty() || value != value.trim() {
                return Err(format!("{name} is required"));
            }
        }
        if self.estimated_cost_usd_micros < 0 {
            return Err("estimated_cost_usd_micros must be non-negative".into());
        }
        Ok(())
    }
}

impl GatewayDecideResponse {
    pub fn admit(admit: GatewayDecideAdmit) -> Self {
        Self {
            contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
            outcome: GatewayDecideOutcome::Admit(admit),
        }
    }

    pub fn deny(reason: GatewayDecideDenyReason, message: impl Into<String>) -> Self {
        Self {
            contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
            outcome: GatewayDecideOutcome::Deny(GatewayDecideDeny {
                reason,
                message: message.into(),
            }),
        }
    }

    /// Edge must not contact upstream on deny.
    pub fn allows_upstream(&self) -> bool {
        matches!(self.outcome, GatewayDecideOutcome::Admit(_))
    }
}

/// Inputs collected by the control-plane handler after subsystem checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayDecideInputs {
    pub request: GatewayDecideRequest,
    /// Ok = (runtime, model, policy_version); Err = policy/capability/residency deny.
    pub route: Result<(String, String, String), (GatewayDecideDenyReason, String)>,
    pub budget_allowed: bool,
    pub budget_scope: String,
    pub budget_grant_id: String,
    pub route_bias: String,
    pub degradation_level: String,
    pub budget_warning: bool,
}

/// Compose a single fat-decide outcome from route + budget subsystem results.
///
/// Ordering: invalid request is rejected before this; unauthorized is handled
/// by the auth boundary. Policy/capability/residency denials take precedence
/// over budget so the edge sees the primary governance reason.
pub fn compose_gateway_decide(inputs: GatewayDecideInputs) -> GatewayDecideResponse {
    let (runtime, model, policy_version) = match inputs.route {
        Ok(route) => route,
        Err((reason, message)) => return GatewayDecideResponse::deny(reason, message),
    };
    if !inputs.budget_allowed {
        return GatewayDecideResponse::deny(
            GatewayDecideDenyReason::BudgetDenied,
            format!(
                "budget denied for scope {} (degradation={})",
                inputs.budget_scope, inputs.degradation_level
            ),
        );
    }
    GatewayDecideResponse::admit(GatewayDecideAdmit {
        resolved_runtime: runtime,
        resolved_model: model,
        policy_version,
        budget_scope: inputs.budget_scope,
        budget_grant_id: inputs.budget_grant_id,
    })
}

/// Stable budget grant stamp for usage/receipt correlation.
pub fn budget_grant_id(scope: &str, operation_id: &str, attempt: u32) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{scope}\0{operation_id}\0{attempt}"));
    format!("budget-grant:{:x}", digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> GatewayDecideRequest {
        GatewayDecideRequest {
            contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
            namespace: "ns".into(),
            principal: "agent".into(),
            requested_model: "gpt-test".into(),
            operation_class: "chat".into(),
            estimated_cost_usd_micros: 0,
            correlation_operation_id: "op-1".into(),
            correlation_attempt: 1,
        }
    }

    #[test]
    fn request_validation_and_deny_blocks_upstream() {
        let mut request = sample_request();
        request.validate().unwrap();
        request.namespace = " ".into();
        assert!(request.validate().is_err());

        let deny = GatewayDecideResponse::deny(
            GatewayDecideDenyReason::CapabilityUnsupported,
            "model family not allowed",
        );
        assert!(!deny.allows_upstream());
        assert_eq!(deny.contract_version, GATEWAY_DECIDE_CONTRACT_VERSION);

        let admit = GatewayDecideResponse::admit(GatewayDecideAdmit {
            resolved_runtime: "openai".into(),
            resolved_model: "gpt-test".into(),
            policy_version: "pv1".into(),
            budget_scope: "project:ns".into(),
            budget_grant_id: "grant-1".into(),
        });
        assert!(admit.allows_upstream());
    }

    #[test]
    fn compose_prefers_policy_deny_over_budget() {
        let response = compose_gateway_decide(GatewayDecideInputs {
            request: sample_request(),
            route: Err((
                GatewayDecideDenyReason::PolicyDenied,
                "model not allowed".into(),
            )),
            budget_allowed: false,
            budget_scope: "project:ns".into(),
            budget_grant_id: "g".into(),
            route_bias: "capable".into(),
            degradation_level: "hard_cap".into(),
            budget_warning: true,
        });
        assert!(!response.allows_upstream());
        match response.outcome {
            GatewayDecideOutcome::Deny(deny) => {
                assert_eq!(deny.reason, GatewayDecideDenyReason::PolicyDenied);
            }
            GatewayDecideOutcome::Admit(_) => panic!("expected deny"),
        }
    }

    #[test]
    fn compose_admits_when_route_and_budget_pass() {
        let response = compose_gateway_decide(GatewayDecideInputs {
            request: sample_request(),
            route: Ok(("ollama".into(), "llama".into(), "pv1".into())),
            budget_allowed: true,
            budget_scope: "project:ns".into(),
            budget_grant_id: "grant-1".into(),
            route_bias: "capable".into(),
            degradation_level: "capable".into(),
            budget_warning: false,
        });
        assert!(response.allows_upstream());
        match response.outcome {
            GatewayDecideOutcome::Admit(admit) => {
                assert_eq!(admit.resolved_model, "llama");
                assert_eq!(admit.budget_grant_id, "grant-1");
            }
            GatewayDecideOutcome::Deny(_) => panic!("expected admit"),
        }
    }
}
