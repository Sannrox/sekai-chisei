//! Explainable fleet-allocation decisions for governed operations.
//!
//! Gunshi owns allocation recommendations, not agent runtimes or workflow
//! execution. Callers remain responsible for dispatching an accepted plan.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const ALLOCATION_CONTRACT_VERSION: &str = "gunshi.allocation/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationRisk {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCapacity {
    pub agent_id: String,
    pub runtime: String,
    pub models: BTreeSet<String>,
    pub tools: BTreeSet<String>,
    pub operation_classes: BTreeSet<String>,
    pub available_slots: u32,
    pub healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityEnvelope {
    pub captured_at_ms: i64,
    pub policy_version: String,
    pub agents: Vec<AgentCapacity>,
    pub budget_remaining_usd_micros: i64,
    pub max_parallel_attempts: u32,
    pub human_attention_minutes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOperation {
    pub operation_id: String,
    pub namespace: String,
    pub operation_class: String,
    pub priority: u16,
    pub risk: OperationRisk,
    pub submitted_at_ms: i64,
    pub required_tools: BTreeSet<String>,
    pub allowed_models: BTreeSet<String>,
    pub max_attempts: u32,
    pub budget_ceiling_usd_micros: i64,
    pub acceptance_criteria: Vec<String>,
    pub approval_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStrategy {
    Conservative,
    PriorityFirst,
    Throughput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Strategy {
    pub strategy_id: String,
    pub version: String,
    pub baseline: BaselineStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSelection {
    pub agent_id: String,
    pub runtime: String,
    pub model: String,
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptStrategy {
    pub max_attempts: u32,
    pub parallel_attempts: u32,
    pub speculative: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationStrategy {
    pub checks: Vec<String>,
    pub acceptance_criteria: Vec<String>,
    pub human_review_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopConditions {
    pub max_cost_usd_micros: i64,
    pub max_attempts: u32,
    pub deadline_ms: Option<i64>,
    pub stop_on_acceptance: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationRules {
    pub approval_required: bool,
    pub escalate_on_budget_exhaustion: bool,
    pub escalate_after_failed_attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub kind: String,
    pub reference: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpectedOutcome {
    pub quality: f64,
    pub cost_usd_micros: i64,
    pub latency_ms: i64,
    pub uncertainty: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AllocationPlan {
    pub contract_version: String,
    pub allocation_id: String,
    pub operation_id: String,
    pub namespace: String,
    pub operation_class: String,
    pub priority: u16,
    pub strategy: Strategy,
    pub policy_version: String,
    pub advisory: bool,
    pub selection: ResourceSelection,
    pub attempts: AttemptStrategy,
    pub verification: VerificationStrategy,
    pub budget_ceiling_usd_micros: i64,
    pub stop_conditions: StopConditions,
    pub escalation: EscalationRules,
    pub evidence: Vec<EvidenceReference>,
    pub expected: ExpectedOutcome,
    pub explanation: Vec<String>,
    pub input_fingerprint: String,
}

impl CapacityEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        required("policy_version", &self.policy_version)?;
        if self.budget_remaining_usd_micros < 0 {
            return Err("capacity budget must be non-negative".into());
        }
        if self.max_parallel_attempts == 0 {
            return Err("capacity must allow at least one parallel attempt".into());
        }
        let mut ids = BTreeSet::new();
        for agent in &self.agents {
            required("agent_id", &agent.agent_id)?;
            required("runtime", &agent.runtime)?;
            if !ids.insert(agent.agent_id.as_str()) {
                return Err(format!("duplicate agent capacity {}", agent.agent_id));
            }
            if agent.models.iter().any(|model| model.trim().is_empty()) {
                return Err(format!("agent {} has an empty model", agent.agent_id));
            }
        }
        Ok(())
    }
}

impl PendingOperation {
    pub fn validate(&self) -> Result<(), String> {
        required("operation_id", &self.operation_id)?;
        required("namespace", &self.namespace)?;
        required("operation_class", &self.operation_class)?;
        if self.max_attempts == 0 {
            return Err("operation max_attempts must be positive".into());
        }
        if self.budget_ceiling_usd_micros < 0 {
            return Err("operation budget ceiling must be non-negative".into());
        }
        if self
            .acceptance_criteria
            .iter()
            .any(|criterion| criterion.trim().is_empty())
        {
            return Err("acceptance criteria must not contain empty values".into());
        }
        Ok(())
    }
}

impl Strategy {
    pub fn validate(&self) -> Result<(), String> {
        required("strategy_id", &self.strategy_id)?;
        required("strategy version", &self.version)
    }
}

impl AllocationPlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != ALLOCATION_CONTRACT_VERSION {
            return Err(format!(
                "unsupported allocation contract {}",
                self.contract_version
            ));
        }
        for (name, value) in [
            ("allocation_id", self.allocation_id.as_str()),
            ("operation_id", self.operation_id.as_str()),
            ("namespace", self.namespace.as_str()),
            ("operation_class", self.operation_class.as_str()),
            ("policy_version", self.policy_version.as_str()),
            ("agent_id", self.selection.agent_id.as_str()),
            ("runtime", self.selection.runtime.as_str()),
            ("model", self.selection.model.as_str()),
            ("input_fingerprint", self.input_fingerprint.as_str()),
        ] {
            required(name, value)?;
        }
        self.strategy.validate()?;
        if self.attempts.max_attempts == 0 || self.attempts.parallel_attempts == 0 {
            return Err("allocation attempts must be positive".into());
        }
        if self.attempts.parallel_attempts > self.attempts.max_attempts {
            return Err("parallel attempts cannot exceed max attempts".into());
        }
        if self.budget_ceiling_usd_micros < 0 || self.stop_conditions.max_cost_usd_micros < 0 {
            return Err("allocation budget limits must be non-negative".into());
        }
        if self.stop_conditions.max_cost_usd_micros > self.budget_ceiling_usd_micros {
            return Err("stop cost cannot exceed the allocation budget ceiling".into());
        }
        if self.stop_conditions.max_attempts != self.attempts.max_attempts {
            return Err("attempt and stop limits must agree".into());
        }
        for (name, value) in [
            ("quality", self.expected.quality),
            ("uncertainty", self.expected.uncertainty),
        ] {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return Err(format!("expected {name} must be between 0 and 1"));
            }
        }
        if self.expected.cost_usd_micros < 0 || self.expected.latency_ms < 0 {
            return Err("expected cost and latency must be non-negative".into());
        }
        Ok(())
    }
}

fn required(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{name} is required"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation() -> PendingOperation {
        PendingOperation {
            operation_id: "op-1".into(),
            namespace: "support".into(),
            operation_class: "triage".into(),
            priority: 80,
            risk: OperationRisk::Low,
            submitted_at_ms: 10,
            required_tools: BTreeSet::from(["search".into()]),
            allowed_models: BTreeSet::from(["local-small".into()]),
            max_attempts: 2,
            budget_ceiling_usd_micros: 50_000,
            acceptance_criteria: vec!["all tickets classified".into()],
            approval_required: false,
        }
    }

    #[test]
    fn contracts_round_trip_without_losing_hard_constraints() {
        let original = operation();
        original.validate().unwrap();
        let encoded = serde_json::to_string(&original).unwrap();
        let decoded: PendingOperation = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.risk, OperationRisk::Low);
        assert_eq!(decoded.required_tools, BTreeSet::from(["search".into()]));
    }

    #[test]
    fn invalid_capacity_and_operation_limits_are_rejected() {
        let mut invalid = operation();
        invalid.max_attempts = 0;
        assert_eq!(
            invalid.validate().unwrap_err(),
            "operation max_attempts must be positive"
        );

        let capacity = CapacityEnvelope {
            captured_at_ms: 10,
            policy_version: "policy-v1".into(),
            agents: Vec::new(),
            budget_remaining_usd_micros: 0,
            max_parallel_attempts: 0,
            human_attention_minutes: 0,
        };
        assert_eq!(
            capacity.validate().unwrap_err(),
            "capacity must allow at least one parallel attempt"
        );
    }
}
