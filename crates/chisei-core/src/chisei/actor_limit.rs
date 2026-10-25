//! Per-principal and per-agent token-bucket limits (#1563).
//!
//! Tenant quotas (#119) bound a tenant. This gate bounds the identities on
//! an actor chain so one user or one agent cannot exhaust shared RPC/MCP
//! capacity. Enforcement stays off until `SEKAI_ACTOR_CHAIN_ENFORCEMENT=1`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use sekai_core::enterprise::{ActorChain, ActorKind};

/// Default refill when enforcement is on and the env value is missing or zero.
pub const DEFAULT_REQUESTS_PER_MINUTE: u32 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBucketLimits {
    pub requests_per_minute: u32,
}

impl TokenBucketLimits {
    fn rate_per_sec(self) -> f64 {
        f64::from(self.requests_per_minute.max(1)) / 60.0
    }

    fn burst(self) -> f64 {
        f64::from(self.requests_per_minute.max(1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorRateError {
    Exhausted {
        kind: ActorKind,
        actor: String,
        retry_after_ms: u64,
    },
    Unavailable,
}

impl std::fmt::Display for ActorRateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exhausted {
                kind,
                retry_after_ms,
                ..
            } => write!(
                f,
                "actor rate limit exhausted for {}; retry_after={retry_after_ms}ms",
                kind.as_str()
            ),
            Self::Unavailable => write!(f, "actor rate limiter unavailable"),
        }
    }
}

impl std::error::Error for ActorRateError {}

#[derive(Clone)]
pub struct ActorRateGate {
    inner: Arc<ActorRateInner>,
}

struct ActorRateInner {
    enabled: bool,
    principal: TokenBucketLimits,
    agent: TokenBucketLimits,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl ActorRateGate {
    pub fn disabled() -> Self {
        Self {
            inner: Arc::new(ActorRateInner {
                enabled: false,
                principal: TokenBucketLimits {
                    requests_per_minute: DEFAULT_REQUESTS_PER_MINUTE,
                },
                agent: TokenBucketLimits {
                    requests_per_minute: DEFAULT_REQUESTS_PER_MINUTE,
                },
                buckets: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn enabled(principal_rpm: u32, agent_rpm: u32) -> Self {
        Self {
            inner: Arc::new(ActorRateInner {
                enabled: true,
                principal: TokenBucketLimits {
                    requests_per_minute: principal_rpm.max(1),
                },
                agent: TokenBucketLimits {
                    requests_per_minute: agent_rpm.max(1),
                },
                buckets: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn from_config(config: &crate::config::Config) -> Self {
        if !config.actor_chain_enforcement {
            return Self::disabled();
        }
        Self::enabled(
            config.principal_requests_per_minute,
            config.agent_requests_per_minute,
        )
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.enabled
    }

    pub fn admit(&self, chain: &ActorChain) -> Result<(), ActorRateError> {
        self.admit_at(chain, Instant::now())
    }

    pub fn admit_at(&self, chain: &ActorChain, now: Instant) -> Result<(), ActorRateError> {
        if !self.inner.enabled {
            return Ok(());
        }
        let keys: Vec<(ActorKind, String)> = chain
            .rate_limit_keys()
            .map(|(kind, id)| (kind, bucket_key(kind, id)))
            .collect();
        let mut buckets = self
            .inner
            .buckets
            .lock()
            .map_err(|_| ActorRateError::Unavailable)?;
        let mut charged: Vec<(String, TokenBucketLimits)> = Vec::new();
        for (kind, key) in &keys {
            let limits = match kind {
                ActorKind::Principal => self.inner.principal,
                ActorKind::Agent => self.inner.agent,
            };
            let remaining = {
                let bucket = buckets.entry(key.clone()).or_insert_with(|| Bucket {
                    tokens: limits.burst(),
                    last: now,
                });
                refill(bucket, now, limits);
                if bucket.tokens >= 1.0 {
                    bucket.tokens -= 1.0;
                    None
                } else {
                    Some(bucket.tokens)
                }
            };
            let Some(remaining) = remaining else {
                charged.push((key.clone(), limits));
                continue;
            };
            for (charged_key, charged_limits) in charged {
                if let Some(refund) = buckets.get_mut(&charged_key) {
                    refund.tokens = (refund.tokens + 1.0).min(charged_limits.burst());
                }
            }
            let retry_after_ms = retry_after_ms(remaining, limits.rate_per_sec());
            metrics::counter!(
                "sekai_actor_limit_throttled_total",
                "kind" => kind.as_str()
            )
            .increment(1);
            return Err(ActorRateError::Exhausted {
                kind: *kind,
                actor: key.clone(),
                retry_after_ms,
            });
        }
        Ok(())
    }
}

fn bucket_key(kind: ActorKind, id: &str) -> String {
    format!("{}:{id}", kind.as_str())
}

fn refill(bucket: &mut Bucket, now: Instant, limits: TokenBucketLimits) {
    let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * limits.rate_per_sec()).min(limits.burst());
    bucket.last = now;
}

fn retry_after_ms(tokens: f64, rate_per_sec: f64) -> u64 {
    if rate_per_sec <= 0.0 {
        return 60_000;
    }
    let wait = ((1.0 - tokens).max(0.0) / rate_per_sec) * 1_000.0;
    wait.ceil() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn chain(subject: &str, act: Option<&str>) -> ActorChain {
        ActorChain::from_authenticated(subject, act).unwrap()
    }

    #[test]
    fn disabled_gate_never_throttles() {
        let gate = ActorRateGate::disabled();
        let now = Instant::now();
        for _ in 0..8 {
            gate.admit_at(&chain("alice", None), now).unwrap();
        }
    }

    #[test]
    fn principal_bucket_throttles_after_burst() {
        let gate = ActorRateGate::enabled(1, 60);
        let now = Instant::now();
        let principal = chain("alice", None);
        gate.admit_at(&principal, now).unwrap();
        let error = gate.admit_at(&principal, now).unwrap_err();
        match error {
            ActorRateError::Exhausted {
                kind,
                retry_after_ms,
                ..
            } => {
                assert_eq!(kind, ActorKind::Principal);
                assert!(retry_after_ms >= 1);
            }
            other => panic!("{other}"),
        }
        gate.admit_at(&principal, now + Duration::from_secs(60))
            .unwrap();
    }

    #[test]
    fn agent_bucket_is_independent_of_the_user_bucket() {
        let gate = ActorRateGate::enabled(60, 1);
        let now = Instant::now();
        let delegated = chain("runtime-1", Some("alice"));
        gate.admit_at(&delegated, now).unwrap();
        let error = gate.admit_at(&delegated, now).unwrap_err();
        match error {
            ActorRateError::Exhausted { kind, .. } => assert_eq!(kind, ActorKind::Agent),
            other => panic!("{other}"),
        }
        gate.admit_at(&chain("alice", None), now).unwrap();
        gate.admit_at(&chain("runtime-2", Some("alice")), now)
            .unwrap();
    }

    #[test]
    fn cloned_gates_share_buckets() {
        let gate = ActorRateGate::enabled(1, 60);
        let clone = gate.clone();
        let now = Instant::now();
        let principal = chain("alice", None);
        clone.admit_at(&principal, now).unwrap();
        let error = gate.admit_at(&principal, now).unwrap_err();
        match error {
            ActorRateError::Exhausted { kind, .. } => assert_eq!(kind, ActorKind::Principal),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn failed_agent_admit_does_not_consume_the_principal_token() {
        let gate = ActorRateGate::enabled(2, 1);
        let now = Instant::now();
        let first = chain("runtime-1", Some("alice"));
        gate.admit_at(&first, now).unwrap();
        gate.admit_at(&first, now).unwrap_err();
        gate.admit_at(&chain("alice", None), now).unwrap();
    }
}
