//! Hooks for the root crate's gateway tests that need a running control plane
//! (`tests/gateway_control_plane.rs`). Only the root crate builds the Sekai
//! and Chisei gRPC services, so those tests cannot live in this crate without
//! a dev-dependency on the root crate, which rebuilds this crate's tests on
//! every root edit (#2590).
//!
//! Behind the `test-support` feature and hidden from docs: not a supported
//! API.

use std::path::PathBuf;
use std::time::Duration;

use axum::Router;
use axum::http::HeaderName;

use super::{GatewayConfig, GatewayRuntime, ResilienceConfig};
use crate::llm::HttpTimeouts;

pub const POLICY_FORMAT: &str = super::POLICY_FORMAT;
pub const DEFAULT_GATEWAY_TIER: &str = super::DEFAULT_GATEWAY_TIER;
pub const DEFAULT_KEY_CACHE_TTL: Duration = Duration::from_secs(super::DEFAULT_KEY_CACHE_TTL_SECS);
pub const DEFAULT_MAX_REQUEST_BYTES: usize = super::DEFAULT_MAX_REQUEST_BYTES;
pub const X_API_KEY: HeaderName = super::X_API_KEY;
pub const X_CHISEI_AGENT: HeaderName = super::X_CHISEI_AGENT;
pub const X_CHISEI_PROJECT: HeaderName = super::X_CHISEI_PROJECT;
pub const X_CHISEI_DATA_CLASS: HeaderName = super::X_CHISEI_DATA_CLASS;
pub const X_CHISEI_OPERATION_ID: HeaderName = super::X_CHISEI_OPERATION_ID;
pub const X_CHISEI_RETRY_SAFETY: HeaderName = super::X_CHISEI_RETRY_SAFETY;

/// Gateway runtime settings a test picks instead of reading the process
/// environment, which parallel tests share.
#[derive(Clone)]
pub struct TestRuntime(GatewayRuntime);

impl TestRuntime {
    pub fn new(key_cache_ttl: Duration) -> Self {
        Self(GatewayRuntime::new(key_cache_ttl, None))
    }

    pub fn with_http_timeouts(self, http_timeouts: HttpTimeouts) -> Self {
        Self(self.0.with_http_timeouts(http_timeouts))
    }

    /// Retry the control plane `retries` times, `backoff` apart, each call
    /// bounded by `timeout`.
    pub fn with_control_plane_retries(
        self,
        retries: u32,
        backoff: Duration,
        timeout: Duration,
    ) -> Self {
        Self(self.0.with_resilience(ResilienceConfig {
            control_plane_retries: retries,
            control_plane_retry_backoff: backoff,
            control_plane_timeout: timeout,
            ..ResilienceConfig::default()
        }))
    }

    pub fn with_recovery_spool_path(self, path: PathBuf) -> Self {
        Self(self.0.with_recovery_spool_path(Some(path)))
    }

    /// Serve in policy mode from the policy file at `policy_path`, with the
    /// egress log in `log_dir`.
    pub fn with_policy(
        mut self,
        policy_path: PathBuf,
        log_dir: &std::path::Path,
    ) -> Result<Self, String> {
        self.0.policy = Some(super::PolicyStore::open(policy_path));
        self.0.egress_log = Some(super::EgressLog::open(log_dir)?);
        Ok(self)
    }

    /// Accept `token` on the admin refresh route.
    pub fn with_admin_token(mut self, token: &str) -> Self {
        self.0.admin_token = Some(token.to_string());
        self
    }
}

/// The gateway router over `runtime` instead of the environment.
pub fn app(config: GatewayConfig, runtime: TestRuntime) -> Router {
    super::app_with_runtime(config, runtime.0)
}
