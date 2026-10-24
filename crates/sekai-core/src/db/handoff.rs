//! Backend-neutral durable handoff persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::handoff::HandoffManifest;

pub trait HandoffBackend: Send + Sync {
    fn create_handoff(
        &self,
        manifest: &HandoffManifest,
        request_id: &str,
    ) -> Result<HandoffManifest, String>;
    fn get_handoff_by_request(
        &self,
        creator: &str,
        request_id: &str,
    ) -> Result<Option<(String, HandoffManifest)>, String>;
    fn get_handoff(&self, id: &str) -> Result<Option<HandoffManifest>, String>;
    fn handoff_is_superseded(&self, id: &str) -> Result<bool, String>;
    fn revoke_handoff(
        &self,
        id: &str,
        actor: &str,
        reason: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<HandoffManifest, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn create_handoff(
            &self,
            value: &HandoffManifest,
            request: &str,
        ) -> Result<HandoffManifest, String> {
            <$target>::create_handoff(self, value, request)
        }
        fn get_handoff_by_request(
            &self,
            creator: &str,
            request: &str,
        ) -> Result<Option<(String, HandoffManifest)>, String> {
            <$target>::get_handoff_by_request(self, creator, request)
        }
        fn get_handoff(&self, id: &str) -> Result<Option<HandoffManifest>, String> {
            <$target>::get_handoff(self, id)
        }
        fn handoff_is_superseded(&self, id: &str) -> Result<bool, String> {
            <$target>::handoff_is_superseded(self, id)
        }
        fn revoke_handoff(
            &self,
            id: &str,
            actor: &str,
            reason: &str,
            request: &str,
            now: i64,
        ) -> Result<HandoffManifest, String> {
            <$target>::revoke_handoff(self, id, actor, reason, request, now)
        }
    };
}

impl HandoffBackend for SekaiDb {
    forward!(SekaiDb);
}
impl HandoffBackend for PostgresDb {
    forward!(PostgresDb);
}
