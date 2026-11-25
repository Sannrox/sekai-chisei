use std::sync::Arc;

use super::SekaiServiceImpl;
use super::db_work::db_work_limiter;
use super::schema_definition_lifecycle::SchemaDefinitionLifecycle;
use crate::sekai::security::SecurityChecker;

impl SekaiServiceImpl {
    pub fn new(db: crate::db::store::SekaiStore) -> Self {
        Self::new_with_gateway_schema_principals(db, Vec::new())
    }

    pub fn new_with_gateway_schema_principals(
        db: crate::db::store::SekaiStore,
        gateway_schema_principals: Vec<String>,
    ) -> Self {
        let security = Arc::new(SecurityChecker::new());
        // An empty ACL cache allows every object without a cached grant, so an
        // unreadable grant table (for example an unsupported persisted role)
        // refuses startup instead of loading no grants.
        let grants = db
            .runtime()
            .list_all_grants()
            .expect("load persisted grants into the access cache");
        security.load(&grants);
        let schema_definitions = SchemaDefinitionLifecycle::load(db.runtime_arc());
        let object_query_cursor_key = db
            .runtime()
            .object_query_cursor_key()
            .expect("initialize durable object query cursor key");
        let db_work = db_work_limiter(&db);
        Self {
            db,
            security,
            db_work,
            schema_definitions,
            gateway_schema_principals,
            site_id: crate::sekai::lease::DEFAULT_SITE_ID.into(),
            object_query_cursor_key,
            object_index_engine: crate::sekai::object_index_engine::ObjectIndexEngineKind::from_env(
            ),
            object_index_dual_read:
                crate::sekai::object_index_engine::ObjectIndexEngineKind::dual_read_from_env(),
            object_log_dual_read: crate::sekai::object_log::ObjectLogDualRead::from_env(),
            cross_store: None,
            runtime_token_authority: None,
            dry_run_host: None,
            embedding_route: None,
            egress: crate::composition::gateway_egress_policy::EgressPolicies::new([]),
        }
    }

    /// Mint runtime tokens in Action work claim responses with `authority`,
    /// the same key the authentication boundary verifies them with.
    pub fn with_runtime_token_authority(
        mut self,
        authority: Option<Arc<crate::identity_assertion::AssertionAuthority>>,
    ) -> Self {
        self.runtime_token_authority = authority;
        self
    }

    pub fn with_dry_run_host(
        mut self,
        host: Option<Arc<dyn crate::sekai::agent_dry_run::AgentDryRunHost>>,
    ) -> Self {
        self.dry_run_host = host;
        self
    }

    /// Withhold read values by the allowed egress in `policies` (ADR 0164).
    pub fn set_egress_policies(
        &mut self,
        policies: Arc<crate::composition::gateway_egress_policy::EgressPolicies>,
    ) {
        self.egress = policies;
    }

    pub fn with_embedding_route(
        mut self,
        route: crate::composition::embedding_catch_up::EmbeddingRoute,
    ) -> Self {
        self.embedding_route = Some(route);
        self
    }

    pub fn with_cross_store_admission(
        mut self,
        clerk: std::sync::Arc<crate::composition::cross_store_admission::CrossStoreAdmission>,
    ) -> Self {
        self.cross_store = Some(clerk);
        self
    }

    /// Budget and usage live on the Chisei store in a split layout.
    pub(crate) fn quota_runtime(&self) -> std::sync::Arc<crate::db::runtime_db::RuntimeDb> {
        self.cross_store
            .as_ref()
            .map(|clerk| clerk.chisei_runtime_arc())
            .unwrap_or_else(|| self.db.runtime_arc())
    }

    pub fn with_site_id(mut self, site_id: impl Into<String>) -> Self {
        self.site_id = site_id.into();
        self
    }

    /// Replaces the object-log dual-read configuration read from the
    /// environment at construction, so a caller can point the gate at its
    /// own log without process-wide variables.
    pub fn with_object_log_dual_read(
        mut self,
        dual_read: crate::sekai::object_log::ObjectLogDualRead,
    ) -> Self {
        self.object_log_dual_read = dual_read;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::SekaiServiceImpl;
    use crate::sekai::security::{Grant, Role};

    /// One unreadable grant row must refuse startup: loading no grants would
    /// leave every protected object with an empty, permissive ACL cache.
    #[test]
    #[should_panic(expected = "load persisted grants into the access cache")]
    fn startup_refuses_a_grant_table_with_an_unsupported_role() {
        let store = crate::db::store::SekaiStore::memory();
        let runtime = store.runtime();
        runtime
            .create_object(&crate::domain::Object {
                id: "ns-ops".into(),
                kind: "namespace".into(),
                name: "ops".into(),
                namespace: "ops".into(),
                external_id: "namespace:ops".into(),
                properties: Default::default(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        runtime
            .create_grant(&Grant {
                id: "g1".into(),
                object_id: "ns-ops".into(),
                principal: "alice".into(),
                role: Role::Editor,
                created: 10,
                ..Default::default()
            })
            .unwrap();
        runtime
            .conn()
            .execute("UPDATE sekai_grants SET role = 'owner' WHERE id = 'g1'", [])
            .unwrap();
        let _ = SekaiServiceImpl::new(store);
    }
}
