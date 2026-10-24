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
        let grants = db.runtime().list_all_grants().unwrap_or_default();
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
            enforce_agent_ceiling: false,
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

    pub fn with_agent_ceiling(mut self, enforce: bool) -> Self {
        self.enforce_agent_ceiling = enforce;
        self
    }

    pub fn with_dry_run_host(
        mut self,
        host: Option<Arc<dyn crate::sekai::agent_dry_run::AgentDryRunHost>>,
    ) -> Self {
        self.dry_run_host = host;
        self
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
}
