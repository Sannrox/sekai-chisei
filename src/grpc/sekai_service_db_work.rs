//! Store work on the blocking pool, bounded by the connection pool.

use super::*;

pub(super) fn db_work_limiter(db: &crate::db::store::SekaiStore) -> Arc<tokio::sync::Semaphore> {
    let permits = db.runtime().connection_pool_max().max(1) as usize;
    Arc::new(tokio::sync::Semaphore::new(permits))
}

impl SekaiServiceImpl {
    /// Registered so wrong-plane Sekai RPCs can return FAILED_PRECONDITION
    /// without requiring Sekai tables on a Chisei-only dest.
    pub fn wrong_plane_placeholder(db: crate::db::store::SekaiStore) -> Self {
        let schema_definitions = SchemaDefinitionLifecycle::empty(db.runtime_arc());
        let db_work = db_work_limiter(&db);
        Self {
            db,
            security: Arc::new(SecurityChecker::new()),
            db_work,
            schema_definitions,
            gateway_schema_principals: Vec::new(),
            site_id: crate::sekai::lease::DEFAULT_SITE_ID.into(),
            object_query_cursor_key: [0u8; 32],
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

    /// Run store work on the blocking pool, bounded by the connection pool.
    pub(super) async fn spawn_db<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T, Status> + Send + 'static,
    ) -> Result<T, Status> {
        let permit = self
            .db_work
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Status::unavailable("database worker closed"))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .unwrap_or_else(|_| Err(Status::unavailable("database worker cancelled")))
    }
}
