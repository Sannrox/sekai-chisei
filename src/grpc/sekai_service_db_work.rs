//! Store work on the blocking pool, bounded by the connection pool.

use super::*;

pub(super) fn db_work_limiter(db: &crate::db::store::SekaiStore) -> Arc<tokio::sync::Semaphore> {
    let permits = db.runtime().connection_pool_max().max(1) as usize;
    Arc::new(tokio::sync::Semaphore::new(permits))
}

impl SekaiServiceImpl {
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
