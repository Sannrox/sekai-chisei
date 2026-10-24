//! Backend-neutral scoped content and reversible reconciliation persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::deduplication::{
    ContentAdmission, ContentObligations, ContentReferenceRequest, ContentScope,
    GarbageCollectionResult, ReconciliationDecision, ReconciliationOutcome, ReconciliationRequest,
    ReconciliationState,
};

pub trait DeduplicationBackend: Send + Sync {
    fn put_scoped_content(
        &self,
        scope: &ContentScope,
        request: &ContentReferenceRequest,
        content: &[u8],
        now_ms: i64,
    ) -> Result<ContentAdmission, String>;
    fn read_scoped_content(
        &self,
        scope: &ContentScope,
        reference_id: &str,
    ) -> Result<Option<Vec<u8>>, String>;
    fn release_content_reference(
        &self,
        scope: &ContentScope,
        reference_id: &str,
        actor: &str,
        reason: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<bool, String>;
    #[allow(clippy::too_many_arguments)]
    fn set_content_obligations(
        &self,
        scope: &ContentScope,
        reference_id: &str,
        obligations: &ContentObligations,
        actor: &str,
        reason: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<bool, String>;
    fn collect_scoped_content_garbage(
        &self,
        scope: &ContentScope,
        actor: &str,
        now_ms: i64,
    ) -> Result<GarbageCollectionResult, String>;
    fn reconcile_objects(
        &self,
        request: &ReconciliationRequest,
        now_ms: i64,
    ) -> Result<ReconciliationOutcome, String>;
    fn reverse_reconciliation(
        &self,
        decision_id: &str,
        actor: &str,
        reason: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ReconciliationOutcome, String>;
    fn reconciliation_state(&self, case_id: &str) -> Result<ReconciliationState, String>;
    fn reconciliation_history(&self, case_id: &str) -> Result<Vec<ReconciliationDecision>, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn put_scoped_content(
            &self,
            scope: &ContentScope,
            request: &ContentReferenceRequest,
            content: &[u8],
            now: i64,
        ) -> Result<ContentAdmission, String> {
            <$target>::put_scoped_content(self, scope, request, content, now)
        }
        fn read_scoped_content(
            &self,
            scope: &ContentScope,
            reference_id: &str,
        ) -> Result<Option<Vec<u8>>, String> {
            <$target>::read_scoped_content(self, scope, reference_id)
        }
        fn release_content_reference(
            &self,
            scope: &ContentScope,
            reference_id: &str,
            actor: &str,
            reason: &str,
            key: &str,
            now: i64,
        ) -> Result<bool, String> {
            <$target>::release_content_reference(self, scope, reference_id, actor, reason, key, now)
        }
        fn set_content_obligations(
            &self,
            scope: &ContentScope,
            reference_id: &str,
            obligations: &ContentObligations,
            actor: &str,
            reason: &str,
            key: &str,
            now: i64,
        ) -> Result<bool, String> {
            <$target>::set_content_obligations(
                self,
                scope,
                reference_id,
                obligations,
                actor,
                reason,
                key,
                now,
            )
        }
        fn collect_scoped_content_garbage(
            &self,
            scope: &ContentScope,
            actor: &str,
            now: i64,
        ) -> Result<GarbageCollectionResult, String> {
            <$target>::collect_scoped_content_garbage(self, scope, actor, now)
        }
        fn reconcile_objects(
            &self,
            request: &ReconciliationRequest,
            now: i64,
        ) -> Result<ReconciliationOutcome, String> {
            <$target>::reconcile_objects(self, request, now)
        }
        fn reverse_reconciliation(
            &self,
            id: &str,
            actor: &str,
            reason: &str,
            key: &str,
            now: i64,
        ) -> Result<ReconciliationOutcome, String> {
            <$target>::reverse_reconciliation(self, id, actor, reason, key, now)
        }
        fn reconciliation_state(&self, id: &str) -> Result<ReconciliationState, String> {
            <$target>::reconciliation_state(self, id)
        }
        fn reconciliation_history(&self, id: &str) -> Result<Vec<ReconciliationDecision>, String> {
            <$target>::reconciliation_history(self, id)
        }
    };
}

impl DeduplicationBackend for SekaiDb {
    forward!(SekaiDb);
}
impl DeduplicationBackend for PostgresDb {
    forward!(PostgresDb);
}
