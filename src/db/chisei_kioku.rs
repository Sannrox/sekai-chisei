//! Backend-neutral Kioku memory persistence.

use crate::chisei::kioku::{
    HumanMemoryReview, KiokuEvidenceLink, KiokuMemory, MemoryLifecycleEvent, MemoryValidation,
};
use crate::db::{postgres::PostgresDb, sekai::SekaiDb};

pub trait ChiseiKiokuBackend: Send + Sync {
    fn insert_kioku_memory(
        &self,
        memory: &KiokuMemory,
        evidence: &[KiokuEvidenceLink],
    ) -> Result<(), String>;
    fn get_kioku_memory(&self, id: &str, version: u32) -> Result<Option<KiokuMemory>, String>;
    fn list_kioku_candidates(
        &self,
        namespace: &str,
        operation_class: Option<&str>,
        limit: usize,
    ) -> Result<Vec<KiokuMemory>, String>;
    fn list_kioku_evidence(&self, id: &str, version: u32)
    -> Result<Vec<KiokuEvidenceLink>, String>;
    fn validate_kioku_candidate(&self, id: &str, version: u32) -> Result<MemoryValidation, String>;
    fn review_kioku_candidate(
        &self,
        id: &str,
        version: u32,
        review: HumanMemoryReview,
    ) -> Result<KiokuMemory, String>;
    fn list_kioku_lifecycle_events(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<MemoryLifecycleEvent>, String>;
    fn record_kioku_lifecycle_event(&self, event: &MemoryLifecycleEvent) -> Result<(), String>;
    fn disable_kioku_memory(
        &self,
        id: &str,
        version: u32,
        actor: &str,
        rationale: &str,
        recorded_at_ms: i64,
    ) -> Result<KiokuMemory, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn insert_kioku_memory(
            &self,
            memory: &KiokuMemory,
            evidence: &[KiokuEvidenceLink],
        ) -> Result<(), String> {
            <$target>::insert_kioku_memory(self, memory, evidence)
        }
        fn get_kioku_memory(&self, id: &str, version: u32) -> Result<Option<KiokuMemory>, String> {
            <$target>::get_kioku_memory(self, id, version)
        }
        fn list_kioku_candidates(
            &self,
            namespace: &str,
            operation_class: Option<&str>,
            limit: usize,
        ) -> Result<Vec<KiokuMemory>, String> {
            <$target>::list_kioku_candidates(self, namespace, operation_class, limit)
        }
        fn list_kioku_evidence(
            &self,
            id: &str,
            version: u32,
        ) -> Result<Vec<KiokuEvidenceLink>, String> {
            <$target>::list_kioku_evidence(self, id, version)
        }
        fn validate_kioku_candidate(
            &self,
            id: &str,
            version: u32,
        ) -> Result<MemoryValidation, String> {
            <$target>::validate_kioku_candidate(self, id, version)
        }
        fn review_kioku_candidate(
            &self,
            id: &str,
            version: u32,
            review: HumanMemoryReview,
        ) -> Result<KiokuMemory, String> {
            <$target>::review_kioku_candidate(self, id, version, review)
        }
        fn list_kioku_lifecycle_events(
            &self,
            id: &str,
            version: u32,
        ) -> Result<Vec<MemoryLifecycleEvent>, String> {
            <$target>::list_kioku_lifecycle_events(self, id, version)
        }
        fn record_kioku_lifecycle_event(&self, event: &MemoryLifecycleEvent) -> Result<(), String> {
            <$target>::record_kioku_lifecycle_event(self, event)
        }
        fn disable_kioku_memory(
            &self,
            id: &str,
            version: u32,
            actor: &str,
            rationale: &str,
            recorded_at_ms: i64,
        ) -> Result<KiokuMemory, String> {
            <$target>::disable_kioku_memory(self, id, version, actor, rationale, recorded_at_ms)
        }
    };
}

impl ChiseiKiokuBackend for SekaiDb {
    forward!(SekaiDb);
}
impl ChiseiKiokuBackend for PostgresDb {
    forward!(PostgresDb);
}
