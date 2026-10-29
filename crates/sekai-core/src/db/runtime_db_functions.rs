//! Dual-backend community-store dispatch for functions.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    /// Stores an operator-only function. A revision with an LLM step is stored only by
    /// `publish_function_revision` once its evaluation gate allows it.
    pub fn create_function(&self, f: &Function) -> Result<(), String> {
        if crate::sekai::function::has_llm_step(f) {
            return Err(crate::sekai::function::LLM_FUNCTION_REQUIRES_GATE.into());
        }
        self.store_function(f)
    }

    /// Stores a revision whose evaluation gate allowed it and records its approval.
    /// Callers must have checked the gate against this revision's digest. Re-publishing
    /// the stored revision only approves it; a different stored revision of the same name
    /// is refused. The row is written before the approval, so a failure leaves nothing
    /// newly invokable.
    pub fn publish_gated_function(&self, f: &Function) -> Result<(), String> {
        let digest = crate::sekai::function::function_digest(f);
        match self.get_function(&f.name)? {
            Some(stored) if crate::sekai::function::function_digest(&stored) == digest => {}
            Some(_) => return Err("function already exists".into()),
            None => self.store_function(f)?,
        }
        match self {
            Self::Sqlite(db) => db.approve_function_gate(&digest, &f.name),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.approve_function_gate(&digest, &f.name))
            }
        }
    }

    /// Whether this revision's digest passed an allowing evaluation gate. Rows stored
    /// before approvals were recorded have none, so they stay unapproved.
    pub fn function_gate_approved(&self, f: &Function) -> Result<bool, String> {
        let digest = crate::sekai::function::function_digest(f);
        match self {
            Self::Sqlite(db) => db.function_gate_approved(&digest),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.function_gate_approved(&digest))
            }
        }
    }

    fn store_function(&self, f: &Function) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_function(f),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_function(f)),
        }
    }

    pub fn get_function(&self, name: &str) -> Result<Option<Function>, String> {
        match self {
            Self::Sqlite(db) => db.get_function(name),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_function(name)),
        }
    }

    pub fn list_functions(&self) -> Result<Vec<Function>, String> {
        match self {
            Self::Sqlite(db) => db.list_functions(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_functions()),
        }
    }
}
