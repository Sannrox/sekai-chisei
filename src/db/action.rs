//! Backend-neutral persistence for reusable action definitions.
//!
//! Action policy and approval records are graph objects and therefore use the
//! graph backend contract. This contract owns the remaining dedicated action
//! table.

use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::action::ActionTypeDef;

pub trait ActionTypeBackend: Send + Sync {
    fn upsert_action_type(&self, action_type: &ActionTypeDef) -> Result<ActionTypeDef, String>;
    fn delete_action_type(&self, name: &str) -> Result<bool, String>;
    fn list_action_types(&self) -> Result<Vec<ActionTypeDef>, String>;
}

impl ActionTypeBackend for SekaiDb {
    fn upsert_action_type(&self, action_type: &ActionTypeDef) -> Result<ActionTypeDef, String> {
        SekaiDb::upsert_action_type(self, action_type)
    }
    fn delete_action_type(&self, name: &str) -> Result<bool, String> {
        SekaiDb::delete_action_type(self, name)
    }
    fn list_action_types(&self) -> Result<Vec<ActionTypeDef>, String> {
        SekaiDb::list_action_types(self)
    }
}

impl ActionTypeBackend for PostgresDb {
    fn upsert_action_type(&self, action_type: &ActionTypeDef) -> Result<ActionTypeDef, String> {
        PostgresDb::upsert_action_type(self, action_type)
    }
    fn delete_action_type(&self, name: &str) -> Result<bool, String> {
        PostgresDb::delete_action_type(self, name)
    }
    fn list_action_types(&self) -> Result<Vec<ActionTypeDef>, String> {
        PostgresDb::list_action_types(self)
    }
}
