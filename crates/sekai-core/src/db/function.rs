//! Backend-neutral durable function definition persistence.
//!
//! Function *execution* stays non-persistent and is evaluated against dataset,
//! graph, and authorization dependencies of the active runtime.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::function::Function;

pub const POSTGRES_FUNCTION_DEFINITION_SURFACE: &str = "sekai.function-definitions";

pub trait FunctionBackend: Send + Sync {
    fn create_function(&self, function: &Function) -> Result<(), String>;
    fn get_function(&self, name: &str) -> Result<Option<Function>, String>;
    fn list_functions(&self) -> Result<Vec<Function>, String>;
}

impl FunctionBackend for SekaiDb {
    fn create_function(&self, function: &Function) -> Result<(), String> {
        SekaiDb::create_function(self, function)
    }
    fn get_function(&self, name: &str) -> Result<Option<Function>, String> {
        SekaiDb::get_function(self, name)
    }
    fn list_functions(&self) -> Result<Vec<Function>, String> {
        SekaiDb::list_functions(self)
    }
}

impl FunctionBackend for PostgresDb {
    fn create_function(&self, function: &Function) -> Result<(), String> {
        PostgresDb::create_function(self, function)
    }
    fn get_function(&self, name: &str) -> Result<Option<Function>, String> {
        PostgresDb::get_function(self, name)
    }
    fn list_functions(&self) -> Result<Vec<Function>, String> {
        PostgresDb::list_functions(self)
    }
}
