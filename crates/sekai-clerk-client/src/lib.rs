//! Public clerk surface for a remote Sekai server (ADR 0082).
//!
//! Chisei may import this crate. It may not import Sekai internals.

pub use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
pub use sekai_proto::sekai::{
    ActionInstance, GetGovernedActionTypeRequest, GetGovernedActionTypeResponse, GetObjectRequest,
    GetObjectResponse, GetPersistedOperationReceiptRequest, GetPersistedOperationReceiptResponse,
    PersistAdmittedActionRequest, PersistAdmittedActionResponse,
};
