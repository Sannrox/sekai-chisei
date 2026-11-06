//! Reference evidence adapters that run outside the plane.
//!
//! The sources stay in the repository's `adapters/` directory next to their
//! fixtures and README; this crate compiles them once for the examples and
//! the conformance test.

#[path = "../../../adapters/sdk.rs"]
pub mod sdk;

#[path = "../../../adapters/github_check_webhook.rs"]
pub mod github_check_webhook;
#[path = "../../../adapters/http_health_poll.rs"]
pub mod http_health_poll;
#[path = "../../../adapters/ontology_concept_catalog.rs"]
pub mod ontology_concept_catalog;
#[path = "../../../adapters/social_post_snapshot.rs"]
pub mod social_post_snapshot;
#[path = "../../../adapters/social_reply.rs"]
pub mod social_reply;
