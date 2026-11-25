//! The one connector runtime (ADR 0148).
//!
//! A worker that claims Source work from the plane's one work queue
//! (ADR 0149) and runs the connector types it implements. It talks to the
//! plane only over gRPC and never links the control-plane packages. It
//! holds the operator's credential bindings; the plane holds only the
//! handles. Placement, schedules and claims stay on the plane, so any
//! number of runtimes can serve a namespace and any of them can stop.
//!
//! A sync applies the Source's snapshot pages as source batches
//! ([`pages`]). The runtime also delivers saved exports whose definition
//! names a Source of a type it implements ([`delivery`]), and applies
//! admitted Actions' external changes to a Source's records ([`effect`]),
//! and runs requested discoveries of a Source ([`discovery`]).
//! The connector types are [`github`] (sync and apply), [`relational`]
//! (snapshot pages, delivery and apply), [`rest`] (paged JSON over HTTP:
//! sync and apply), [`event_stream`] (JSON records from one topic of an
//! event-stream cluster: sync), which reads through the [`broker`] client,
//! and [`object_storage`] (rows of the objects under one bucket prefix,
//! mirrored against the plane's live records: sync).
//! Given a gateway route, it also runs the row-wise model steps of
//! `llm-rows` transforms ([`llm_rows`]).

pub mod broker;
pub mod credentials;
pub mod delivery;
pub mod discovery;
pub mod effect;
pub mod event_stream;
pub mod github;
pub mod llm_rows;
pub mod object_storage;
pub mod pages;
pub mod relational;
pub mod rest;
pub mod runtime;
pub mod sync;

pub use credentials::{CredentialBinding, CredentialBindings, Credentials, Secret, SlotSource};
pub use effect::Effected;
pub use runtime::{Ran, Runtime, RuntimeOptions};
pub use sync::{Connectors, Open, Prepared, SyncFailure, prepare};
