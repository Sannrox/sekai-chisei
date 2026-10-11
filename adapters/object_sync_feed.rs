//! Bounded ordered change-feed runner for v2 source-sync adapters.
//!
//! Implementation lives in `sekai-source-sdk`.
#![allow(unused_imports)]

pub use sekai_source_sdk::{
    ChangeFeedPage, ChangeFeedRunError, ChangeFeedSource, ChangeFeedSourceFailure, run_change_feed,
};
