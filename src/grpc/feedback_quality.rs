//! Combined-mode worker that verifies later observations against findings (#1233).
//!
//! Records quality and verification objects in the finding namespace. Eval-suite
//! promotion requires `SEKAI_FEEDBACK_QUALITY_PROMOTE=1`. Never closes tracker
//! issues, activates learning, or changes detector policy.

use super::chisei_service::ChiseiServiceImpl;
use crate::chisei::feedback_quality_eval::promote_quality_to_eval;
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::feedback_package::PACKAGE_ID;
use crate::sekai::feedback_quality::{
    POLL_INTERVAL_SECS, RUNTIME_ID, evaluate_namespace, maintainer_control, quality_corpus_case,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const RUN_AS_ENV: &str = "SEKAI_FEEDBACK_QUALITY_RUN_AS";
const PROMOTE_ENV: &str = "SEKAI_FEEDBACK_QUALITY_PROMOTE";

pub(super) fn spawn_feedback_quality(db: Arc<RuntimeDb>, chisei: Arc<ChiseiServiceImpl>) {
    tracing::info!(
        interval_secs = POLL_INTERVAL_SECS,
        runtime = RUNTIME_ID,
        "feedback quality worker enabled"
    );
    tokio::spawn(async move {
        let evaluating = Mutex::new(());
        let mut interval = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let Ok(_guard) = evaluating.try_lock() else {
                continue;
            };
            let db = db.clone();
            let chisei = chisei.clone();
            if let Err(error) = tokio::task::spawn_blocking(move || quality_pass(&db, &chisei))
                .await
                .unwrap_or_else(|error| Err(error.to_string()))
            {
                tracing::error!(%error, "feedback quality pass failed");
            }
        }
    });
}

fn configured_run_as() -> String {
    std::env::var(RUN_AS_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| RUNTIME_ID.to_string())
}

fn promote_enabled() -> bool {
    matches!(
        std::env::var(PROMOTE_ENV)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

fn quality_pass(db: &RuntimeDb, chisei: &ChiseiServiceImpl) -> Result<(), String> {
    let control = maintainer_control();
    debug_assert!(!control.close_issue);
    debug_assert!(!control.activate_learning);
    debug_assert!(!control.change_detector_policy);
    let actor = configured_run_as();
    let promote = promote_enabled();
    let now_ms = chrono::Utc::now().timestamp_millis();
    for namespace in db.list_live_package_namespaces(PACKAGE_ID)? {
        let report = evaluate_namespace(db, &namespace, &actor, now_ms)
            .map_err(|error| format!("{error:?}"))?;
        if !promote {
            continue;
        }
        for record in report.records {
            let case = quality_corpus_case(&record);
            match promote_quality_to_eval(&chisei.db, &actor, &case, now_ms) {
                Ok(_) => {}
                Err(error) if error.contains("unavailable on the PostgreSQL") => {
                    tracing::info!(
                        namespace = %namespace,
                        "feedback quality eval suite unavailable on this store"
                    );
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_worker_polls_every_15_seconds() {
        assert_eq!(POLL_INTERVAL_SECS, 15);
        assert_eq!(RUNTIME_ID, "feedback-quality");
        let control = maintainer_control();
        assert!(!control.close_issue);
        assert!(!control.activate_learning);
        assert!(!control.change_detector_policy);
    }
}
