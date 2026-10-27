//! Shared SQLite/PostgreSQL conformance for live policy shadow state (#1630).

use sekai_chisei::chisei::policy::Policy;
use sekai_chisei::chisei::policy_shadow::{
    ACTIVATION_CLAIM_MS, ACTIVATION_IN_PROGRESS, MAX_SHADOW_SAMPLES, PolicyShadow,
    PolicyShadowReport, ShadowDelta, ShadowSample,
};
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::ext::*;

trait ShadowHarness {
    fn start(&self, shadow: &PolicyShadow) -> Result<(), String>;
    fn stop(&self, namespace: &str, shadow_id: Option<&str>) -> Result<bool, String>;
    fn stop_unclaimed(&self, namespace: &str, now_ms: i64) -> Result<bool, String>;
    fn find(&self, scopes: &[String]) -> Result<Option<PolicyShadow>, String>;
    fn claim(&self, namespace: &str, shadow_id: &str, now_ms: i64) -> Result<bool, String>;
    fn confirm(&self, namespace: &str, shadow_id: &str, at: i64, now: i64) -> Result<bool, String>;
    fn record(&self, shadow_id: &str, sample: &ShadowSample) -> Result<(), String>;
    fn report(&self, namespace: &str) -> Result<Option<PolicyShadowReport>, String>;
}

macro_rules! harness {
    ($db:ty) => {
        impl ShadowHarness for $db {
            fn start(&self, shadow: &PolicyShadow) -> Result<(), String> {
                self.start_policy_shadow(shadow)
            }
            fn stop(&self, namespace: &str, shadow_id: Option<&str>) -> Result<bool, String> {
                self.stop_policy_shadow(namespace, shadow_id, None)
            }
            fn stop_unclaimed(&self, namespace: &str, now_ms: i64) -> Result<bool, String> {
                self.stop_policy_shadow(namespace, None, Some(now_ms))
            }
            fn find(&self, scopes: &[String]) -> Result<Option<PolicyShadow>, String> {
                self.find_policy_shadow(scopes)
            }
            fn claim(&self, namespace: &str, shadow_id: &str, now_ms: i64) -> Result<bool, String> {
                self.claim_policy_shadow_activation(namespace, shadow_id, now_ms)
            }
            fn confirm(
                &self,
                namespace: &str,
                shadow_id: &str,
                at: i64,
                now: i64,
            ) -> Result<bool, String> {
                self.confirm_policy_shadow_activation(namespace, shadow_id, at, now)
            }
            fn record(&self, shadow_id: &str, sample: &ShadowSample) -> Result<(), String> {
                self.record_policy_shadow_observation(shadow_id, sample)
            }
            fn report(&self, namespace: &str) -> Result<Option<PolicyShadowReport>, String> {
                self.policy_shadow_report(namespace)
            }
        }
    };
}
harness!(SekaiDb);
harness!(PostgresDb);

fn shadow(namespace: &str, run: &str, default_model: &str) -> PolicyShadow {
    let candidate = Policy {
        allowed_runtimes: vec!["native".into()],
        allowed_models: vec!["native-default".into()],
        default_runtime: "native".into(),
        default_model: default_model.into(),
        data_class: "internal".into(),
    };
    PolicyShadow {
        shadow_id: format!("{namespace}-{run}"),
        namespace: namespace.into(),
        candidate_version: candidate.version(),
        candidate,
        active_version: String::new(),
        min_evaluations: 1,
        min_match_rate_bps: 9_000,
        started_by: "root".into(),
        started_at_ms: 1,
    }
}

fn sample(delta: ShadowDelta, at: i64) -> ShadowSample {
    ShadowSample {
        delta,
        preferred_runtime: "openai".into(),
        preferred_model: "gpt-5.5".into(),
        active: "allow native/native-default".into(),
        candidate: "deny: model not allowed".into(),
        observed_at_ms: at,
    }
}

fn exercise(db: &dyn ShadowHarness, prefix: &str) {
    let namespace = format!("{prefix}-ns");
    let first = shadow(&namespace, "first", "native-default");
    db.start(&first).unwrap();
    let run = first.shadow_id.as_str();

    db.record(run, &sample(ShadowDelta::Unchanged, 1)).unwrap();
    for at in 0..MAX_SHADOW_SAMPLES + 4 {
        db.record(run, &sample(ShadowDelta::WouldDeny, at)).unwrap();
    }
    // A decision for a run that is no longer active is ignored.
    db.record("gone", &sample(ShadowDelta::ReRouted, 1))
        .unwrap();

    let report = db.report(&namespace).unwrap().unwrap();
    assert_eq!(report.shadow, first);
    assert_eq!(report.counts.evaluated, MAX_SHADOW_SAMPLES + 5);
    assert_eq!(report.counts.unchanged, 1);
    assert_eq!(report.counts.would_deny, MAX_SHADOW_SAMPLES + 4);
    assert_eq!(report.counts.re_routed, 0);
    assert_eq!(report.samples.len() as i64, MAX_SHADOW_SAMPLES);
    assert!(
        report
            .samples
            .iter()
            .all(|sample| sample.delta == ShadowDelta::WouldDeny)
    );
    assert!(report.verdict().is_err());

    // The first shadowed scope in rank order wins.
    let other = format!("{prefix}-other");
    let scopes = [
        format!("{prefix}-unshadowed"),
        namespace.clone(),
        other.clone(),
    ];
    db.start(&shadow(&other, "other", "native-default"))
        .unwrap();
    assert_eq!(db.find(&scopes).unwrap().unwrap(), first);
    assert!(db.stop(&other, None).unwrap());

    // A restart with the same candidate is a new run: the old run's
    // observations no longer count and its samples are gone.
    let second = shadow(&namespace, "second", "native-default");
    assert_eq!(second.candidate_version, first.candidate_version);
    db.start(&second).unwrap();
    db.record(run, &sample(ShadowDelta::WouldDeny, 1)).unwrap();
    let report = db.report(&namespace).unwrap().unwrap();
    assert_eq!(report.shadow, second);
    assert_eq!(report.counts.evaluated, 0);
    assert!(report.samples.is_empty());

    // An admitted activation holds its run against replacement until the
    // claim lapses.
    assert!(!db.claim(&namespace, run, 10).unwrap());
    // A report that does not pass cannot be claimed.
    assert!(!db.claim(&namespace, &second.shadow_id, 10).unwrap());
    db.record(&second.shadow_id, &sample(ShadowDelta::Unchanged, 5))
        .unwrap();
    assert!(db.claim(&namespace, &second.shadow_id, 10).unwrap());
    // Counting pauses while the claim is live.
    db.record(&second.shadow_id, &sample(ShadowDelta::WouldDeny, 11))
        .unwrap();
    let claimed = db.report(&namespace).unwrap().unwrap();
    assert_eq!(
        (claimed.counts.evaluated, claimed.counts.would_deny),
        (1, 0)
    );
    assert!(db.confirm(&namespace, &second.shadow_id, 10, 11).unwrap());
    assert!(
        !db.confirm(&namespace, &second.shadow_id, 10, 10 + ACTIVATION_CLAIM_MS)
            .unwrap()
    );
    assert!(!db.confirm(&namespace, &second.shadow_id, 9, 11).unwrap());
    let mut third = shadow(&namespace, "third", "native-default");
    third.started_at_ms = 10 + ACTIVATION_CLAIM_MS - 1;
    assert_eq!(db.start(&third).unwrap_err(), ACTIVATION_IN_PROGRESS);
    assert_eq!(
        db.stop_unclaimed(&namespace, 11).unwrap_err(),
        ACTIVATION_IN_PROGRESS
    );
    third.started_at_ms = 10 + ACTIVATION_CLAIM_MS;
    db.start(&third).unwrap();
    assert!(db.stop(&namespace, Some(&third.shadow_id)).unwrap());
    db.start(&second).unwrap();

    // Stopping a specific run leaves a replacement in place.
    assert!(!db.stop(&namespace, Some(run)).unwrap());
    assert!(db.stop(&namespace, Some(&second.shadow_id)).unwrap());
    assert!(!db.stop(&namespace, None).unwrap());
    assert!(db.report(&namespace).unwrap().is_none());
}

#[test]
fn sqlite_policy_shadow_conformance() {
    exercise(&SekaiDb::new(":memory:").unwrap(), "sqlite");
}

fn postgres() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_policy_shadow_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let namespace = format!("{prefix}-kept");
    let kept = shadow(&namespace, "kept", "native-default");
    postgres().start(&kept).unwrap();
    let restarted = postgres();
    assert_eq!(restarted.report(&namespace).unwrap().unwrap().shadow, kept);
    restarted.stop(&namespace, None).unwrap();
}
