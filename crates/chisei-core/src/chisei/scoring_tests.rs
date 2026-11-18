//! Tests of `chisei::scoring` that break the run write through the store's
//! connection (#2716).

use std::sync::Mutex;

use super::*;

fn fail_suite_writes_for(db: &ChiseiStore, suite_id: Option<&str>) {
    let sql = match suite_id {
        Some(id) => format!(
            "CREATE TRIGGER fail_suite_write BEFORE INSERT ON chisei_eval_suites
             WHEN NEW.id = '{id}'
             BEGIN SELECT RAISE(ABORT, 'injected suite write failure'); END;"
        ),
        None => "DROP TRIGGER fail_suite_write;".into(),
    };
    db.runtime().conn().execute_batch(&sql).unwrap();
}

#[derive(Default)]
struct RecordingWriter(Mutex<Vec<String>>);

#[async_trait::async_trait]
impl KnowledgeWriter for RecordingWriter {
    async fn write_knowledge(
        &self,
        request: &KnowledgeWriteRequest,
    ) -> Result<KnowledgeWriteOutcome, String> {
        self.0.lock().unwrap().push(request.request_id.clone());
        Ok(KnowledgeWriteOutcome::Accepted)
    }
}

struct PassJudge;

#[async_trait::async_trait]
impl Judge for PassJudge {
    async fn judge(
        &self,
        _model: &str,
        _rubric: &str,
        _spec: &str,
        _output: &str,
    ) -> Result<JudgeVerdict, JudgeError> {
        Ok(JudgeVerdict {
            score: 80,
            passed: true,
            reasoning: "ok".into(),
        })
    }
}

fn observe_metered(db: &ChiseiStore, request_id: &str, namespace: &str, ts: i64) {
    db.put_sample_observation(&SampleObservation {
        request_id: request_id.into(),
        namespace: namespace.into(),
        spec: "do the thing".into(),
        resolved_model: "model-a".into(),
        output_content: "done".into(),
        sample_reason: "base".into(),
        input_tokens: 10,
        output_tokens: 20,
        stop_reason: "end_turn".into(),
        timestamp: ts,
        scored: false,
        task_class: "primary".into(),
        cost_usd_micros: 42,
    })
    .unwrap();
}

fn portfolio_samples(db: &ChiseiStore, namespace: &str) -> i64 {
    crate::chisei::portfolio::PortfolioStore::new(db.clone())
        .frontier(namespace, "primary")
        .unwrap()
        .iter()
        .map(|point| point.sample_count)
        .sum()
}

#[tokio::test]
async fn failed_run_write_skips_only_its_namespace_and_defers_side_effects() {
    let db = ChiseiStore::memory();
    let eval = Arc::new(EvalStore::with_db(db.clone()));
    observe_metered(&db, "a-1", "a", 100);
    observe_metered(&db, "a-2", "a", 101);
    observe_metered(&db, "b-1", "b", 102);
    let writer = Arc::new(RecordingWriter::default());
    let job = ScoringJob::with_judge(db.clone(), eval, Arc::new(PassJudge), 16, "judge")
        .with_knowledge_writer(writer.clone());

    fail_suite_writes_for(&db, Some("sampling-a"));
    assert_eq!(job.run_once().await.unwrap(), 1);
    assert_eq!(db.list_eval_run_records("sampling-b").unwrap().len(), 1);
    assert!(db.list_eval_run_records("sampling-a").unwrap().is_empty());
    assert_eq!(portfolio_samples(&db, "a"), 0);
    assert_eq!(*writer.0.lock().unwrap(), ["b-1"]);

    fail_suite_writes_for(&db, None);
    assert_eq!(job.run_once().await.unwrap(), 2);
    assert_eq!(portfolio_samples(&db, "a"), 2);
    assert_eq!(portfolio_samples(&db, "b"), 1);
    let mut written = writer.0.lock().unwrap().clone();
    written.sort();
    assert_eq!(written, ["a-1", "a-2", "b-1"]);
    assert!(db.list_unscored_observations(16).unwrap().is_empty());
}
