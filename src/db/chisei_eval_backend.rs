//! Backend-neutral evaluation and sample-observation persistence.

use crate::chisei::{eval, scoring::SampleObservation};
use crate::db::{postgres::PostgresDb, sekai::SekaiDb};

pub trait ChiseiEvalBackend: Send + Sync {
    fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String>;
    fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String>;
    fn put_eval_run(&self, run: &eval::Run) -> Result<(), String>;
    fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String>;
    fn put_eval_iteration(&self, iteration: &eval::Iteration) -> Result<(), String>;
    fn list_eval_iteration_records(&self, suite_id: &str) -> Result<Vec<eval::Iteration>, String>;
    fn put_sample_observation(&self, observation: &SampleObservation) -> Result<(), String>;
    fn get_sample_observation(
        &self,
        _request_id: &str,
    ) -> Result<Option<SampleObservation>, String> {
        Ok(None)
    }
    fn get_sample_observation_in_namespace(
        &self,
        _request_id: &str,
        _namespace: &str,
    ) -> Result<Option<SampleObservation>, String> {
        Ok(None)
    }
    fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String>;
    fn delete_observation(&self, request_id: &str) -> Result<(), String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
            <$target>::put_eval_suite(self, suite)
        }
        fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String> {
            <$target>::get_eval_suite_record(self, id)
        }
        fn put_eval_run(&self, run: &eval::Run) -> Result<(), String> {
            <$target>::put_eval_run(self, run)
        }
        fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String> {
            <$target>::get_eval_run_record(self, id)
        }
        fn put_eval_iteration(&self, iteration: &eval::Iteration) -> Result<(), String> {
            <$target>::put_eval_iteration(self, iteration)
        }
        fn list_eval_iteration_records(
            &self,
            suite_id: &str,
        ) -> Result<Vec<eval::Iteration>, String> {
            <$target>::list_eval_iteration_records(self, suite_id)
        }
        fn put_sample_observation(&self, observation: &SampleObservation) -> Result<(), String> {
            <$target>::put_sample_observation(self, observation)
        }
        fn get_sample_observation(
            &self,
            request_id: &str,
        ) -> Result<Option<SampleObservation>, String> {
            <$target>::get_sample_observation(self, request_id)
        }
        fn get_sample_observation_in_namespace(
            &self,
            request_id: &str,
            namespace: &str,
        ) -> Result<Option<SampleObservation>, String> {
            <$target>::get_sample_observation_in_namespace(self, request_id, namespace)
        }
        fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String> {
            <$target>::bump_observation_attempts(self, request_id)
        }
        fn delete_observation(&self, request_id: &str) -> Result<(), String> {
            <$target>::delete_observation(self, request_id)
        }
    };
}

impl ChiseiEvalBackend for SekaiDb {
    forward!(SekaiDb);
}
impl ChiseiEvalBackend for PostgresDb {
    forward!(PostgresDb);
}
