//! Labelled invoice fixture set for function-revision extraction gates (#1327).
//!
//! #1312 already scores an LLM revision over a fixture set before publish.
//! This module freezes one invoice document type, expected vendor labels, and
//! the evaluation threshold so a worse extraction is denied and an unchanged
//! revision still publishes.

use crate::domain::Object;
use crate::sekai::function::{Function, LlmStep, OperatorStep, PipelineStep};
use std::collections::{BTreeMap, HashMap};

pub const INVOICE_KIND: &str = "invoice";
pub const INVOICE_EXTRACTION_EXPECTED_VENDOR: &str = "ACME";
pub const INVOICE_EXTRACTION_THRESHOLD_MICROS: u32 = 800_000;
pub const INVOICE_EXTRACTION_OUTPUT_SCHEMA: &str = r#"{"type":"object","properties":{"id":{"type":"string"},"vendor":{"type":"string"},"confidence_micros":{"type":"integer"}},"required":["id","vendor","confidence_micros"],"additionalProperties":false}"#;

/// Frozen labelled invoices for the extraction evaluation set.
pub fn invoice_extraction_fixtures() -> Vec<Object> {
    vec![
        invoice_fixture("invoice:acme-40", "INV-40", "ACME", "40.00"),
        invoice_fixture("invoice:acme-12", "INV-12", "ACME", "12.50"),
    ]
}

fn invoice_fixture(id: &str, number: &str, vendor: &str, total: &str) -> Object {
    Object {
        id: id.into(),
        kind: INVOICE_KIND.into(),
        name: number.into(),
        namespace: "records".into(),
        external_id: number.into(),
        properties: HashMap::from([
            ("vendor".into(), vendor.into()),
            ("total".into(), total.into()),
            ("expected_label".into(), vendor.into()),
        ]),
        created: 1,
        updated: 1,
    }
}

/// Invoice extraction revision scored by the function-revision gate.
pub fn invoice_extraction_function(name: &str, prompt_revision: &str) -> Function {
    Function {
        name: name.into(),
        description: "Extract vendor from labelled invoice fixtures".into(),
        params: vec![],
        created: 0,
        pipeline: vec![
            PipelineStep::Operator(OperatorStep {
                op: "filter".into(),
                kind: INVOICE_KIND.into(),
                property: "vendor".into(),
                value: INVOICE_EXTRACTION_EXPECTED_VENDOR.into(),
                relation: "".into(),
                dir: "".into(),
                func: "".into(),
                field: "".into(),
                alias: "".into(),
            }),
            PipelineStep::Llm(LlmStep {
                prompt_revision: prompt_revision.into(),
                input_bindings: BTreeMap::from([("vendor".into(), "vendor".into())]),
                output_schema: INVOICE_EXTRACTION_OUTPUT_SCHEMA.into(),
                model_route: "native/scripted".into(),
                minimum_confidence_micros: 0,
            }),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::evaluation_execution::{
        STOCHASTIC_TRIAL_RESULT_CONTRACT, StochasticEvaluator, StochasticEvaluatorRegistry,
        StochasticTrialError, StochasticTrialInput, StochasticTrialOutput, VERDICT_ALLOW,
        VERDICT_DENY,
    };
    use crate::chisei::stochastic_evaluation::BOUNDED_RUBRIC_IMPLEMENTATION_DIGEST;
    use crate::composition::function_revision_gate::{
        FunctionRevisionGateRequest, gate_function_revision, publish_function_revision,
    };
    use crate::db::runtime_db::RuntimeDb;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::evidence::EvidenceClassification;
    use crate::sekai::function::{FunctionBudget, FunctionHost, LlmStepHost};
    use crate::sekai::markings::PrincipalAuthority;
    use std::sync::Arc;

    struct ScriptedHost {
        output: serde_json::Value,
    }

    impl LlmStepHost for ScriptedHost {
        fn complete(
            &self,
            _prompt_revision: &str,
            _model_route: &str,
            _bound_inputs: &serde_json::Value,
            _output_schema: &str,
        ) -> Result<serde_json::Value, String> {
            Ok(self.output.clone())
        }
    }

    struct InvoiceVendorRubric;

    #[async_trait::async_trait]
    impl StochasticEvaluator for InvoiceVendorRubric {
        async fn evaluate_trial(
            &self,
            input: &StochasticTrialInput,
        ) -> Result<StochasticTrialOutput, StochasticTrialError> {
            let expected = input
                .base
                .parameters
                .get("expected_label")
                .and_then(|value| value.as_str())
                .unwrap_or(INVOICE_EXTRACTION_EXPECTED_VENDOR);
            let passed = !input.base.evidence.is_empty()
                && input.base.evidence.iter().all(|evidence| {
                    evidence
                        .content
                        .get("output")
                        .and_then(|output| output.get("vendor"))
                        .and_then(|vendor| vendor.as_str())
                        == Some(expected)
                });
            Ok(StochasticTrialOutput {
                contract_version: STOCHASTIC_TRIAL_RESULT_CONTRACT.into(),
                passed,
                score_micros: if passed { 900_000 } else { 100_000 },
                reason_code: if passed {
                    "criteria_met".into()
                } else {
                    "criteria_not_met".into()
                },
                result: serde_json::json!({}),
                input_tokens: 10,
                output_tokens: 5,
            })
        }
    }

    fn db() -> RuntimeDb {
        RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()))
    }

    fn host() -> FunctionHost {
        FunctionHost {
            now_ms: 1_700_000_000_000,
            rng_seed: 7,
        }
    }

    fn authority() -> PrincipalAuthority {
        PrincipalAuthority {
            principal: "evaluator".into(),
            classification_ceiling: Some(EvidenceClassification::Public),
            classification_token: Some(EvidenceClassification::Public.as_str().into()),
            allowed_purposes: Default::default(),
            declassify_markings: Default::default(),
        }
    }

    fn registry() -> StochasticEvaluatorRegistry {
        let registry = StochasticEvaluatorRegistry::default();
        registry
            .register(
                BOUNDED_RUBRIC_IMPLEMENTATION_DIGEST,
                Arc::new(InvoiceVendorRubric),
            )
            .unwrap();
        registry
    }

    fn seed(db: &RuntimeDb) -> Vec<Object> {
        let fixtures = invoice_extraction_fixtures();
        for fixture in &fixtures {
            db.create_object(fixture).unwrap();
        }
        fixtures
    }

    fn gate(
        db: &RuntimeDb,
        function: &Function,
        fixtures: &[Object],
        output: serde_json::Value,
    ) -> crate::composition::function_revision_gate::FunctionRevisionGate {
        gate_function_revision(FunctionRevisionGateRequest {
            db,
            function,
            fixtures,
            llm_host: &ScriptedHost { output },
            evaluator_authority: &authority(),
            registry: &registry(),
            minimum_mean_score_micros: INVOICE_EXTRACTION_THRESHOLD_MICROS,
            expected_label: INVOICE_EXTRACTION_EXPECTED_VENDOR,
            host: host(),
            budget: FunctionBudget::default(),
        })
        .unwrap()
    }

    #[test]
    fn worse_invoice_extraction_is_denied_and_not_published() {
        let db = db();
        let fixtures = seed(&db);
        let function = invoice_extraction_function("extract-invoice-worse", "invoice/degraded");
        let result = gate(
            &db,
            &function,
            &fixtures,
            serde_json::json!({
                "id": "inv-wrong",
                "vendor": "GARBAGE",
                "confidence_micros": 900_000
            }),
        );
        assert_eq!(result.verdict(), VERDICT_DENY);
        let error = publish_function_revision(&db, &function, &result).unwrap_err();
        assert!(error.contains("publish denied"));
        assert!(db.get_function("extract-invoice-worse").unwrap().is_none());
    }

    #[test]
    fn unchanged_invoice_extraction_passes_and_publishes() {
        let db = db();
        let fixtures = seed(&db);
        let function = invoice_extraction_function("extract-invoice-stable", "invoice/v1");
        let result = gate(
            &db,
            &function,
            &fixtures,
            serde_json::json!({
                "id": "inv-1",
                "vendor": "ACME",
                "confidence_micros": 900_000
            }),
        );
        assert_eq!(result.verdict(), VERDICT_ALLOW);
        publish_function_revision(&db, &function, &result).unwrap();
        assert!(db.get_function("extract-invoice-stable").unwrap().is_some());
    }
}
