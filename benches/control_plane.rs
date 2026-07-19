use sekai_chisei::chisei::egress::{filter_property, new_record};
use sekai_chisei::chisei::gunshi::{AllocationRequest, recommend_baseline};
use sekai_chisei::chisei::kioku::{KiokuMemory, memory_claim_digest};
use sekai_chisei::chisei::policy::{Policy, PolicyResolver};
use sekai_chisei::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
};
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::{ListFilter, Object};
use sekai_chisei::harness::{HarnessEvent, RetrySafety, StreamAssembly, retry_disposition};
use sekai_chisei::sekai::attestation::{PolicyAttestation, attestation_content_hash};
use sekai_chisei::sekai::evidence::{
    EVIDENCE_ENVELOPE_VERSION, EvidenceClassification, EvidenceEnvelope, EvidenceIntent,
    EvidenceSignal, EvidenceTarget, SchemaCompatibility,
};
use sekai_chisei::sekai::evidence_store::{
    EvidenceProducerCapability, EvidenceSchemaDefinition, canonical_content_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MANIFEST_VERSION: &str = "sekai.performance-manifest/v1";
const REPORT_VERSION: &str = "sekai.performance-report/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    contract_version: String,
    fixture_version: String,
    description: String,
    workloads: Vec<Workload>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Workload {
    id: String,
    description: String,
    category: String,
    dataset_size: usize,
    concurrency: usize,
    operations_per_iteration: usize,
    warmup_iterations: usize,
    sample_iterations: usize,
    fixture: String,
    observes: Vec<String>,
    budgets: Budgets,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Budgets {
    p50_latency_us: f64,
    p95_latency_us: f64,
    p99_latency_us: f64,
}

#[derive(Debug, Serialize)]
struct Report<'a> {
    contract_version: &'static str,
    manifest_version: &'a str,
    fixture_version: &'a str,
    recorded_at: String,
    hardware: Hardware,
    build_profile: String,
    crate_version: &'static str,
    results: Vec<ResultRow<'a>>,
    uncertainty: &'static str,
}

#[derive(Debug, Serialize)]
struct Hardware {
    description: String,
    operating_system: String,
    rustc: String,
}

#[derive(Debug, Serialize)]
struct ResultRow<'a> {
    id: &'a str,
    category: &'a str,
    fixture: &'a str,
    dataset_size: usize,
    concurrency: usize,
    operations_per_iteration: usize,
    samples: usize,
    p50_latency_us: f64,
    p95_latency_us: f64,
    p99_latency_us: f64,
    mean_latency_us: f64,
    standard_deviation_us: f64,
    relative_standard_deviation_percent: f64,
    throughput_operations_per_second: f64,
    within_budget: bool,
}

fn main() -> Result<(), String> {
    // Cargo passes `--bench` to the harness, so positional detection must skip
    // flags rather than trusting argv[1].
    let manifest_path = env::args()
        .skip(1)
        .find(|argument| !argument.starts_with('-'))
        .unwrap_or_else(|| "benchmarks/manifest-v1.json".to_string());
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("read benchmark manifest {manifest_path}: {error}"))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("parse benchmark manifest {manifest_path}: {error}"))?;
    validate_manifest(&manifest)?;

    let report = Report {
        contract_version: REPORT_VERSION,
        manifest_version: &manifest.contract_version,
        fixture_version: &manifest.fixture_version,
        recorded_at: required_metadata("SEKAI_BENCH_RECORDED_AT")?,
        hardware: Hardware {
            description: required_metadata("SEKAI_BENCH_HARDWARE")?,
            operating_system: required_metadata("SEKAI_BENCH_OS")?,
            rustc: required_metadata("SEKAI_BENCH_RUSTC")?,
        },
        build_profile: required_metadata("SEKAI_BENCH_PROFILE")?,
        crate_version: env!("CARGO_PKG_VERSION"),
        results: manifest
            .workloads
            .iter()
            .map(run_workload)
            .collect::<Result<Vec<_>, _>>()?,
        uncertainty: "Sample standard deviation and relative standard deviation describe run-to-run variance; provider delay is excluded because all fixtures are local.",
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("serialize benchmark report: {error}"))?
    );
    Ok(())
}

fn required_metadata(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required for reproducible benchmark metadata"))
}

fn validate_manifest(manifest: &Manifest) -> Result<(), String> {
    if manifest.contract_version != MANIFEST_VERSION {
        return Err(format!(
            "unsupported benchmark manifest version {}",
            manifest.contract_version
        ));
    }
    if manifest.fixture_version.trim().is_empty() || manifest.description.trim().is_empty() {
        return Err("benchmark manifest requires fixture_version and description".into());
    }
    if manifest.workloads.is_empty() {
        return Err("benchmark manifest requires at least one workload".into());
    }
    let mut ids = std::collections::BTreeSet::new();
    for workload in &manifest.workloads {
        if !ids.insert(workload.id.as_str()) {
            return Err(format!("duplicate benchmark workload {}", workload.id));
        }
        if workload.description.trim().is_empty()
            || workload.category.trim().is_empty()
            || workload.fixture.trim().is_empty()
            || workload.dataset_size == 0
            || workload.concurrency == 0
            || workload.operations_per_iteration == 0
            || workload.warmup_iterations == 0
            || workload.sample_iterations < 10
            || workload.observes.is_empty()
        {
            return Err(format!("benchmark workload {} is incomplete", workload.id));
        }
        let budgets = &workload.budgets;
        if !budgets.p50_latency_us.is_finite()
            || !budgets.p95_latency_us.is_finite()
            || !budgets.p99_latency_us.is_finite()
            || budgets.p50_latency_us <= 0.0
            || budgets.p50_latency_us > budgets.p95_latency_us
            || budgets.p95_latency_us > budgets.p99_latency_us
        {
            return Err(format!(
                "benchmark workload {} has invalid budgets",
                workload.id
            ));
        }
        drop(workload_factory(workload)?);
    }
    Ok(())
}

type Benchmark = Box<dyn FnMut() -> Result<(), String>>;

fn run_workload(workload: &Workload) -> Result<ResultRow<'_>, String> {
    let mut benchmark = workload_factory(workload)?;
    for _ in 0..workload.warmup_iterations {
        benchmark()?;
    }
    let mut samples = Vec::with_capacity(workload.sample_iterations);
    for _ in 0..workload.sample_iterations {
        let started = Instant::now();
        benchmark()?;
        samples.push(started.elapsed().as_secs_f64() * 1_000_000.0);
    }
    samples.sort_by(f64::total_cmp);
    let p50 = percentile(&samples, 0.50);
    let p95 = percentile(&samples, 0.95);
    let p99 = percentile(&samples, 0.99);
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance = samples
        .iter()
        .map(|sample| (sample - mean).powi(2))
        .sum::<f64>()
        / (samples.len() - 1) as f64;
    let standard_deviation = variance.sqrt();
    Ok(ResultRow {
        id: &workload.id,
        category: &workload.category,
        fixture: &workload.fixture,
        dataset_size: workload.dataset_size,
        concurrency: workload.concurrency,
        operations_per_iteration: workload.operations_per_iteration,
        samples: samples.len(),
        p50_latency_us: rounded(p50),
        p95_latency_us: rounded(p95),
        p99_latency_us: rounded(p99),
        mean_latency_us: rounded(mean),
        standard_deviation_us: rounded(standard_deviation),
        relative_standard_deviation_percent: rounded(standard_deviation / mean * 100.0),
        throughput_operations_per_second: rounded(
            1_000_000.0 / mean * workload.operations_per_iteration as f64,
        ),
        within_budget: p50 <= workload.budgets.p50_latency_us
            && p95 <= workload.budgets.p95_latency_us
            && p99 <= workload.budgets.p99_latency_us,
    })
}

fn percentile(samples: &[f64], quantile: f64) -> f64 {
    let rank = (samples.len() as f64 * quantile).ceil() as usize;
    samples[rank.saturating_sub(1).min(samples.len() - 1)]
}

fn rounded(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn workload_factory(workload: &Workload) -> Result<Benchmark, String> {
    Ok(match workload.id.as_str() {
        "startup_fresh_sqlite" => startup_benchmark(),
        "policy_resolution_cold" => cold_policy_benchmark(),
        "policy_resolution_warm" => warm_policy_benchmark(),
        "gateway_stream_text_tools" => stream_benchmark(false),
        "gateway_stream_cancelled_usage" => stream_benchmark(true),
        "context_egress_filtering" => egress_benchmark(workload.dataset_size),
        "receipt_audit_assembly" => receipt_benchmark(workload.dataset_size),
        "evidence_ingest_project_retract" => evidence_benchmark(workload.dataset_size)?,
        "kioku_candidate_fingerprinting" => kioku_benchmark(workload.dataset_size)?,
        "gunshi_advisory_planning" => gunshi_benchmark()?,
        "mixed_persistence_reconciliation" => {
            persistence_benchmark(workload.concurrency, workload.dataset_size)?
        }
        "provider_failure_fallback" => retry_benchmark(workload.dataset_size),
        "report_attestation_export" => attestation_benchmark(workload.dataset_size),
        id => return Err(format!("benchmark workload {id} has no runner")),
    })
}

fn policy() -> Policy {
    Policy {
        allowed_runtimes: vec!["openai".into(), "ollama".into()],
        allowed_models: vec!["openai/gpt-5.5".into(), "ollama/llama3.2:latest".into()],
        default_runtime: "ollama".into(),
        default_model: "ollama/llama3.2:latest".into(),
        data_class: "internal".into(),
    }
}

fn startup_benchmark() -> Benchmark {
    let mut directories = Vec::new();
    Box::new(move || {
        let directory = tempfile::Builder::new()
            .prefix("sekai-startup-benchmark-")
            .tempdir()
            .map_err(|error| format!("create startup benchmark directory: {error}"))?;
        let path = directory.path().join("sekai.db");
        let db = SekaiDb::new(path.to_str().ok_or("benchmark path is not UTF-8")?)?;
        db.ping()?;
        drop(db);
        directories.push(directory);
        Ok(())
    })
}

fn cold_policy_benchmark() -> Benchmark {
    Box::new(|| {
        let resolver = PolicyResolver::new();
        resolver.set_namespace_policy("benchmark", policy());
        black_box(resolver.resolve("benchmark", "openai", "openai/gpt-5.5")?);
        Ok(())
    })
}

fn warm_policy_benchmark() -> Benchmark {
    let resolver = PolicyResolver::new();
    resolver.set_namespace_policy("benchmark", policy());
    Box::new(move || {
        black_box(resolver.resolve("benchmark", "openai", "openai/gpt-5.5")?);
        Ok(())
    })
}

fn stream_benchmark(cancelled: bool) -> Benchmark {
    let terminal = if cancelled {
        "response.cancelled"
    } else {
        "response.completed"
    };
    let status = if cancelled { "cancelled" } else { "completed" };
    let events = vec![
        HarnessEvent {
            event: "response.output_text.delta".into(),
            data: json!({"item_id":"msg-1","output_index":0,"delta":"sanitized output"}),
        },
        HarnessEvent {
            event: "response.function_call_arguments.delta".into(),
            data: json!({"item_id":"tool-1","output_index":1,"delta":"{\"query\":\"status\"}"}),
        },
        HarnessEvent {
            event: "response.output_item.done".into(),
            data: json!({"output_index":0,"item":{"id":"msg-1","type":"message","status":"completed"}}),
        },
        HarnessEvent {
            event: "response.output_item.done".into(),
            data: json!({"output_index":1,"item":{"id":"tool-1","type":"function_call","status":"completed","call_id":"call-1","name":"inspect","arguments":"{\"query\":\"status\"}"}}),
        },
        HarnessEvent {
            event: terminal.into(),
            data: json!({"type":terminal,"response":{"status":status,"usage":{"input_tokens":32,"output_tokens":8,"total_tokens":40}}}),
        },
    ];
    Box::new(move || {
        let assembled = StreamAssembly::from_events(black_box(&events))?;
        if assembled.usage.as_ref().is_some_and(|usage| usage.partial) != cancelled {
            return Err("stream fixture produced incorrect partial usage".into());
        }
        black_box(assembled);
        Ok(())
    })
}

fn benchmark_object(index: usize) -> Object {
    Object {
        id: format!("object-{index}"),
        kind: "benchmark_fixture".into(),
        name: format!("Sanitized object {index}"),
        namespace: "benchmark".into(),
        external_id: format!("fixture:{index}"),
        properties: HashMap::from([
            (
                "public_summary".into(),
                "synthetic benchmark payload".into(),
            ),
            ("private_note".into(), "redacted synthetic value".into()),
            (
                "chisei.egress.external_properties".into(),
                "public_summary".into(),
            ),
        ]),
        created: index as i64,
        updated: index as i64,
    }
}

fn egress_benchmark(dataset_size: usize) -> Benchmark {
    let objects = (0..dataset_size).map(benchmark_object).collect::<Vec<_>>();
    Box::new(move || {
        for object in &objects {
            let mut record = new_record(object);
            black_box(filter_property(object, "public_summary", &mut record, true));
            black_box(filter_property(object, "private_note", &mut record, true));
            if record.included_fields.len() != 1 || record.redacted_fields.len() != 1 {
                return Err("egress fixture violated its expected classification".into());
            }
        }
        Ok(())
    })
}

fn receipt_benchmark(dataset_size: usize) -> Benchmark {
    let events = (0..dataset_size)
        .map(|index| {
            let kind = match index {
                0 => ReceiptEventKind::IntentRecorded,
                1 => ReceiptEventKind::PolicyDecided,
                2 => ReceiptEventKind::RouteSelected,
                3 => ReceiptEventKind::BudgetDecided,
                index if index + 1 == dataset_size => ReceiptEventKind::OutcomeRecorded,
                _ => ReceiptEventKind::PolicyDecided,
            };
            OperationReceiptEvent {
                event_id: format!("event-{index}"),
                operation_id: "operation-benchmark".into(),
                parent_event_id: (index > 0).then(|| "event-0".into()),
                timestamp_ms: index as i64,
                kind,
                surface: kind.surface(),
                actor: "benchmark-actor".into(),
                references: vec![],
                attributes: BTreeMap::new(),
            }
        })
        .collect();
    let receipt = OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: "operation-benchmark".into(),
        parent_operation_id: None,
        namespace: "benchmark".into(),
        operation_class: "fixture".into(),
        initiating_actor: "benchmark-actor".into(),
        schema_version: "fixture/v1".into(),
        policy_version: "policy-fixture-v1".into(),
        started_at_ms: 0,
        completed_at_ms: Some(1),
        events,
        uncovered_surfaces: vec![],
        reporter_grants: vec![],
    };
    Box::new(move || {
        let completeness = receipt.completeness();
        if !completeness.complete {
            return Err(format!(
                "receipt fixture is incomplete: errors={:?}, missing={:?}",
                completeness.errors, completeness.missing_surfaces
            ));
        }
        black_box(serde_json::to_vec(&receipt).map_err(|error| error.to_string())?);
        Ok(())
    })
}

fn evidence_benchmark(dataset_size: usize) -> Result<Benchmark, String> {
    Ok(Box::new(move || {
        let db = configured_evidence_db()?;
        for index in 0..dataset_size as u64 {
            let content = json!({"result":"passed","fixture_index":index});
            let envelope = EvidenceEnvelope {
                contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
                source_type: "benchmark_fixture".into(),
                source_instance: "fixture-primary".into(),
                source_record_id: format!("record-{index}"),
                source_version: "upsert-1".into(),
                source_sequence: 1,
                target: EvidenceTarget {
                    namespace: "benchmark".into(),
                    object_external_id: "benchmark:target".into(),
                    object_kind: "benchmark_target".into(),
                },
                evidence_type: "verification.result".into(),
                signal: EvidenceSignal::Verification,
                schema_id: "verification.result".into(),
                schema_version: "1.0.0".into(),
                schema_compatibility: SchemaCompatibility::Exact,
                observed_at_ms: 100 + index as i64,
                collected_at_ms: 100 + index as i64,
                expires_at_ms: None,
                content_digest: canonical_content_digest(&content)?,
                content,
                relationships: vec![],
                producer_identity: "producer:benchmark".into(),
                confidence_bps: 10_000,
                classification: EvidenceClassification::Internal,
                provenance: BTreeMap::new(),
                idempotency_key: format!("upsert-{index}"),
                intent: EvidenceIntent::Upsert,
                causality: None,
            };
            let admitted =
                db.submit_evidence(&envelope, "producer:benchmark", 1_000_000 + index as i64)?;
            if !admitted.accepted {
                return Err("synthetic evidence was not admitted".into());
            }
            let projected =
                db.project_evidence_submission(&admitted.submission.id, 1_000_001 + index as i64)?;
            if !projected.projected {
                return Err("synthetic evidence was not projected".into());
            }
            black_box(db.get_evidence_submission(&admitted.submission.id)?);

            let mut retraction = envelope;
            retraction.source_version = "retract-2".into();
            retraction.source_sequence = 2;
            retraction.idempotency_key = format!("retract-{index}");
            retraction.intent = EvidenceIntent::Retract;
            let admitted_retraction =
                db.submit_evidence(&retraction, "producer:benchmark", 1_000_002 + index as i64)?;
            db.project_evidence_submission(
                &admitted_retraction.submission.id,
                1_000_003 + index as i64,
            )?;
        }
        Ok(())
    }))
}

fn configured_evidence_db() -> Result<SekaiDb, String> {
    let db = SekaiDb::new(":memory:")?;
    db.upsert_evidence_producer(
        &EvidenceProducerCapability {
            producer_identity: "producer:benchmark".into(),
            config_version: 1,
            source_types: vec!["benchmark_fixture".into()],
            source_instances: vec!["fixture-primary".into()],
            namespaces: vec!["benchmark".into()],
            evidence_types: vec!["verification.result".into()],
            target_kinds: vec!["benchmark_target".into()],
            classification_ceiling: EvidenceClassification::Internal,
            allowed_intents: vec![EvidenceIntent::Upsert, EvidenceIntent::Retract],
            allow_operation_attachment: false,
            replay_window_ms: 1_000_000_000,
            max_clock_skew_ms: 1_000_000_000,
            max_payload_bytes: 1_024,
            max_relationships: 4,
            rate_limit_per_minute: 1_000_000,
            max_retained_submissions: 100_000,
            revoked: false,
        },
        1,
    )?;
    db.register_evidence_schema(
        &EvidenceSchemaDefinition {
            schema_id: "verification.result".into(),
            schema_version: "1.0.0".into(),
            evidence_type: "verification.result".into(),
            compatible_versions: vec![],
        },
        1,
    )?;
    db.create_object(&Object {
        id: "evidence-target".into(),
        kind: "benchmark_target".into(),
        name: "Synthetic evidence target".into(),
        namespace: "benchmark".into(),
        external_id: "benchmark:target".into(),
        properties: HashMap::new(),
        created: 1,
        updated: 1,
    })?;
    Ok(db)
}

fn kioku_benchmark(dataset_size: usize) -> Result<Benchmark, String> {
    let template: KiokuMemory = serde_json::from_value(json!({
        "contract_version":"kioku.memory/v1","id":"memory-0","version":1,
        "kind":"recommendation","claim":"Use bounded synthetic fixtures",
        "namespace":"benchmark","operation_classes":["fixture"],
        "outcome_definition":"deterministic completion","confidence_bps":9000,
        "sample_size":32,"uncertainty":"synthetic baseline","producer_identity":"benchmark",
        "derivation_method":"sanitized fixture","classification":"internal",
        "state":"active","created_at_ms":1
    }))
    .map_err(|error| format!("construct Kioku fixture: {error}"))?;
    let memories = (0..dataset_size)
        .map(|index| {
            let mut memory = template.clone();
            memory.id = format!("memory-{index}");
            memory
        })
        .collect::<Vec<_>>();
    Ok(Box::new(move || {
        for memory in &memories {
            black_box(memory_claim_digest(memory));
        }
        Ok(())
    }))
}

fn gunshi_benchmark() -> Result<Benchmark, String> {
    let request: AllocationRequest = serde_json::from_value(json!({
        "capacity":{"captured_at_ms":1000,"policy_version":"policy-fixture-v1",
          "agents":[{"agent_id":"agent-1","runtime":"native","models":["model-a"],
            "tools":["inspect"],"operation_classes":["fixture"],"available_slots":8,"healthy":true}],
          "model_profiles":[{"model":"model-a","quality":0.9,"cost_per_attempt_usd_micros":1000,
            "latency_ms":100,"uncertainty":0.1}],"budget_remaining_usd_micros":100000,
          "max_parallel_attempts":8,"human_attention_minutes":10},
        "operations":[{"operation_id":"operation-1","namespace":"benchmark","operation_class":"fixture",
          "priority":10,"risk":"low","submitted_at_ms":1,"required_tools":["inspect"],
          "allowed_models":["model-a"],"max_attempts":2,"budget_ceiling_usd_micros":5000,
          "acceptance_criteria":["receipt complete"],"approval_required":false}],
        "strategy":{"strategy_id":"baseline","version":"1","baseline":"throughput"}
    })).map_err(|error| format!("construct Gunshi fixture: {error}"))?;
    Ok(Box::new(move || {
        black_box(recommend_baseline(&request)?);
        Ok(())
    }))
}

fn persistence_benchmark(concurrency: usize, dataset_size: usize) -> Result<Benchmark, String> {
    let directory = tempfile::Builder::new()
        .prefix("sekai-persistence-benchmark-")
        .tempdir()
        .map_err(|error| format!("create persistence benchmark directory: {error}"))?;
    let path = directory.path().join("sekai.db");
    let db = Arc::new(SekaiDb::new(
        path.to_str().ok_or("benchmark path is not UTF-8")?,
    )?);
    for index in 0..dataset_size {
        db.create_object(&benchmark_object(index))?;
    }
    let sequence = Arc::new(AtomicU64::new(dataset_size as u64));
    let state = PersistenceState {
        db: Some(db),
        _directory: directory,
    };
    Ok(Box::new(move || {
        let mut threads = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let db = Arc::clone(state.db.as_ref().expect("benchmark database is live"));
            let sequence = Arc::clone(&sequence);
            threads.push(std::thread::spawn(move || -> Result<(), String> {
                let index = sequence.fetch_add(1, Ordering::Relaxed) as usize;
                let object = benchmark_object(index);
                retry_database_pressure(|| db.create_object(&object))?;
                black_box(retry_database_pressure(|| db.get_object(&object.id))?);
                black_box(retry_database_pressure(|| {
                    db.list_objects(&ListFilter {
                        namespace: Some("benchmark".into()),
                        limit: 16,
                        ..Default::default()
                    })
                })?);
                retry_database_pressure(|| db.delete_object(&object.id))?;
                Ok(())
            }));
        }
        for thread in threads {
            thread
                .join()
                .map_err(|_| "persistence benchmark worker panicked".to_string())??;
        }
        Ok(())
    }))
}

fn retry_database_pressure<T>(
    mut operation: impl FnMut() -> Result<T, String>,
) -> Result<T, String> {
    const MAX_ATTEMPTS: usize = 20;
    for attempt in 1..=MAX_ATTEMPTS {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if error.contains("database is locked") && attempt < MAX_ATTEMPTS => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded retry loop always returns")
}

struct PersistenceState {
    db: Option<Arc<SekaiDb>>,
    _directory: tempfile::TempDir,
}

impl Drop for PersistenceState {
    fn drop(&mut self) {
        drop(self.db.take());
    }
}

fn retry_benchmark(dataset_size: usize) -> Benchmark {
    let cases = [
        ("rate_limited", RetrySafety::Safe),
        ("upstream_unavailable", RetrySafety::Safe),
        ("upstream_timeout", RetrySafety::Ambiguous),
        ("quota_exhausted", RetrySafety::NotRetryable),
    ];
    Box::new(move || {
        for index in 0..dataset_size {
            let (code, safety) = cases[index % cases.len()];
            black_box(retry_disposition(code, safety));
        }
        Ok(())
    })
}

fn attestation_benchmark(dataset_size: usize) -> Benchmark {
    let attestations = (0..dataset_size)
        .map(|index| PolicyAttestation {
            id: format!("attestation-{index}"),
            decision_id: format!("decision-{index}"),
            policy_kind: "action_policy".into(),
            policy_scope: "benchmark".into(),
            policy_version: "policy-fixture-v1".into(),
            policy_snapshot: "{\"risk\":\"low\"}".into(),
            inputs: HashMap::from([("action".into(), "inspect".into())]),
            decision: "allow".into(),
            content_hash: String::new(),
            created: index as i64,
        })
        .collect::<Vec<_>>();
    Box::new(move || {
        let exports = attestations
            .iter()
            .map(|attestation| (attestation_content_hash(attestation), attestation))
            .collect::<Vec<_>>();
        black_box(serde_json::to_vec(&exports).map_err(|error| error.to_string())?);
        Ok(())
    })
}
