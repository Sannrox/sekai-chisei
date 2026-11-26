//! Eval dataset definitions through namespace-authorized calls (#2306).
//!
//! A namespace sees the definitions in the server's directory
//! (`CHISEI_EVAL_DATASETS_DIR`, read-only) and the ones put under it. Put
//! needs namespace write access and leaves an audit decision; get, list and
//! case paging need read access and only ever read the caller's namespace.
//!
//! Recorded definitions (ADR 0153, #3513) are put through the same call under
//! their own contract. They need namespace admin and the Sekai plane in this
//! process; get and list show their selection, never the instance ids, and
//! case paging shows only the cases the caller can read.

use super::*;
use crate::chisei::eval_dataset::recorded::{
    RecordedDatasetSelection, RecordedEvalDatasetDefinition, RecordedEvalDatasetStore,
    StoredRecordedEvalDataset, is_recorded_dataset, is_recorded_definition,
};
use crate::chisei::eval_dataset::{
    DatasetSources, EvalDataset, EvalDatasetDefinition, EvalDatasetDefinitionStore,
    StoredEvalDatasetDefinition, datasets_directory, directory_definitions, is_not_found,
};
use crate::chisei_store::ChiseiDecisionStore;
use crate::composition::recorded_eval_cases as recorded;

const SOURCE_STORED: &str = "stored";
const SOURCE_DIRECTORY: &str = "directory";
const SOURCE_RECORDED: &str = "recorded";
const DEFINITION_PAGE: (usize, usize) = (50, 200);
const CASE_PAGE: (usize, usize) = (100, 1_000);

/// `name@version` for `namespace`, from the directory or the namespace's
/// stored definitions. Blocking: run off the async runtime.
pub(super) fn resolve_dataset(
    store: &sekai_core::db::runtime_db::RuntimeDb,
    namespace: &str,
    name: &str,
    version: &str,
) -> Result<EvalDataset, Status> {
    let directory = datasets_directory();
    DatasetSources {
        directory: directory.as_deref(),
        store,
        namespace,
    }
    .resolve(name, version)
    .or_else(|error| {
        if !is_not_found(&error) {
            return Err(error);
        }
        // A name the directory and the synthetic store do not hold may be a
        // recorded definition.
        match resolve_recorded(store, namespace, name, version) {
            Ok(Some((_, dataset))) => Ok(dataset),
            Ok(None) => Err(error),
            Err(status) => Err(status.message().to_string()),
        }
    })
    .map_err(Status::not_found)
}

/// The recorded definition stored at `name@version` and its dataset.
pub(super) fn resolve_recorded(
    store: &sekai_core::db::runtime_db::RuntimeDb,
    namespace: &str,
    name: &str,
    version: &str,
) -> Result<Option<(StoredRecordedEvalDataset, EvalDataset)>, Status> {
    let Some(stored) = store
        .get_recorded_eval_dataset(namespace, name, Some(version))
        .map_err(Status::internal)?
    else {
        return Ok(None);
    };
    let dataset = stored
        .definition
        .dataset(namespace)
        .map_err(Status::internal)?;
    Ok((dataset.version == version).then_some((stored, dataset)))
}

/// A recorded version as a definition record. Its JSON is the selection: the
/// instance ids stay out of reads that do not check clearance per case.
fn recorded_record(
    record: StoredRecordedEvalDataset,
) -> Result<EvalDatasetDefinitionRecord, Status> {
    Ok(EvalDatasetDefinitionRecord {
        namespace: record.namespace,
        name: record.definition.selection.name.clone(),
        version: record.version,
        definition_json: serde_json::to_string(&record.definition.selection)
            .map_err(|error| Status::internal(error.to_string()))?,
        source: SOURCE_RECORDED.into(),
        digest: record.digest,
        case_count: record.case_count,
        created_by: record.created_by,
        created_at_ms: record.created_at_ms,
    })
}

fn page_size(requested: u32, (default, max): (usize, usize)) -> usize {
    match requested {
        0 => default,
        requested => (requested as usize).min(max),
    }
}

fn stored_record(
    record: StoredEvalDatasetDefinition,
) -> Result<EvalDatasetDefinitionRecord, Status> {
    Ok(EvalDatasetDefinitionRecord {
        namespace: record.namespace,
        name: record.definition.name.clone(),
        version: record.version,
        definition_json: serde_json::to_string(&record.definition)
            .map_err(|error| Status::internal(error.to_string()))?,
        source: SOURCE_STORED.into(),
        digest: record.digest,
        case_count: record.case_count,
        created_by: record.created_by,
        created_at_ms: record.created_at_ms,
    })
}

/// A directory definition at the version it generates now.
fn directory_record(
    definition: EvalDatasetDefinition,
) -> Result<EvalDatasetDefinitionRecord, String> {
    let dataset = definition.generate()?;
    Ok(EvalDatasetDefinitionRecord {
        namespace: String::new(),
        name: definition.name.clone(),
        version: dataset.version,
        definition_json: serde_json::to_string(&definition).map_err(|error| error.to_string())?,
        source: SOURCE_DIRECTORY.into(),
        digest: dataset.digest,
        case_count: dataset.cases.len() as u64,
        created_by: String::new(),
        created_at_ms: 0,
    })
}

/// The audit decision for a recorded version: the dataset, version and case
/// count, never the instance ids (ADR 0153 rule 7).
fn recorded_decision(record: &StoredRecordedEvalDataset) -> crate::sekai::audit::Decision {
    let name = &record.definition.selection.name;
    crate::sekai::audit::Decision {
        id: format!(
            "eval-dataset-definition:{}:{name}@{}",
            record.namespace, record.version
        ),
        timestamp: record.created_at_ms,
        actor: record.created_by.clone(),
        action: "eval_dataset_definition/put".into(),
        reason: "recorded eval dataset definition version stored".into(),
        evidence: HashMap::from([
            ("namespace".into(), record.namespace.clone()),
            ("dataset".into(), name.clone()),
            ("dataset_version".into(), record.version.clone()),
            ("dataset_digest".into(), record.digest.clone()),
            ("source".into(), SOURCE_RECORDED.into()),
            ("case_count".into(), record.case_count.to_string()),
        ]),
        target_id: format!("{}/{name}", record.namespace),
        outcome: "stored".into(),
    }
}

/// The audit decision for a stored version. Built from the stored row, so a
/// put retried after its audit write failed records the same decision.
fn definition_decision(record: &StoredEvalDatasetDefinition) -> crate::sekai::audit::Decision {
    let name = &record.definition.name;
    crate::sekai::audit::Decision {
        id: format!(
            "eval-dataset-definition:{}:{name}@{}",
            record.namespace, record.version
        ),
        timestamp: record.created_at_ms,
        actor: record.created_by.clone(),
        action: "eval_dataset_definition/put".into(),
        reason: "eval dataset definition version stored".into(),
        evidence: HashMap::from([
            ("namespace".into(), record.namespace.clone()),
            ("dataset".into(), name.clone()),
            ("dataset_version".into(), record.version.clone()),
            ("dataset_digest".into(), record.digest.clone()),
        ]),
        target_id: format!("{}/{name}", record.namespace),
        outcome: "stored".into(),
    }
}

pub(super) async fn put_eval_dataset_definition(
    service: &ChiseiServiceImpl,
    req: Request<PutEvalDatasetDefinitionRequest>,
) -> Result<Response<PutEvalDatasetDefinitionResponse>, Status> {
    if is_recorded_definition(&req.get_ref().definition_json) {
        return put_recorded_definition(service, req).await;
    }
    let actor = authenticated_actor(&req);
    let request = req.into_inner();
    require_namespace_write_access(service.sekai_facts.reader(), &actor, &request.namespace)?;
    let store = service.db.runtime_arc();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let stored = tokio::task::spawn_blocking(move || {
        let record = StoredEvalDatasetDefinition::new(
            &request.namespace,
            &request.definition_json,
            &actor,
            now_ms,
        )
        .map_err(Status::invalid_argument)?;
        let directory = datasets_directory();
        let sources = DatasetSources {
            directory: directory.as_deref(),
            store: store.as_ref(),
            namespace: &request.namespace,
        };
        if sources
            .directory_definition(&record.definition.name)
            .map_err(Status::failed_precondition)?
            .is_some()
        {
            return Err(Status::failed_precondition(
                "the server's definitions directory defines this eval dataset; it is read-only",
            ));
        }
        if store
            .get_recorded_eval_dataset(&request.namespace, &record.definition.name, None)
            .map_err(Status::internal)?
            .is_some()
        {
            return Err(Status::failed_precondition(
                "a recorded eval dataset holds this name",
            ));
        }
        // Refuse what the audit write would refuse before anything is stored.
        crate::sekai::audit::validate_decision(&definition_decision(&record))
            .map_err(Status::invalid_argument)?;
        store
            .put_eval_dataset_definition(&record)
            .map_err(Status::internal)
    })
    .await
    .map_err(|_| Status::internal("eval dataset definition task failed"))??;
    service
        .db
        .record_decisions_idempotently(&[definition_decision(&stored)])
        .map_err(|_| {
            Status::unavailable("eval dataset definition audit unavailable; retry the put")
        })?;
    Ok(Response::new(PutEvalDatasetDefinitionResponse {
        record: Some(stored_record(stored)?),
    }))
}

/// Put a recorded definition: select the decided instances the caller can
/// read, freeze them as case references and store the version. Namespace
/// admin only: it turns review decisions into a reusable labelled set.
async fn put_recorded_definition(
    service: &ChiseiServiceImpl,
    req: Request<PutEvalDatasetDefinitionRequest>,
) -> Result<Response<PutEvalDatasetDefinitionResponse>, Status> {
    let actor = authenticated_actor(&req);
    let context = enterprise_authenticated_context(&req)?.cloned();
    require_namespace_admin_access(
        service.sekai_facts.reader(),
        &actor,
        context.as_ref(),
        &req.get_ref().namespace,
    )?;
    let sekai = service.in_process_sekai_service()?;
    let caller = recorded::caller_of(&req);
    let request = req.into_inner();
    if request.definition_json.len() > crate::chisei::eval_dataset::MAX_STORED_DEFINITION_BYTES {
        return Err(Status::invalid_argument(
            "recorded eval dataset definition is too large",
        ));
    }
    let selection = RecordedDatasetSelection::parse(&request.definition_json)
        .map_err(Status::invalid_argument)?;
    let store = service.db.runtime_arc();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let stored = tokio::task::spawn_blocking(move || {
        let directory = datasets_directory();
        let sources = DatasetSources {
            directory: directory.as_deref(),
            store: store.as_ref(),
            namespace: &request.namespace,
        };
        if sources
            .directory_definition(&selection.name)
            .map_err(Status::failed_precondition)?
            .is_some()
            || store
                .get_eval_dataset_definition(&request.namespace, &selection.name, None)
                .map_err(Status::internal)?
                .is_some()
        {
            return Err(Status::failed_precondition(
                "a synthetic eval dataset definition holds this name",
            ));
        }
        let cases = recorded::select_cases(&sekai, &caller, &request.namespace, &selection)?;
        let definition = RecordedEvalDatasetDefinition::freeze(selection, cases)
            .map_err(Status::failed_precondition)?;
        let record = StoredRecordedEvalDataset::new(&request.namespace, definition, &actor, now_ms)
            .map_err(Status::internal)?;
        crate::sekai::audit::validate_decision(&recorded_decision(&record))
            .map_err(Status::invalid_argument)?;
        store
            .put_recorded_eval_dataset(&record)
            .map_err(Status::internal)
    })
    .await
    .map_err(|_| Status::internal("eval dataset definition task failed"))??;
    service
        .db
        .record_decisions_idempotently(&[recorded_decision(&stored)])
        .map_err(|_| {
            Status::unavailable("eval dataset definition audit unavailable; retry the put")
        })?;
    Ok(Response::new(PutEvalDatasetDefinitionResponse {
        record: Some(recorded_record(stored)?),
    }))
}

pub(super) async fn get_eval_dataset_definition(
    service: &ChiseiServiceImpl,
    req: Request<GetEvalDatasetDefinitionRequest>,
) -> Result<Response<GetEvalDatasetDefinitionResponse>, Status> {
    // Admitted for tenant assertions (#3056).
    require_request_namespace_read(service.sekai_facts.reader(), &req, &req.get_ref().namespace)?;
    let request = req.into_inner();
    let store = service.db.runtime_arc();
    let record = tokio::task::spawn_blocking(move || {
        let version = Some(request.version.as_str()).filter(|version| !version.is_empty());
        let directory = datasets_directory();
        let sources = DatasetSources {
            directory: directory.as_deref(),
            store: store.as_ref(),
            namespace: &request.namespace,
        };
        if let Some(definition) = sources
            .directory_definition(&request.name)
            .map_err(Status::failed_precondition)?
        {
            let record = directory_record(definition).map_err(Status::failed_precondition)?;
            if version.is_none_or(|version| version == record.version) {
                return Ok(record);
            }
        }
        if let Some(record) = store
            .get_eval_dataset_definition(&request.namespace, &request.name, version)
            .map_err(Status::internal)?
        {
            return stored_record(record);
        }
        store
            .get_recorded_eval_dataset(&request.namespace, &request.name, version)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("eval dataset definition not found"))
            .and_then(recorded_record)
    })
    .await
    .map_err(|_| Status::internal("eval dataset definition task failed"))??;
    Ok(Response::new(GetEvalDatasetDefinitionResponse {
        record: Some(record),
    }))
}

pub(super) async fn list_eval_dataset_definitions(
    service: &ChiseiServiceImpl,
    req: Request<ListEvalDatasetDefinitionsRequest>,
) -> Result<Response<ListEvalDatasetDefinitionsResponse>, Status> {
    // Admitted for tenant assertions (#3056).
    require_request_namespace_read(service.sekai_facts.reader(), &req, &req.get_ref().namespace)?;
    let request = req.into_inner();
    let limit = page_size(request.page_size, DEFINITION_PAGE);
    let store = service.db.runtime_arc();
    let response = tokio::task::spawn_blocking(move || {
        // The token is the last name of the previous page.
        let after = request.page_token;
        // A directory file that no longer generates is left out, like one
        // that does not parse: it must not hide the others.
        let directory: Vec<EvalDatasetDefinitionRecord> = datasets_directory()
            .map(|directory| directory_definitions(&directory))
            .unwrap_or_default()
            .into_iter()
            .filter(|definition| definition.name > after)
            .filter_map(|definition| directory_record(definition).ok())
            .take(limit + 1)
            .collect();
        let stored = store
            .list_eval_dataset_definitions(&request.namespace, &after, limit + 1)
            .map_err(Status::internal)?
            .into_iter()
            .map(stored_record)
            .collect::<Result<Vec<_>, _>>()?;
        let recorded = store
            .list_recorded_eval_datasets(&request.namespace, &after, limit + 1)
            .map_err(Status::internal)?
            .into_iter()
            .map(recorded_record)
            .collect::<Result<Vec<_>, _>>()?;
        // By name; the directory's entry wins a name both hold, as on get,
        // then the synthetic store's.
        let rank = |record: &EvalDatasetDefinitionRecord| match record.source.as_str() {
            SOURCE_DIRECTORY => 0,
            SOURCE_STORED => 1,
            _ => 2,
        };
        let mut definitions: Vec<EvalDatasetDefinitionRecord> = directory
            .into_iter()
            .chain(stored)
            .chain(recorded)
            .collect();
        definitions.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| rank(left).cmp(&rank(right)))
        });
        definitions.dedup_by(|later, earlier| later.name == earlier.name);
        let next_page_token = if definitions.len() > limit {
            definitions.truncate(limit);
            definitions
                .last()
                .map(|record| record.name.clone())
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok::<_, Status>(ListEvalDatasetDefinitionsResponse {
            definitions,
            next_page_token,
        })
    })
    .await
    .map_err(|_| Status::internal("eval dataset definition task failed"))??;
    Ok(Response::new(response))
}

pub(super) async fn list_eval_dataset_cases(
    service: &ChiseiServiceImpl,
    req: Request<ListEvalDatasetCasesRequest>,
) -> Result<Response<ListEvalDatasetCasesResponse>, Status> {
    // Admitted for tenant assertions (#3056).
    require_request_namespace_read(service.sekai_facts.reader(), &req, &req.get_ref().namespace)?;
    let caller = recorded::caller_of(&req);
    let sekai = service.in_process_sekai_service().ok();
    let request = req.into_inner();
    let limit = page_size(request.page_size, CASE_PAGE);
    // The token is `<version>/<offset>`: a version never changes, so an
    // offset into it is stable across pages.
    let offset = match request.page_token.as_str() {
        "" => 0,
        token => token
            .strip_prefix(&format!("{}/", request.dataset_version))
            .and_then(|offset| offset.parse::<usize>().ok())
            .ok_or_else(|| {
                Status::invalid_argument("page_token is not for this dataset version")
            })?,
    };
    let store = service.db.runtime_arc();
    let response = tokio::task::spawn_blocking(move || {
        let dataset = resolve_dataset(
            store.as_ref(),
            &request.namespace,
            &request.dataset,
            &request.dataset_version,
        )
        .map_err(|status| {
            if is_not_found(status.message()) {
                status
            } else {
                Status::failed_precondition(status.message())
            }
        })?;
        let cases = if is_recorded_dataset(&dataset) {
            readable_recorded_cases(
                store.as_ref(),
                sekai.as_deref(),
                &caller,
                &request,
                &dataset,
            )?
        } else {
            dataset.cases.clone()
        };
        let total = cases.len();
        if offset > total {
            return Err(Status::invalid_argument("page_token is past the last case"));
        }
        let end = (offset + limit).min(total);
        let cases = cases[offset..end]
            .iter()
            .map(|case| EvalDatasetCase {
                case_id: case.case_id.clone(),
                input: case.input.clone().into_iter().collect(),
                expected: case.expected.clone(),
                tags: case.tags.clone(),
            })
            .collect();
        Ok(ListEvalDatasetCasesResponse {
            cases,
            cases_total: total as u64,
            dataset_digest: dataset.digest,
            next_page_token: if end < total {
                format!("{}/{end}", dataset.version)
            } else {
                String::new()
            },
        })
    })
    .await
    .map_err(|_| Status::internal("eval dataset cases task failed"))??;
    Ok(Response::new(response))
}

/// The cases of a recorded version the caller can read. Every source must
/// still stand, or the version answers "not found"; a case the caller cannot
/// read is left out, so it looks like a case the version never had.
fn readable_recorded_cases(
    store: &sekai_core::db::runtime_db::RuntimeDb,
    sekai: Option<&crate::grpc::sekai_service::SekaiServiceImpl>,
    caller: &Request<()>,
    request: &ListEvalDatasetCasesRequest,
    dataset: &EvalDataset,
) -> Result<Vec<crate::chisei::eval_dataset::EvalCase>, Status> {
    let sekai =
        sekai.ok_or_else(|| Status::failed_precondition(recorded::RECORDED_NEEDS_COMBINED))?;
    let (stored, _) = resolve_recorded(
        store,
        &request.namespace,
        &request.dataset,
        &request.dataset_version,
    )?
    .ok_or_else(|| Status::not_found(crate::chisei::eval_dataset::DATASET_NOT_FOUND))?;
    let sources = recorded::sources(sekai, &request.namespace, &stored.definition)?;
    let readable = recorded::readable(sekai, caller, &sources)?;
    Ok(dataset
        .cases
        .iter()
        .zip(readable)
        .filter(|(_, readable)| *readable)
        .map(|(case, _)| case.clone())
        .collect())
}
