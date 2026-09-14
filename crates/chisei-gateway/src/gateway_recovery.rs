use super::*;

pub(super) async fn append_gateway_recovery(
    runtime: &GatewayRuntime,
    record: GatewayRecoveryRecord,
) -> bool {
    let Some(path) = recovery_spool_path(runtime) else {
        return false;
    };
    let Ok(mut line) = serde_json::to_vec(&record) else {
        return false;
    };
    line.push(b'\n');
    let max_bytes = runtime.recovery_spool_max_bytes;
    let _guard = runtime.recovery_spool_lock.lock().await;
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::{Read, Seek, SeekFrom, Write};
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let current_bytes = std::fs::metadata(&path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let needs_separator = if current_bytes == 0 {
            false
        } else {
            let mut existing = std::fs::OpenOptions::new().read(true).open(&path)?;
            existing.seek(SeekFrom::End(-1))?;
            let mut tail = [0u8; 1];
            existing.read_exact(&mut tail)?;
            tail[0] != b'\n'
        };
        if current_bytes
            .saturating_add(line.len() as u64)
            .saturating_add(u64::from(needs_separator))
            > max_bytes
        {
            return Err(std::io::Error::other("gateway recovery spool is full"));
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(path)?;
        if needs_separator {
            file.write_all(b"\n")?;
        }
        file.write_all(&line)?;
        file.sync_all()
    })
    .await
    .is_ok_and(|result| result.is_ok())
}
pub(super) fn spawn_gateway_recovery_replay(config: GatewayConfig, runtime: GatewayRuntime) {
    if runtime.recovery_replay_running.swap(true, Ordering::AcqRel) {
        return;
    }
    tokio::spawn(async move {
        let initial_records = match recovery_spool_path(&runtime) {
            Some(path) => tokio::fs::read(path)
                .await
                .map(|bytes| {
                    bytes
                        .split(|byte| *byte == b'\n')
                        .filter(|line| !line.is_empty())
                        .count()
                })
                .unwrap_or(0),
            None => 0,
        };
        let max_batches = initial_records.div_ceil(RECOVERY_REPLAY_YIELD_INTERVAL);
        for _ in 0..max_batches {
            let (pending, progressed, deferred) = replay_gateway_recovery(&config, &runtime).await;
            if !pending || (!progressed && !deferred) {
                break;
            }
            tokio::task::yield_now().await;
        }
        runtime
            .recovery_replay_running
            .store(false, Ordering::Release);
    });
}
pub(super) async fn llm_recovery_row_exists(
    sekai: &mut SekaiServiceClient<GatewayClient>,
    values: &HashMap<String, String>,
) -> Result<bool, tonic::Status> {
    let Some((column, value)) = ["receipt_id", "request_id"].into_iter().find_map(|column| {
        values
            .get(column)
            .filter(|value| !value.is_empty())
            .map(|value| (column, value))
    }) else {
        return Ok(false);
    };
    match sekai
        .query_rows(gateway_request(QueryRowsRequest {
            dataset_id: "llm_calls".into(),
            query: Some(RowQuery {
                filters: vec![RowFilter {
                    column: column.into(),
                    op: "eq".into(),
                    value: value.clone(),
                }],
                columns: vec![column.into()],
                limit: 1,
                offset: 0,
            }),
        }))
        .await
    {
        Ok(response) => Ok(!response.into_inner().rows.is_empty()),
        Err(error) if error.code() == tonic::Code::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
pub(super) async fn replay_gateway_recovery(
    config: &GatewayConfig,
    runtime: &GatewayRuntime,
) -> (bool, bool, bool) {
    let Some(path) = recovery_spool_path(runtime) else {
        return (false, false, false);
    };
    if !tokio::fs::metadata(&path)
        .await
        .is_ok_and(|metadata| metadata.len() > 0)
    {
        return (false, false, false);
    }
    let Some(target) = config.chisei_grpc_target.as_deref() else {
        return (false, false, false);
    };
    let Ok(channel) = connect_sekai_as_gateway_with_timeout(
        target,
        Some(runtime.resilience.control_plane_timeout),
    )
    .await
    else {
        return (true, false, false);
    };
    let _guard = runtime.recovery_spool_lock.lock().await;
    let Ok(bytes) = tokio::fs::read(&path).await else {
        return (false, false, false);
    };
    let mut failed = Vec::new();
    let mut deferred = Vec::new();
    let mut attempted = 0usize;
    let mut progressed = false;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if attempted >= RECOVERY_REPLAY_YIELD_INTERVAL {
            deferred.push(line.to_vec());
            continue;
        }
        attempted += 1;
        let Ok(record) = serde_json::from_slice::<GatewayRecoveryRecord>(line) else {
            warn!("discarding malformed gateway recovery record");
            continue;
        };
        let replayed = match record {
            GatewayRecoveryRecord::Receipt {
                actor,
                operation_id,
                receipt_json,
                outcome: _,
            } => {
                let project = serde_json::from_str::<OperationReceipt>(&receipt_json)
                    .map(|receipt| receipt.namespace)
                    .unwrap_or_default();
                ChiseiServiceClient::new(channel.clone())
                    .record_usage(gateway_request(RecordUsageRequest {
                        user_id: actor.clone(),
                        tokens_used: 0,
                        subject: format!("gateway-receipt:{operation_id}"),
                        project,
                        agent: actor,
                        key_id: String::new(),
                        work_unit: String::new(),
                        metric: String::new(),
                        idempotency_key: format!("gateway-receipt:{operation_id}"),
                        operation_receipt_json: receipt_json,
                        sample_observation: None,
                    }))
                    .await
                    .is_ok()
            }
            GatewayRecoveryRecord::LlmRow { values } => {
                let mut sekai = SekaiServiceClient::new(channel.clone());
                match llm_recovery_row_exists(&mut sekai, &values).await {
                    Ok(true) => true,
                    Ok(false) => append_llm_calls_rows(
                        runtime,
                        &mut sekai,
                        AppendRowsRequest {
                            dataset_id: "llm_calls".into(),
                            rows: vec![Row { values }],
                        },
                    )
                    .await
                    .is_ok(),
                    Err(_) => false,
                }
            }
        };
        if !replayed {
            failed.push(line.to_vec());
        } else {
            progressed = true;
        }
    }
    let had_deferred = !deferred.is_empty();
    deferred.extend(failed);
    let pending = !deferred.is_empty();
    let rewritten = deferred
        .into_iter()
        .flat_map(|mut line| {
            line.push(b'\n');
            line
        })
        .collect::<Vec<_>>();
    let path_for_log = path.clone();
    let rewrite_result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        if rewritten.is_empty() {
            match std::fs::remove_file(&path) {
                Ok(()) => sync_parent_directory(&path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        } else {
            let temporary =
                PathBuf::from(format!("{}.{}.tmp", path.display(), uuid::Uuid::new_v4()));
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            options.mode(0o600);
            let result = (|| {
                let mut file = options.open(&temporary)?;
                file.write_all(&rewritten)?;
                file.sync_all()?;
                std::fs::rename(&temporary, &path)?;
                sync_parent_directory(&path)
            })();
            if result.is_err() {
                let _ = std::fs::remove_file(temporary);
            }
            result
        }
    })
    .await;
    if !rewrite_result.is_ok_and(|result| result.is_ok()) {
        error!(path = %path_for_log.display(), "gateway recovery spool rewrite failed");
        return (true, false, false);
    }
    (pending, progressed, had_deferred)
}
pub(super) fn sync_parent_directory(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}
pub(super) fn gateway_request<T>(message: T) -> GrpcRequest<T> {
    let mut request = GrpcRequest::new(message);
    request
        .metadata_mut()
        .insert("x-principal", "chisei-gateway".parse().unwrap());
    crate::obs::otel::inject_current_context(request.metadata_mut());
    request
}
pub(super) fn principal_request<T>(
    message: T,
    principal: &str,
) -> Result<GrpcRequest<T>, tonic::Status> {
    let mut request = GrpcRequest::new(message);
    let principal = tonic::metadata::MetadataValue::try_from(principal)
        .map_err(|_| tonic::Status::internal("invalid authenticated gateway principal"))?;
    request.metadata_mut().insert("x-principal", principal);
    crate::obs::otel::inject_current_context(request.metadata_mut());
    Ok(request)
}
