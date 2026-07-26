use crate::db::postgres::PostgresDb;
use crate::sekai::audit::Decision;
use crate::sekai::capability_package::{
    CapabilityPackageManifest, PackageInstallation, PackageLifecycleEvent, parse_package_version,
    request_digest as package_request_digest, run_eval_suites,
    simple_request_digest as package_simple_request_digest, validate_context,
};
use crate::sekai::ledger;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

impl PostgresDb {
    pub fn install_capability_package(
        &self,
        namespace: &str,
        manifest: &CapabilityPackageManifest,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        validate_context(namespace, actor, request_id)?;
        // Until package-trust tables are complete on PostgreSQL, only the
        // grandfather path is available: reject invalid signatures but keep
        // unsigned installs allowed. Operators cannot enable `signed` here yet.
        let trust = crate::sekai::capability_package::evaluate_package_trust(
            crate::sekai::capability_package::PACKAGE_TRUST_UNSIGNED_ALLOWED,
            &[],
            manifest,
        )?;
        if !trust.allowed {
            return Err(format!("package trust denied: {}", trust.reason));
        }
        let trust_evidence = crate::sekai::capability_package::package_trust_evidence(&trust);
        let manifest_digest = manifest.digest()?;
        let request_digest = package_request_digest("install", namespace, manifest, "")?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_package(&mut tx, namespace, &manifest.name)?;
        if let Some(existing) = replay(&mut tx, namespace, actor, request_id, &request_digest)? {
            return existing
                .ok_or_else(|| "idempotent install no longer has an active installation".into());
        }
        if load_installation(&mut tx, namespace, &manifest.name)?.is_some() {
            return Err("package already installed in namespace".into());
        }
        store_manifest(&mut tx, namespace, manifest, &manifest_digest, now_ms)?;
        tx.execute(
            "INSERT INTO sekai_capability_package_installations
             (namespace,package_name,current_version,previous_version,state,installed_by,updated_by,installed_at_ms,updated_at_ms)
             VALUES($1,$2,$3,'','active',$4,$4,$5,$5)",
            &[
                &namespace,
                &manifest.name.as_str(),
                &manifest.version.as_str(),
                &actor,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        append_event(
            &mut tx,
            namespace,
            manifest,
            "install",
            actor,
            request_id,
            &request_digest,
            &manifest_digest,
            &format!("manifest_validated;{trust_evidence}"),
            now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        self.get_capability_package(namespace, &manifest.name)?
            .ok_or_else(|| "package installation missing after commit".into())
    }

    pub fn upgrade_capability_package(
        &self,
        namespace: &str,
        manifest: &CapabilityPackageManifest,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        validate_context(namespace, actor, request_id)?;
        let trust = crate::sekai::capability_package::evaluate_package_trust(
            crate::sekai::capability_package::PACKAGE_TRUST_UNSIGNED_ALLOWED,
            &[],
            manifest,
        )?;
        if !trust.allowed {
            return Err(format!("package trust denied: {}", trust.reason));
        }
        let trust_evidence = crate::sekai::capability_package::package_trust_evidence(&trust);
        let manifest_digest = manifest.digest()?;
        let request_digest = package_request_digest("upgrade", namespace, manifest, "")?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_package(&mut tx, namespace, &manifest.name)?;
        if let Some(existing) = replay(&mut tx, namespace, actor, request_id, &request_digest)? {
            return existing
                .ok_or_else(|| "idempotent upgrade no longer has an active installation".into());
        }
        let current = load_installation(&mut tx, namespace, &manifest.name)?
            .ok_or_else(|| "package is not installed in namespace".to_string())?;
        let current_version = parse_package_version(&current.current_version)
            .ok_or_else(|| "installed package version is invalid".to_string())?;
        let next_version = parse_package_version(&manifest.version)
            .ok_or_else(|| "upgrade package version is invalid".to_string())?;
        if next_version <= current_version {
            return Err("upgrade version must be newer than the installed version".into());
        }
        store_manifest(&mut tx, namespace, manifest, &manifest_digest, now_ms)?;
        tx.execute(
            "UPDATE sekai_capability_package_installations
             SET previous_version=current_version,current_version=$1,state='active',
                 updated_by=$2,updated_at_ms=$3
             WHERE namespace=$4 AND package_name=$5",
            &[
                &manifest.version.as_str(),
                &actor,
                &now_ms,
                &namespace,
                &manifest.name.as_str(),
            ],
        )
        .map_err(|error| error.to_string())?;
        append_event(
            &mut tx,
            namespace,
            manifest,
            "upgrade",
            actor,
            request_id,
            &request_digest,
            &manifest_digest,
            &format!("manifest_validated;{trust_evidence}"),
            now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        self.get_capability_package(namespace, &manifest.name)?
            .ok_or_else(|| "package installation missing after commit".into())
    }

    pub fn rollback_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        self.transition_capability_package(
            namespace,
            package_name,
            "rollback",
            actor,
            request_id,
            now_ms,
        )
    }

    pub fn disable_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        self.transition_capability_package(
            namespace,
            package_name,
            "disable",
            actor,
            request_id,
            now_ms,
        )
    }

    pub fn uninstall_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        validate_context(namespace, actor, request_id)?;
        let request_digest = package_simple_request_digest("uninstall", namespace, package_name);
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_package(&mut tx, namespace, package_name)?;
        if let Some(original_result) =
            replay(&mut tx, namespace, actor, request_id, &request_digest)?
        {
            if original_result.is_none()
                && load_installation(&mut tx, namespace, package_name)?.is_none()
            {
                return Ok(());
            }
            return Err("stale uninstall retry conflicts with a newer installation".into());
        }
        let current = load_installation(&mut tx, namespace, package_name)?
            .ok_or_else(|| "package is not installed in namespace".to_string())?;
        let (manifest, stored_digest) =
            load_manifest_record(&mut tx, namespace, package_name, &current.current_version)?;
        let digest = manifest.digest()?;
        if digest != stored_digest {
            return Err("capability package manifest digest mismatch".into());
        }
        tx.execute(
            "DELETE FROM sekai_capability_package_installations
             WHERE namespace=$1 AND package_name=$2",
            &[&namespace, &package_name],
        )
        .map_err(|error| error.to_string())?;
        append_event(
            &mut tx,
            namespace,
            &manifest,
            "uninstall",
            actor,
            request_id,
            &request_digest,
            &digest,
            "history_retained",
            now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn evaluate_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        validate_context(namespace, actor, request_id)?;
        let request_digest = package_simple_request_digest("evaluate", namespace, package_name);
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_package(&mut tx, namespace, package_name)?;
        if replay(&mut tx, namespace, actor, request_id, &request_digest)?.is_some() {
            return Ok(true);
        }
        let current = load_installation(&mut tx, namespace, package_name)?
            .ok_or_else(|| "package is not installed in namespace".to_string())?;
        if current.state != "active" {
            return Err("disabled package cannot be evaluated".into());
        }
        let (manifest, stored_digest) =
            load_manifest_record(&mut tx, namespace, package_name, &current.current_version)?;
        let digest = manifest.digest()?;
        if digest != stored_digest {
            return Err("capability package manifest digest mismatch".into());
        }
        let checks_run = run_eval_suites(&manifest)?;
        append_event(
            &mut tx,
            namespace,
            &manifest,
            "evaluate",
            actor,
            request_id,
            &request_digest,
            &digest,
            &format!("{checks_run}_checks_passed"),
            now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    fn transition_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        action: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        validate_context(namespace, actor, request_id)?;
        let request_digest = package_simple_request_digest(action, namespace, package_name);
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_package(&mut tx, namespace, package_name)?;
        if let Some(existing) = replay(&mut tx, namespace, actor, request_id, &request_digest)? {
            return existing.ok_or_else(|| {
                "idempotent transition no longer has an active installation".into()
            });
        }
        let current = load_installation(&mut tx, namespace, package_name)?
            .ok_or_else(|| "package is not installed in namespace".to_string())?;
        let (version, previous, state) = match action {
            "rollback" if !current.previous_version.is_empty() => {
                (current.previous_version.clone(), String::new(), "active")
            }
            "rollback" => return Err("package has no previous version to roll back to".into()),
            "disable" if current.state == "active" => (
                current.current_version.clone(),
                current.previous_version.clone(),
                "disabled",
            ),
            "disable" => return Err("package is already disabled".into()),
            _ => return Err("unsupported package transition".into()),
        };
        let (manifest, stored_digest) =
            load_manifest_record(&mut tx, namespace, package_name, &version)?;
        let digest = manifest.digest()?;
        if digest != stored_digest {
            return Err("capability package manifest digest mismatch".into());
        }
        tx.execute(
            "UPDATE sekai_capability_package_installations
             SET current_version=$1,previous_version=$2,state=$3,updated_by=$4,updated_at_ms=$5
             WHERE namespace=$6 AND package_name=$7",
            &[
                &version.as_str(),
                &previous.as_str(),
                &state,
                &actor,
                &now_ms,
                &namespace,
                &package_name,
            ],
        )
        .map_err(|error| error.to_string())?;
        append_event(
            &mut tx,
            namespace,
            &manifest,
            action,
            actor,
            request_id,
            &request_digest,
            &digest,
            "transition_applied",
            now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        self.get_capability_package(namespace, package_name)?
            .ok_or_else(|| "package installation missing after commit".into())
    }

    pub fn get_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Option<PackageInstallation>, String> {
        self.connection()?
            .query_opt(
                "SELECT namespace,package_name,current_version,previous_version,state,
                        installed_by,updated_by,installed_at_ms,updated_at_ms
                 FROM sekai_capability_package_installations
                 WHERE namespace=$1 AND package_name=$2",
                &[&namespace, &package_name],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_installation)
            .transpose()
    }

    pub fn get_capability_package_manifest(
        &self,
        namespace: &str,
        package_name: &str,
        version: &str,
    ) -> Result<Option<CapabilityPackageManifest>, String> {
        self.connection()?
            .query_opt(
                "SELECT manifest_json FROM sekai_capability_package_versions
                 WHERE namespace=$1 AND package_name=$2 AND package_version=$3",
                &[&namespace, &package_name, &version],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .transpose()
    }

    pub fn list_capability_package_events(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Vec<PackageLifecycleEvent>, String> {
        self.connection()?
            .query(
                "SELECT sequence,namespace,package_name,package_version,action,actor,request_id,
                        manifest_digest,evidence,recorded_at_ms
                 FROM sekai_capability_package_events
                 WHERE namespace=$1 AND package_name=$2
                 ORDER BY sequence",
                &[&namespace, &package_name],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_event)
            .collect()
    }

    pub fn list_capability_package_decisions(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Vec<Decision>, String> {
        let target = format!("capability-package:{namespace}:{package_name}");
        self.connection()?
            .query(
                "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome
                 FROM sekai_decisions
                 WHERE target_id=$1
                 ORDER BY COALESCE(seq, 0), timestamp, id",
                &[&target.as_str()],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_decision)
            .collect()
    }
}

fn lock_package(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    package_name: &str,
) -> Result<(), String> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 261))",
        &[&namespace, &package_name],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn store_manifest(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    manifest: &CapabilityPackageManifest,
    digest: &str,
    now_ms: i64,
) -> Result<(), String> {
    let json = serde_json::to_string(manifest).map_err(|error| error.to_string())?;
    let existing: Option<String> = tx
        .query_opt(
            "SELECT manifest_digest FROM sekai_capability_package_versions
             WHERE namespace=$1 AND package_name=$2 AND package_version=$3",
            &[
                &namespace,
                &manifest.name.as_str(),
                &manifest.version.as_str(),
            ],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0));
    if existing
        .as_deref()
        .is_some_and(|existing| existing != digest)
    {
        return Err("package version is immutable".into());
    }
    tx.execute(
        "INSERT INTO sekai_capability_package_versions
         (namespace,package_name,package_version,manifest_json,manifest_digest,created_at_ms)
         VALUES($1,$2,$3,$4,$5,$6)
         ON CONFLICT(namespace,package_name,package_version) DO NOTHING",
        &[
            &namespace,
            &manifest.name.as_str(),
            &manifest.version.as_str(),
            &json.as_str(),
            &digest,
            &now_ms,
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn load_manifest_record(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    name: &str,
    version: &str,
) -> Result<(CapabilityPackageManifest, String), String> {
    let row = tx
        .query_one(
            "SELECT manifest_json,manifest_digest FROM sekai_capability_package_versions
             WHERE namespace=$1 AND package_name=$2 AND package_version=$3",
            &[&namespace, &name, &version],
        )
        .map_err(|error| error.to_string())?;
    let json: String = row.get(0);
    let digest: String = row.get(1);
    Ok((
        serde_json::from_str(&json).map_err(|error| error.to_string())?,
        digest,
    ))
}

fn load_installation(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    name: &str,
) -> Result<Option<PackageInstallation>, String> {
    tx.query_opt(
        "SELECT namespace,package_name,current_version,previous_version,state,
                installed_by,updated_by,installed_at_ms,updated_at_ms
         FROM sekai_capability_package_installations
         WHERE namespace=$1 AND package_name=$2",
        &[&namespace, &name],
    )
    .map_err(|error| error.to_string())?
    .map(row_to_installation)
    .transpose()
}

#[allow(clippy::too_many_arguments)]
fn append_event(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    manifest: &CapabilityPackageManifest,
    action: &str,
    actor: &str,
    request_id: &str,
    request_digest: &str,
    manifest_digest: &str,
    evidence: &str,
    now_ms: i64,
) -> Result<(), String> {
    let result_json = serde_json::to_string(&load_installation(tx, namespace, &manifest.name)?)
        .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_capability_package_events
         (namespace,package_name,package_version,action,actor,request_id,request_digest,
          manifest_digest,evidence,result_json,recorded_at_ms)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        &[
            &namespace,
            &manifest.name.as_str(),
            &manifest.version.as_str(),
            &action,
            &actor,
            &request_id,
            &request_digest,
            &manifest_digest,
            &evidence,
            &result_json.as_str(),
            &now_ms,
        ],
    )
    .map_err(|error| error.to_string())?;
    let audit_evidence = HashMap::from([
        ("namespace".into(), namespace.into()),
        ("package_name".into(), manifest.name.clone()),
        ("package_version".into(), manifest.version.clone()),
        ("manifest_digest".into(), manifest_digest.into()),
        ("request_id".into(), request_id.into()),
        ("lifecycle_evidence".into(), evidence.into()),
    ]);
    insert_chained_decision(
        tx,
        &Decision {
            id: format!(
                "capability-package:{:x}",
                Sha256::digest(format!("{namespace}\0{actor}\0{request_id}"))
            ),
            timestamp: now_ms,
            actor: actor.into(),
            action: format!("capability_package.{action}"),
            reason: "governed capability package lifecycle transition".into(),
            evidence: audit_evidence,
            target_id: format!("capability-package:{namespace}:{}", manifest.name),
            outcome: "succeeded".into(),
        },
    )
}

fn insert_chained_decision(
    tx: &mut postgres::Transaction<'_>,
    decision: &Decision,
) -> Result<(), String> {
    tx.query_one("SELECT pg_advisory_xact_lock(25012)", &[])
        .map_err(|error| error.to_string())?;
    let head = tx
        .query_opt(
            "SELECT seq,entry_hash FROM sekai_decisions
             WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1 FOR UPDATE",
            &[],
        )
        .map_err(|error| error.to_string())?;
    let (head_seq, head_hash) = head
        .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)))
        .unwrap_or((0, String::new()));
    let sequence = head_seq + 1;
    let evidence = serde_json::to_string(&decision.evidence).map_err(|error| error.to_string())?;
    let entry_hash = ledger::entry_hash(sequence, &head_hash, decision, &evidence);
    tx.execute(
        "INSERT INTO sekai_decisions
         (id,timestamp,actor,action,reason,evidence,target_id,outcome,seq,prev_hash,entry_hash)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        &[
            &decision.id,
            &decision.timestamp,
            &decision.actor,
            &decision.action,
            &decision.reason,
            &evidence,
            &decision.target_id,
            &decision.outcome,
            &sequence,
            &head_hash,
            &entry_hash,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn replay(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    actor: &str,
    request_id: &str,
    expected_digest: &str,
) -> Result<Option<Option<PackageInstallation>>, String> {
    let prior = tx
        .query_opt(
            "SELECT request_digest,result_json FROM sekai_capability_package_events
             WHERE namespace=$1 AND actor=$2 AND request_id=$3",
            &[&namespace, &actor, &request_id],
        )
        .map_err(|error| error.to_string())?;
    match prior {
        None => Ok(None),
        Some(row) => {
            let digest: String = row.get(0);
            let result_json: String = row.get(1);
            if digest != expected_digest {
                return Err("request_id was already used for different package input".into());
            }
            Ok(Some(
                serde_json::from_str(&result_json).map_err(|error| error.to_string())?,
            ))
        }
    }
}

fn row_to_installation(row: postgres::Row) -> Result<PackageInstallation, String> {
    Ok(PackageInstallation {
        namespace: row.get(0),
        package_name: row.get(1),
        current_version: row.get(2),
        previous_version: row.get(3),
        state: row.get(4),
        installed_by: row.get(5),
        updated_by: row.get(6),
        installed_at_ms: row.get(7),
        updated_at_ms: row.get(8),
    })
}

fn row_to_event(row: postgres::Row) -> Result<PackageLifecycleEvent, String> {
    Ok(PackageLifecycleEvent {
        sequence: row.get(0),
        namespace: row.get(1),
        package_name: row.get(2),
        package_version: row.get(3),
        action: row.get(4),
        actor: row.get(5),
        request_id: row.get(6),
        manifest_digest: row.get(7),
        evidence: row.get(8),
        recorded_at_ms: row.get(9),
    })
}

fn row_to_decision(row: postgres::Row) -> Result<Decision, String> {
    let evidence_str: String = row.get(5);
    Ok(Decision {
        id: row.get(0),
        timestamp: row.get(1),
        actor: row.get(2),
        action: row.get(3),
        reason: row.get(4),
        evidence: serde_json::from_str(&evidence_str).unwrap_or_default(),
        target_id: row.get(6),
        outcome: row.get(7),
    })
}
