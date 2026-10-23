//! Signed definition package export and import (#1700).
//!
//! Export packages a published revision the caller can read and signs it with
//! this plane's package key. Import verifies the envelope against this plane's
//! trusted package keys, recomputes every digest, and opens a branch and
//! proposal holding exactly the package members. Import never merges; the
//! proposal goes through the normal review and merge gates.
//!
//! Keys come from the environment at call time, so rotation needs no restart:
//! `SEKAI_DEFINITION_PACKAGE_SIGNING_KEY` (file with a 32-byte hex seed) and
//! `SEKAI_DEFINITION_PACKAGE_SIGNER` (`identity/key_id`) for export, and
//! `SEKAI_DEFINITION_PACKAGE_TRUSTED_KEYS` (JSON file of trusted public keys)
//! for import. Without them, export and import fail closed.

use super::*;
use crate::sekai::definition_package::{
    self as package_domain, PackageEnvelope, PackageProvenance, REFUSAL_INCOMPATIBLE,
};
use crate::shomei::TrustedKeyring;
use ed25519_dalek::{SigningKey, VerifyingKey};

pub const SIGNING_KEY_ENV: &str = "SEKAI_DEFINITION_PACKAGE_SIGNING_KEY";
pub const SIGNER_ENV: &str = "SEKAI_DEFINITION_PACKAGE_SIGNER";
pub const TRUSTED_KEYS_ENV: &str = "SEKAI_DEFINITION_PACKAGE_TRUSTED_KEYS";

/// The key this plane signs exported packages with.
pub(super) struct PackageSigner {
    pub identity: String,
    pub key_id: String,
    pub key: SigningKey,
}

/// One entry of the trusted package keys file.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedPackageKey {
    identity: String,
    key_id: String,
    public_key: String,
}

fn decode_key(field: &str, value: &str) -> Result<[u8; 32], String> {
    let value = value.trim();
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{field} must be 32 hexadecimal bytes"));
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{field} must be 32 hexadecimal bytes"))?;
    }
    Ok(bytes)
}

fn package_signer_from_env() -> Result<PackageSigner, Status> {
    let unavailable = || {
        Status::failed_precondition(format!(
            "definition package signing requires {SIGNING_KEY_ENV} and {SIGNER_ENV}"
        ))
    };
    let path = std::env::var(SIGNING_KEY_ENV).map_err(|_| unavailable())?;
    let signer = std::env::var(SIGNER_ENV).map_err(|_| unavailable())?;
    let (identity, key_id) = signer
        .split_once('/')
        .filter(|(identity, key_id)| !identity.is_empty() && !key_id.is_empty())
        .ok_or_else(unavailable)?;
    let seed = std::fs::read_to_string(&path)
        .map_err(|_| Status::failed_precondition("definition package signing key is unreadable"))
        .and_then(|value| {
            decode_key("definition package signing key", &value)
                .map_err(Status::failed_precondition)
        })?;
    Ok(PackageSigner {
        identity: identity.into(),
        key_id: key_id.into(),
        key: SigningKey::from_bytes(&seed),
    })
}

/// Parses the trusted package keys file: a JSON array of
/// `{"identity", "key_id", "public_key"}` with hex Ed25519 public keys.
pub(super) fn package_keyring_from_json(json: &str) -> Result<TrustedKeyring, String> {
    let entries: Vec<TrustedPackageKey> = serde_json::from_str(json)
        .map_err(|error| format!("trusted definition package keys are invalid: {error}"))?;
    let mut keyring = TrustedKeyring::new();
    for entry in entries {
        let key = VerifyingKey::from_bytes(&decode_key("trusted public key", &entry.public_key)?)
            .map_err(|error| format!("trusted public key is invalid: {error}"))?;
        keyring.trust(entry.identity, entry.key_id, key)?;
    }
    Ok(keyring)
}

fn package_keyring_from_env() -> Result<TrustedKeyring, Status> {
    let path = std::env::var(TRUSTED_KEYS_ENV).map_err(|_| {
        Status::failed_precondition(format!(
            "{}: definition package import requires {TRUSTED_KEYS_ENV}",
            package_domain::REFUSAL_UNVERIFIED
        ))
    })?;
    let json = std::fs::read_to_string(path).map_err(|_| {
        Status::failed_precondition("trusted definition package keys are unreadable")
    })?;
    package_keyring_from_json(&json).map_err(Status::failed_precondition)
}

pub(super) async fn export_definition_package(
    service: &SekaiServiceImpl,
    req: Request<ExportDefinitionPackageRequest>,
) -> Result<Response<ExportDefinitionPackageResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let signer = package_signer_from_env()?;
    export_definition_package_as(service, req, &signer)
}

/// Export with an explicit signer.
pub(super) fn export_definition_package_as(
    service: &SekaiServiceImpl,
    req: Request<ExportDefinitionPackageRequest>,
    signer: &PackageSigner,
) -> Result<Response<ExportDefinitionPackageResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    let revision_digest = if input.revision_digest.is_empty() {
        service
            .db
            .runtime()
            .get_published_definition_revision(&input.namespace)
            .map_err(|_| Status::internal("definition revision unavailable"))?
            .ok_or_else(|| Status::not_found("definition revision unavailable"))?
            .revision_digest
    } else {
        definition_branch_domain::validate_digest("revision_digest", &input.revision_digest)
            .map_err(Status::invalid_argument)?;
        input.revision_digest
    };
    // Read access to the revision covers every member, as for GetDefinitionMember.
    authorize_definition_revision(
        service,
        &principals,
        &input.namespace,
        &revision_digest,
        false,
    )?;
    let revision = service
        .db
        .runtime()
        .get_definition_revision(&input.namespace, &revision_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?
        .filter(|revision| revision.published)
        .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
    let members = service
        .db
        .runtime()
        .get_definition_members(&input.namespace, &revision.revision_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    let package = package_domain::build_package(
        members
            .into_iter()
            .map(|member| (member.member_kind, member.member_id, member.definition_json)),
    )
    .map_err(Status::internal)?;
    let envelope = package_domain::sign_package(
        package,
        PackageProvenance {
            source_namespace: input.namespace,
            source_revision_digest: revision.revision_digest,
            exported_at_ms: now_millis(),
        },
        &signer.identity,
        &signer.key_id,
        &signer.key,
    )
    .map_err(Status::internal)?;
    Ok(Response::new(ExportDefinitionPackageResponse {
        package_digest: envelope.package.package_digest.clone(),
        envelope_json: serde_json::to_string(&envelope)
            .map_err(|_| Status::internal("definition package could not be encoded"))?,
    }))
}

pub(super) async fn import_definition_package(
    service: &SekaiServiceImpl,
    req: Request<ImportDefinitionPackageRequest>,
) -> Result<Response<ImportDefinitionPackageResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let keyring = package_keyring_from_env()?;
    import_definition_package_with(service, req, &keyring)
}

/// Import against an explicit keyring.
pub(super) fn import_definition_package_with(
    service: &SekaiServiceImpl,
    req: Request<ImportDefinitionPackageRequest>,
    keyring: &TrustedKeyring,
) -> Result<Response<ImportDefinitionPackageResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    // Verification and every check precede the first write, the genesis seed.
    let envelope: PackageEnvelope = package_domain::verify_envelope(&input.envelope_json, keyring)
        .map_err(Status::failed_precondition)?;
    let members = envelope
        .package
        .members
        .iter()
        .map(|member| {
            definition_branch_domain::DefinitionMemberInput {
                member_kind: member.kind.clone(),
                member_id: member.id.clone(),
                definition_json: member.definition_json.clone(),
                member_digest: String::new(),
            }
            .prepare(&input.namespace)
            .map_err(|error| {
                Status::failed_precondition(format!(
                    "{REFUSAL_INCOMPATIBLE}: member {}/{}: {error}",
                    member.kind, member.id
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let existing = service
        .db
        .runtime()
        .get_published_definition_revision(&input.namespace)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    let needs_genesis = existing.is_none();
    let published = match existing {
        Some(published) => {
            authorize_definition_revision(
                service,
                &principals,
                &input.namespace,
                &published.revision_digest,
                true,
            )?;
            published
        }
        // Seeded only after every check below passes.
        None => super::rpc_definitions::definition_genesis(&input.namespace)
            .map_err(Status::invalid_argument)?,
    };
    // Write access is needed only where the import changes something:
    // added or changed members and members the package lacks.
    let published_digests = published
        .members
        .iter()
        .map(|member| {
            (
                (member.member_kind.clone(), member.member_id.clone()),
                member.member_digest.clone(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let package_keys = members
        .iter()
        .map(|member| (member.member_kind.clone(), member.member_id.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    let changed = members
        .iter()
        .filter(|member| {
            published_digests.get(&(member.member_kind.clone(), member.member_id.clone()))
                != Some(&member.member_digest)
        })
        .map(|member| (member.member_kind.clone(), member.member_id.clone()));
    let removed = published_digests
        .keys()
        .filter(|key| !package_keys.contains(*key))
        .cloned();
    for (member_kind, member_id) in changed.chain(removed).collect::<Vec<_>>() {
        authorize_definition_member_write(service, &principals, &member_kind, &member_id)?;
    }
    // The response shows the candidate, so the caller must be able to read
    // every incoming member before anything is written.
    for (member_kind, member_id) in &package_keys {
        authorize_definition_member_read(service, &principals, member_kind, member_id)?;
    }
    let request = definition_proposal_domain::ProposeDefinitionImport {
        namespace: input.namespace,
        branch_id: input.branch_id,
        proposal_id: input.proposal_id,
        source_package_digest: envelope.package.package_digest.clone(),
        members,
        expected_published_digest: published.revision_digest.clone(),
        idempotency_key: input.idempotency_key,
    };
    request.prepare().map_err(|error| {
        if error.starts_with(REFUSAL_INCOMPATIBLE) {
            Status::failed_precondition(error)
        } else {
            Status::invalid_argument(error)
        }
    })?;
    if needs_genesis {
        // A fresh namespace cannot hold a replay, so the import is checked
        // here, before the genesis seed. Otherwise the backend checks it after
        // its idempotent replay, inside the write transaction.
        package_domain::check_importable(&published, &[], &request.members)
            .map_err(map_definition_write_error)?;
    }
    if needs_genesis {
        // The empty genesis every namespace starts from; seeding is idempotent.
        super::rpc_definitions::seed_definition_genesis(service, &request.namespace)?;
    }
    let actor = principals
        .first()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let result = service
        .db
        .runtime()
        .propose_definition_import(&request, actor, now_millis())
        .map_err(map_definition_write_error)?;
    let definition_branch_domain::DefinitionWriteResult::CreateProposal { proposal } = result
    else {
        return Err(Status::internal("definition replay result is invalid"));
    };
    // A retry can replay a proposal made against an earlier head, so the
    // returned revisions are authorized again, as rollback does.
    authorize_definition_revision(
        service,
        &principals,
        &proposal.namespace,
        &proposal.base_digest,
        true,
    )?;
    authorize_definition_revision(
        service,
        &principals,
        &proposal.namespace,
        &proposal.candidate_digest,
        false,
    )?;
    authorize_proposal_member_writes(
        service,
        &principals,
        &proposal.namespace,
        &proposal.base_digest,
        &proposal.candidate_digest,
    )?;
    let runtime = service.db.runtime();
    let load = |digest: &str| {
        let revision = runtime
            .get_definition_revision(&proposal.namespace, digest)
            .map_err(|_| Status::internal("definition revision unavailable"))?
            .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
        let members = runtime
            .get_definition_members(&proposal.namespace, digest)
            .map_err(|_| Status::internal("definition revision unavailable"))?;
        Ok::<_, Status>((revision, members))
    };
    let (base, base_members) = load(&proposal.base_digest)?;
    let (candidate, candidate_members) = load(&proposal.candidate_digest)?;
    let preview = definition_diff_domain::compare_definition_revisions(
        &base,
        &base_members,
        &candidate,
        &candidate_members,
    )
    .map_err(map_definition_write_error)?;
    Ok(Response::new(ImportDefinitionPackageResponse {
        proposal: Some(to_proto_definition_proposal(&proposal)),
        preview: Some(to_proto_definition_revision_diff(&preview)),
        source_namespace: envelope.provenance.source_namespace,
        source_revision_digest: envelope.provenance.source_revision_digest,
        signer_identity: envelope.signature.identity,
    }))
}
