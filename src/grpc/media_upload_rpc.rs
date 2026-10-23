//! Governed media upload RPCs (#1623, ADR 0123).
//!
//! Only the uploader sees or continues its session, and every chunk and
//! the completion re-check that it may still write the namespace and create
//! the file's object there. The file becomes a reserved `media_attachment`
//! object, so generic object RPCs never touch it, and `ReadMedia` applies the
//! ordinary object read checks: namespace role, tenant and collaboration
//! scope, grants, marking and object security policy. A caller who fails
//! any of them gets `NOT_FOUND`.

use super::*;
use crate::sekai::media_upload::{
    self, MAX_CHUNK_BYTES, MEDIA_KIND, MediaError, MediaUpload, MediaUploadRequest,
};
use crate::sekai::object_security::ObjectSecurityOperation;
use crate::sekai::purpose_authorization::PurposePresentation;

struct Caller<'a> {
    service: &'a SekaiServiceImpl,
    principals: Vec<String>,
    policy_context: crate::sekai::object_security::PrincipalPolicyContext,
    tenant_context: Option<RequestEnterpriseContext>,
    purpose: Option<PurposePresentation>,
}

fn media_status(error: MediaError) -> Status {
    match error {
        MediaError::Invalid(message) => Status::invalid_argument(message),
        MediaError::NotFound => Status::not_found("media upload not found"),
        MediaError::Conflict => Status::already_exists(
            "the idempotency key is in use for a different file; use a new key",
        ),
        MediaError::Offset(received) => {
            Status::failed_precondition(format!("the upload continues at offset {received}"))
        }
        MediaError::Completed => Status::failed_precondition("the upload is already complete"),
        MediaError::Changed => {
            Status::failed_precondition("the upload changed; check its status and complete again")
        }
        MediaError::Storage(message) => Status::internal(message),
    }
}

fn upload_status(upload: &MediaUpload) -> MediaUploadStatus {
    MediaUploadStatus {
        upload_id: upload.upload_id.clone(),
        size_bytes: upload.request.size_bytes,
        received_bytes: upload.received_bytes,
        complete: upload.object_id.is_some(),
        media_reference: upload.reference().unwrap_or_default(),
    }
}

/// The object a completed upload becomes.
fn media_object(upload: &MediaUpload) -> domain::Object {
    let request = &upload.request;
    let mut properties = HashMap::from([
        (
            media_upload::PROPERTY_UPLOAD_ID.to_string(),
            upload.upload_id.clone(),
        ),
        (media_upload::PROPERTY_SHA256.into(), request.sha256.clone()),
        (
            media_upload::PROPERTY_SIZE_BYTES.into(),
            request.size_bytes.to_string(),
        ),
        (
            media_upload::PROPERTY_MEDIA_TYPE.into(),
            request.media_type.clone(),
        ),
        (
            media_upload::PROPERTY_FILE_NAME.into(),
            request.file_name.clone(),
        ),
    ]);
    if !request.access_marking.is_empty() {
        properties.insert(
            markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            request.access_marking.clone(),
        );
    }
    domain::Object {
        id: request.object_id(),
        kind: MEDIA_KIND.into(),
        name: if request.file_name.is_empty() {
            upload.upload_id.clone()
        } else {
            request.file_name.clone()
        },
        namespace: request.namespace.clone(),
        external_id: String::new(),
        properties,
        created: upload.created_at_ms,
        updated: upload.created_at_ms,
    }
}

impl<'a> Caller<'a> {
    fn new<T: 'static>(service: &'a SekaiServiceImpl, req: &Request<T>) -> Result<Self, Status> {
        let principals = caller_principals(req);
        require_authenticated(&principals)?;
        Ok(Self {
            service,
            policy_context: principal_policy_context(req),
            tenant_context: request_tenant_context(service.db.runtime(), req)?,
            purpose: request_purpose_presentation(req, &principals),
            principals,
        })
    }

    fn db(&self) -> &RuntimeDb {
        self.service.db.runtime()
    }

    fn actor(&self) -> String {
        self.principals.first().cloned().unwrap_or_default()
    }

    /// The caller may write the namespace, no freeze stops it, and it could
    /// create `object` there and still read it under its marking.
    fn authorize_write(&self, object: &domain::Object) -> Result<(), Status> {
        let db = self.db();
        let tenant = self.tenant_context.as_ref();
        enforce_collaboration_namespace(db, tenant, &object.namespace, true)?;
        check_team_namespace(db, &self.principals, &object.namespace, true)?;
        refuse_frozen_object_write(
            db,
            &object.namespace,
            &self.principals,
            tenant,
            crate::enterprise::NamespaceAction::Write,
        )?;
        let lattice = load_classification_lattice(db, &object.namespace)?;
        crate::sekai::classification_lattice::validate_written_marking_token(
            markings::object_marking_token(object),
            lattice.as_ref(),
        )
        .map_err(Status::invalid_argument)?;
        if !collaboration_object_permitted(
            db,
            tenant,
            object,
            crate::enterprise::NamespaceAction::Write,
        )? || !object_passes_marking(db, object, &self.principals)?
        {
            return Err(Status::permission_denied("access denied"));
        }
        // Property and value-instance write grants apply as on any create.
        // The properties are the upload's own, so any it could not keep is a
        // refusal rather than a silent drop.
        let mut granted = object.clone();
        enforce_property_grant_mutation(db, None, &mut granted)?;
        if granted.properties != object.properties {
            return Err(Status::permission_denied("access denied"));
        }
        check_object_acl_with_audit(
            db,
            &self.service.security,
            &object.id,
            &self.principals,
            tenant,
            ObjectSecurityOperation::Create,
        )?;
        enforce_object_operation_access(
            db,
            object,
            &self.principals,
            tenant,
            ObjectSecurityOperation::Create,
            "media_upload",
            self.purpose.as_ref(),
        )?;
        Ok(())
    }

    /// The caller may still read the session's namespace.
    fn authorize_session_read(&self, upload: &MediaUpload) -> Result<(), Status> {
        let namespace = &upload.request.namespace;
        enforce_collaboration_namespace(self.db(), self.tenant_context.as_ref(), namespace, false)?;
        check_team_namespace(self.db(), &self.principals, namespace, false)
    }

    /// The caller's own session. Another uploader's session is `NOT_FOUND`.
    fn own_upload(&self, upload_id: &str) -> Result<MediaUpload, Status> {
        self.db()
            .get_media_upload(upload_id)
            .map_err(media_status)?
            .filter(|upload| upload.request.uploader == self.actor())
            .ok_or_else(|| media_status(MediaError::NotFound))
    }

    /// Whether the caller may read a stored media object: the object read
    /// checks, without the reserved-kind exclusion that hides it from
    /// generic object RPCs.
    fn may_read(&self, object: &domain::Object) -> bool {
        let db = self.db();
        let tenant = self.tenant_context.as_ref();
        check_team_namespace(db, &self.principals, &object.namespace, false).is_ok()
            && enforce_collaboration_namespace(db, tenant, &object.namespace, false).is_ok()
            && collaboration_object_permitted(
                db,
                tenant,
                object,
                crate::enterprise::NamespaceAction::Read,
            )
            .unwrap_or(false)
            && check_read(&self.service.security, &object.id, &self.principals).is_ok()
            && object_passes_marking(db, object, &self.principals).unwrap_or(false)
            // The full policy decision: the generic visibility helpers skip
            // active object policies for reserved kinds.
            && enforce_object_operation_access(
                db,
                object,
                &self.principals,
                tenant,
                ObjectSecurityOperation::Read,
                "read_media",
                self.purpose.as_ref(),
            )
            .is_ok()
    }
}

// Every handler runs on the bounded database worker pool: sessions and
// chunks are database reads and writes, and completion hashes the file.
pub(super) async fn begin_media_upload(
    service: &SekaiServiceImpl,
    req: Request<BeginMediaUploadRequest>,
) -> Result<Response<MediaUploadStatus>, Status> {
    let owned = service.clone();
    service
        .spawn_db(move || begin_media_upload_blocking(&owned, req))
        .await
}

pub(super) async fn upload_media_chunk(
    service: &SekaiServiceImpl,
    req: Request<UploadMediaChunkRequest>,
) -> Result<Response<MediaUploadStatus>, Status> {
    let owned = service.clone();
    service
        .spawn_db(move || upload_media_chunk_blocking(&owned, req))
        .await
}

pub(super) async fn complete_media_upload(
    service: &SekaiServiceImpl,
    req: Request<CompleteMediaUploadRequest>,
) -> Result<Response<MediaUploadStatus>, Status> {
    let owned = service.clone();
    service
        .spawn_db(move || complete_media_upload_blocking(&owned, req))
        .await
}

pub(super) async fn get_media_upload(
    service: &SekaiServiceImpl,
    req: Request<GetMediaUploadRequest>,
) -> Result<Response<MediaUploadStatus>, Status> {
    let owned = service.clone();
    service
        .spawn_db(move || get_media_upload_blocking(&owned, req))
        .await
}

pub(super) async fn read_media(
    service: &SekaiServiceImpl,
    req: Request<ReadMediaRequest>,
) -> Result<Response<ReadMediaResponse>, Status> {
    let owned = service.clone();
    service
        .spawn_db(move || read_media_blocking(&owned, req))
        .await
}

fn begin_media_upload_blocking(
    service: &SekaiServiceImpl,
    req: Request<BeginMediaUploadRequest>,
) -> Result<Response<MediaUploadStatus>, Status> {
    let caller = Caller::new(service, &req)?;
    let input = req.into_inner();
    let request = MediaUploadRequest {
        namespace: input.namespace,
        uploader: caller.actor(),
        idempotency_key: input.idempotency_key,
        size_bytes: input.size_bytes,
        sha256: input.sha256,
        media_type: input.media_type,
        file_name: input.file_name,
        access_marking: input.access_marking.trim().to_string(),
    };
    request.validate().map_err(media_status)?;
    let now = now_millis();
    let pending = MediaUpload {
        upload_id: request.upload_id(),
        request,
        received_bytes: 0,
        attempt: 0,
        object_id: None,
        created_at_ms: now,
        updated_at_ms: now,
    };
    caller.authorize_write(&media_object(&pending))?;
    let upload = caller
        .db()
        .begin_media_upload(&pending.request, now)
        .map_err(media_status)?;
    Ok(Response::new(upload_status(&upload)))
}

fn upload_media_chunk_blocking(
    service: &SekaiServiceImpl,
    req: Request<UploadMediaChunkRequest>,
) -> Result<Response<MediaUploadStatus>, Status> {
    let caller = Caller::new(service, &req)?;
    let input = req.into_inner();
    if input.data.is_empty() || input.data.len() > MAX_CHUNK_BYTES {
        return Err(Status::invalid_argument(format!(
            "a chunk holds 1 to {MAX_CHUNK_BYTES} bytes"
        )));
    }
    let upload = caller.own_upload(&input.upload_id)?;
    caller.authorize_write(&media_object(&upload))?;
    let upload = caller
        .db()
        .append_media_chunk(&upload.upload_id, input.offset, &input.data, now_millis())
        .map_err(media_status)?;
    Ok(Response::new(upload_status(&upload)))
}

fn complete_media_upload_blocking(
    service: &SekaiServiceImpl,
    req: Request<CompleteMediaUploadRequest>,
) -> Result<Response<MediaUploadStatus>, Status> {
    let caller = Caller::new(service, &req)?;
    let upload = caller.own_upload(&req.get_ref().upload_id)?;
    if upload.object_id.is_some() {
        caller.authorize_session_read(&upload)?;
        return Ok(Response::new(upload_status(&upload)));
    }
    let db = caller.db();
    let object = media_object(&upload);
    // The create below must be fenced on the policy this authorization saw.
    let generation = object_security_generation(db, &object.namespace)?;
    caller.authorize_write(&object)?;
    let size = upload.request.size_bytes;
    if upload.received_bytes != size {
        return Err(Status::failed_precondition(format!(
            "the upload holds {} of {size} bytes",
            upload.received_bytes
        )));
    }
    let stored = media_upload::stored_sha256(size, |offset, len| {
        db.read_media_bytes(&upload.upload_id, offset, len)
    })
    .map_err(media_status)?;
    if stored != upload.request.sha256 {
        // Drop the bytes so the same upload can be sent again.
        db.reset_media_upload(&upload.upload_id, upload.attempt, now_millis())
            .map_err(media_status)?;
        return Err(Status::invalid_argument(format!(
            "checksum mismatch: the received file has sha256 {stored}, not {}; send it again from offset 0",
            upload.request.sha256
        )));
    }
    // A crash after the create leaves the object without a finished
    // session; completing again finds the object and finishes.
    let existing = db.get_object(&object.id).map_err(Status::internal)?;
    match existing {
        Some(stored) if stored.kind == MEDIA_KIND && stored.namespace == object.namespace => {}
        Some(_) => return Err(Status::internal("media object id is taken")),
        None => {
            if let Err(error) =
                db.create_object_with_authorized_policy(&object, &caller.actor(), Some(&generation))
            {
                // Another instance may have completed it at the same time.
                let raced = db
                    .get_object(&object.id)
                    .map_err(Status::internal)?
                    .is_some_and(|stored| stored.kind == MEDIA_KIND);
                if !raced {
                    return Err(if error.starts_with("object_security_denied") {
                        Status::permission_denied("access denied")
                    } else if error.contains("generation") {
                        Status::failed_precondition("object policy changed; complete again")
                    } else {
                        Status::internal(error)
                    });
                }
            }
        }
    }
    let upload = db
        .finish_media_upload(&upload.upload_id, &object.id, upload.attempt, now_millis())
        .map_err(media_status)?;
    Ok(Response::new(upload_status(&upload)))
}

fn get_media_upload_blocking(
    service: &SekaiServiceImpl,
    req: Request<GetMediaUploadRequest>,
) -> Result<Response<MediaUploadStatus>, Status> {
    let caller = Caller::new(service, &req)?;
    let upload = caller.own_upload(&req.get_ref().upload_id)?;
    caller.authorize_session_read(&upload)?;
    Ok(Response::new(upload_status(&upload)))
}

fn read_media_blocking(
    service: &SekaiServiceImpl,
    req: Request<ReadMediaRequest>,
) -> Result<Response<ReadMediaResponse>, Status> {
    let caller = Caller::new(service, &req)?;
    let input = req.into_inner();
    let hidden = || Status::not_found("media not found");
    let object_id = media_upload::parse_reference(&input.media_reference).map_err(media_status)?;
    let db = caller.db();
    let object = db
        .get_object(object_id)
        .map_err(Status::internal)?
        .filter(|object| object.kind == MEDIA_KIND)
        .ok_or_else(hidden)?;
    if !caller.may_read(&object) {
        return Err(hidden());
    }
    let upload_id = object
        .properties
        .get(media_upload::PROPERTY_UPLOAD_ID)
        .cloned()
        .ok_or_else(hidden)?;
    let upload = db
        .get_media_upload(&upload_id)
        .map_err(media_status)?
        .filter(|upload| upload.object_id.as_deref() == Some(object_id))
        .ok_or_else(hidden)?;
    // Metadata as a read of the object shows it: a property the caller may
    // not read comes back empty.
    let shown = service.resolve_computed_for_response_with_policy(
        object,
        &caller.principals,
        Some(&caller.policy_context),
        caller.tenant_context.as_ref(),
        caller.purpose.as_ref(),
    )?;
    let property = |name: &str| shown.properties.get(name).cloned().unwrap_or_default();
    let size = upload.request.size_bytes;
    if input.offset > size {
        return Err(Status::out_of_range(format!(
            "offset passes the file's {size} bytes"
        )));
    }
    let limit = match input.limit as usize {
        0 => MAX_CHUNK_BYTES,
        limit => limit.min(MAX_CHUNK_BYTES),
    };
    let len = limit.min((size - input.offset) as usize);
    let data = db
        .read_media_bytes(&upload_id, input.offset, len)
        .map_err(media_status)?;
    Ok(Response::new(ReadMediaResponse {
        data,
        size_bytes: property(media_upload::PROPERTY_SIZE_BYTES)
            .parse()
            .unwrap_or_default(),
        sha256: property(media_upload::PROPERTY_SHA256),
        media_type: property(media_upload::PROPERTY_MEDIA_TYPE),
        file_name: property(media_upload::PROPERTY_FILE_NAME),
        access_marking: property(markings::OBJECT_CLASSIFICATION_PROPERTY),
    }))
}
