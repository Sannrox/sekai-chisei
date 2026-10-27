//! Object comment RPCs (#1442).
//!
//! Visibility follows the target: a caller who cannot read the target object,
//! or the property a comment is anchored to, gets `NOT_FOUND` for the thread
//! and never sees the comment in a listing or a count. A body that quoted a
//! property hidden from the caller is redacted (see `object_comment`).

use super::*;
use crate::sekai::object_comment::{self, CommentError, ObjectComment as StoredComment};
use crate::sekai::object_security::ObjectSecurityOperation;
use crate::sekai::purpose_authorization::PurposePresentation;
use std::collections::HashMap;

/// The target as stored and as the caller would read it directly.
struct Target {
    full: domain::Object,
    visible: domain::Object,
}

impl Target {
    fn shows(&self, property: &str) -> bool {
        property.is_empty() || self.visible.properties.contains_key(property)
    }
}

struct Caller<'a> {
    service: &'a SekaiServiceImpl,
    principals: Vec<String>,
    policy_context: crate::sekai::object_security::PrincipalPolicyContext,
    tenant_context: Option<RequestEnterpriseContext>,
    purpose: Option<PurposePresentation>,
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

    fn actor(&self) -> String {
        self.principals.first().cloned().unwrap_or_default()
    }

    /// Comment writes need only read access to the target, but a write
    /// freeze on its namespace or on the caller still stops them.
    fn refuse_frozen(&self, target: &Target) -> Result<(), Status> {
        refuse_frozen_object_write(
            self.service.db.runtime(),
            &target.full.namespace,
            &self.principals,
            self.tenant_context.as_ref(),
            crate::enterprise::NamespaceAction::Write,
        )
    }

    /// The target if the caller can read it; `NOT_FOUND` otherwise, the same
    /// as a missing object.
    fn target(&self, object_id: &str) -> Result<Target, Status> {
        let db = self.service.db.runtime();
        let full = db
            .get_object(object_id)
            .map_err(Status::internal)?
            .filter(|object| {
                object_is_visible_for_purpose(
                    db,
                    &self.service.security,
                    object,
                    &self.principals,
                    self.tenant_context.as_ref(),
                    ObjectSecurityOperation::Read,
                    self.purpose.as_ref(),
                )
            })
            .ok_or_else(|| Status::not_found("not found"))?;
        // The same projection a direct read returns: policy property grants,
        // value instances and schema restricted properties.
        let visible = self
            .service
            .resolve_computed_for_response_with_policy(
                full.clone(),
                &self.principals,
                Some(&self.policy_context),
                self.tenant_context.as_ref(),
                self.purpose.as_ref(),
            )
            .map_err(|_| Status::not_found("not found"))?;
        Ok(Target { full, visible })
    }

    /// Every mentioned principal must be able to read the target and property,
    /// judged as that principal alone: the caller's authenticated context is
    /// the sender's, not theirs. Mentions are re-checked under the
    /// recipient's own context whenever they list them.
    fn check_mentions(
        &self,
        target: &Target,
        property: &str,
        mentions: &[String],
    ) -> Result<(), Status> {
        let db = self.service.db.runtime();
        // With the enterprise extension a recipient's access depends on their
        // own tenant context, which only their requests carry.
        if !mentions.is_empty() && db.enterprise_extension().is_some() {
            return Err(Status::failed_precondition(
                "mentions need the recipient's tenant context and are not available with the enterprise extension",
            ));
        }
        for mention in mentions {
            let alone = std::slice::from_ref(mention);
            let reads = object_is_visible_for(
                db,
                &self.service.security,
                &target.full,
                alone,
                None,
                ObjectSecurityOperation::Read,
            ) && (property.is_empty()
                || self
                    .service
                    .resolve_computed_for_response_with_policy(
                        target.full.clone(),
                        alone,
                        Some(&principal_policy_context_from(alone, None)),
                        None,
                        None,
                    )
                    .is_ok_and(|view| view.properties.contains_key(property)));
            if !reads {
                return Err(Status::invalid_argument(format!(
                    "mentioned principal {mention:?} cannot read this object"
                )));
            }
        }
        Ok(())
    }

    fn render(&self, comment: &StoredComment, target: &Target) -> Result<ObjectComment, Status> {
        let receipt_id = self
            .service
            .db
            .runtime()
            .list_object_changes(&comment.id, 1, 0)
            .map_err(Status::internal)?
            .into_iter()
            .next()
            .map(|change| change.id)
            .unwrap_or_default();
        Ok(ObjectComment {
            comment_id: comment.id.clone(),
            object_id: comment.target_object_id.clone(),
            property: comment.target_property.clone(),
            body: object_comment::body_for(comment, &self.actor(), &target.visible.properties),
            author: comment.author.clone(),
            mentions: comment.mentions.clone(),
            resolved: comment.resolved,
            resolved_by: comment.resolved_by.clone(),
            created_at_ms: comment.created_at_ms,
            updated_at_ms: comment.updated_at_ms,
            receipt_id,
        })
    }
}

fn comment_status(error: CommentError) -> Status {
    match error {
        CommentError::Invalid(message) => Status::invalid_argument(message),
        CommentError::Conflict => Status::failed_precondition("comment changed since it was read"),
        CommentError::Storage(message) => Status::internal(message),
    }
}

pub(super) async fn create_object_comment(
    service: &SekaiServiceImpl,
    req: Request<CreateObjectCommentRequest>,
) -> Result<Response<CreateObjectCommentResponse>, Status> {
    let caller = Caller::new(service, &req)?;
    let input = req.into_inner();
    object_comment::validate_target_property(&input.property).map_err(comment_status)?;
    let mentions =
        object_comment::validate_content(&input.body, &input.mentions).map_err(comment_status)?;
    let target = caller.target(&input.object_id)?;
    // Mentions are listed per namespace, so the target must have one.
    if target.full.namespace.is_empty() {
        return Err(Status::invalid_argument(
            "objects outside a namespace cannot take comments",
        ));
    }
    // A missing property and a hidden one answer alike.
    if !target.shows(&input.property) {
        return Err(Status::not_found("not found"));
    }
    caller.check_mentions(&target, &input.property, &mentions)?;
    caller.refuse_frozen(&target)?;
    let now = now_millis();
    let quoted_properties =
        object_comment::quoted_properties(&input.body, &target.visible.properties);
    let comment = StoredComment {
        id: format!("comment:{}", uuid::Uuid::new_v4().as_simple()),
        namespace: target.full.namespace.clone(),
        target_object_id: target.full.id.clone(),
        target_property: input.property,
        body: input.body,
        author: caller.actor(),
        quoted_properties,
        mentions,
        resolved: false,
        resolved_by: String::new(),
        created_at_ms: now,
        updated_at_ms: now,
    };
    object_comment::create(service.db.runtime(), &comment).map_err(comment_status)?;
    Ok(Response::new(CreateObjectCommentResponse {
        comment: Some(caller.render(&comment, &target)?),
    }))
}

pub(super) async fn update_object_comment(
    service: &SekaiServiceImpl,
    req: Request<UpdateObjectCommentRequest>,
) -> Result<Response<UpdateObjectCommentResponse>, Status> {
    let caller = Caller::new(service, &req)?;
    let input = req.into_inner();
    let db = service.db.runtime();
    let previous = object_comment::get(db, &input.comment_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("not found"))?;
    let target = caller.target(&previous.target_object_id)?;
    if !target.shows(&previous.target_property) {
        return Err(Status::not_found("not found"));
    }
    if input.expected_updated_at_ms != previous.updated_at_ms {
        return Err(comment_status(CommentError::Conflict));
    }
    let actor = caller.actor();
    let mut next = previous.clone();
    if let Some(body) = input.body {
        if previous.author != actor {
            return Err(Status::permission_denied("only the author edits a comment"));
        }
        next.mentions =
            object_comment::validate_content(&body, &input.mentions).map_err(comment_status)?;
        caller.check_mentions(&target, &previous.target_property, &next.mentions)?;
        // Quotes recorded earlier stay: the old value may still be in the text.
        let mut quoted = previous.quoted_properties.clone();
        quoted.extend(object_comment::quoted_properties(
            &body,
            &target.visible.properties,
        ));
        quoted.sort();
        quoted.dedup();
        next.quoted_properties = quoted;
        next.body = body;
    } else if !input.mentions.is_empty() {
        return Err(Status::invalid_argument(
            "mentions change only with the body",
        ));
    }
    if let Some(resolved) = input.resolved {
        next.resolved = resolved;
        next.resolved_by = if resolved {
            actor.clone()
        } else {
            String::new()
        };
    }
    if next == previous {
        return Err(Status::invalid_argument("nothing to change"));
    }
    caller.refuse_frozen(&target)?;
    // Strictly increasing, so the timestamp is also the next write's precondition.
    next.updated_at_ms = now_millis().max(previous.updated_at_ms + 1);
    object_comment::update(db, &previous, &next, &actor).map_err(comment_status)?;
    Ok(Response::new(UpdateObjectCommentResponse {
        comment: Some(caller.render(&next, &target)?),
    }))
}

pub(super) async fn list_object_comments(
    service: &SekaiServiceImpl,
    req: Request<ListObjectCommentsRequest>,
) -> Result<Response<ListObjectCommentsResponse>, Status> {
    let caller = Caller::new(service, &req)?;
    let input = req.into_inner();
    let target = caller.target(&input.object_id)?;
    let visible: Vec<StoredComment> = object_comment::list_for_target(
        service.db.runtime(),
        &target.full.namespace,
        &target.full.id,
    )
    .map_err(Status::failed_precondition)?
    .into_iter()
    .filter(|comment| target.shows(&comment.target_property))
    .collect();
    let total = visible.len() as i32;
    let comments = visible
        .iter()
        .filter(|comment| input.include_resolved || !comment.resolved)
        .map(|comment| caller.render(comment, &target))
        .collect::<Result<_, _>>()?;
    Ok(Response::new(ListObjectCommentsResponse {
        comments,
        total,
    }))
}

pub(super) async fn list_comment_mentions(
    service: &SekaiServiceImpl,
    req: Request<ListCommentMentionsRequest>,
) -> Result<Response<ListCommentMentionsResponse>, Status> {
    let caller = Caller::new(service, &req)?;
    let namespace = req.into_inner().namespace;
    authorize_source_sync_namespace(
        service,
        &caller.principals,
        caller.tenant_context.as_ref(),
        &namespace,
        false,
    )?;
    let mentioning =
        object_comment::list_mentioning(service.db.runtime(), &namespace, &caller.actor())
            .map_err(Status::failed_precondition)?;
    let mut targets: HashMap<String, Option<Target>> = HashMap::new();
    let mut comments = Vec::new();
    for comment in &mentioning {
        let target = targets
            .entry(comment.target_object_id.clone())
            .or_insert_with(|| caller.target(&comment.target_object_id).ok());
        if let Some(target) = target
            && target.shows(&comment.target_property)
        {
            comments.push(caller.render(comment, target)?);
        }
    }
    Ok(Response::new(ListCommentMentionsResponse { comments }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::runtime_db::RuntimeDb;
    use crate::db::sekai::SekaiDb;
    use std::sync::Arc;
    use tonic::metadata::MetadataValue;

    fn service() -> SekaiServiceImpl {
        SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
            RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap())),
        )))
    }

    fn as_principal<T>(payload: T, principal: &str) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    fn grant(svc: &SekaiServiceImpl, object_id: &str, principal: &str) -> security::Grant {
        let grant = security::Grant {
            id: format!("grant-{object_id}-{principal}"),
            object_id: object_id.into(),
            principal: principal.into(),
            role: security::Role::Viewer,
            created: 0,
            ..Default::default()
        };
        svc.db.runtime().create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
        grant
    }

    /// `doc` is readable by alice and bob only; carol has no access.
    fn fixture() -> SekaiServiceImpl {
        let svc = service();
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: "doc".into(),
                kind: "document".into(),
                name: "doc".into(),
                namespace: "acme".into(),
                external_id: "acme:doc".into(),
                properties: HashMap::from([("title".into(), "Q3 plan".into())]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        grant(&svc, "doc", "alice");
        grant(&svc, "doc", "bob");
        svc
    }

    async fn comment(
        svc: &SekaiServiceImpl,
        author: &str,
        mentions: &[&str],
    ) -> Result<ObjectComment, Status> {
        create_object_comment(
            svc,
            as_principal(
                CreateObjectCommentRequest {
                    object_id: "doc".into(),
                    property: String::new(),
                    body: "numbers look off".into(),
                    mentions: mentions.iter().map(|m| m.to_string()).collect(),
                },
                author,
            ),
        )
        .await
        .map(|response| response.into_inner().comment.unwrap())
    }

    async fn thread(
        svc: &SekaiServiceImpl,
        principal: &str,
    ) -> Result<ListObjectCommentsResponse, Status> {
        list_object_comments(
            svc,
            as_principal(
                ListObjectCommentsRequest {
                    object_id: "doc".into(),
                    include_resolved: true,
                },
                principal,
            ),
        )
        .await
        .map(Response::into_inner)
    }

    async fn mentions(svc: &SekaiServiceImpl, principal: &str) -> Vec<String> {
        list_comment_mentions(
            svc,
            as_principal(
                ListCommentMentionsRequest {
                    namespace: "acme".into(),
                },
                principal,
            ),
        )
        .await
        .unwrap()
        .into_inner()
        .comments
        .into_iter()
        .map(|c| c.comment_id)
        .collect()
    }

    #[tokio::test]
    async fn comments_follow_object_read_access() {
        let svc = fixture();
        let rejected = comment(&svc, "alice", &["carol"]).await.unwrap_err();
        assert_eq!(rejected.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            comment(&svc, "carol", &[]).await.unwrap_err().code(),
            tonic::Code::NotFound
        );

        let created = comment(&svc, "alice", &["bob"]).await.unwrap();
        assert_eq!(created.author, "alice");
        assert!(created.created_at_ms > 0);
        assert!(
            !created.receipt_id.is_empty(),
            "the change log is the receipt"
        );
        assert_eq!(created.mentions, ["bob"]);

        let seen = thread(&svc, "bob").await.unwrap();
        assert_eq!(seen.total, 1);
        assert_eq!(seen.comments[0].comment_id, created.comment_id);
        assert_eq!(
            mentions(&svc, "bob").await,
            std::slice::from_ref(&created.comment_id)
        );

        // Carol gets neither the thread, its count, nor a mention.
        assert_eq!(
            thread(&svc, "carol").await.unwrap_err().code(),
            tonic::Code::NotFound
        );
        assert!(mentions(&svc, "carol").await.is_empty());
        // Generic reads never return the comment object or its raw history.
        let generic = svc
            .get_object(as_principal(
                GetObjectRequest {
                    id: created.comment_id.clone(),
                },
                "alice",
            ))
            .await;
        assert!(generic.is_err());
        let history = svc
            .list_object_changes(as_principal(
                ListObjectChangesRequest {
                    object_id: created.comment_id.clone(),
                    ..Default::default()
                },
                "carol",
            ))
            .await
            .unwrap_err();
        assert_eq!(history.code(), tonic::Code::NotFound);

        // Losing access to the object loses its comments and mentions.
        svc.db.runtime().delete_grant("grant-doc-bob").unwrap();
        svc.security.remove_grant("doc", "bob");
        assert_eq!(
            thread(&svc, "bob").await.unwrap_err().code(),
            tonic::Code::NotFound
        );
        assert!(mentions(&svc, "bob").await.is_empty());
    }

    #[tokio::test]
    async fn only_the_author_edits_and_stale_writes_fail() {
        let svc = fixture();
        let created = comment(&svc, "alice", &[]).await.unwrap();
        let update = |principal: &str, body: Option<&str>, resolved: Option<bool>, expected| {
            update_object_comment(
                &svc,
                as_principal(
                    UpdateObjectCommentRequest {
                        comment_id: created.comment_id.clone(),
                        body: body.map(Into::into),
                        mentions: Vec::new(),
                        resolved,
                        expected_updated_at_ms: expected,
                    },
                    principal,
                ),
            )
        };
        let not_author = update("bob", Some("edited"), None, created.updated_at_ms)
            .await
            .unwrap_err();
        assert_eq!(not_author.code(), tonic::Code::PermissionDenied);

        let resolved = update("bob", None, Some(true), created.updated_at_ms)
            .await
            .unwrap()
            .into_inner()
            .comment
            .unwrap();
        assert!(resolved.resolved);
        assert_eq!(resolved.resolved_by, "bob");
        assert_ne!(resolved.receipt_id, created.receipt_id);

        let stale = update("alice", Some("edited"), None, created.updated_at_ms)
            .await
            .unwrap_err();
        assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
        let edited = update("alice", Some("edited"), None, resolved.updated_at_ms)
            .await
            .unwrap()
            .into_inner()
            .comment
            .unwrap();
        assert_eq!(edited.body, "edited");

        let history = svc
            .db
            .runtime()
            .list_object_changes(&created.comment_id, 10, 0)
            .unwrap();
        assert!(history.iter().any(|c| c.field == "properties.body"
            && c.old_value == "numbers look off"
            && c.changed_by == "alice"));
        let open = list_object_comments(
            &svc,
            as_principal(
                ListObjectCommentsRequest {
                    object_id: "doc".into(),
                    include_resolved: false,
                },
                "alice",
            ),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(open.comments.is_empty());
        assert_eq!(open.total, 1);
    }

    #[tokio::test]
    async fn a_write_freeze_stops_comment_writes() {
        let svc = fixture();
        svc.db
            .runtime()
            .set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
                scope_kind: crate::sekai::write_freeze::SCOPE_NAMESPACE.into(),
                scope_value: "acme".into(),
                mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
                reason: "maintenance".into(),
                enabled: true,
                updated_ms: 1,
            })
            .unwrap();
        let frozen = comment(&svc, "alice", &[]).await.unwrap_err();
        assert_eq!(frozen.code(), tonic::Code::FailedPrecondition, "{frozen:?}");
    }
}
