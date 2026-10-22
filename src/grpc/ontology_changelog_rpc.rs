//! GetOntologyChangelog: what changed in the namespaces a reader can see (#1471).
//!
//! The reader is the caller, or a team or principal a credential admin names
//! to build that reader's digest. Every namespace, revision member and
//! consumer binding is authorized as the reader, so a reader without access
//! to a namespace gets no entry for it.

use super::*;
use crate::sekai::definition_consumer_impact::{
    BINDING_KIND, COMPLETENESS_UNAVAILABLE, MAX_VISIBLE_BINDINGS, report_consumer_impact,
};
use crate::sekai::ontology_changelog::{
    CHANGE_DEFINITION_REVISION, CHANGE_POLICY_ACTIVATION, MAX_CHANGELOG_NAMESPACES,
    MAX_CHANGELOG_REVISIONS, MAX_CHANGELOG_SCAN, summarize, validate_window, visible_changes,
};

struct Reader<'a> {
    service: &'a SekaiServiceImpl,
    principals: Vec<String>,
    /// The caller's own authenticated context, policy context and purpose;
    /// for another reader's digest, only what that principal alone has.
    tenant_context: Option<RequestEnterpriseContext>,
    policy_context: crate::sekai::object_security::PrincipalPolicyContext,
    purpose: Option<crate::sekai::purpose_authorization::PurposePresentation>,
}

impl Reader<'_> {
    fn can_read_namespace(&self, namespace: &str) -> bool {
        authorize_source_sync_namespace(
            self.service,
            &self.principals,
            self.tenant_context.as_ref(),
            namespace,
            false,
        )
        .is_ok()
    }

    /// Consumer bindings in `namespace` the reader can see.
    fn visible_bindings(&self, namespace: &str) -> Result<Vec<domain::Object>, Status> {
        let filter = domain::ListFilter {
            kind: Some(BINDING_KIND.into()),
            namespace: Some(namespace.into()),
            limit: (MAX_VISIBLE_BINDINGS as i32).saturating_add(1),
            order_by: "name".into(),
            ..domain::ListFilter::default()
        };
        list_objects_with_marking(
            self.service.db.runtime(),
            &filter,
            &self.principals,
            &self.policy_context,
            self.purpose.as_ref(),
            self.tenant_context.as_ref(),
            |objects, _, _| Ok(objects),
        )
        .map(|(objects, _)| objects)
    }

    fn revision_entry(
        &self,
        namespace: &str,
        history: &definition_proposal_domain::PublishedDefinitionRevisionHistoryEntry,
        bindings: Option<&[domain::Object]>,
    ) -> Result<Option<OntologyChangelogEntry>, Status> {
        let db = self.service.db.runtime();
        let proposal = db
            .get_definition_proposal(namespace, &history.proposal_id)
            .map_err(|_| Status::internal("definition proposal unavailable"))?;
        let mut entry = OntologyChangelogEntry {
            namespace: namespace.into(),
            change_kind: CHANGE_DEFINITION_REVISION.into(),
            revision_digest: history.revision_digest.clone(),
            previous_revision_digest: history.previous_published_digest.clone(),
            author: proposal
                .as_ref()
                .map(|p| p.created_by.clone())
                .unwrap_or_default(),
            approvers: proposal
                .as_ref()
                .map(|p| p.approvals.iter().map(|a| a.actor.clone()).collect())
                .unwrap_or_default(),
            published_by: history.actor.clone(),
            changed_at_ms: history.published_at_ms,
            receipt_id: history.receipt_id.clone(),
            ..OntologyChangelogEntry::default()
        };
        if history.previous_published_digest.is_empty() {
            entry.summary = vec!["first published revision".into()];
            entry.compatibility = "compatible".into();
            return Ok(Some(entry));
        }
        let revision = |digest: &str| {
            let revision = db
                .get_definition_revision(namespace, digest)
                .map_err(|_| Status::internal("definition revision unavailable"))?
                .ok_or_else(|| Status::not_found("definition revision unavailable"))?;
            let members = db
                .get_definition_members(namespace, &revision.revision_digest)
                .map_err(|_| Status::internal("definition revision unavailable"))?;
            Ok::<_, Status>((revision, members))
        };
        let (from, from_members) = revision(&history.previous_published_digest)?;
        let (to, to_members) = revision(&history.revision_digest)?;
        let compatibility = definition_diff_domain::classify_definition_revision_compatibility(
            &from,
            &from_members,
            &to,
            &to_members,
        )
        .map_err(map_definition_write_error)?;
        // The diff names members and properties only, never bodies; members
        // the reader may not read are dropped, and a revision with no visible
        // change leaves no entry.
        let (diff, class) = visible_changes(&compatibility, |kind, id| {
            authorize_definition_member_read(self.service, &self.principals, kind, id).is_ok()
        });
        entry.summary = summarize(&diff);
        if entry.summary.is_empty() {
            return Ok(None);
        }
        entry.compatibility = class;
        match bindings {
            Some(bindings) => {
                let report = report_consumer_impact(&diff, bindings);
                entry.impact_completeness = report.completeness;
                entry.affected_consumers = report
                    .impacts
                    .into_iter()
                    .map(|impact| DefinitionConsumerImpactPath {
                        owner: impact.owner,
                        resource_identity: impact.resource_identity,
                        member_kind: impact.member_kind,
                        member_id: impact.member_id,
                        property: impact.property,
                        source_locator: impact.source_locator,
                    })
                    .collect();
            }
            None => entry.impact_completeness = COMPLETENESS_UNAVAILABLE.into(),
        }
        Ok(Some(entry))
    }

    fn namespace_entries(
        &self,
        namespace: &str,
        since_ms: i64,
        until_ms: i64,
    ) -> Result<Vec<OntologyChangelogEntry>, Status> {
        let db = self.service.db.runtime();
        let bindings = self.visible_bindings(namespace).ok();
        let mut entries = Vec::new();
        let mut page_token = String::new();
        let (mut scanned, mut in_window) = (0usize, 0usize);
        // History is newest first; stop at the first revision before the window.
        'pages: loop {
            let (page, next) = db
                .list_published_definition_revisions(namespace, "", "", &page_token, 100)
                .map_err(|_| Status::internal("definition revision unavailable"))?;
            for history in &page {
                scanned += 1;
                if scanned > MAX_CHANGELOG_SCAN {
                    return Err(Status::resource_exhausted(
                        "too much definition history before the window",
                    ));
                }
                if history.published_at_ms < since_ms {
                    break 'pages;
                }
                if history.published_at_ms >= until_ms {
                    continue;
                }
                in_window += 1;
                if in_window > MAX_CHANGELOG_REVISIONS {
                    return Err(Status::resource_exhausted(
                        "too many definition revisions in the window",
                    ));
                }
                if let Some(entry) = self.revision_entry(namespace, history, bindings.as_deref())? {
                    entries.push(entry);
                }
            }
            if next.is_empty() {
                break;
            }
            page_token = next;
        }
        if let Some(activation) = db
            .get_object_security_activation(namespace)
            .map_err(map_object_security_error)?
            .filter(|a| a.activated_at_ms >= since_ms && a.activated_at_ms < until_ms)
        {
            // Only kinds whose object type the reader may read are named.
            let summary: Vec<String> = activation
                .policies
                .iter()
                .filter(|(kind, _)| {
                    authorize_definition_member_read(
                        self.service,
                        &self.principals,
                        "object_type",
                        kind,
                    )
                    .is_ok()
                })
                .map(|(kind, digest)| format!("object security policy for {kind} is {digest}"))
                .collect();
            if !summary.is_empty() {
                entries.push(OntologyChangelogEntry {
                    namespace: namespace.into(),
                    change_kind: CHANGE_POLICY_ACTIVATION.into(),
                    revision_digest: activation.activation_id.clone(),
                    summary,
                    published_by: activation.activated_by.clone(),
                    changed_at_ms: activation.activated_at_ms,
                    ..OntologyChangelogEntry::default()
                });
            }
        }
        Ok(entries)
    }
}

pub(super) async fn get_ontology_changelog(
    service: &SekaiServiceImpl,
    req: Request<GetOntologyChangelogRequest>,
) -> Result<Response<GetOntologyChangelogResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let policy_context = principal_policy_context(&req);
    let purpose = request_purpose_presentation(&req, &principals);
    let input = req.into_inner();
    validate_window(input.since_ms, input.until_ms).map_err(Status::invalid_argument)?;
    let caller = principals.first().cloned().unwrap_or_default();
    let reader = if input.reader.trim().is_empty() || input.reader == caller {
        Reader {
            service,
            principals: principals.clone(),
            tenant_context,
            policy_context,
            purpose,
        }
    } else {
        // Building someone else's digest is an admin act; it is authorized as
        // that reader alone, never with the admin's own access. With the
        // enterprise extension the reader's access depends on their own
        // tenant context, which only their requests carry.
        require_credential_admin(&principals)?;
        if service.db.runtime().enterprise_extension().is_some() {
            return Err(Status::failed_precondition(
                "a digest for another reader needs that reader's tenant context and is not available with the enterprise extension",
            ));
        }
        let principals = vec![input.reader.trim().to_string()];
        Reader {
            service,
            policy_context: principal_policy_context_from(&principals, None),
            principals,
            tenant_context: None,
            purpose: None,
        }
    };
    let mut namespaces: Vec<String> = if input.namespaces.is_empty() {
        let mut held = Vec::new();
        for principal in &reader.principals {
            held.extend(
                service
                    .db
                    .runtime()
                    .list_namespace_roles_for_principal(principal)
                    .map_err(Status::internal)?
                    .into_iter()
                    .map(|(namespace, _)| namespace),
            );
        }
        held
    } else {
        input.namespaces
    };
    namespaces.sort();
    namespaces.dedup();
    if namespaces.len() > MAX_CHANGELOG_NAMESPACES {
        return Err(Status::invalid_argument(format!(
            "a changelog covers at most {MAX_CHANGELOG_NAMESPACES} namespaces"
        )));
    }
    let mut entries = Vec::new();
    for namespace in &namespaces {
        if reader.can_read_namespace(namespace) {
            entries.extend(reader.namespace_entries(namespace, input.since_ms, input.until_ms)?);
        }
    }
    entries.sort_by(|left, right| {
        (left.changed_at_ms, &left.namespace, &left.revision_digest).cmp(&(
            right.changed_at_ms,
            &right.namespace,
            &right.revision_digest,
        ))
    });
    Ok(Response::new(GetOntologyChangelogResponse {
        reader: reader.principals.join(","),
        since_ms: input.since_ms,
        until_ms: input.until_ms,
        entries,
    }))
}
