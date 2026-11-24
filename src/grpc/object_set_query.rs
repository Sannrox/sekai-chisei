//! Authorized EvaluateObjectSet over existing list and one-hop traverse.

use super::*;
use crate::chisei::receipt::{
    GovernedReference, OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent,
    ReceiptEventKind,
};
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::object_set::{
    BoundObjectSet, ObjectSetDescriptor as DomainObjectSetDescriptor, ObjectSetError,
    ObjectSetQueryRecord, ObjectSetTraversal as DomainObjectSetTraversal,
};
use std::collections::BTreeMap;

const INDEX_SCAN_BATCH_SIZE: i32 = 256;

struct ObjectSetAuthority<'a> {
    principals: &'a [String],
    tenant_context: Option<&'a RequestEnterpriseContext>,
    purpose: Option<&'a crate::sekai::purpose_authorization::PurposePresentation>,
}

struct QueryAttribution {
    operation_id: Option<String>,
    actor: String,
    type_denied: bool,
}

impl SekaiServiceImpl {
    pub(super) async fn evaluate_visible_object_set(
        &self,
        req: Request<EvaluateObjectSetRequest>,
    ) -> Result<Response<EvaluateObjectSetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let policy_context = principal_policy_context(&req);
        let purpose = request_purpose_presentation(&req, &principals);
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let authority = ObjectSetAuthority {
            principals: &principals,
            tenant_context: tenant_context.as_ref(),
            purpose: purpose.as_ref(),
        };
        let operation_id = Self::catalog_metadata_value(&req, "x-sekai-operation-id");
        let actor = principals.first().cloned().unwrap_or_default();
        let inner = req.into_inner();
        let bound =
            self.authorize_object_set_read(&principals, tenant_context.as_ref(), inner.descriptor)?;
        let type_denied = object_set_type_denied(
            self.db.runtime(),
            &bound.descriptor.namespace,
            &bound.descriptor.kind,
        )?;
        let attribution = QueryAttribution {
            operation_id,
            actor,
            type_denied,
        };
        if attribution.type_denied {
            return self.object_set_page(
                &bound,
                Vec::new(),
                0,
                String::new(),
                Vec::new(),
                crate::sekai::object_set::EVALUATE_SOURCE_UNKNOWN.into(),
                &attribution,
            );
        }
        let principal_context_digest =
            crate::sekai::purpose_authorization::purpose_bound_context_digest(
                &policy_context
                    .digest()
                    .map_err(|_| Status::permission_denied("access denied"))?,
                purpose.as_ref().map(|presented| presented.purpose.as_str()),
            )
            .map_err(|_| Status::permission_denied("access denied"))?;
        let policy_activation_digest = match self
            .db
            .runtime()
            .get_object_security_activation(&bound.descriptor.namespace)
            .map_err(Status::internal)?
        {
            Some(activation) => {
                crate::sekai::object_security::object_security_activation_digest(&activation)
                    .map_err(Status::internal)?
            }
            None => "legacy".into(),
        };
        let mut filter = bound.filter.clone();
        if !inner.page_token.is_empty() {
            let cursor = crate::sekai::object_security::ObjectQueryCursor::decode(
                &inner.page_token,
                &self.object_query_cursor_key,
                now_millis(),
            )
            .map_err(Status::failed_precondition)?;
            if cursor.principal_context_digest != principal_context_digest
                || cursor.namespace != bound.descriptor.namespace
                || cursor.policy_activation_digest != policy_activation_digest
                || cursor.query_digest != bound.query_digest
            {
                return Err(Status::failed_precondition(
                    "object set cursor authority or query has changed",
                ));
            }
            filter.offset = cursor.offset;
        }
        let hops = crate::sekai::object_set::resolved_hops(&bound.descriptor);
        if bound.descriptor.aggregation.is_some() || hops.len() > 1 {
            return self.evaluate_aggregated_object_set(
                &bound,
                &hops,
                &authority,
                inner.required_freshness_ms,
                now_millis(),
                &attribution,
            );
        }
        // Indexed scan lists the near kind. One-hop still walks declared
        // links from authorized near objects after a datasource exists.
        let indexed = self
            .db
            .runtime()
            .get_object_type_datasource(&bound.descriptor.namespace, &bound.descriptor.kind)
            .map_err(Status::internal)?
            .is_some();
        if indexed && bound.descriptor.traversal.is_none() {
            return self.evaluate_indexed_object_set(
                &bound,
                inner.required_freshness_ms,
                filter.offset,
                (&principal_context_digest, &policy_activation_digest),
                now_millis(),
                &authority,
                &attribution,
            );
        }
        if indexed && inner.required_freshness_ms > 0 {
            let status = self
                .db
                .runtime()
                .object_type_index_status(
                    &bound.descriptor.namespace,
                    &bound.descriptor.kind,
                    now_millis(),
                )
                .map_err(Status::internal)?
                .ok_or_else(|| Status::failed_precondition("object type index is stale"))?;
            if !crate::sekai::object_type_index::freshness_holds(
                &status,
                inner.required_freshness_ms,
            ) {
                return Err(Status::failed_precondition("object type index is stale"));
            }
        }
        let (near, total) = if bound.spatial.is_some() {
            spatial_list_page(
                self.db.runtime(),
                &bound,
                filter.offset,
                &policy_context,
                &authority,
                |objects, principals, tenant_context| {
                    self.resolve_computed_for_responses_with_policy(
                        objects,
                        principals,
                        Some(&policy_context),
                        tenant_context,
                        purpose.as_ref(),
                    )
                },
            )?
        } else {
            list_objects_with_marking(
                self.db.runtime(),
                &filter,
                &principals,
                &policy_context,
                purpose.as_ref(),
                tenant_context.as_ref(),
                |objects, principals, tenant_context| {
                    self.resolve_computed_for_responses_with_policy(
                        objects,
                        principals,
                        Some(&policy_context),
                        tenant_context,
                        purpose.as_ref(),
                    )
                },
            )?
        };
        let returned = near.len() as i32;
        let members = if bound.descriptor.traversal.is_some() {
            collect_one_hop_members(
                self,
                &bound,
                &near,
                &principals,
                &policy_context,
                tenant_context.as_ref(),
                purpose.as_ref(),
            )?
        } else {
            near
        };
        let next_offset = filter.offset.saturating_add(returned);
        let next_page_token = if next_offset < total && returned > 0 {
            crate::sekai::object_security::ObjectQueryCursor::issue(
                next_offset,
                principal_context_digest,
                bound.descriptor.namespace.clone(),
                policy_activation_digest,
                bound.query_digest.clone(),
                now_millis(),
            )
            .and_then(|cursor| cursor.encode(&self.object_query_cursor_key))
            .map_err(Status::internal)?
        } else {
            String::new()
        };
        self.object_set_page(
            &bound,
            members,
            total,
            next_page_token,
            Vec::new(),
            crate::sekai::object_set::EVALUATE_SOURCE_UNKNOWN.into(),
            &attribution,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn object_set_page(
        &self,
        bound: &BoundObjectSet,
        mut members: Vec<domain::Object>,
        mut total: i32,
        mut next_page_token: String,
        mut aggregates: Vec<ObjectSetAggregateRow>,
        source: String,
        attribution: &QueryAttribution,
    ) -> Result<Response<EvaluateObjectSetResponse>, Status> {
        if attribution.type_denied {
            members.clear();
            aggregates.clear();
            total = 0;
            next_page_token.clear();
        }
        let outcome = if attribution.type_denied {
            crate::sekai::object_set::OUTCOME_DENIED
        } else if members.is_empty() && aggregates.is_empty() {
            crate::sekai::object_set::OUTCOME_EMPTY
        } else {
            crate::sekai::object_set::OUTCOME_OK
        };
        let record = crate::sekai::object_set::query_record(bound, &members, outcome)
            .map_err(Status::internal)?;
        if let Some(operation_id) = attribution.operation_id.as_deref() {
            self.persist_object_set_query_receipt(
                operation_id,
                &attribution.actor,
                &bound.descriptor.namespace,
                &record,
            )?;
        }
        Ok(Response::new(EvaluateObjectSetResponse {
            contract_version: bound.descriptor.contract_version.clone(),
            definition_digest: bound.descriptor.definition_digest.clone(),
            kind: bound.member_kind.clone(),
            members: members.iter().map(to_proto_obj).collect(),
            total,
            next_page_token,
            authority: false,
            aggregates,
            source,
            query_digest: record.query_digest,
            object_versions: record
                .object_versions
                .into_iter()
                .map(|version| ObjectVersionRead {
                    id: version.id,
                    version: version.version,
                })
                .collect(),
            outcome: outcome.into(),
        }))
    }

    fn persist_object_set_query_receipt(
        &self,
        operation_id: &str,
        actor: &str,
        namespace: &str,
        record: &ObjectSetQueryRecord,
    ) -> Result<(), Status> {
        let now = now_millis();
        let event = |suffix: &str,
                     parent: Option<&str>,
                     kind: ReceiptEventKind,
                     attributes: BTreeMap<String, String>,
                     references: Vec<GovernedReference>| {
            OperationReceiptEvent {
                event_id: format!("{operation_id}:{suffix}"),
                operation_id: operation_id.into(),
                parent_event_id: parent.map(|value| format!("{operation_id}:{value}")),
                timestamp_ms: now,
                surface: kind.surface(),
                kind,
                actor: actor.into(),
                references,
                attributes,
            }
        };
        let attributes = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect::<BTreeMap<_, _>>()
        };
        let query_record =
            serde_json::to_string(record).map_err(|error| Status::internal(error.to_string()))?;
        let denied = record.outcome == crate::sekai::object_set::OUTCOME_DENIED;
        let policy_decision = if denied { "deny" } else { "allow" };
        let budget_decision = if denied {
            "not_applicable_policy_denied"
        } else {
            "not_applicable_read"
        };
        let references = if denied {
            Vec::new()
        } else {
            record
                .object_versions
                .iter()
                .map(|version| GovernedReference {
                    kind: "object".into(),
                    reference: version.id.clone(),
                    content_hash: Some(version.version.clone()),
                    disclosed_fields: Vec::new(),
                    omitted: false,
                    omission_reason: None,
                })
                .collect()
        };
        let intent = event(
            "intent",
            None,
            ReceiptEventKind::IntentRecorded,
            attributes(&[
                ("capability", "EvaluateObjectSet"),
                ("query_digest", &record.query_digest),
                ("kind", &record.kind),
            ]),
            Vec::new(),
        );
        let policy = event(
            "policy",
            Some("intent"),
            ReceiptEventKind::PolicyDecided,
            attributes(&[("decision", policy_decision)]),
            Vec::new(),
        );
        let routing = event(
            "routing",
            Some("policy"),
            ReceiptEventKind::RouteSelected,
            attributes(&[("route", "native")]),
            Vec::new(),
        );
        let budget = event(
            "budget",
            Some("routing"),
            ReceiptEventKind::BudgetDecided,
            attributes(&[("decision", budget_decision)]),
            Vec::new(),
        );
        let mut outcome_attributes = attributes(&[
            ("outcome", &record.outcome),
            ("query_digest", &record.query_digest),
            ("kind", &record.kind),
            ("definition_digest", &record.definition_digest),
        ]);
        outcome_attributes.insert(
            crate::sekai::object_set::QUERY_RECORD_ATTR.into(),
            query_record,
        );
        let outcome = event(
            "outcome",
            Some("budget"),
            ReceiptEventKind::OutcomeRecorded,
            outcome_attributes,
            references,
        );
        let receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: operation_id.into(),
            parent_operation_id: None,
            namespace: namespace.into(),
            operation_class: crate::sekai::object_set::QUERY_RECEIPT_CLASS.into(),
            initiating_actor: actor.into(),
            schema_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            policy_version: "object_security".into(),
            started_at_ms: now,
            completed_at_ms: Some(now),
            events: vec![intent, policy, routing, budget, outcome],
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest: None,
            artifact: None,
        };
        if let Some(cross_store) = &self.cross_store {
            cross_store
                .chisei_runtime_arc()
                .put_operation_receipt(&receipt)
                .map_err(Status::internal)
        } else {
            self.db
                .runtime()
                .put_operation_receipt(&receipt)
                .map_err(Status::internal)
        }
    }
}

pub(super) fn object_set_type_denied(
    db: &RuntimeDb,
    namespace: &str,
    kind: &str,
) -> Result<bool, Status> {
    match db.active_object_policy(namespace, kind) {
        Ok(_) => Ok(false),
        Err(error) if error.starts_with("object_security_denied") => Ok(true),
        Err(_) => Err(Status::unavailable("object authorization unavailable")),
    }
}

impl SekaiServiceImpl {
    /// The read checks every object-set read passes: tenant, team and
    /// namespace read, read of the published definition, and the property
    /// query rules for the properties it filters, orders or groups by.
    /// Returns the set bound to the published revision.
    pub(super) fn authorize_object_set_read(
        &self,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
        descriptor: Option<ObjectSetDescriptor>,
    ) -> Result<crate::sekai::object_set::BoundObjectSet, Status> {
        let descriptor = parse_object_set_descriptor(
            descriptor.ok_or_else(|| Status::invalid_argument("object-set descriptor required"))?,
        )?;
        self.authorize_domain_object_set_read(principals, tenant_context, descriptor)
    }

    /// The checks on an object set's namespace and kind that do not depend
    /// on its definition revision: tenant, team, source namespace, and the
    /// reserved governance kinds.
    pub(super) fn authorize_object_set_scope(
        &self,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
        descriptor: &DomainObjectSetDescriptor,
    ) -> Result<(), Status> {
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context,
            &descriptor.namespace,
            false,
        )?;
        check_team_namespace(self.db.runtime(), principals, &descriptor.namespace, false)?;
        authorize_source_sync_namespace(
            self,
            principals,
            tenant_context,
            &descriptor.namespace,
            false,
        )?;
        if is_reserved_governance_kind(&descriptor.kind)
            || descriptor
                .traversal
                .as_ref()
                .is_some_and(|traversal| is_reserved_governance_kind(&traversal.far_kind))
        {
            return Err(Status::not_found("object set unavailable"));
        }
        Ok(())
    }

    /// [`Self::authorize_object_set_read`] for a parsed descriptor.
    pub(super) fn authorize_domain_object_set_read(
        &self,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
        descriptor: DomainObjectSetDescriptor,
    ) -> Result<crate::sekai::object_set::BoundObjectSet, Status> {
        self.authorize_object_set_scope(principals, tenant_context, &descriptor)?;
        let published = self
            .db
            .runtime()
            .get_published_definition_revision(&descriptor.namespace)
            .map_err(|_| Status::internal("definition revision unavailable"))?
            .ok_or_else(|| {
                Status::failed_precondition("object set definition revision is stale")
            })?;
        authorize_definition_revision(
            self,
            principals,
            &published.namespace,
            &published.revision_digest,
            true,
        )?;
        let members = self
            .db
            .runtime()
            .get_definition_members(&published.namespace, &published.revision_digest)
            .map_err(|_| Status::internal("definition revision unavailable"))?;
        let bound = descriptor
            .prepare(&published.revision_digest, &members)
            .map_err(map_object_set_error)?;
        {
            let schema = self
                .schema_definitions
                .snapshot()
                .map_err(map_schema_definition_lifecycle_error)?;
            let mut queried_properties = bound
                .filter
                .property_filters
                .iter()
                .filter(|property_filter| property_filter.key != domain::OBJECT_ID_FILTER_KEY)
                .map(|property_filter| property_filter.key.clone())
                .collect::<Vec<_>>();
            if let Some(order_property) = queried_order_property(&bound.filter.order_by) {
                queried_properties.push(order_property);
            }
            if let Some(spatial) = &bound.spatial {
                queried_properties.push(spatial.property.clone());
            }
            if let Some(aggregation) = &bound.descriptor.aggregation
                && !aggregation.group_by.is_empty()
            {
                queried_properties.push(aggregation.group_by.clone());
            }
            ensure_property_query_allowed(
                &schema,
                principals,
                tenant_context,
                bound.filter.kind.as_deref().unwrap_or_default(),
                queried_properties.clone(),
            )?;
            ensure_property_grant_query_allowed(
                self.db.runtime(),
                bound.filter.namespace.as_deref(),
                bound.filter.kind.as_deref(),
                queried_properties,
            )?;
            if let Some(aggregation) = &bound.descriptor.aggregation
                && !aggregation.property.is_empty()
            {
                let hops = crate::sekai::object_set::resolved_hops(&bound.descriptor);
                let leaf_kind = hops
                    .last()
                    .map(|hop| hop.far_kind.as_str())
                    .unwrap_or(bound.descriptor.kind.as_str());
                ensure_property_query_allowed(
                    &schema,
                    principals,
                    tenant_context,
                    leaf_kind,
                    [aggregation.property.clone()],
                )?;
                ensure_property_grant_query_allowed(
                    self.db.runtime(),
                    Some(bound.descriptor.namespace.as_str()),
                    Some(leaf_kind),
                    [aggregation.property.as_str()],
                )?;
            }
        }
        Ok(bound)
    }
    #[allow(clippy::too_many_arguments)]
    fn evaluate_indexed_object_set(
        &self,
        bound: &BoundObjectSet,
        required_freshness_ms: i64,
        offset: i32,
        cursor_authority: (&str, &str),
        now_ms: i64,
        authority: &ObjectSetAuthority<'_>,
        attribution: &QueryAttribution,
    ) -> Result<Response<EvaluateObjectSetResponse>, Status> {
        let (principal_context_digest, policy_activation_digest) = cursor_authority;
        let status = self
            .db
            .runtime()
            .object_type_index_status(&bound.descriptor.namespace, &bound.descriptor.kind, now_ms)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::failed_precondition("object type index is stale"))?;
        if !crate::sekai::object_type_index::freshness_holds(&status, required_freshness_ms) {
            return Err(Status::failed_precondition("object type index is stale"));
        }
        let query = crate::sekai::dataset::RowQuery {
            // Caller filters as written, except the id filter, which only
            // its prepared form (`OBJECT_ID_FILTER_KEY`) pushes onto members.
            filters: bound
                .descriptor
                .property_filters
                .iter()
                .zip(&bound.filter.property_filters)
                .map(|(filter, prepared)| {
                    let filter = if prepared.key == domain::OBJECT_ID_FILTER_KEY {
                        prepared
                    } else {
                        filter
                    };
                    crate::sekai::dataset::RowFilter {
                        column: filter.key.clone(),
                        op: filter.op.clone(),
                        value: filter.value.clone(),
                    }
                })
                .collect(),
            columns: Vec::new(),
            limit: if bound.descriptor.limit > 0 {
                bound.descriptor.limit
            } else {
                crate::sekai::object_set::DEFAULT_EVALUATE_LIMIT
            },
            offset,
        };
        let mut objects = Vec::new();
        let mut meter =
            crate::sekai::object_set::CostMeter::new(bound.descriptor.cost_limit.clone());
        let page_limit = query.limit;
        // Authorized membership can drop SQL rows, so offset/limit cannot be
        // pushed into the index query. Walk matching members to count and
        // page, as the tenant path already did.
        let mut scan = crate::sekai::dataset::RowQuery { offset: 0, ..query };
        let mut total: i32 = 0;
        loop {
            meter.charge(0).map_err(map_object_set_error)?;
            scan.limit = (meter.limit.max_rows_scanned - meter.rows)
                .saturating_add(1)
                .clamp(1, INDEX_SCAN_BATCH_SIZE);
            let members = self
                .db
                .runtime()
                .list_visible_index_members(
                    &bound.descriptor.namespace,
                    &bound.descriptor.kind,
                    &scan,
                )
                .map_err(Status::internal)?;
            let scanned = members.len() as i32;
            meter.charge(scanned).map_err(map_object_set_error)?;
            for member in members {
                if let Some(object) =
                    self.authorized_index_object(&member, authority, status.indexed_at_ms)?
                    && bound.spatial_matches(&object)
                {
                    if total >= offset.max(0) && objects.len() < page_limit as usize {
                        objects.push(object);
                    }
                    total = total.saturating_add(1);
                }
                meter.charge(0).map_err(map_object_set_error)?;
            }
            if scanned < scan.limit {
                break;
            }
            scan.offset = scan.offset.saturating_add(scanned);
        }
        let extras = self.unindexed_kind_objects(bound, authority, &mut meter)?;
        let extra_total = i32::try_from(extras.len()).unwrap_or(i32::MAX);
        let index_total = total;
        let total = index_total.saturating_add(extra_total);
        if offset < index_total {
            let room = (query.limit as usize).saturating_sub(objects.len());
            objects.extend(extras.into_iter().take(room));
        } else {
            objects.clear();
            let skip = offset.saturating_sub(index_total).max(0) as usize;
            objects.extend(
                extras
                    .into_iter()
                    .skip(skip)
                    .take(query.limit.max(0) as usize),
            );
        }
        let returned = objects.len() as i32;
        let next_offset = offset.saturating_add(returned);
        let next_page_token = if next_offset < total && returned > 0 {
            crate::sekai::object_security::ObjectQueryCursor::issue(
                next_offset,
                principal_context_digest.to_string(),
                bound.descriptor.namespace.clone(),
                policy_activation_digest.to_string(),
                bound.query_digest.clone(),
                now_ms,
            )
            .and_then(|cursor| cursor.encode(&self.object_query_cursor_key))
            .map_err(Status::internal)?
        } else {
            String::new()
        };
        self.object_set_page(
            bound,
            objects,
            total,
            next_page_token,
            Vec::new(),
            crate::sekai::object_set::EVALUATE_SOURCE_SQL_PROJECTION.into(),
            attribution,
        )
    }

    fn unindexed_kind_objects(
        &self,
        bound: &BoundObjectSet,
        authority: &ObjectSetAuthority<'_>,
        meter: &mut crate::sekai::object_set::CostMeter,
    ) -> Result<Vec<domain::Object>, Status> {
        let mut extras = Vec::new();
        let mut offset = 0i32;
        let page_size = domain::MAX_LIST_LIMIT;
        loop {
            meter.charge(0).map_err(map_object_set_error)?;
            let page = self
                .db
                .runtime()
                .list_kind_objects_outside_index(
                    &bound.descriptor.namespace,
                    &bound.descriptor.kind,
                    offset,
                    page_size,
                )
                .map_err(Status::internal)?;
            let scanned = page.len();
            meter.charge(scanned as i32).map_err(map_object_set_error)?;
            for object in page {
                if source_tombstoned(&object) || !object_matches_bound_filters(&object, bound) {
                    continue;
                }
                match require_visible_read_root(
                    self.db.runtime(),
                    &self.security,
                    object.clone(),
                    authority.principals,
                    authority.tenant_context,
                    "evaluate_object_set",
                    authority.purpose,
                ) {
                    Ok(_) => extras.push(self.resolve_computed_for_response(
                        object,
                        authority.principals,
                        authority.tenant_context,
                        authority.purpose,
                    )?),
                    Err(status)
                        if matches!(
                            status.code(),
                            tonic::Code::NotFound | tonic::Code::PermissionDenied
                        ) => {}
                    Err(status) => return Err(status),
                }
            }
            if scanned < page_size as usize {
                break;
            }
            offset = offset.saturating_add(page_size);
        }
        Ok(extras)
    }

    fn unindexed_kind_members(
        &self,
        bound: &BoundObjectSet,
        authority: &ObjectSetAuthority<'_>,
        meter: &mut crate::sekai::object_set::CostMeter,
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>, Status> {
        Ok(self
            .unindexed_kind_objects(bound, authority, meter)?
            .into_iter()
            .map(index_member_from_object)
            .collect())
    }

    fn authorized_index_object(
        &self,
        member: &crate::sekai::object_type_index::ObjectTypeIndexMember,
        authority: &ObjectSetAuthority<'_>,
        indexed_at_ms: i64,
    ) -> Result<Option<domain::Object>, Status> {
        let Some(object) = self.visible_index_object(member, authority, indexed_at_ms)? else {
            return Ok(None);
        };
        self.resolve_computed_for_response(
            object,
            authority.principals,
            authority.tenant_context,
            authority.purpose,
        )
        .map(Some)
    }

    fn visible_index_object(
        &self,
        member: &crate::sekai::object_type_index::ObjectTypeIndexMember,
        authority: &ObjectSetAuthority<'_>,
        indexed_at_ms: i64,
    ) -> Result<Option<domain::Object>, Status> {
        let snapshot = domain::Object {
            id: member.object_id.clone(),
            kind: member.kind.clone(),
            name: member.source_key.clone(),
            namespace: member.namespace.clone(),
            external_id: member.source_key.clone(),
            properties: crate::sekai::object_schema::properties_as_cells(&member.properties)
                .into_iter()
                .collect(),
            created: indexed_at_ms,
            updated: indexed_at_ms,
        };
        let live = self
            .db
            .runtime()
            .get_object(&member.object_id)
            .map_err(Status::internal)?;
        let authorized = live.unwrap_or_else(|| snapshot.clone());
        match require_visible_read_root(
            self.db.runtime(),
            &self.security,
            authorized,
            authority.principals,
            authority.tenant_context,
            "evaluate_object_set",
            authority.purpose,
        ) {
            Ok(_) => Ok(Some(snapshot)),
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::NotFound | tonic::Code::PermissionDenied
                ) =>
            {
                Ok(None)
            }
            Err(status) => Err(status),
        }
    }

    fn require_hop_projection_ready(
        &self,
        bound: &BoundObjectSet,
        hops: &[crate::sekai::object_set::ObjectSetTraversal],
    ) -> Result<(), Status> {
        let published = bound.descriptor.definition_digest.as_str();
        let mut kinds = vec![bound.descriptor.kind.as_str()];
        kinds.extend(hops.iter().map(|hop| hop.far_kind.as_str()));
        if !self
            .db
            .runtime()
            .hop_projection_kinds_ready(&bound.descriptor.namespace, &kinds, published)
            .map_err(Status::internal)?
        {
            return Err(Status::failed_precondition(
                "object index hop projection is stale",
            ));
        }
        Ok(())
    }

    fn hop_projection_paths(
        &self,
        bound: &BoundObjectSet,
        hops: &[crate::sekai::object_set::ObjectSetTraversal],
        roots: &[crate::sekai::object_type_index::ObjectTypeIndexMember],
        meter: &mut crate::sekai::object_set::CostMeter,
        needed_leaf: &[String],
    ) -> Result<Vec<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>>, Status> {
        let mut key_paths: Vec<Vec<crate::sekai::object_index_engine::HopKey>> = roots
            .iter()
            .map(|member| {
                vec![crate::sekai::object_index_engine::HopKey::from_member(
                    member,
                )]
            })
            .collect();
        let mut leaf_members: std::collections::HashMap<
            String,
            crate::sekai::object_type_index::ObjectTypeIndexMember,
        > = std::collections::HashMap::new();
        for (hop_index, hop) in hops.iter().enumerate() {
            let incoming = hop.is_incoming();
            let mut parent_keys = std::collections::HashSet::new();
            for path in &key_paths {
                let parent = path.last().expect("path");
                parent_keys.insert(parent.source_key.clone());
                if !incoming {
                    parent_keys.insert(parent.object_id.clone());
                }
            }
            let parent_keys: Vec<String> = parent_keys.into_iter().collect();
            // Edges `(parent key, child source key)`. Outgoing: far rows whose
            // join property names the parent. Incoming: the parent's own join
            // property names the far key (#2412).
            let pairs = if incoming && hop_index == 0 {
                // Roots are loaded with their join property and include
                // members outside the index, which the join table lacks.
                Ok(roots
                    .iter()
                    .filter_map(|root| {
                        root.properties
                            .get(&hop.join_property)
                            .map(|value| (root.source_key.clone(), value.as_cell()))
                    })
                    .collect())
            } else if incoming {
                self.db.runtime().list_index_join_values(
                    &bound.descriptor.namespace,
                    &hops[hop_index - 1].far_kind,
                    &hop.join_property,
                    &parent_keys,
                )
            } else {
                self.db.runtime().list_index_join_children(
                    &bound.descriptor.namespace,
                    &hop.far_kind,
                    &hop.join_property,
                    &parent_keys,
                )
            }
            .map_err(Status::internal)?;
            let mut child_keys = std::collections::HashSet::new();
            for (_, source_key) in &pairs {
                child_keys.insert(source_key.clone());
            }
            let child_keys: Vec<String> = child_keys.into_iter().collect();
            let last = hop_index + 1 == hops.len();
            let child_by_key = if last {
                let children = self
                    .db
                    .runtime()
                    .list_index_members_by_keys_projected(
                        &bound.descriptor.namespace,
                        &hop.far_kind,
                        &child_keys,
                        Some(needed_leaf),
                    )
                    .map_err(Status::internal)?;
                meter
                    .charge(children.len() as i32)
                    .map_err(map_object_set_error)?;
                let mut by_key = std::collections::HashMap::new();
                for member in children {
                    by_key.insert(
                        member.source_key.clone(),
                        crate::sekai::object_index_engine::HopKey::from_member(&member),
                    );
                    leaf_members.insert(member.source_key.clone(), member);
                }
                by_key
            } else {
                let idents = self
                    .db
                    .runtime()
                    .list_index_member_idents(
                        &bound.descriptor.namespace,
                        &hop.far_kind,
                        &child_keys,
                    )
                    .map_err(Status::internal)?;
                meter
                    .charge(idents.len() as i32)
                    .map_err(map_object_set_error)?;
                idents
                    .into_iter()
                    .map(|(source_key, object_id)| {
                        (
                            source_key.clone(),
                            crate::sekai::object_index_engine::HopKey {
                                kind: hop.far_kind.clone(),
                                source_key,
                                object_id,
                            },
                        )
                    })
                    .collect()
            };
            let extend = if incoming {
                crate::sekai::object_index_engine::join_key_paths_incoming
            } else {
                crate::sekai::object_index_engine::join_key_paths
            };
            key_paths = extend(key_paths, &pairs, &child_by_key);
            meter
                .charge(key_paths.len() as i32)
                .map_err(map_object_set_error)?;
        }
        let roots_by_key: std::collections::HashMap<
            &str,
            &crate::sekai::object_type_index::ObjectTypeIndexMember,
        > = roots
            .iter()
            .map(|member| (member.source_key.as_str(), member))
            .collect();
        Ok(key_paths
            .into_iter()
            .map(|path| {
                let last = path.len().saturating_sub(1);
                path.into_iter()
                    .enumerate()
                    .map(|(index, key)| {
                        if index == 0 {
                            roots_by_key
                                .get(key.source_key.as_str())
                                .copied()
                                .cloned()
                                .unwrap_or_else(|| key.stub_member())
                        } else if index == last {
                            leaf_members
                                .get(&key.source_key)
                                .cloned()
                                .unwrap_or_else(|| key.stub_member())
                        } else {
                            key.stub_member()
                        }
                    })
                    .collect()
            })
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_aggregated_object_set(
        &self,
        bound: &BoundObjectSet,
        hops: &[crate::sekai::object_set::ObjectSetTraversal],
        authority: &ObjectSetAuthority<'_>,
        required_freshness_ms: i64,
        now_ms: i64,
        attribution: &QueryAttribution,
    ) -> Result<Response<EvaluateObjectSetResponse>, Status> {
        let constrained = authority.tenant_context.is_some();
        let engine = if constrained {
            crate::sekai::object_index_engine::ObjectIndexEngineKind::NestedLoop
        } else {
            self.object_index_engine
        };
        let dual_read = self.object_index_dual_read && !constrained;
        let log_dual_read = self.object_log_dual_read.enabled && !constrained;
        let mut meter =
            crate::sekai::object_set::CostMeter::new(bound.descriptor.cost_limit.clone());
        if dual_read && bound.descriptor.cost_limit.max_rows_scanned <= 0 {
            return Err(Status::failed_precondition(
                "object index dual-read requires max_rows_scanned",
            ));
        }
        if log_dual_read && bound.descriptor.cost_limit.max_rows_scanned <= 0 {
            return Err(Status::failed_precondition(
                "object-log dual-read requires max_rows_scanned",
            ));
        }
        let aggregation = bound.descriptor.aggregation.clone().ok_or_else(|| {
            Status::invalid_argument("object-set aggregation required for multi-hop evaluate")
        })?;
        // An incoming first hop reads its join property on the root.
        let root_hops = hops
            .first()
            .filter(|hop| hop.is_incoming())
            .map_or(&[][..], std::slice::from_ref);
        let needed_root =
            aggregate_plan_properties(&aggregation, &bound.descriptor.property_filters, root_hops);
        let needed_leaf = aggregate_plan_properties(&aggregation, &[], &[]);
        let needed_nested = aggregate_plan_properties(&aggregation, &[], hops);
        let read_properties = aggregate_read_properties(
            &bound.descriptor.kind,
            &aggregation,
            &bound.descriptor.property_filters,
            hops,
        );
        let mut layers = Vec::new();
        let mut kind = bound.descriptor.kind.clone();
        let empty = crate::sekai::dataset::RowQuery::default();
        for (index, hop) in std::iter::once(None)
            .chain(hops.iter().map(Some))
            .enumerate()
        {
            if let Some(hop) = hop {
                kind = hop.far_kind.clone();
            }
            if self
                .db
                .runtime()
                .get_object_type_datasource(&bound.descriptor.namespace, &kind)
                .map_err(Status::internal)?
                .is_none()
            {
                return Err(Status::failed_precondition(
                    "object-set aggregation requires an index on every hop kind",
                ));
            }
            let status = self
                .db
                .runtime()
                .object_type_index_status(&bound.descriptor.namespace, &kind, now_ms)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::failed_precondition("object type index is stale"))?;
            if index == 0
                && !crate::sekai::object_type_index::freshness_holds(&status, required_freshness_ms)
            {
                return Err(Status::failed_precondition("object type index is stale"));
            }
            let load_members = index == 0
                || engine == crate::sekai::object_index_engine::ObjectIndexEngineKind::NestedLoop
                || dual_read;
            if !load_members {
                layers.push(Vec::new());
                continue;
            }
            let query = if index == 0 {
                crate::sekai::dataset::RowQuery {
                    filters: bound
                        .descriptor
                        .property_filters
                        .iter()
                        .map(|filter| crate::sekai::dataset::RowFilter {
                            column: filter.key.clone(),
                            op: filter.op.clone(),
                            value: filter.value.clone(),
                        })
                        .collect(),
                    ..empty.clone()
                }
            } else {
                empty.clone()
            };
            let needed = if index == 0 {
                needed_root.as_slice()
            } else {
                needed_nested.as_slice()
            };
            if constrained && let Some(properties) = read_properties.get(kind.as_str()) {
                let schema = self
                    .schema_definitions
                    .snapshot()
                    .map_err(map_schema_definition_lifecycle_error)?;
                ensure_property_query_allowed(
                    &schema,
                    authority.principals,
                    authority.tenant_context,
                    &kind,
                    properties.iter().cloned(),
                )?;
                ensure_property_grant_query_allowed(
                    self.db.runtime(),
                    Some(&bound.descriptor.namespace),
                    Some(&kind),
                    properties,
                )?;
            }
            let mut visible = self.scan_index_layer(
                &bound.descriptor.namespace,
                &kind,
                query,
                if constrained { None } else { Some(needed) },
                &mut meter,
                |member| self.authorized_index_object(member, authority, status.indexed_at_ms),
            )?;
            if index == 0 {
                // Clerk extras of the queried kind. Hop layers stay index-only:
                // hop projection joins stored index rows, not clerk extras.
                visible.extend(self.unindexed_kind_members(bound, authority, &mut meter)?);
            }
            layers.push(visible);
        }
        self.require_hop_projection_ready(bound, hops)?;
        let projected = if engine
            == crate::sekai::object_index_engine::ObjectIndexEngineKind::HopProjection
        {
            Some(self.hop_projection_paths(bound, hops, &layers[0], &mut meter, &needed_leaf)?)
        } else {
            None
        };
        let mut paths: Vec<Vec<&crate::sekai::object_type_index::ObjectTypeIndexMember>> =
            layers[0].iter().map(|member| vec![member]).collect();
        if engine == crate::sekai::object_index_engine::ObjectIndexEngineKind::NestedLoop
            || dual_read
        {
            for (hop_index, hop) in hops.iter().enumerate() {
                let join = if hop.is_incoming() {
                    crate::sekai::object_index_engine::join_paths_nested_incoming
                } else {
                    crate::sekai::object_index_engine::join_paths_nested
                };
                paths = join(
                    paths,
                    &layers[hop_index + 1],
                    &hop.join_property,
                    &mut meter,
                )
                .map_err(map_object_set_error)?;
            }
        }
        if let Some(projected) = projected.as_ref()
            && dual_read
        {
            let projected_sig = crate::sekai::object_index_engine::path_signature(
                &projected
                    .iter()
                    .map(|path| path.iter().collect())
                    .collect::<Vec<Vec<_>>>(),
            );
            if projected_sig != crate::sekai::object_index_engine::path_signature(&paths) {
                return Err(Status::internal(
                    "object index hop-projection dual-read mismatch",
                ));
            }
        }
        if log_dual_read
            && crate::sekai::object_log::should_fetch_canary_policies(
                &self.object_log_dual_read,
                &bound.descriptor,
                hops,
                &aggregation,
                bound.descriptor.cost_limit.max_rows_scanned,
            )
        {
            let mut kinds = vec![bound.descriptor.kind.as_str()];
            kinds.extend(hops.iter().map(|hop| hop.far_kind.as_str()));
            let read = &read_properties;
            let schema = self
                .schema_definitions
                .snapshot()
                .map_err(map_schema_definition_lifecycle_error)?;
            let mut policies = Vec::new();
            for kind in &kinds {
                policies.push(
                    self.db
                        .runtime()
                        .active_object_policy(&bound.descriptor.namespace, kind)
                        .map_err(Status::internal)?,
                );
            }
            let canary = crate::sekai::object_log::project_object_log_acl(
                kinds.iter().zip(policies.iter()).map(|(kind, policy)| {
                    crate::sekai::object_log::ObjectLogAclKind {
                        kind,
                        policy: policy.as_ref(),
                        schema_properties: schema.get(kind).map(|object_type| {
                            object_type
                                .properties
                                .iter()
                                .map(|property| property.name.clone())
                                .collect()
                        }),
                        read_properties: read.get(kind).cloned().unwrap_or_default(),
                    }
                }),
            )
            .and_then(|acl| {
                let sql_paths: Vec<Vec<&crate::sekai::object_type_index::ObjectTypeIndexMember>> =
                    if let Some(projected) = projected.as_ref() {
                        projected.iter().map(|path| path.iter().collect()).collect()
                    } else {
                        paths.clone()
                    };
                let log_path = self
                    .object_log_dual_read
                    .log_path
                    .as_deref()
                    .ok_or(crate::sekai::object_log::ObjectLogCompareError::MissingLog)?;
                crate::sekai::object_log::compare_sql_to_log_path(
                    log_path,
                    &bound.descriptor,
                    hops,
                    &aggregation,
                    &sql_paths,
                    acl,
                )
            });
            crate::sekai::object_log::record_canary_outcome(&canary);
            match canary {
                Ok(())
                | Err(crate::sekai::object_log::ObjectLogCompareError::GrantNarrowed)
                | Err(crate::sekai::object_log::ObjectLogCompareError::Unsupported(_)) => {}
                Err(error) => {
                    return Err(Status::failed_precondition(error.message()));
                }
            }
        }
        let rows: Vec<(String, Option<f64>)> = if let Some(projected) = projected.as_ref() {
            projected
                .iter()
                .map(|path| aggregate_path_row(&path[0], path.last().expect("path"), &aggregation))
                .collect()
        } else {
            paths
                .iter()
                .map(|path| aggregate_path_row(path[0], path[path.len() - 1], &aggregation))
                .collect()
        };
        let aggregates = crate::sekai::object_set::aggregate_groups(&rows, &aggregation.function)
            .map_err(map_object_set_error)?;
        let aggregates = aggregates
            .into_iter()
            .map(|row| ObjectSetAggregateRow {
                group_key: row.group_key,
                value: row.value,
                count: row.count,
            })
            .collect::<Vec<_>>();
        let total = aggregates.len() as i32;
        self.object_set_page(
            bound,
            Vec::new(),
            total,
            String::new(),
            aggregates,
            crate::sekai::object_set::EVALUATE_SOURCE_SQL_PROJECTION.into(),
            attribution,
        )
    }
}

impl SekaiServiceImpl {
    /// Every index member of one kind that `admit` lets through, read in
    /// batches under `meter`: of `query.limit` members when it is set,
    /// else of the default batch size. `admit` returns the object as the reader may
    /// see it, whose properties replace the member's, or `None` to leave
    /// the member out. Shared by object-set aggregation and federated
    /// aggregates (#1997), so both scan and authorize one way.
    pub(super) fn scan_index_layer(
        &self,
        namespace: &str,
        kind: &str,
        query: crate::sekai::dataset::RowQuery,
        needed: Option<&[String]>,
        meter: &mut crate::sekai::object_set::CostMeter,
        mut admit: impl FnMut(
            &crate::sekai::object_type_index::ObjectTypeIndexMember,
        ) -> Result<Option<domain::Object>, Status>,
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>, Status> {
        self.scan_index_layer_pages(namespace, kind, query, needed, meter, |members| {
            members.iter().map(&mut admit).collect()
        })
    }

    /// [`scan_index_layer`] with one `admit_page` call per store page so a
    /// reader can batch member-keyed lookups. `admit_page` returns one
    /// optional object per member, in the same order.
    pub(super) fn scan_index_layer_pages(
        &self,
        namespace: &str,
        kind: &str,
        mut query: crate::sekai::dataset::RowQuery,
        needed: Option<&[String]>,
        meter: &mut crate::sekai::object_set::CostMeter,
        mut admit_page: impl FnMut(
            &[crate::sekai::object_type_index::ObjectTypeIndexMember],
        ) -> Result<Vec<Option<domain::Object>>, Status>,
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>, Status> {
        let batch = if query.limit > 0 {
            query.limit
        } else {
            INDEX_SCAN_BATCH_SIZE
        };
        let mut visible = Vec::new();
        loop {
            meter.charge(0).map_err(map_object_set_error)?;
            query.limit = (meter.limit.max_rows_scanned - meter.rows)
                .saturating_add(1)
                .clamp(1, batch);
            let members = self
                .db
                .runtime()
                .list_visible_index_members_projected(namespace, kind, &query, needed)
                .map_err(Status::internal)?;
            let scanned = members.len() as i32;
            meter.charge(scanned).map_err(map_object_set_error)?;
            let admitted = admit_page(&members)?;
            if admitted.len() != members.len() {
                return Err(Status::internal("index page admission length mismatch"));
            }
            for (mut member, object) in members.into_iter().zip(admitted) {
                if let Some(object) = object {
                    member.properties = object
                        .properties
                        .into_iter()
                        .map(|(key, value)| {
                            (
                                key,
                                crate::sekai::object_schema::PropertyValue::String(value),
                            )
                        })
                        .collect();
                    visible.push(member);
                }
                meter.charge(0).map_err(map_object_set_error)?;
            }
            if scanned < query.limit {
                break;
            }
            query.offset = query.offset.saturating_add(scanned);
        }
        Ok(visible)
    }
}

fn aggregate_read_properties<'a>(
    root_kind: &'a str,
    aggregation: &crate::sekai::object_set::ObjectSetAggregation,
    filters: &[crate::domain::PropertyFilter],
    hops: &'a [crate::sekai::object_set::ObjectSetTraversal],
) -> std::collections::BTreeMap<&'a str, std::collections::BTreeSet<String>> {
    let mut read = std::collections::BTreeMap::<&str, std::collections::BTreeSet<String>>::new();
    let root = read.entry(root_kind).or_default();
    root.extend(filters.iter().map(|filter| filter.key.clone()));
    if !aggregation.group_by.is_empty() {
        root.insert(aggregation.group_by.clone());
    }
    let mut near_kind = root_kind;
    for hop in hops {
        read.entry(hop.far_kind.as_str()).or_default();
        if !hop.join_property.is_empty() {
            // The join property lives on the far kind for an outgoing hop and
            // on the near kind for an incoming one.
            let owner = if hop.is_incoming() {
                near_kind
            } else {
                hop.far_kind.as_str()
            };
            read.entry(owner)
                .or_default()
                .insert(hop.join_property.clone());
        }
        near_kind = hop.far_kind.as_str();
    }
    if !aggregation.function.eq_ignore_ascii_case("count") && !aggregation.property.is_empty() {
        let leaf_kind = hops.last().map_or(root_kind, |hop| hop.far_kind.as_str());
        read.entry(leaf_kind)
            .or_default()
            .insert(aggregation.property.clone());
    }
    read
}

fn aggregate_plan_properties(
    aggregation: &crate::sekai::object_set::ObjectSetAggregation,
    filters: &[crate::domain::PropertyFilter],
    hops: &[crate::sekai::object_set::ObjectSetTraversal],
) -> Vec<String> {
    let mut keys = Vec::new();
    if !aggregation.group_by.is_empty() {
        keys.push(aggregation.group_by.clone());
    }
    if !aggregation.function.eq_ignore_ascii_case("count") && !aggregation.property.is_empty() {
        keys.push(aggregation.property.clone());
    }
    for filter in filters {
        if !filter.key.is_empty() {
            keys.push(filter.key.clone());
        }
    }
    for hop in hops {
        if !hop.join_property.is_empty() {
            keys.push(hop.join_property.clone());
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

fn aggregate_path_row(
    root: &crate::sekai::object_type_index::ObjectTypeIndexMember,
    leaf: &crate::sekai::object_type_index::ObjectTypeIndexMember,
    aggregation: &crate::sekai::object_set::ObjectSetAggregation,
) -> (String, Option<f64>) {
    // group_by is planned and granted on the root kind. Reading it from the
    // leaf would skip that kind's property grants.
    let group = root
        .properties
        .get(&aggregation.group_by)
        .map(|value| value.as_cell())
        .unwrap_or_else(|| root.source_key.clone());
    let value = if aggregation.function.eq_ignore_ascii_case("count") {
        Some(1.0)
    } else {
        leaf.properties
            .get(&aggregation.property)
            .and_then(|raw| raw.as_cell().parse().ok())
    };
    (group, value)
}

fn parse_object_set_descriptor(
    descriptor: ObjectSetDescriptor,
) -> Result<DomainObjectSetDescriptor, Status> {
    Ok(DomainObjectSetDescriptor {
        contract_version: descriptor.contract_version,
        namespace: descriptor.namespace,
        kind: descriptor.kind,
        definition_digest: descriptor.definition_digest,
        property_filters: descriptor
            .property_filters
            .into_iter()
            .map(|filter| domain::PropertyFilter {
                key: filter.key,
                op: filter.op,
                value: filter.value,
            })
            .collect(),
        order_by: descriptor.order_by,
        descending: descriptor.descending,
        limit: descriptor.limit,
        traversal: descriptor
            .traversal
            .map(|traversal| DomainObjectSetTraversal {
                relation: traversal.relation,
                direction: traversal.direction,
                far_kind: traversal.far_kind,
                join_property: traversal.join_property,
            }),
        hops: descriptor
            .hops
            .into_iter()
            .map(|traversal| DomainObjectSetTraversal {
                relation: traversal.relation,
                direction: traversal.direction,
                far_kind: traversal.far_kind,
                join_property: traversal.join_property,
            })
            .collect(),
        aggregation: descriptor.aggregation.map(|aggregation| {
            crate::sekai::object_set::ObjectSetAggregation {
                function: aggregation.function,
                property: aggregation.property,
                group_by: aggregation.group_by,
            }
        }),
        cost_limit: descriptor
            .cost_limit
            .map(|limit| crate::sekai::object_set::ObjectSetCostLimit {
                max_rows_scanned: limit.max_rows_scanned,
                max_depth: limit.max_depth,
                max_time_ms: limit.max_time_ms,
            })
            .unwrap_or_default(),
        spatial: descriptor.spatial.map(|spatial| {
            crate::sekai::object_set::ObjectSetSpatialPredicate {
                property: spatial.property,
                operator: spatial.operator,
                geometry_json: spatial.geometry_json,
                max_distance_m: spatial.max_distance_m,
            }
        }),
    })
}

/// One page of a spatially filtered list. The predicate cannot run in SQL,
/// so this walks every visible row (read checks first, so denied rows are
/// never matched or counted), charges the cost meter per visible row, and
/// pages the matches. Returns the page and the matching total.
fn spatial_list_page<F>(
    db: &RuntimeDb,
    bound: &BoundObjectSet,
    offset: i32,
    policy_context: &crate::sekai::object_security::PrincipalPolicyContext,
    authority: &ObjectSetAuthority<'_>,
    resolve: F,
) -> Result<(Vec<domain::Object>, i32), Status>
where
    F: FnOnce(
        Vec<domain::Object>,
        &[String],
        Option<&RequestEnterpriseContext>,
    ) -> Result<Vec<domain::Object>, Status>,
{
    let mut meter = crate::sekai::object_set::CostMeter::new(bound.descriptor.cost_limit.clone());
    let skip = offset.max(0) as usize;
    let page_limit = bound.filter.limit.clamp(1, domain::MAX_LIST_LIMIT) as usize;
    let mut matched = 0usize;
    let mut page = Vec::new();
    for_each_visible_object(
        db,
        &bound.filter,
        authority.principals,
        policy_context,
        authority.purpose,
        authority.tenant_context,
        &mut |object| {
            meter.charge(1).map_err(map_object_set_error)?;
            if bound.spatial_matches(&object) {
                if matched >= skip && page.len() < page_limit {
                    page.push(object);
                }
                matched = matched.saturating_add(1);
            }
            Ok(true)
        },
        &mut || true,
    )?;
    let total = i32::try_from(matched).unwrap_or(i32::MAX);
    Ok((
        resolve(page, authority.principals, authority.tenant_context)?,
        total,
    ))
}

fn collect_one_hop_members(
    service: &SekaiServiceImpl,
    bound: &BoundObjectSet,
    near: &[domain::Object],
    principals: &[String],
    policy_context: &crate::sekai::object_security::PrincipalPolicyContext,
    tenant_context: Option<&RequestEnterpriseContext>,
    purpose: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
) -> Result<Vec<domain::Object>, Status> {
    let traversal = bound
        .descriptor
        .traversal
        .as_ref()
        .expect("one-hop evaluation requires a declared traversal");
    let direction = if traversal.direction == "incoming" {
        domain::Direction::Incoming
    } else {
        domain::Direction::Outgoing
    };
    let mut seen = HashSet::new();
    let mut recorded_purposes = HashSet::new();
    let mut members = Vec::new();
    for start in near {
        let links = service
            .db
            .runtime()
            .get_links_with_policy_context(
                &start.id,
                &traversal.relation,
                &direction,
                policy_context,
            )
            .map_err(Status::internal)?;
        for link in links {
            let target = match direction {
                domain::Direction::Outgoing => &link.to_id,
                domain::Direction::Incoming => &link.from_id,
            };
            if !seen.insert(target.clone()) {
                continue;
            }
            let Some(object) = service
                .db
                .runtime()
                .get_object_with_policy_context(target, policy_context)
                .map_err(Status::internal)?
            else {
                continue;
            };
            if object.kind != traversal.far_kind {
                continue;
            }
            if !purpose_kind_permitted(
                service.db.runtime(),
                &object.namespace,
                &object.kind,
                purpose,
            )? {
                continue;
            }
            if !object_is_visible(
                service.db.runtime(),
                &service.security,
                &object,
                principals,
                tenant_context,
            ) {
                continue;
            }
            if !purpose_allows_kind(
                service.db.runtime(),
                &object.namespace,
                &object.kind,
                purpose,
                &mut recorded_purposes,
            )? {
                continue;
            }
            members.push(object);
        }
    }
    service.resolve_computed_for_responses_with_policy(
        members,
        principals,
        Some(policy_context),
        tenant_context,
        purpose,
    )
}

fn map_object_set_error(error: ObjectSetError) -> Status {
    match error {
        ObjectSetError::InvalidArgument(message) => Status::invalid_argument(message),
        ObjectSetError::Stale(message) => Status::failed_precondition(message),
        ObjectSetError::Unsupported(message) => Status::invalid_argument(message),
        ObjectSetError::LimitExceeded(message) => Status::failed_precondition(message),
    }
}

impl SekaiServiceImpl {
    /// Streams an object set as CSV, JSON Lines, or Parquet. The caller passes every
    /// read check of EvaluateObjectSet and holds an active export grant on
    /// the namespace; rows and properties are what a read would return. The
    /// receipt is written before the first byte; an export that does not
    /// finish (a dropped client, an error) leaves it aborted.
    pub(super) async fn export_object_set_rpc(
        &self,
        req: Request<ExportObjectSetRequest>,
    ) -> Result<Response<ExportStream>, Status> {
        let caller = ExportCaller::from_request(self, &req)?;
        let inner = req.into_inner();
        let prepared = self.prepare_object_set_export(
            caller,
            inner.descriptor,
            inner.properties,
            &inner.format,
        )?;
        Ok(Response::new(run_export(
            self.db.runtime().clone(),
            prepared,
        )))
    }

    /// What `caller` may export of this source, checked now: the export's
    /// receipt source, its header, and the row writer to run.
    pub(super) fn prepare_object_set_export(
        &self,
        caller: ExportCaller,
        descriptor: Option<ObjectSetDescriptor>,
        properties: Vec<String>,
        format: &str,
    ) -> Result<PreparedExport, Status> {
        use crate::sekai::data_export::{ExportFormat, ExportSource, RowEncoder};
        let ExportCaller {
            principals,
            policy_context,
            purpose,
            tenant_context,
        } = caller;
        let inner = ExportObjectSetRequest {
            descriptor,
            properties,
            format: format.into(),
        };
        let format = ExportFormat::parse(&inner.format)
            .ok_or_else(|| Status::invalid_argument("format must be csv, jsonl, or parquet"))?;
        let encoder = RowEncoder::new(format, inner.properties.clone(), true)
            .map_err(Status::invalid_argument)?;
        let bound =
            self.authorize_object_set_read(&principals, tenant_context.as_ref(), inner.descriptor)?;
        // The export scan does not evaluate the predicate; refuse rather
        // than export rows it would have excluded.
        if bound.spatial.is_some() {
            return Err(Status::invalid_argument(
                "object-set export does not support a spatial predicate",
            ));
        }
        let namespace = bound.descriptor.namespace.clone();
        // Fail closed: reading a set never entitles taking it out.
        let granted_via = export_grantee(
            self.db.runtime(),
            &principals,
            &namespace,
            "object_set",
            &bound.descriptor.kind,
        )?;
        let plan = crate::sekai::export_fingerprint::namespace_plan(self.db.runtime(), &namespace)
            .map_err(Status::internal)?;
        let fingerprint_properties = plan
            .as_ref()
            .map(crate::sekai::export_fingerprint::FingerprintPlan::properties)
            .unwrap_or_default();
        let fingerprint_group_size = if plan.is_some() {
            crate::sekai::export_fingerprint::FINGERPRINT_GROUP_SIZE as u32
        } else {
            0
        };
        // The receipt names who asked; the grant that allowed it is evidence.
        let actor = principals[0].clone();
        if bound.descriptor.aggregation.is_some()
            || !crate::sekai::object_set::resolved_hops(&bound.descriptor).is_empty()
            || self
                .db
                .runtime()
                .get_object_type_datasource(&namespace, &bound.descriptor.kind)
                .map_err(Status::internal)?
                .is_some()
        {
            return Err(Status::unimplemented(
                "export covers object sets of one stored kind, without traversal or aggregation",
            ));
        }
        let source = ExportSource {
            namespace,
            source_kind: "object_set",
            source_id: bound.descriptor.kind.clone(),
            source_version: bound.query_digest.clone(),
            definition_digest: bound.descriptor.definition_digest.clone(),
            format,
            columns: inner.properties,
            granted_via,
            fingerprint_properties,
            fingerprint_group_size,
        };
        let mut filter = bound.filter;
        filter.offset = 0;
        let service = self.clone();
        let db = self.db.runtime().clone();
        Ok(PreparedExport {
            actor,
            source,
            header: encoder.header(),
            rows: Box::new(move |writer: &std::cell::RefCell<ExportWriter>| {
                let export_id = writer.borrow().operation_id().to_string();
                let mut sink = crate::sekai::export_fingerprint::FingerprintSink::new(
                    export_id, encoder, plan,
                );
                // Rows are resolved per batch exactly as a read projects them.
                let mut batch = Vec::with_capacity(EXPORT_BATCH);
                let mut connected = true;
                {
                    let emit = |batch: &mut Vec<domain::Object>,
                                sink: &mut crate::sekai::export_fingerprint::FingerprintSink|
                     -> Result<bool, Status> {
                        let markings: Vec<String> = batch
                            .iter()
                            .map(|object| {
                                crate::sekai::markings::object_marking_token(object)
                                    .unwrap_or("")
                                    .to_string()
                            })
                            .collect();
                        let resolved = service.resolve_computed_for_responses_with_policy(
                            std::mem::take(batch),
                            &principals,
                            Some(&policy_context),
                            tenant_context.as_ref(),
                            purpose.as_ref(),
                        )?;
                        let mut writer = writer.borrow_mut();
                        for (object, marking) in resolved.iter().zip(markings) {
                            let encoded = sink
                                .push(&object.id, &marking, object.properties.clone())
                                .map_err(Status::invalid_argument)?;
                            for part in encoded {
                                if !writer.write(part.bytes, part.rows) {
                                    return Ok(false);
                                }
                            }
                        }
                        Ok(true)
                    };
                    for_each_visible_object(
                        &db,
                        &filter,
                        &principals,
                        &policy_context,
                        purpose.as_ref(),
                        tenant_context.as_ref(),
                        &mut |object| {
                            batch.push(object);
                            if batch.len() == EXPORT_BATCH {
                                connected = emit(&mut batch, &mut sink)?;
                            }
                            Ok(connected)
                        },
                        // A long scan over rows the caller may not see still
                        // renews the lease, and stops once it is lost.
                        &mut || writer.borrow_mut().keep_alive(),
                    )?;
                    if connected {
                        connected = emit(&mut batch, &mut sink)?;
                    }
                }
                if !connected {
                    return Ok(false);
                }
                let mut writer = writer.borrow_mut();
                for part in sink.finish().map_err(Status::internal)? {
                    if !writer.write(part.bytes, part.rows) {
                        return Ok(false);
                    }
                }
                Ok(true)
            }),
        })
    }
}

fn source_tombstoned(object: &domain::Object) -> bool {
    object
        .properties
        .get("sync_tombstoned")
        .is_some_and(|value| value == "true")
}

fn index_member_from_object(
    object: domain::Object,
) -> crate::sekai::object_type_index::ObjectTypeIndexMember {
    crate::sekai::object_type_index::ObjectTypeIndexMember {
        namespace: object.namespace,
        kind: object.kind,
        source_key: object.id.clone(),
        object_id: object.id,
        properties: object
            .properties
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    crate::sekai::object_schema::PropertyValue::String(value),
                )
            })
            .collect(),
        content_hash: String::new(),
        hidden: false,
        from_edit: false,
    }
}

fn object_matches_bound_filters(object: &domain::Object, bound: &BoundObjectSet) -> bool {
    if bound
        .filter
        .kind
        .as_ref()
        .is_some_and(|kind| object.kind != *kind)
        || bound
            .filter
            .namespace
            .as_ref()
            .is_some_and(|namespace| object.namespace != *namespace)
    {
        return false;
    }
    if !bound.spatial_matches(object) {
        return false;
    }
    bound.filter.property_filters.iter().all(|filter| {
        if let Some(ids) = domain::object_id_filter_ids(&filter.key, &filter.op, &filter.value) {
            return ids.is_ok_and(|ids| ids.contains(&object.id));
        }
        let Some(actual) = object.properties.get(&filter.key) else {
            return false;
        };
        match filter.op.as_str() {
            "eq" => actual == &filter.value,
            "gt" | "gte" | "lt" | "lte" => {
                let Ok(left) = actual.parse::<f64>() else {
                    return false;
                };
                let Ok(right) = filter.value.parse::<f64>() else {
                    return false;
                };
                match filter.op.as_str() {
                    "gt" => left > right,
                    "gte" => left >= right,
                    "lt" => left < right,
                    "lte" => left <= right,
                    _ => false,
                }
            }
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::definition_branch::{
        DefinitionMember, DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };
    use crate::sekai::security;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tonic::metadata::MetadataValue;

    #[test]
    fn index_member_from_object_keys_extras_by_object_id() {
        let member = index_member_from_object(domain::Object {
            id: "obj-a".into(),
            kind: "Ticket".into(),
            name: "shared".into(),
            namespace: "ops".into(),
            external_id: "shared".into(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        });
        let other = index_member_from_object(domain::Object {
            id: "obj-b".into(),
            kind: "Ticket".into(),
            name: "shared".into(),
            namespace: "ops".into(),
            external_id: "shared".into(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        });
        assert_eq!(member.source_key, "obj-a");
        assert_eq!(other.source_key, "obj-b");
        assert_ne!(member.source_key, other.source_key);
    }

    #[test]
    fn aggregate_plan_properties_keeps_group_numeric_filter_and_join_keys() {
        let aggregation = crate::sekai::object_set::ObjectSetAggregation {
            function: "sum".into(),
            property: "amount".into(),
            group_by: "region".into(),
        };
        let filters = [crate::domain::PropertyFilter {
            key: "tier".into(),
            op: "eq".into(),
            value: "1".into(),
        }];
        let hops = [crate::sekai::object_set::ObjectSetTraversal {
            join_property: "customer_id".into(),
            ..Default::default()
        }];
        assert_eq!(
            aggregate_plan_properties(&aggregation, &filters, &[]),
            vec!["amount".to_string(), "region".into(), "tier".into()]
        );
        assert_eq!(
            aggregate_plan_properties(&aggregation, &[], &[]),
            vec!["amount".to_string(), "region".into()]
        );
        assert_eq!(
            aggregate_plan_properties(&aggregation, &[], &hops),
            vec!["amount".to_string(), "customer_id".into(), "region".into()]
        );
        let count = crate::sekai::object_set::ObjectSetAggregation {
            function: "count".into(),
            property: "amount".into(),
            group_by: String::new(),
        };
        assert!(aggregate_plan_properties(&count, &[], &[]).is_empty());
        let hops = [crate::sekai::object_set::ObjectSetTraversal {
            far_kind: "Shipment".into(),
            join_property: "order_id".into(),
            ..Default::default()
        }];
        let planned = aggregate_read_properties("Customer", &aggregation, &filters, &hops);
        assert!(planned["Customer"].contains("region"));
        assert!(planned["Customer"].contains("tier"));
        assert!(!planned["Shipment"].contains("region"));
        assert!(planned["Shipment"].contains("amount"));
        assert!(planned["Shipment"].contains("order_id"));
    }

    #[test]
    fn aggregate_path_row_groups_by_root_not_leaf() {
        let root = crate::sekai::object_type_index::ObjectTypeIndexMember {
            namespace: "sales".into(),
            kind: "Customer".into(),
            source_key: "c1".into(),
            object_id: "Customer:c1".into(),
            properties: std::collections::BTreeMap::from([("region".into(), "eu".into())]),
            content_hash: String::new(),
            hidden: false,
            from_edit: false,
        };
        let leaf = crate::sekai::object_type_index::ObjectTypeIndexMember {
            namespace: "sales".into(),
            kind: "Shipment".into(),
            source_key: "s1".into(),
            object_id: "Shipment:s1".into(),
            properties: std::collections::BTreeMap::from([
                ("region".into(), "west".into()),
                ("amount".into(), "10".into()),
            ]),
            content_hash: String::new(),
            hidden: false,
            from_edit: false,
        };
        let aggregation = crate::sekai::object_set::ObjectSetAggregation {
            function: "sum".into(),
            property: "amount".into(),
            group_by: "region".into(),
        };
        assert_eq!(
            aggregate_path_row(&root, &leaf, &aggregation),
            ("eu".into(), Some(10.0))
        );
        let mut root_without_region = root.clone();
        root_without_region.properties.remove("region");
        assert_eq!(
            aggregate_path_row(&root_without_region, &leaf, &aggregation),
            ("c1".into(), Some(10.0))
        );
    }

    fn service() -> SekaiServiceImpl {
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db))
    }

    fn with_named_principal<T>(payload: T, principal: &str) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    fn grant_namespace(svc: &SekaiServiceImpl, namespace: &str, principal: &str) {
        let (_, grants) = svc
            .db
            .runtime()
            .ensure_team_namespace(namespace, principal, security::Role::Admin, "local")
            .unwrap();
        for grant in grants {
            svc.security.add_grant(&grant);
        }
    }

    fn member(namespace: &str, kind: &str, id: &str, json: &str) -> DefinitionMember {
        DefinitionMemberInput {
            member_kind: kind.into(),
            member_id: id.into(),
            definition_json: json.into(),
            member_digest: String::new(),
        }
        .prepare(namespace)
        .unwrap()
    }

    fn seed_sales_definition(svc: &SekaiServiceImpl) -> String {
        let members = vec![
            member(
                "sales",
                "object_type",
                "Customer",
                r#"{"name":"Customer","properties":{"region":{"type":"string"},"tier":{"type":"integer"}}}"#,
            ),
            member(
                "sales",
                "object_type",
                "Order",
                r#"{"name":"Order","properties":{"status":{"type":"string"}}}"#,
            ),
            member(
                "sales",
                "link_type",
                "placed",
                r#"{"name":"placed","from":"Customer","to":"Order"}"#,
            ),
        ];
        let revision = prepare_revision(
            "sales",
            "",
            members.iter().map(|item| DefinitionRevisionMember {
                member_kind: item.member_kind.clone(),
                member_id: item.member_id.clone(),
                member_digest: item.member_digest.clone(),
            }),
            true,
            "root",
            1,
        )
        .unwrap();
        svc.db
            .runtime()
            .seed_published_definition_revision(&revision, &members)
            .unwrap();
        revision.revision_digest
    }

    fn object(
        id: &str,
        kind: &str,
        name: &str,
        properties: &[(&str, &str)],
        created: i64,
    ) -> domain::Object {
        domain::Object {
            id: id.into(),
            kind: kind.into(),
            name: name.into(),
            namespace: "sales".into(),
            external_id: format!("sales:{id}"),
            properties: properties
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
            created,
            updated: created,
        }
    }

    fn seed_customers_and_orders(svc: &SekaiServiceImpl) {
        for item in [
            object(
                "c-eu-2",
                "Customer",
                "North",
                &[("region", "eu"), ("tier", "2")],
                10,
            ),
            object(
                "c-eu-3",
                "Customer",
                "South",
                &[("region", "eu"), ("tier", "3")],
                11,
            ),
            object(
                "c-us-2",
                "Customer",
                "West",
                &[("region", "us"), ("tier", "2")],
                12,
            ),
            object(
                "c-eu-1",
                "Customer",
                "East",
                &[("region", "eu"), ("tier", "1")],
                13,
            ),
        ] {
            svc.db.runtime().create_object(&item).unwrap();
        }
        for (id, name, created) in [
            ("o-south", "SO-1", 20),
            ("o-north", "NO-1", 21),
            ("o-west", "WO-1", 22),
        ] {
            svc.db
                .runtime()
                .create_object(&object(id, "Order", name, &[("status", "open")], created))
                .unwrap();
        }
        for (id, from, to) in [
            ("l-south", "c-eu-3", "o-south"),
            ("l-north", "c-eu-2", "o-north"),
            ("l-west", "c-us-2", "o-west"),
        ] {
            svc.db
                .runtime()
                .create_link(&domain::Link {
                    id: id.into(),
                    from_id: from.into(),
                    to_id: to.into(),
                    relation: "placed".into(),
                    created: 30,
                })
                .unwrap();
        }
    }

    fn descriptor(digest: &str, limit: i32) -> ObjectSetDescriptor {
        ObjectSetDescriptor {
            spatial: None,
            contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: digest.into(),
            property_filters: vec![
                PropertyFilter {
                    key: "region".into(),
                    op: "eq".into(),
                    value: "eu".into(),
                },
                PropertyFilter {
                    key: "tier".into(),
                    op: "gte".into(),
                    value: "2".into(),
                },
            ],
            order_by: "property:tier".into(),
            descending: true,
            limit,
            traversal: Some(ObjectSetTraversal {
                relation: "placed".into(),
                direction: "outgoing".into(),
                far_kind: "Order".into(),
                join_property: String::new(),
            }),
            hops: Vec::new(),
            aggregation: None,
            cost_limit: None,
        }
    }

    const GEO_SQUARE: &str = r#"{"type":"sekai.geospatial-value/v1","kind":"polygon","crs":"EPSG:4326","coordinates":[[13.0,52.0],[14.0,52.0],[14.0,53.0],[13.0,53.0],[13.0,52.0]]}"#;

    fn geo_point(lon: f64, lat: f64) -> String {
        format!(
            r#"{{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:4326","coordinates":[{lon},{lat}]}}"#
        )
    }

    /// A `sites` namespace whose Site kind declares `region` and `location`,
    /// with two sites in Berlin, one in Munich and one without a location.
    fn seed_sites(svc: &SekaiServiceImpl) -> String {
        let members = vec![member(
            "sites",
            "object_type",
            "Site",
            r#"{"name":"Site","properties":{"region":{"type":"string"},"location":{"type":"string"}}}"#,
        )];
        let revision = prepare_revision(
            "sites",
            "",
            members.iter().map(|item| DefinitionRevisionMember {
                member_kind: item.member_kind.clone(),
                member_id: item.member_id.clone(),
                member_digest: item.member_digest.clone(),
            }),
            true,
            "root",
            1,
        )
        .unwrap();
        svc.db
            .runtime()
            .seed_published_definition_revision(&revision, &members)
            .unwrap();
        for (id, location, created) in [
            ("s-mitte", Some(geo_point(13.405, 52.52)), 10),
            ("s-kreuzberg", Some(geo_point(13.41, 52.50)), 11),
            ("s-munich", Some(geo_point(11.58, 48.14)), 12),
            ("s-nowhere", None, 13),
        ] {
            let mut site = object(id, "Site", id, &[("region", "de")], created);
            site.namespace = "sites".into();
            site.external_id = format!("sites:{id}");
            if let Some(location) = location {
                site.properties.insert("location".into(), location);
            }
            svc.db.runtime().create_object(&site).unwrap();
        }
        revision.revision_digest
    }

    fn spatial_sites(
        digest: &str,
        operator: &str,
        geometry_json: &str,
        max_distance_m: f64,
    ) -> ObjectSetDescriptor {
        ObjectSetDescriptor {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION_V3.into(),
            namespace: "sites".into(),
            kind: "Site".into(),
            definition_digest: digest.into(),
            spatial: Some(ObjectSetSpatialPredicate {
                property: "location".into(),
                operator: operator.into(),
                geometry_json: geometry_json.into(),
                max_distance_m,
            }),
            ..Default::default()
        }
    }

    async fn evaluate_sites(
        svc: &SekaiServiceImpl,
        descriptor: ObjectSetDescriptor,
        page_token: String,
    ) -> Result<EvaluateObjectSetResponse, Status> {
        svc.evaluate_object_set(with_named_principal(
            EvaluateObjectSetRequest {
                descriptor: Some(descriptor),
                page_token,
                required_freshness_ms: 0,
            },
            "alice",
        ))
        .await
        .map(Response::into_inner)
    }

    fn member_ids(response: &EvaluateObjectSetResponse) -> Vec<&str> {
        response
            .members
            .iter()
            .map(|member| member.id.as_str())
            .collect()
    }

    /// #2333: the spatial predicate filters, counts and pages only matching
    /// visible rows, and the property grant is checked before any match.
    #[tokio::test]
    async fn evaluate_object_set_spatial_predicate_matches_after_authorization() {
        let svc = service();
        grant_namespace(&svc, "sites", "alice");
        let digest = seed_sites(&svc);

        let mut near = spatial_sites(&digest, "distance", &geo_point(13.405, 52.52), 5_000.0);
        near.limit = 1;
        let first = evaluate_sites(&svc, near.clone(), String::new())
            .await
            .unwrap();
        assert_eq!(first.total, 2);
        assert_eq!(member_ids(&first), ["s-kreuzberg"]);
        let second = evaluate_sites(&svc, near, first.next_page_token)
            .await
            .unwrap();
        assert_eq!(member_ids(&second), ["s-mitte"]);
        assert!(second.next_page_token.is_empty());

        let contains = evaluate_sites(
            &svc,
            spatial_sites(&digest, "contains", GEO_SQUARE, 0.0),
            String::new(),
        )
        .await
        .unwrap();
        assert_eq!(contains.total, 0);
        let intersects = evaluate_sites(
            &svc,
            spatial_sites(&digest, "intersects", GEO_SQUARE, 0.0),
            String::new(),
        )
        .await
        .unwrap();
        assert_eq!(member_ids(&intersects), ["s-kreuzberg", "s-mitte"]);

        let mut v2 = spatial_sites(&digest, "intersects", GEO_SQUARE, 0.0);
        v2.contract_version = crate::sekai::object_set::CONTRACT_VERSION_V2.into();
        let invalid_ring = GEO_SQUARE.replace(",[13.0,52.0]]}", "]}");
        for rejected in [v2, spatial_sites(&digest, "intersects", &invalid_ring, 0.0)] {
            let error = evaluate_sites(&svc, rejected, String::new())
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }

        // Only `region` is granted, so a predicate on `location` is refused
        // before any row is matched.
        // Activation needs one revision per instantiated kind, including the
        // namespace's governance kinds; those allow everything.
        let kinds = svc
            .db
            .runtime()
            .list_objects(&domain::ListFilter {
                namespace: Some("sites".into()),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|object| object.kind)
            .collect::<std::collections::BTreeSet<_>>();
        let mut activation = BTreeMap::new();
        for (index, kind) in kinds.into_iter().enumerate() {
            let policy = crate::sekai::object_security::ObjectSecurityPolicy {
                contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION
                    .into(),
                namespace: "sites".into(),
                kind: kind.clone(),
                rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                    operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                    predicates: vec![
                        crate::sekai::object_security::ObjectSecurityPredicate::AllowAll,
                    ],
                }],
                property_grants: (kind == "Site").then(|| {
                    vec![crate::sekai::object_security::PropertyGrant {
                        property: "region".into(),
                        access: crate::sekai::object_security::PropertyGrantAccess::Read,
                    }]
                }),
                value_instance_grants: None,
                required_purpose: None,
            };
            let revision = svc
                .db
                .runtime()
                .put_object_security_policy(
                    &policy,
                    "root",
                    &format!("put-{kind}"),
                    1 + index as i64,
                )
                .unwrap();
            activation.insert(kind, revision.revision_digest);
        }
        svc.db
            .runtime()
            .activate_object_security_policies("sites", &activation, "root", "activate-sites", 40)
            .unwrap();
        let denied = evaluate_sites(
            &svc,
            spatial_sites(&digest, "intersects", GEO_SQUARE, 0.0),
            String::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn evaluate_object_set_filters_pages_and_traverses_without_client_join() {
        exercise_evaluate_filters_pages_and_traverses(service()).await;
    }

    /// #1086: the product loop evaluates object sets on community PostgreSQL
    /// with the same members, order, and paging as SQLite.
    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_evaluate_object_set_matches_sqlite() {
        let scratch = crate::db::ScratchDatabase::create();
        // The last pool handle drops outside the runtime: closing a
        // synchronous client from an async worker panics.
        let db = Arc::new(RuntimeDb::Postgres(Arc::new(scratch.connect())));
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(exercise_evaluate_filters_pages_and_traverses(
                SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(
                    db.clone(),
                )),
            ));
        drop(db);
    }

    async fn exercise_evaluate_filters_pages_and_traverses(svc: SekaiServiceImpl) {
        grant_namespace(&svc, "sales", "alice");
        let digest = seed_sales_definition(&svc);
        seed_customers_and_orders(&svc);

        let first = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor(&digest, 1)),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(!first.authority);
        assert_eq!(
            first.source,
            crate::sekai::object_set::EVALUATE_SOURCE_UNKNOWN
        );
        assert_eq!(
            first.contract_version,
            crate::sekai::object_set::CONTRACT_VERSION
        );
        assert_eq!(first.definition_digest, digest);
        assert_eq!(first.kind, "Order");
        assert_eq!(first.total, 2);
        assert_eq!(first.members.len(), 1);
        assert_eq!(first.members[0].id, "o-south");
        assert!(!first.next_page_token.is_empty());

        let second = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor(&digest, 1)),
                    page_token: first.next_page_token,
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(second.members.len(), 1);
        assert_eq!(second.members[0].id, "o-north");
        assert!(second.next_page_token.is_empty());
        assert!(!second.members.iter().any(|object| object.id == "o-west"));
    }

    #[tokio::test]
    async fn evaluate_object_set_refuses_a_pre_upgrade_query_digest_cursor() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        let digest = seed_sales_definition(&svc);
        seed_customers_and_orders(&svc);
        let descriptor = descriptor(&digest, 1);
        let first = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor.clone()),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(!first.next_page_token.is_empty());

        let bound = svc
            .authorize_object_set_read(&["alice".into()], None, Some(descriptor.clone()))
            .unwrap();
        let list_digest =
            crate::sekai::object_security::object_query_digest(&bound.filter).unwrap();
        let mut concatenated = Sha256::new();
        concatenated.update(crate::sekai::object_set::CONTRACT_VERSION.as_bytes());
        concatenated.update(bound.descriptor.definition_digest.as_bytes());
        concatenated.update(list_digest.as_bytes());
        for hop in crate::sekai::object_set::resolved_hops(&bound.descriptor) {
            concatenated.update(hop.relation.as_bytes());
            concatenated.update(hop.direction.as_bytes());
            concatenated.update(hop.far_kind.as_bytes());
            concatenated.update(hop.join_property.as_bytes());
        }
        let old_digest = format!("{:x}", concatenated.finalize());
        assert_ne!(old_digest, bound.query_digest);

        let current = crate::sekai::object_security::ObjectQueryCursor::decode(
            &first.next_page_token,
            &svc.object_query_cursor_key,
            1,
        )
        .unwrap();
        let stale = crate::sekai::object_security::ObjectQueryCursor::issue(
            current.offset,
            current.principal_context_digest,
            current.namespace,
            current.policy_activation_digest,
            old_digest,
            current.expires_at_ms - crate::sekai::object_security::OBJECT_QUERY_CURSOR_TTL_MS,
        )
        .unwrap()
        .encode(&svc.object_query_cursor_key)
        .unwrap();
        let refused = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor.clone()),
                    page_token: stale,
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            refused.message(),
            "object set cursor authority or query has changed"
        );

        let fresh = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(fresh.total, first.total);
        assert_eq!(fresh.members.len(), first.members.len());
    }

    #[tokio::test]
    async fn evaluate_object_set_id_filter_returns_only_readable_ids() {
        exercise_id_filter_returns_only_readable_ids(service()).await;
    }

    /// #2706: the id filter answers the same on PostgreSQL as on SQLite.
    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_evaluate_object_set_id_filter_matches_sqlite() {
        let scratch = crate::db::ScratchDatabase::create();
        let db = Arc::new(RuntimeDb::Postgres(Arc::new(scratch.connect())));
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(exercise_id_filter_returns_only_readable_ids(
                SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(
                    db.clone(),
                )),
            ));
        drop(db);
    }

    /// #2706: `id in [..]` returns exactly the listed objects the caller may
    /// read. A marked, privately granted, other-namespace, wrong-kind or
    /// missing id is absent, and the answer does not tell them apart.
    async fn exercise_id_filter_returns_only_readable_ids(svc: SekaiServiceImpl) {
        grant_namespace(&svc, "sales", "alice");
        let digest = seed_sales_definition(&svc);
        seed_customers_and_orders(&svc);
        let mut marked = object("c-marked", "Customer", "Marked", &[], 14);
        marked.properties.insert(
            crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            "restricted".into(),
        );
        let mut elsewhere = object("c-hr", "Customer", "Elsewhere", &[], 15);
        elsewhere.namespace = "hr".into();
        elsewhere.external_id = "hr:c-hr".into();
        for item in [
            marked,
            object("c-private", "Customer", "Private", &[], 16),
            elsewhere,
            domain::Object {
                id: "profile-alice".into(),
                kind: crate::sekai::markings::PRINCIPAL_PROFILE_KIND.into(),
                name: "alice".into(),
                namespace: String::new(),
                external_id: crate::sekai::markings::principal_profile_external_id("alice"),
                properties: std::collections::HashMap::from([
                    (
                        crate::sekai::markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                        "public".into(),
                    ),
                    (
                        crate::sekai::markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                        "true".into(),
                    ),
                ]),
                created: 1,
                updated: 1,
            },
        ] {
            svc.db.runtime().create_object(&item).unwrap();
        }
        for (object_id, principal) in [("c-private", "bob"), ("profile-alice", "root")] {
            let grant = security::Grant {
                id: format!("grant-{object_id}"),
                object_id: object_id.into(),
                principal: principal.into(),
                role: security::Role::Admin,
                created: 1,
                ..Default::default()
            };
            svc.db.runtime().create_grant(&grant).unwrap();
            svc.security.add_grant(&grant);
        }
        let by_ids = |ids: &[&str]| ObjectSetDescriptor {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: digest.clone(),
            property_filters: vec![PropertyFilter {
                key: "id".into(),
                op: "in".into(),
                value: serde_json::to_string(ids).unwrap(),
            }],
            ..Default::default()
        };
        let evaluate = |descriptor: ObjectSetDescriptor| {
            svc.evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor),
                    ..Default::default()
                },
                "alice",
            ))
        };

        let mixed = evaluate(by_ids(&[
            "missing",
            "c-marked",
            "c-eu-2",
            "c-private",
            "c-hr",
            "o-south",
            "c-eu-3",
            "c-eu-2",
        ]))
        .await
        .unwrap()
        .into_inner();
        let mut visible = member_ids(&mixed);
        visible.sort_unstable();
        assert_eq!(visible, ["c-eu-2", "c-eu-3"]);
        assert_eq!(mixed.total, 2);

        // Existing-but-unreadable ids answer exactly as missing ids do.
        let hidden = evaluate(by_ids(&["c-marked", "c-private", "c-hr"]))
            .await
            .unwrap()
            .into_inner();
        let missing = evaluate(by_ids(&["nope-1", "nope-2", "nope-3"]))
            .await
            .unwrap()
            .into_inner();
        for response in [&hidden, &missing] {
            assert!(response.members.is_empty());
            assert_eq!(response.total, 0);
            assert!(response.next_page_token.is_empty());
        }

        let over_bound = (0..=crate::sekai::object_set::MAX_ID_FILTER_VALUES)
            .map(|index| format!("id-{index}"))
            .collect::<Vec<_>>();
        let over_bound = over_bound.iter().map(String::as_str).collect::<Vec<_>>();
        let refused = evaluate(by_ids(&over_bound)).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);

        // `in` stays unknown on properties, as on a server without it.
        let mut on_property = by_ids(&["eu"]);
        on_property.property_filters[0].key = "region".into();
        let unsupported = evaluate(on_property).await.unwrap_err();
        let mut unknown_op = by_ids(&["eu"]);
        unknown_op.property_filters[0] = PropertyFilter {
            key: "region".into(),
            op: "contains".into(),
            value: "eu".into(),
        };
        let existing = evaluate(unknown_op).await.unwrap_err();
        assert_eq!(unsupported.code(), existing.code());
        assert_eq!(unsupported.message(), existing.message());
    }

    #[tokio::test]
    async fn evaluate_object_set_fails_closed_for_stale_wrong_type_and_hidden_state() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        let digest = seed_sales_definition(&svc);
        seed_customers_and_orders(&svc);

        let stale = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor("sha256:deadbeef", 2)),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(stale.code(), tonic::Code::FailedPrecondition);

        let mut wrong = descriptor(&digest, 2);
        wrong.property_filters[1].value = "gold".into();
        let typed = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(wrong),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(typed.code(), tonic::Code::InvalidArgument);

        let mut contains = descriptor(&digest, 2);
        contains.property_filters[0].op = "contains".into();
        let unsupported = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(contains),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(unsupported.code(), tonic::Code::InvalidArgument);

        let policy = crate::sekai::object_security::ObjectSecurityPolicy {
            contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                predicates: vec![
                    crate::sekai::object_security::ObjectSecurityPredicate::PropertyEquals {
                        property: "region".into(),
                        value: "eu".into(),
                    },
                ],
            }],
            property_grants: Some(vec![crate::sekai::object_security::PropertyGrant {
                property: "region".into(),
                access: crate::sekai::object_security::PropertyGrantAccess::Read,
            }]),
            value_instance_grants: None,
            required_purpose: None,
        };
        let customer_revision = svc
            .db
            .runtime()
            .put_object_security_policy(&policy, "root", "put-object-set", 1)
            .unwrap();
        let instantiated = svc
            .db
            .runtime()
            .list_objects(&domain::ListFilter {
                namespace: Some("sales".into()),
                ..Default::default()
            })
            .unwrap();
        let mut activation =
            BTreeMap::from([("Customer".into(), customer_revision.revision_digest)]);
        for (index, kind) in instantiated
            .iter()
            .map(|object| object.kind.as_str())
            .filter(|kind| *kind != "Customer")
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .enumerate()
        {
            let extra = crate::sekai::object_security::ObjectSecurityPolicy {
                contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION
                    .into(),
                namespace: "sales".into(),
                kind: kind.into(),
                rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                    operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                    predicates: vec![
                        crate::sekai::object_security::ObjectSecurityPredicate::AllowAll,
                    ],
                }],
                property_grants: None,
                value_instance_grants: None,
                required_purpose: None,
            };
            let revision = svc
                .db
                .runtime()
                .put_object_security_policy(
                    &extra,
                    "root",
                    &format!("put-object-set-{kind}"),
                    10 + index as i64,
                )
                .unwrap();
            activation.insert(kind.to_string(), revision.revision_digest);
        }
        svc.db
            .runtime()
            .activate_object_security_policies(
                "sales",
                &activation,
                "root",
                "activate-object-set",
                40,
            )
            .unwrap();

        let hidden_filter = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor(&digest, 10)),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(hidden_filter.code(), tonic::Code::PermissionDenied);

        let mut region_only = descriptor(&digest, 10);
        region_only.property_filters.truncate(1);
        region_only.order_by.clear();
        region_only.traversal = None;
        let visible = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(region_only),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(visible.total, 3);
        assert!(!visible.members.iter().any(|object| object.id == "c-us-2"));
        assert!(!visible.authority);
    }

    #[tokio::test]
    async fn evaluate_object_set_reads_index_and_fails_closed_on_freshness() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_definition(&svc);
        svc.db
            .runtime()
            .create_dataset(&crate::sekai::dataset::Dataset {
                id: "ds-customers".into(),
                name: "customers".into(),
                columns: vec![
                    crate::sekai::dataset::ColumnDef {
                        name: "customer_id".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "region".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "hidden".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                ],
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        svc.db
            .runtime()
            .append_rows(
                "ds-customers",
                &[
                    std::collections::HashMap::from([
                        ("customer_id".into(), "c1".into()),
                        ("region".into(), "eu".into()),
                        ("hidden".into(), "0".into()),
                    ]),
                    std::collections::HashMap::from([
                        ("customer_id".into(), "c-hidden".into()),
                        ("region".into(), "eu".into()),
                        ("hidden".into(), "true".into()),
                    ]),
                ],
            )
            .unwrap();
        svc.register_object_type_datasource(with_named_principal(
            RegisterObjectTypeDatasourceRequest {
                datasource: Some(ObjectTypeDatasource {
                    contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    definition_digest: digest.clone(),
                    dataset_id: "ds-customers".into(),
                    key_column: "customer_id".into(),
                    property_mapping: std::collections::HashMap::from([(
                        "region".into(),
                        "region".into(),
                    )]),
                    hidden_column: "hidden".into(),
                    edits_only: false,
                    conflict_rule: String::new(),
                    source_timestamp_property: String::new(),
                }),
                idempotency_key: "reg-1".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.reindex_object_type(with_named_principal(
            ReindexObjectTypeRequest {
                namespace: "sales".into(),
                kind: "Customer".into(),
                full_rebuild: true,
            },
            "local",
        ))
        .await
        .unwrap();
        let mut descriptor = descriptor(&digest, 10);
        descriptor.property_filters.clear();
        descriptor.order_by.clear();
        descriptor.traversal = None;
        let page = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor.clone()),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.total, 1);
        assert_eq!(
            page.source,
            crate::sekai::object_set::EVALUATE_SOURCE_SQL_PROJECTION
        );
        assert_eq!(page.members[0].id, "Customer:c1");
        assert!(
            !page
                .members
                .iter()
                .any(|object| object.id.contains("hidden"))
        );
        svc.db
            .runtime()
            .update_dataset(&crate::sekai::dataset::Dataset {
                id: "ds-customers".into(),
                name: "customers".into(),
                columns: vec![crate::sekai::dataset::ColumnDef {
                    name: "customer_id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                }],
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        let quarantined = svc
            .reindex_object_type(with_named_principal(
                ReindexObjectTypeRequest {
                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    full_rebuild: false,
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(quarantined.quarantined);
        let stale = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor),
                    page_token: String::new(),
                    required_freshness_ms: 60_000,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn evaluate_object_set_includes_clerk_objects_outside_index() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_definition(&svc);
        svc.db
            .runtime()
            .create_dataset(&crate::sekai::dataset::Dataset {
                id: "ds-customers".into(),
                name: "customers".into(),
                columns: vec![
                    crate::sekai::dataset::ColumnDef {
                        name: "customer_id".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "region".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "hidden".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                ],
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        svc.db
            .runtime()
            .append_rows(
                "ds-customers",
                &[std::collections::HashMap::from([
                    ("customer_id".into(), "c1".into()),
                    ("region".into(), "eu".into()),
                    ("hidden".into(), "0".into()),
                ])],
            )
            .unwrap();
        svc.register_object_type_datasource(with_named_principal(
            RegisterObjectTypeDatasourceRequest {
                datasource: Some(ObjectTypeDatasource {
                    contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    definition_digest: digest.clone(),
                    dataset_id: "ds-customers".into(),
                    key_column: "customer_id".into(),
                    property_mapping: std::collections::HashMap::from([(
                        "region".into(),
                        "region".into(),
                    )]),
                    hidden_column: "hidden".into(),
                    edits_only: false,
                    conflict_rule: String::new(),
                    source_timestamp_property: String::new(),
                }),
                idempotency_key: "reg-extra".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.reindex_object_type(with_named_principal(
            ReindexObjectTypeRequest {
                namespace: "sales".into(),
                kind: "Customer".into(),
                full_rebuild: true,
            },
            "local",
        ))
        .await
        .unwrap();
        svc.db
            .runtime()
            .create_object(&object(
                "c-manual",
                "Customer",
                "Manual",
                &[("region", "ap")],
                50,
            ))
            .unwrap();
        svc.db
            .runtime()
            .create_object(&object(
                "c-tombstone",
                "Customer",
                "Gone",
                &[("region", "us"), ("sync_tombstoned", "true")],
                51,
            ))
            .unwrap();
        let mut descriptor = descriptor(&digest, 10);
        descriptor.property_filters.clear();
        descriptor.order_by.clear();
        descriptor.traversal = None;
        let page = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor.clone()),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.total, 2);
        let ids: Vec<&str> = page
            .members
            .iter()
            .map(|object| object.id.as_str())
            .collect();
        assert!(ids.contains(&"Customer:c1"), "{ids:?}");
        assert!(ids.contains(&"c-manual"), "{ids:?}");
        assert!(!ids.contains(&"c-tombstone"), "{ids:?}");

        descriptor.contract_version = crate::sekai::object_set::CONTRACT_VERSION_V2.into();
        descriptor.aggregation = Some(ObjectSetAggregation {
            function: "count".into(),
            property: String::new(),
            group_by: "region".into(),
        });
        descriptor.cost_limit = Some(ObjectSetCostLimit {
            max_rows_scanned: 100,
            max_depth: 1,
            max_time_ms: 0,
        });
        let counted = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        let counted_total: i64 = counted.aggregates.iter().map(|row| row.count).sum();
        assert_eq!(counted_total, 2, "{:?}", counted.aggregates);
    }

    #[tokio::test]
    async fn evaluate_object_set_one_hop_survives_datasource_registration() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_definition(&svc);
        seed_customers_and_orders(&svc);
        svc.db
            .runtime()
            .create_dataset(&crate::sekai::dataset::Dataset {
                id: "ds-customers".into(),
                name: "customers".into(),
                columns: vec![
                    crate::sekai::dataset::ColumnDef {
                        name: "customer_id".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "region".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "hidden".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                ],
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        svc.register_object_type_datasource(with_named_principal(
            RegisterObjectTypeDatasourceRequest {
                datasource: Some(ObjectTypeDatasource {
                    contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    definition_digest: digest.clone(),
                    dataset_id: "ds-customers".into(),
                    key_column: "customer_id".into(),
                    property_mapping: std::collections::HashMap::from([(
                        "region".into(),
                        "region".into(),
                    )]),
                    hidden_column: "hidden".into(),
                    edits_only: false,
                    conflict_rule: String::new(),
                    source_timestamp_property: String::new(),
                }),
                idempotency_key: "reg-one-hop".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.reindex_object_type(with_named_principal(
            ReindexObjectTypeRequest {
                namespace: "sales".into(),
                kind: "Customer".into(),
                full_rebuild: true,
            },
            "local",
        ))
        .await
        .unwrap();
        let page = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor(&digest, 10)),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.kind, "Order");
        assert_eq!(page.total, 2);
        let ids: Vec<&str> = page
            .members
            .iter()
            .map(|object| object.id.as_str())
            .collect();
        assert!(ids.contains(&"o-south"), "{ids:?}");
        assert!(ids.contains(&"o-north"), "{ids:?}");
        assert!(!ids.contains(&"o-west"), "{ids:?}");
    }

    #[tokio::test]
    async fn evaluate_object_set_skips_denied_index_members_without_hiding_later_rows() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_definition(&svc);
        svc.db
            .runtime()
            .create_dataset(&crate::sekai::dataset::Dataset {
                id: "ds-customers".into(),
                name: "customers".into(),
                columns: vec![
                    crate::sekai::dataset::ColumnDef {
                        name: "customer_id".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "region".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "hidden".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                ],
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        svc.db
            .runtime()
            .append_rows(
                "ds-customers",
                &[
                    std::collections::HashMap::from([
                        ("customer_id".into(), "a1".into()),
                        ("region".into(), "eu".into()),
                        ("hidden".into(), "0".into()),
                    ]),
                    std::collections::HashMap::from([
                        ("customer_id".into(), "z1".into()),
                        ("region".into(), "eu".into()),
                        ("hidden".into(), "0".into()),
                    ]),
                ],
            )
            .unwrap();
        svc.register_object_type_datasource(with_named_principal(
            RegisterObjectTypeDatasourceRequest {
                datasource: Some(ObjectTypeDatasource {
                    contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    definition_digest: digest.clone(),
                    dataset_id: "ds-customers".into(),
                    key_column: "customer_id".into(),
                    property_mapping: std::collections::HashMap::from([(
                        "region".into(),
                        "region".into(),
                    )]),
                    hidden_column: "hidden".into(),
                    edits_only: false,
                    conflict_rule: String::new(),
                    source_timestamp_property: String::new(),
                }),
                idempotency_key: "reg-acl-page".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.reindex_object_type(with_named_principal(
            ReindexObjectTypeRequest {
                namespace: "sales".into(),
                kind: "Customer".into(),
                full_rebuild: true,
            },
            "local",
        ))
        .await
        .unwrap();
        let grant = crate::sekai::security::Grant {
            id: "grant-a1-bob".into(),
            object_id: "Customer:a1".into(),
            principal: "bob".into(),
            role: crate::sekai::security::Role::Viewer,
            created: 0,
            ..Default::default()
        };
        svc.db.runtime().create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
        let mut descriptor = descriptor(&digest, 1);
        descriptor.property_filters.clear();
        descriptor.order_by.clear();
        descriptor.traversal = None;
        let page = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(descriptor),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.total, 1, "{:?}", page.members);
        assert_eq!(page.members.len(), 1);
        assert_eq!(page.members[0].id, "Customer:z1");
    }

    #[tokio::test]
    async fn evaluate_object_set_index_honors_numeric_filter_ops() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_definition(&svc);
        svc.db
            .runtime()
            .create_dataset(&crate::sekai::dataset::Dataset {
                id: "ds-customers".into(),
                name: "customers".into(),
                columns: vec![
                    crate::sekai::dataset::ColumnDef {
                        name: "customer_id".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "region".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "tier".into(),
                        col_type: "integer".into(),
                        classification: "public".into(),
                    },
                    crate::sekai::dataset::ColumnDef {
                        name: "hidden".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    },
                ],
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        svc.db
            .runtime()
            .append_rows(
                "ds-customers",
                &[
                    std::collections::HashMap::from([
                        ("customer_id".into(), "c-low".into()),
                        ("region".into(), "eu".into()),
                        ("tier".into(), "1".into()),
                        ("hidden".into(), "0".into()),
                    ]),
                    std::collections::HashMap::from([
                        ("customer_id".into(), "c-high".into()),
                        ("region".into(), "eu".into()),
                        ("tier".into(), "3".into()),
                        ("hidden".into(), "0".into()),
                    ]),
                ],
            )
            .unwrap();
        svc.register_object_type_datasource(with_named_principal(
            RegisterObjectTypeDatasourceRequest {
                datasource: Some(ObjectTypeDatasource {
                    contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    definition_digest: digest.clone(),
                    dataset_id: "ds-customers".into(),
                    key_column: "customer_id".into(),
                    property_mapping: std::collections::HashMap::from([
                        ("region".into(), "region".into()),
                        ("tier".into(), "tier".into()),
                    ]),
                    hidden_column: "hidden".into(),
                    edits_only: false,
                    conflict_rule: String::new(),
                    source_timestamp_property: String::new(),
                }),
                idempotency_key: "reg-filter".into(),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.reindex_object_type(with_named_principal(
            ReindexObjectTypeRequest {
                namespace: "sales".into(),
                kind: "Customer".into(),
                full_rebuild: true,
            },
            "local",
        ))
        .await
        .unwrap();
        let mut request = descriptor(&digest, 10);
        request.property_filters = vec![PropertyFilter {
            key: "tier".into(),
            op: "gte".into(),
            value: "2".into(),
        }];
        request.order_by.clear();
        request.traversal = None;
        let page = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(request),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.members.len(), 1);
        assert_eq!(page.members[0].id, "Customer:c-high");

        // #2706: the id filter selects index members by object id and
        // combines with the other filters on the index path.
        for (extra, expected) in [
            (None, vec!["Customer:c-high", "Customer:c-low"]),
            (
                Some(PropertyFilter {
                    key: "tier".into(),
                    op: "gte".into(),
                    value: "2".into(),
                }),
                vec!["Customer:c-high"],
            ),
        ] {
            let mut request = descriptor(&digest, 10);
            request.order_by.clear();
            request.traversal = None;
            request.property_filters = vec![PropertyFilter {
                key: "id".into(),
                op: "in".into(),
                value: r#"["Customer:c-low","Customer:c-high","Customer:missing"]"#.into(),
            }];
            request.property_filters.extend(extra);
            let page = svc
                .evaluate_object_set(with_named_principal(
                    EvaluateObjectSetRequest {
                        descriptor: Some(request),
                        ..Default::default()
                    },
                    "alice",
                ))
                .await
                .unwrap()
                .into_inner();
            let mut ids = member_ids(&page);
            ids.sort_unstable();
            assert_eq!(ids, expected);
            assert_eq!(
                page.source,
                crate::sekai::object_set::EVALUATE_SOURCE_SQL_PROJECTION
            );
        }
    }

    #[tokio::test]
    async fn evaluate_object_set_index_hides_live_marking_from_delegated_human() {
        let svc = service();
        grant_namespace(&svc, "sales", "service-a");
        grant_namespace(&svc, "sales", "human-a");
        let digest = seed_sales_definition(&svc);
        index_kind(
            &svc,
            &digest,
            "Customer",
            "ds-c",
            "customer_id",
            &[("region", "region")],
            vec![hashmap(&[
                ("customer_id", "c1"),
                ("region", "eu"),
                ("hidden", "0"),
            ])],
        );
        let object_id = "Customer:c1";
        for (principal, role) in [
            ("service-a", security::Role::Admin),
            ("human-a", security::Role::Viewer),
        ] {
            let grant = security::Grant {
                id: format!("indexed-marking-{principal}"),
                object_id: object_id.into(),
                principal: principal.into(),
                role,
                created: 1,
                ..Default::default()
            };
            svc.db.runtime().create_grant(&grant).unwrap();
            svc.security.add_grant(&grant);
        }
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: object_id.into(),
                kind: "Customer".into(),
                name: "c1".into(),
                namespace: "sales".into(),
                external_id: "c1".into(),
                properties: std::collections::HashMap::from([(
                    crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    "restricted".into(),
                )]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        for (actor, ceiling) in [("service-a", "restricted"), ("human-a", "public")] {
            let profile = domain::Object {
                id: format!("profile-{actor}"),
                kind: crate::sekai::markings::PRINCIPAL_PROFILE_KIND.into(),
                name: actor.into(),
                namespace: String::new(),
                external_id: crate::sekai::markings::principal_profile_external_id(actor),
                properties: std::collections::HashMap::from([
                    (
                        crate::sekai::markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                        ceiling.into(),
                    ),
                    (
                        crate::sekai::markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                        "true".into(),
                    ),
                ]),
                created: 1,
                updated: 1,
            };
            svc.db.runtime().create_object(&profile).unwrap();
            let grant = security::Grant {
                id: format!("profile-grant-{actor}"),
                object_id: profile.id,
                principal: "root".into(),
                role: security::Role::Admin,
                created: 1,
                ..Default::default()
            };
            svc.db.runtime().create_grant(&grant).unwrap();
            svc.security.add_grant(&grant);
        }
        let descriptor = ObjectSetDescriptor {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: digest,
            cost_limit: Some(ObjectSetCostLimit {
                max_rows_scanned: 100,
                max_depth: 3,
                max_time_ms: 0,
            }),
            ..Default::default()
        };
        for (actor, expected) in [(None, 1), (Some("human-a"), 0)] {
            let mut context = crate::enterprise::AuthenticatedContext::machine(
                crate::enterprise::AuthenticatedPrincipal {
                    subject: "service-a".into(),
                    credential_id: "service-credential".into(),
                },
            );
            context.act = actor.map(str::to_string);
            let mut request = Request::new(EvaluateObjectSetRequest {
                descriptor: Some(descriptor.clone()),
                ..Default::default()
            });
            request.extensions_mut().insert(context);
            let result = svc.evaluate_object_set(request).await.unwrap().into_inner();
            assert_eq!(result.total, expected, "act={actor:?}");
            assert_eq!(result.members.len(), expected as usize, "act={actor:?}");
        }
    }

    #[tokio::test]
    async fn evaluate_object_set_index_fails_closed_on_authorization_outage() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_definition(&svc);
        index_kind(
            &svc,
            &digest,
            "Customer",
            "ds-c-outage",
            "customer_id",
            &[("region", "region")],
            vec![hashmap(&[
                ("customer_id", "c1"),
                ("region", "eu"),
                ("hidden", "0"),
            ])],
        );
        svc.db
            .runtime()
            .conn()
            .execute(
                "INSERT INTO sekai_classification_lattices
                 (namespace, contract_version, digest, lattice_json, created_by, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                ("sales", "v1", "stale", "{", "root", 1_i64),
            )
            .unwrap();
        let context = crate::enterprise::AuthenticatedContext::machine(
            crate::enterprise::AuthenticatedPrincipal {
                subject: "alice".into(),
                credential_id: "service-credential".into(),
            },
        );
        let mut request = Request::new(EvaluateObjectSetRequest {
            descriptor: Some(ObjectSetDescriptor {
                contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                namespace: "sales".into(),
                kind: "Customer".into(),
                definition_digest: digest,
                cost_limit: Some(ObjectSetCostLimit {
                    max_rows_scanned: 100,
                    max_depth: 3,
                    max_time_ms: 0,
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
        request.extensions_mut().insert(context);
        let err = svc.evaluate_object_set(request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert!(err.message().contains("unavailable"));
    }

    #[tokio::test]
    async fn evaluate_object_set_two_hop_aggregates_without_hidden_leakage() {
        let mut svc = service();
        assert_eq!(
            svc.object_index_engine,
            crate::sekai::object_index_engine::ObjectIndexEngineKind::HopProjection
        );
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        let page = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![
                            ObjectSetTraversal {
                                relation: "placed".into(),
                                direction: "outgoing".into(),
                                far_kind: "Order".into(),
                                join_property: "customer_id".into(),
                            },
                            ObjectSetTraversal {
                                relation: "ships".into(),
                                direction: "outgoing".into(),
                                far_kind: "Shipment".into(),
                                join_property: "order_id".into(),
                            },
                        ],
                        aggregation: Some(ObjectSetAggregation {
                            function: "sum".into(),
                            property: "amount".into(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 100,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.aggregates.len(), 1);
        assert_eq!(page.aggregates[0].group_key, "eu");
        assert_eq!(page.aggregates[0].value, 10.0);
        assert_eq!(page.aggregates[0].count, 1);
        assert!(page.members.is_empty());
        assert!(!page.authority);
        assert_eq!(
            page.source,
            crate::sekai::object_set::EVALUATE_SOURCE_SQL_PROJECTION
        );

        grant_namespace(&svc, "sales", "service-a");
        grant_namespace(&svc, "sales", "human-a");
        let grant = security::Grant {
            id: "indexed-service-grant".into(),
            object_id: "Customer:c1".into(),
            principal: "service-a".into(),
            role: security::Role::Admin,
            created: 1,
            ..Default::default()
        };
        svc.db.runtime().create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
        let mut allowed_descriptor = None;
        for aggregation in [false, true] {
            let mut desc = ObjectSetDescriptor {
                contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                namespace: "sales".into(),
                kind: "Customer".into(),
                definition_digest: page.definition_digest.clone(),
                ..Default::default()
            };
            if aggregation {
                desc.hops = vec![ObjectSetTraversal {
                    relation: "placed".into(),
                    direction: "outgoing".into(),
                    far_kind: "Order".into(),
                    join_property: "customer_id".into(),
                }];
                desc.aggregation = Some(ObjectSetAggregation {
                    function: "count".into(),
                    group_by: "region".into(),
                    ..Default::default()
                });
                desc.cost_limit = Some(ObjectSetCostLimit {
                    max_rows_scanned: 100,
                    max_depth: 3,
                    max_time_ms: 0,
                });
            }
            allowed_descriptor = Some(desc.clone());
            for (actor, expected) in [(None, 1), (Some("human-a"), 0)] {
                let mut context = crate::enterprise::AuthenticatedContext::machine(
                    crate::enterprise::AuthenticatedPrincipal {
                        subject: "service-a".into(),
                        credential_id: "service-credential".into(),
                    },
                );
                context.act = actor.map(str::to_string);
                let mut request = Request::new(EvaluateObjectSetRequest {
                    descriptor: Some(desc.clone()),
                    ..Default::default()
                });
                request.extensions_mut().insert(context.clone());
                let result = svc.evaluate_object_set(request).await.unwrap().into_inner();
                assert_eq!(
                    result.total, expected,
                    "aggregation={aggregation}, act={actor:?}"
                );
            }
        }

        svc.db
            .runtime()
            .append_rows(
                "ds-c",
                &[hashmap(&[
                    ("customer_id", "c-denied"),
                    ("region", "eu"),
                    ("hidden", "0"),
                ])],
            )
            .unwrap();
        svc.db
            .runtime()
            .apply_object_type_index("sales", "Customer", true, 20)
            .unwrap();
        let denied_grant = security::Grant {
            id: "indexed-other-grant".into(),
            object_id: "Customer:c-denied".into(),
            principal: "other-human".into(),
            role: security::Role::Viewer,
            created: 1,
            ..Default::default()
        };
        svc.db.runtime().create_grant(&denied_grant).unwrap();
        svc.security.add_grant(&denied_grant);
        let mut limited = ObjectSetDescriptor {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: page.definition_digest.clone(),
            limit: 1,
            cost_limit: Some(ObjectSetCostLimit {
                max_rows_scanned: 1,
                max_depth: 3,
                max_time_ms: 0,
            }),
            ..Default::default()
        };
        let context = crate::enterprise::AuthenticatedContext::machine(
            crate::enterprise::AuthenticatedPrincipal {
                subject: "service-a".into(),
                credential_id: "service-credential".into(),
            },
        );
        let mut request = Request::new(EvaluateObjectSetRequest {
            descriptor: Some(limited.clone()),
            ..Default::default()
        });
        request.extensions_mut().insert(context.clone());
        assert_eq!(
            svc.evaluate_object_set(request).await.unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
        limited.cost_limit.as_mut().unwrap().max_rows_scanned = 100;
        let mut request = Request::new(EvaluateObjectSetRequest {
            descriptor: Some(limited),
            ..Default::default()
        });
        request.extensions_mut().insert(context);
        let limited_page = svc.evaluate_object_set(request).await.unwrap().into_inner();
        assert_eq!(limited_page.total, 1);
        assert_eq!(limited_page.members.len(), 1);
        assert_eq!(limited_page.members[0].id, "Customer:c1");

        let mut join_limited = allowed_descriptor.clone().unwrap();
        join_limited.cost_limit.as_mut().unwrap().max_rows_scanned = 4;
        let mut request = Request::new(EvaluateObjectSetRequest {
            descriptor: Some(join_limited),
            ..Default::default()
        });
        request
            .extensions_mut()
            .insert(crate::enterprise::AuthenticatedContext::machine(
                crate::enterprise::AuthenticatedPrincipal {
                    subject: "service-a".into(),
                    credential_id: "service-credential".into(),
                },
            ));
        let denied = svc.evaluate_object_set(request).await.unwrap_err();
        assert_eq!(denied.code(), tonic::Code::FailedPrecondition);
        assert!(denied.message().contains("max_rows_scanned"));

        let human_grant = security::Grant {
            id: "indexed-human-grant".into(),
            principal: "human-a".into(),
            ..grant.clone()
        };
        svc.db.runtime().create_grant(&human_grant).unwrap();
        svc.security.add_grant(&human_grant);
        let mut context = crate::enterprise::AuthenticatedContext::machine(
            crate::enterprise::AuthenticatedPrincipal {
                subject: "service-a".into(),
                credential_id: "service-credential".into(),
            },
        );
        context.act = Some("human-a".into());
        let mut request = Request::new(EvaluateObjectSetRequest {
            descriptor: allowed_descriptor.clone(),
            ..Default::default()
        });
        request.extensions_mut().insert(context.clone());
        assert_eq!(
            svc.evaluate_object_set(request)
                .await
                .unwrap()
                .into_inner()
                .total,
            1
        );

        let mut policies = BTreeMap::new();
        for kind in ["Customer", "Order", "Shipment"] {
            svc.db
                .runtime()
                .create_object(&domain::Object {
                    id: format!("policy-sentinel-{kind}"),
                    kind: kind.into(),
                    name: kind.into(),
                    namespace: "sales".into(),
                    external_id: String::new(),
                    properties: std::collections::HashMap::new(),
                    created: 1,
                    updated: 1,
                })
                .unwrap();
        }
        let kinds = svc
            .db
            .runtime()
            .list_objects(&domain::ListFilter {
                namespace: Some("sales".into()),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|object| object.kind)
            .collect::<std::collections::BTreeSet<_>>();
        for kind in kinds {
            let properties = match kind.as_str() {
                "Customer" => Some(vec!["region"]),
                "Order" => Some(vec!["customer_id"]),
                "Shipment" => Some(vec!["order_id", "amount"]),
                _ => None,
            };
            let policy = crate::sekai::object_security::ObjectSecurityPolicy {
                contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION
                    .into(),
                namespace: "sales".into(),
                kind: kind.clone(),
                rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                    operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                    predicates: vec![
                        crate::sekai::object_security::ObjectSecurityPredicate::AllowAll,
                    ],
                }],
                property_grants: properties.map(|properties| {
                    properties
                        .into_iter()
                        .map(|property| crate::sekai::object_security::PropertyGrant {
                            property: property.into(),
                            access: crate::sekai::object_security::PropertyGrantAccess::Read,
                        })
                        .collect()
                }),
                value_instance_grants: None,
                required_purpose: None,
            };
            let revision = svc
                .db
                .runtime()
                .put_object_security_policy(&policy, "root", &format!("put-index-{kind}"), 100)
                .unwrap();
            policies.insert(kind, revision.revision_digest);
        }
        svc.db
            .runtime()
            .activate_object_security_policies(
                "sales",
                &policies,
                "root",
                "activate-index-grants",
                101,
            )
            .unwrap();
        let mut request = Request::new(EvaluateObjectSetRequest {
            descriptor: allowed_descriptor,
            ..Default::default()
        });
        request.extensions_mut().insert(context);
        assert_eq!(
            svc.evaluate_object_set(request)
                .await
                .unwrap()
                .into_inner()
                .total,
            1
        );

        let mut projected = service();
        grant_namespace(&projected, "sales", "alice");
        grant_namespace(&projected, "sales", "local");
        let digest = seed_sales_with_shipments(&projected);
        seed_indexed_customer_order_shipment(&projected, &digest);
        projected.object_index_engine =
            crate::sekai::object_index_engine::ObjectIndexEngineKind::HopProjection;
        projected.object_index_dual_read = true;
        let hop_page = projected
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![
                            ObjectSetTraversal {
                                relation: "placed".into(),
                                direction: "outgoing".into(),
                                far_kind: "Order".into(),
                                join_property: "customer_id".into(),
                            },
                            ObjectSetTraversal {
                                relation: "ships".into(),
                                direction: "outgoing".into(),
                                far_kind: "Shipment".into(),
                                join_property: "order_id".into(),
                            },
                        ],
                        aggregation: Some(ObjectSetAggregation {
                            function: "sum".into(),
                            property: "amount".into(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 100,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(hop_page.aggregates, page.aggregates);
        assert!(!hop_page.authority);

        svc.object_index_engine =
            crate::sekai::object_index_engine::ObjectIndexEngineKind::NestedLoop;
        let refused = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: page.definition_digest.clone(),
                        hops: vec![ObjectSetTraversal {
                            relation: "placed".into(),
                            direction: "outgoing".into(),
                            far_kind: "Order".into(),
                            join_property: "customer_id".into(),
                        }],
                        aggregation: Some(ObjectSetAggregation {
                            function: "count".into(),
                            property: String::new(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 1,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert!(refused.message().contains("max_rows_scanned"));
    }

    #[tokio::test]
    async fn default_multi_hop_evaluate_fails_closed_when_join_is_unready() {
        let svc = service();
        assert_eq!(
            svc.object_index_engine,
            crate::sekai::object_index_engine::ObjectIndexEngineKind::HopProjection
        );
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        assert!(
            svc.db
                .runtime()
                .hop_projection_ready("sales", "Order")
                .unwrap()
        );
        svc.db
            .runtime()
            .set_hop_projection_ready("sales", "Order", false, 99)
            .unwrap();
        let err = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![ObjectSetTraversal {
                            relation: "placed".into(),
                            direction: "outgoing".into(),
                            far_kind: "Order".into(),
                            join_property: "customer_id".into(),
                        }],
                        aggregation: Some(ObjectSetAggregation {
                            function: "count".into(),
                            property: String::new(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 100,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("hop projection is stale"));
    }

    #[tokio::test]
    async fn dual_read_evaluate_fails_closed_without_row_cost_limit() {
        let mut svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        svc.object_index_dual_read = true;
        let err = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![ObjectSetTraversal {
                            relation: "placed".into(),
                            direction: "outgoing".into(),
                            far_kind: "Order".into(),
                            join_property: "customer_id".into(),
                        }],
                        aggregation: Some(ObjectSetAggregation {
                            function: "count".into(),
                            property: String::new(),
                            group_by: "region".into(),
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message()
                .contains("dual-read requires max_rows_scanned")
        );
    }

    #[tokio::test]
    async fn hop_projection_evaluate_fails_closed_when_join_is_unready() {
        let mut svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        svc.object_index_engine =
            crate::sekai::object_index_engine::ObjectIndexEngineKind::HopProjection;
        assert!(
            svc.db
                .runtime()
                .hop_projection_ready("sales", "Order")
                .unwrap()
        );
        svc.db
            .runtime()
            .set_hop_projection_ready("sales", "Order", false, 99)
            .unwrap();
        let err = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![ObjectSetTraversal {
                            relation: "placed".into(),
                            direction: "outgoing".into(),
                            far_kind: "Order".into(),
                            join_property: "customer_id".into(),
                        }],
                        aggregation: Some(ObjectSetAggregation {
                            function: "count".into(),
                            property: String::new(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 100,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("hop projection is stale"));
    }

    #[tokio::test]
    async fn hop_projection_evaluate_fails_closed_when_datasource_revision_is_stale() {
        let mut svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        svc.object_index_engine =
            crate::sekai::object_index_engine::ObjectIndexEngineKind::HopProjection;
        assert!(
            svc.db
                .runtime()
                .hop_projection_ready("sales", "Order")
                .unwrap()
        );
        let mut stale = svc
            .db
            .runtime()
            .get_object_type_datasource("sales", "Order")
            .unwrap()
            .unwrap();
        stale.definition_digest = format!("sha256:{}", "ab".repeat(32));
        svc.db
            .runtime()
            .register_object_type_datasource(&stale, 99)
            .unwrap();
        let err = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![ObjectSetTraversal {
                            relation: "placed".into(),
                            direction: "outgoing".into(),
                            far_kind: "Order".into(),
                            join_property: "customer_id".into(),
                        }],
                        aggregation: Some(ObjectSetAggregation {
                            function: "count".into(),
                            property: String::new(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 100,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("hop projection is stale"));
    }

    #[tokio::test]
    async fn hop_projection_evaluate_fails_closed_when_same_digest_binding_changes() {
        let mut svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        svc.object_index_engine =
            crate::sekai::object_index_engine::ObjectIndexEngineKind::HopProjection;
        assert!(
            svc.db
                .runtime()
                .hop_projection_ready("sales", "Order")
                .unwrap()
        );
        let mut rebound = svc
            .db
            .runtime()
            .get_object_type_datasource("sales", "Order")
            .unwrap()
            .unwrap();
        rebound.dataset_id = "ds-orders-v2".into();
        svc.db
            .runtime()
            .register_object_type_datasource(&rebound, 99)
            .unwrap();
        assert!(
            !svc.db
                .runtime()
                .hop_projection_ready("sales", "Order")
                .unwrap()
        );
        let err = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![ObjectSetTraversal {
                            relation: "placed".into(),
                            direction: "outgoing".into(),
                            far_kind: "Order".into(),
                            join_property: "customer_id".into(),
                        }],
                        aggregation: Some(ObjectSetAggregation {
                            function: "count".into(),
                            property: String::new(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 100,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("hop projection is stale"));
    }

    #[tokio::test]
    async fn nested_loop_evaluate_fails_closed_when_join_is_unready() {
        let mut svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        svc.object_index_engine =
            crate::sekai::object_index_engine::ObjectIndexEngineKind::NestedLoop;
        assert!(
            svc.db
                .runtime()
                .hop_projection_ready("sales", "Order")
                .unwrap()
        );
        svc.db
            .runtime()
            .set_hop_projection_ready("sales", "Order", false, 99)
            .unwrap();
        let err = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![ObjectSetTraversal {
                            relation: "placed".into(),
                            direction: "outgoing".into(),
                            far_kind: "Order".into(),
                            join_property: "customer_id".into(),
                        }],
                        aggregation: Some(ObjectSetAggregation {
                            function: "count".into(),
                            property: String::new(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 100,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("hop projection is stale"));
    }

    #[tokio::test]
    async fn nested_loop_evaluate_fails_closed_when_same_digest_binding_changes() {
        let mut svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        svc.object_index_engine =
            crate::sekai::object_index_engine::ObjectIndexEngineKind::NestedLoop;
        assert!(
            svc.db
                .runtime()
                .hop_projection_ready("sales", "Order")
                .unwrap()
        );
        let mut rebound = svc
            .db
            .runtime()
            .get_object_type_datasource("sales", "Order")
            .unwrap()
            .unwrap();
        rebound.dataset_id = "ds-orders-v2".into();
        svc.db
            .runtime()
            .register_object_type_datasource(&rebound, 99)
            .unwrap();
        assert!(
            !svc.db
                .runtime()
                .hop_projection_ready("sales", "Order")
                .unwrap()
        );
        let err = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![ObjectSetTraversal {
                            relation: "placed".into(),
                            direction: "outgoing".into(),
                            far_kind: "Order".into(),
                            join_property: "customer_id".into(),
                        }],
                        aggregation: Some(ObjectSetAggregation {
                            function: "count".into(),
                            property: String::new(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 100,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("hop projection is stale"));
    }

    #[tokio::test]
    async fn evaluate_object_set_object_log_dual_read_matches_and_fails_closed() {
        let mut svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        seed_mikura_customer_order_shipment(&log, "eu");
        svc.object_log_dual_read = crate::sekai::object_log::ObjectLogDualRead {
            enabled: true,
            log_path: Some(log.clone()),
            sample_n: 1,
        };
        let request = EvaluateObjectSetRequest {
            descriptor: Some(ObjectSetDescriptor {
                contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                namespace: "sales".into(),
                kind: "Customer".into(),
                definition_digest: digest.clone(),
                hops: vec![
                    ObjectSetTraversal {
                        relation: "placed".into(),
                        direction: "outgoing".into(),
                        far_kind: "Order".into(),
                        join_property: "customer_id".into(),
                    },
                    ObjectSetTraversal {
                        relation: "ships".into(),
                        direction: "outgoing".into(),
                        far_kind: "Shipment".into(),
                        join_property: "order_id".into(),
                    },
                ],
                aggregation: Some(ObjectSetAggregation {
                    function: "sum".into(),
                    property: "amount".into(),
                    group_by: "region".into(),
                }),
                cost_limit: Some(ObjectSetCostLimit {
                    max_rows_scanned: 100,
                    max_depth: 3,
                    max_time_ms: 0,
                }),
                ..Default::default()
            }),
            page_token: String::new(),
            required_freshness_ms: 0,
        };
        let page = svc
            .evaluate_object_set(with_named_principal(request.clone(), "alice"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.aggregates.len(), 1);
        assert_eq!(page.aggregates[0].value, 10.0);
        assert!(!page.authority);
        assert_eq!(
            page.source,
            crate::sekai::object_set::EVALUATE_SOURCE_SQL_PROJECTION
        );

        // Same roots and sum, different group: only a grouped compare fails.
        let regrouped = dir.path().join("regrouped.mikura");
        seed_mikura_customer_order_shipment(&regrouped, "us");
        svc.object_log_dual_read.log_path = Some(regrouped);
        let err = svc
            .evaluate_object_set(with_named_principal(request.clone(), "alice"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("mismatch"), "{}", err.message());

        svc.object_log_dual_read.enabled = false;
        let off = svc
            .evaluate_object_set(with_named_principal(request, "alice"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(off.aggregates, page.aggregates);
    }

    #[tokio::test]
    async fn indexed_hops_honour_direction() {
        exercise_indexed_hop_direction(service()).await;
    }

    /// #2412 on PostgreSQL: the indexed hop path takes the same direction.
    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_indexed_hops_honour_direction() {
        let scratch = crate::db::ScratchDatabase::create();
        let db = Arc::new(RuntimeDb::Postgres(Arc::new(scratch.connect())));
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(exercise_indexed_hop_direction(SekaiServiceImpl::new(
                crate::db::store::SekaiStore::from_shared_runtime(db.clone()),
            )));
        drop(db);
    }

    /// Incoming hops follow the near row's join property to the far key,
    /// alone and mixed with outgoing hops (#2412). Both SQL engines and the
    /// object log answer every request: either dual-read fails it on any
    /// disagreement.
    async fn exercise_indexed_hop_direction(mut svc: SekaiServiceImpl) {
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        seed_mikura_customer_order_shipment(&log, "eu");
        svc.object_index_dual_read = true;
        svc.object_log_dual_read = crate::sekai::object_log::ObjectLogDualRead {
            enabled: true,
            log_path: Some(log),
            sample_n: 1,
        };
        let hop = |relation: &str, direction: &str, far_kind: &str, join_property: &str| {
            ObjectSetTraversal {
                relation: relation.into(),
                direction: direction.into(),
                far_kind: far_kind.into(),
                join_property: join_property.into(),
            }
        };
        let evaluate = |root: &str, group_by: &str, hops: Vec<ObjectSetTraversal>| {
            with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: root.into(),
                        definition_digest: digest.clone(),
                        hops,
                        aggregation: Some(ObjectSetAggregation {
                            function: "count".into(),
                            group_by: group_by.into(),
                            ..Default::default()
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 100,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            )
        };
        let groups = |page: &EvaluateObjectSetResponse| -> Vec<(String, i64)> {
            page.aggregates
                .iter()
                .map(|group| (group.group_key.clone(), group.count))
                .collect()
        };
        for (root, group_by, hops, expected) in [
            // Each order reaches the customer its `customer_id` names.
            (
                "Order",
                "customer_id",
                vec![hop("placed", "incoming", "Customer", "customer_id")],
                vec![("c1", 1)],
            ),
            // Two incoming hops; the hidden shipment stays out.
            (
                "Shipment",
                "amount",
                vec![
                    hop("ships", "incoming", "Order", "order_id"),
                    hop("placed", "incoming", "Customer", "customer_id"),
                ],
                vec![("10", 1)],
            ),
            // Incoming then outgoing: back to the customer's orders.
            (
                "Order",
                "customer_id",
                vec![
                    hop("placed", "incoming", "Customer", "customer_id"),
                    hop("placed", "outgoing", "Order", "customer_id"),
                ],
                vec![("c1", 1)],
            ),
        ] {
            let page = svc
                .evaluate_object_set(evaluate(root, group_by, hops))
                .await
                .unwrap_or_else(|status| panic!("{root}: {status}"))
                .into_inner();
            let expected: Vec<(String, i64)> = expected
                .into_iter()
                .map(|(key, count)| (key.to_string(), count))
                .collect();
            assert_eq!(groups(&page), expected, "{root}");
        }

        // `placed` runs Customer to Order, so an incoming hop from a customer
        // does not match the declared link and is refused (#2455).
        let status = svc
            .evaluate_object_set(evaluate(
                "Customer",
                "region",
                vec![hop("placed", "incoming", "Order", "customer_id")],
            ))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);

        // A root outside the index follows its own join property too. The
        // log holds only indexed rows, so only the SQL engines compare here.
        svc.object_log_dual_read.enabled = false;
        svc.db
            .runtime()
            .create_object(&object(
                "o-clerk",
                "Order",
                "Clerk order",
                &[("customer_id", "c1")],
                30,
            ))
            .unwrap();
        let page = svc
            .evaluate_object_set(evaluate(
                "Order",
                "customer_id",
                vec![hop("placed", "incoming", "Customer", "customer_id")],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(groups(&page), vec![("c1".to_string(), 2)]);
    }

    #[tokio::test]
    async fn object_log_dual_read_fails_closed_without_row_cost_limit() {
        let mut svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        svc.object_log_dual_read = crate::sekai::object_log::ObjectLogDualRead {
            enabled: true,
            log_path: None,
            sample_n: 1,
        };
        let err = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![ObjectSetTraversal {
                            relation: "placed".into(),
                            direction: "outgoing".into(),
                            far_kind: "Order".into(),
                            join_property: "customer_id".into(),
                        }],
                        aggregation: Some(ObjectSetAggregation {
                            function: "count".into(),
                            property: String::new(),
                            group_by: "region".into(),
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message()
                .contains("object-log dual-read requires max_rows_scanned")
        );
    }

    #[tokio::test]
    async fn aggregate_property_fails_closed_when_leaf_grant_denies() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        grant_namespace(&svc, "sales", "local");
        let digest = seed_sales_with_shipments(&svc);
        seed_indexed_customer_order_shipment(&svc, &digest);
        svc.db
            .runtime()
            .create_object(&object(
                "s-gate",
                "Shipment",
                "S1",
                &[("order_id", "o1"), ("amount", "10")],
                30,
            ))
            .unwrap();
        let shipment = crate::sekai::object_security::ObjectSecurityPolicy {
            contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "sales".into(),
            kind: "Shipment".into(),
            rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: Some(vec![crate::sekai::object_security::PropertyGrant {
                property: "order_id".into(),
                access: crate::sekai::object_security::PropertyGrantAccess::Read,
            }]),
            value_instance_grants: None,
            required_purpose: None,
        };
        let shipment_revision = svc
            .db
            .runtime()
            .put_object_security_policy(&shipment, "root", "put-shipment", 1)
            .unwrap();
        let instantiated = svc
            .db
            .runtime()
            .list_objects(&domain::ListFilter {
                namespace: Some("sales".into()),
                ..Default::default()
            })
            .unwrap();
        let mut activation = std::collections::BTreeMap::from([(
            "Shipment".into(),
            shipment_revision.revision_digest,
        )]);
        for (index, kind) in instantiated
            .iter()
            .map(|object| object.kind.as_str())
            .filter(|kind| *kind != "Shipment")
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .enumerate()
        {
            let extra = crate::sekai::object_security::ObjectSecurityPolicy {
                contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION
                    .into(),
                namespace: "sales".into(),
                kind: kind.into(),
                rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                    operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                    predicates: vec![
                        crate::sekai::object_security::ObjectSecurityPredicate::AllowAll,
                    ],
                }],
                property_grants: None,
                value_instance_grants: None,
                required_purpose: None,
            };
            let revision = svc
                .db
                .runtime()
                .put_object_security_policy(
                    &extra,
                    "root",
                    &format!("put-{kind}"),
                    10 + index as i64,
                )
                .unwrap();
            activation.insert(kind.to_string(), revision.revision_digest);
        }
        svc.db
            .runtime()
            .activate_object_security_policies("sales", &activation, "root", "activate", 40)
            .unwrap();
        let err = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(ObjectSetDescriptor {
                        contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                        namespace: "sales".into(),
                        kind: "Customer".into(),
                        definition_digest: digest,
                        hops: vec![
                            ObjectSetTraversal {
                                relation: "placed".into(),
                                direction: "outgoing".into(),
                                far_kind: "Order".into(),
                                join_property: "customer_id".into(),
                            },
                            ObjectSetTraversal {
                                relation: "ships".into(),
                                direction: "outgoing".into(),
                                far_kind: "Shipment".into(),
                                join_property: "order_id".into(),
                            },
                        ],
                        aggregation: Some(ObjectSetAggregation {
                            function: "sum".into(),
                            property: "amount".into(),
                            group_by: "region".into(),
                        }),
                        cost_limit: Some(ObjectSetCostLimit {
                            max_rows_scanned: 100,
                            max_depth: 3,
                            max_time_ms: 0,
                        }),
                        ..Default::default()
                    }),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    fn seed_sales_with_shipments(svc: &SekaiServiceImpl) -> String {
        let members = vec![
            member(
                "sales",
                "object_type",
                "Customer",
                r#"{"name":"Customer","properties":{"region":{"type":"string"}}}"#,
            ),
            member(
                "sales",
                "object_type",
                "Order",
                r#"{"name":"Order","properties":{"customer_id":{"type":"string"}}}"#,
            ),
            member(
                "sales",
                "object_type",
                "Shipment",
                r#"{"name":"Shipment","properties":{"order_id":{"type":"string"},"amount":{"type":"number"}}}"#,
            ),
            member(
                "sales",
                "link_type",
                "placed",
                r#"{"name":"placed","from":"Customer","to":"Order"}"#,
            ),
            member(
                "sales",
                "link_type",
                "ships",
                r#"{"name":"ships","from":"Order","to":"Shipment"}"#,
            ),
        ];
        let revision = prepare_revision(
            "sales",
            "",
            members.iter().map(|item| DefinitionRevisionMember {
                member_kind: item.member_kind.clone(),
                member_id: item.member_id.clone(),
                member_digest: item.member_digest.clone(),
            }),
            true,
            "author",
            1,
        )
        .unwrap();
        svc.db
            .runtime()
            .seed_published_definition_revision(&revision, &members)
            .unwrap();
        revision.revision_digest
    }

    fn seed_indexed_customer_order_shipment(svc: &SekaiServiceImpl, digest: &str) {
        index_kind(
            svc,
            digest,
            "Customer",
            "ds-c",
            "customer_id",
            &[("region", "region")],
            vec![
                hashmap(&[("customer_id", "c1"), ("region", "eu"), ("hidden", "0")]),
                hashmap(&[
                    ("customer_id", "c-hidden"),
                    ("region", "eu"),
                    ("hidden", "true"),
                ]),
            ],
        );
        index_kind(
            svc,
            digest,
            "Order",
            "ds-o",
            "order_id",
            &[("customer_id", "customer_id")],
            vec![hashmap(&[
                ("order_id", "o1"),
                ("customer_id", "c1"),
                ("hidden", "0"),
            ])],
        );
        index_kind(
            svc,
            digest,
            "Shipment",
            "ds-s",
            "shipment_id",
            &[("order_id", "order_id"), ("amount", "amount")],
            vec![
                hashmap(&[
                    ("shipment_id", "s1"),
                    ("order_id", "o1"),
                    ("amount", "10"),
                    ("hidden", "0"),
                ]),
                hashmap(&[
                    ("shipment_id", "s-hidden"),
                    ("order_id", "o1"),
                    ("amount", "99"),
                    ("hidden", "true"),
                ]),
            ],
        );
    }

    fn hashmap(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect()
    }

    fn index_kind(
        svc: &SekaiServiceImpl,
        digest: &str,
        kind: &str,
        dataset_id: &str,
        key: &str,
        mapping: &[(&str, &str)],
        rows: Vec<std::collections::HashMap<String, String>>,
    ) {
        let mut columns = vec![key, "hidden"];
        for (_, column) in mapping {
            columns.push(*column);
        }
        columns.sort();
        columns.dedup();
        svc.db
            .runtime()
            .create_dataset(&crate::sekai::dataset::Dataset {
                id: dataset_id.into(),
                name: dataset_id.into(),
                columns: columns
                    .iter()
                    .map(|name| crate::sekai::dataset::ColumnDef {
                        name: (*name).into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    })
                    .collect(),
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        svc.db.runtime().append_rows(dataset_id, &rows).unwrap();
        let binding = crate::sekai::object_type_index::ObjectTypeDatasource {
            contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: kind.into(),
            definition_digest: digest.into(),
            dataset_id: dataset_id.into(),
            key_column: key.into(),
            property_mapping: mapping
                .iter()
                .map(|(property, column)| ((*property).into(), (*column).into()))
                .collect(),
            hidden_column: "hidden".into(),
            edits_only: false,
            conflict_rule: String::new(),
            source_timestamp_property: String::new(),
        }
        .prepare()
        .unwrap();
        svc.db
            .runtime()
            .register_object_type_datasource(&binding, 10)
            .unwrap();
        svc.db
            .runtime()
            .apply_object_type_index("sales", kind, true, 20)
            .unwrap();
    }

    /// Mirror of the indexed sales fixture, with customer `c1` in `region`.
    fn seed_mikura_customer_order_shipment(path: &std::path::Path, region: &str) {
        let mut store = mikura::Store::create(path).unwrap();
        mikura_ingest::BatchIngest::run(
            &mut store,
            vec![
                mikura::ObjectRecord {
                    action_id: None,
                    r#gen: 1,
                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    key: "c1".into(),
                    hidden: false,
                    props: std::collections::HashMap::from([("region".into(), region.into())]),
                    schema_version: 1,
                },
                mikura::ObjectRecord {
                    action_id: None,
                    r#gen: 1,
                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    key: "c-hidden".into(),
                    hidden: true,
                    props: std::collections::HashMap::from([("region".into(), "eu".into())]),
                    schema_version: 1,
                },
                mikura::ObjectRecord {
                    action_id: None,
                    r#gen: 1,
                    namespace: "sales".into(),
                    kind: "Order".into(),
                    key: "o1".into(),
                    hidden: false,
                    props: std::collections::HashMap::from([("customer_id".into(), "c1".into())]),
                    schema_version: 1,
                },
                mikura::ObjectRecord {
                    action_id: None,
                    r#gen: 1,
                    namespace: "sales".into(),
                    kind: "Shipment".into(),
                    key: "s1".into(),
                    hidden: false,
                    props: std::collections::HashMap::from([
                        ("order_id".into(), "o1".into()),
                        ("amount".into(), "10".into()),
                    ]),
                    schema_version: 1,
                },
                mikura::ObjectRecord {
                    action_id: None,
                    r#gen: 1,
                    namespace: "sales".into(),
                    kind: "Shipment".into(),
                    key: "s-hidden".into(),
                    hidden: true,
                    props: std::collections::HashMap::from([
                        ("order_id".into(), "o1".into()),
                        ("amount".into(), "99".into()),
                    ]),
                    schema_version: 1,
                },
            ],
        )
        .unwrap();
    }

    /// A replay reads the rows its run pinned, not the live set, and is
    /// refused once the caller can no longer read a pinned object.
    #[tokio::test]
    async fn replays_read_pinned_object_sets_and_re_authorize_them() {
        use crate::sekai::dataset::{ColumnDef, Dataset};
        use crate::sekai::governed_transform::{ANALYTICAL_CLASS, CONTRACT_VERSION};
        let svc = service();
        let digest = seed_sales_definition(&svc);
        seed_customers_and_orders(&svc);
        for id in ["ops-orders", "ops-out"] {
            svc.db
                .runtime()
                .create_dataset(&Dataset {
                    id: id.into(),
                    name: id.into(),
                    columns: vec![ColumnDef {
                        name: "customer".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    }],
                    object_id: String::new(),
                    created: 1,
                    partition_keys: Vec::new(),
                })
                .unwrap();
        }
        let order =
            |customer: &str| HashMap::from([("customer".to_string(), customer.to_string())]);
        svc.db
            .runtime()
            .append_rows("ops-orders", &[order("c-eu-2"), order("c-eu-3")])
            .unwrap();
        let customers = serde_json::to_string(&crate::sekai::object_set::ObjectSetDescriptor {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: digest.clone(),
            property_filters: vec![domain::PropertyFilter {
                key: "region".into(),
                op: "eq".into(),
                value: "eu".into(),
            }],
            ..Default::default()
        })
        .unwrap();
        let definition = || GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "named".into(),
            output_dataset_id: "ops-out".into(),
            profile: ANALYTICAL_CLASS.into(),
            sql: "SELECT o.customer, c.name FROM orders o \
                  JOIN customers c ON c.id = o.customer ORDER BY o.customer"
                .into(),
            inputs: vec![
                TransformInput {
                    alias: "orders".into(),
                    dataset_id: "ops-orders".into(),
                    object_set: String::new(),
                },
                TransformInput {
                    alias: "customers".into(),
                    dataset_id: String::new(),
                    object_set: customers.clone(),
                },
            ],
            ..GovernedTransform::default()
        };
        svc.put_governed_transform(with_named_principal(
            PutGovernedTransformRequest {
                transform: Some(definition()),
            },
            "local",
        ))
        .await
        .unwrap();
        let run = svc
            .run_governed_transform(with_named_principal(
                RunGovernedTransformRequest {
                    namespace: "ops".into(),
                    transform_id: "named".into(),
                    incremental: false,
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner()
            .run
            .unwrap();
        let pin = run.input_versions["object-set:customers"].clone();

        // The objects change; the replay still reads what the run read.
        let mut renamed = svc.db.runtime().get_object("c-eu-2").unwrap().unwrap();
        renamed.name = "Renamed".into();
        renamed.updated += 1;
        svc.db.runtime().update_object(&renamed).unwrap();
        let replay = || {
            svc.replay_governed_transform(with_named_principal(
                ReplayGovernedTransformRequest {
                    namespace: "ops".into(),
                    transform_id: "named".into(),
                    ..Default::default()
                },
                "local",
            ))
        };
        let replayed = replay().await.unwrap().into_inner().replay.unwrap();
        assert!(replayed.diff.as_ref().unwrap().reproduced, "{replayed:?}");
        assert_eq!(replayed.output_digest, run.output_digest);
        let input = replayed
            .inputs
            .iter()
            .find(|input| input.dataset_id == "object-set:customers")
            .expect("the pinned set is a replay input");
        assert_eq!(input.version_id, pin);

        // A pinned property restricted since is refused, though the caller
        // may read it: object-set rows never carry restricted properties.
        let property = |name: &str, classification: &str| PropertyDef {
            name: name.into(),
            r#type: "string".into(),
            classification: classification.into(),
            ..Default::default()
        };
        let restrict = |classification: &'static str| {
            svc.create_schema_type(with_named_principal(
                CreateSchemaTypeRequest {
                    r#type: Some(ObjectType {
                        kind: "Customer".into(),
                        properties: vec![property("region", classification)],
                        ..Default::default()
                    }),
                },
                "local",
            ))
        };
        restrict("internal").await.unwrap();
        let restricted = replay().await.unwrap_err();
        assert_eq!(
            restricted.code(),
            tonic::Code::PermissionDenied,
            "{restricted:?}"
        );
        assert!(restricted.message().contains("property"), "{restricted:?}");
        restrict("public").await.unwrap();
        assert!(replay().await.is_ok());

        // An object classified since raises the replay's marking with it,
        // which a branch of an unmarked output refuses.
        let mut marked = svc.db.runtime().get_object("c-eu-3").unwrap().unwrap();
        marked.properties.insert(
            crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            "internal".into(),
        );
        marked.updated += 1;
        svc.db.runtime().update_object(&marked).unwrap();
        let raised = replay().await.unwrap_err();
        assert!(raised.message().contains("marking"), "{raised:?}");
        marked
            .properties
            .remove(crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY);
        marked.updated += 1;
        svc.db.runtime().update_object(&marked).unwrap();
        assert!(replay().await.is_ok());

        // A pinned object moved to another kind is not the object read.
        let mut moved = svc.db.runtime().get_object("c-eu-3").unwrap().unwrap();
        moved.kind = "Order".into();
        moved.updated += 1;
        svc.db.runtime().update_object(&moved).unwrap();
        let moved_away = replay().await.unwrap_err();
        assert_eq!(
            moved_away.code(),
            tonic::Code::PermissionDenied,
            "{moved_away:?}"
        );
        moved.kind = "Customer".into();
        moved.updated += 1;
        svc.db.runtime().update_object(&moved).unwrap();
        assert!(replay().await.is_ok());

        // A pinned object the caller can no longer read refuses the replay.
        let owner = security::Grant {
            id: "owner-c-eu-2".into(),
            object_id: "c-eu-2".into(),
            principal: "bob".into(),
            role: security::Role::Admin,
            created: 0,
            ..Default::default()
        };
        svc.db.runtime().create_grant(&owner).unwrap();
        svc.security.add_grant(&owner);
        let refused = replay().await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{refused:?}");

        // A redefinition reading another set under the same alias finds no
        // pin of its own, rather than the old set's rows.
        let us = serde_json::to_string(&crate::sekai::object_set::ObjectSetDescriptor {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: digest.clone(),
            property_filters: vec![domain::PropertyFilter {
                key: "region".into(),
                op: "eq".into(),
                value: "us".into(),
            }],
            ..Default::default()
        })
        .unwrap();
        let mut redefined = definition();
        redefined.inputs[1].object_set = us;
        svc.put_governed_transform(with_named_principal(
            PutGovernedTransformRequest {
                transform: Some(redefined),
            },
            "local",
        ))
        .await
        .unwrap();
        let other = replay().await.unwrap_err();
        assert_eq!(other.code(), tonic::Code::FailedPrecondition, "{other:?}");
        assert!(other.message().contains("descriptor"), "{other:?}");
    }

    /// An isolated run streams the object set its putter reads, matching
    /// `EvaluateObjectSet` for the same principal, to a labelled worker only.
    #[tokio::test]
    async fn isolated_runs_stream_object_set_inputs_to_labelled_workers() {
        use crate::sekai::dataset::{ColumnDef, Dataset};
        use crate::sekai::governed_transform::{ISOLATED_CLASS, OBJECT_SET_INPUT_LABEL};
        let svc = service();
        let digest = seed_sales_definition(&svc);
        seed_customers_and_orders(&svc);
        for id in ["ops-orders", "ops-out"] {
            svc.db
                .runtime()
                .create_dataset(&Dataset {
                    id: id.into(),
                    name: id.into(),
                    columns: vec![ColumnDef {
                        name: "customer".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    }],
                    object_id: String::new(),
                    created: 1,
                    partition_keys: Vec::new(),
                })
                .unwrap();
        }
        let eu = || ObjectSetDescriptor {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: digest.clone(),
            property_filters: vec![PropertyFilter {
                key: "region".into(),
                op: "eq".into(),
                value: "eu".into(),
            }],
            limit: 100,
            ..Default::default()
        };
        let domain_eu = serde_json::to_string(&crate::sekai::object_set::ObjectSetDescriptor {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: digest.clone(),
            property_filters: vec![domain::PropertyFilter {
                key: "region".into(),
                op: "eq".into(),
                value: "eu".into(),
            }],
            ..Default::default()
        })
        .unwrap();
        svc.put_governed_transform(with_named_principal(
            PutGovernedTransformRequest {
                transform: Some(GovernedTransform {
                    contract_version: crate::sekai::governed_transform::CONTRACT_VERSION.into(),
                    namespace: "ops".into(),
                    transform_id: "iso-sets".into(),
                    output_dataset_id: "ops-out".into(),
                    profile: ISOLATED_CLASS.into(),
                    engine: "python".into(),
                    runtime_image: "runner:1".into(),
                    code: "print('ok')".into(),
                    inputs: vec![
                        TransformInput {
                            alias: "orders".into(),
                            dataset_id: "ops-orders".into(),
                            object_set: String::new(),
                        },
                        TransformInput {
                            alias: "customers".into(),
                            dataset_id: String::new(),
                            object_set: domain_eu,
                        },
                    ],
                    ..GovernedTransform::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        let run = svc
            .run_governed_transform(with_named_principal(
                RunGovernedTransformRequest {
                    namespace: "ops".into(),
                    transform_id: "iso-sets".into(),
                    incremental: false,
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner()
            .run
            .unwrap();
        assert!(run.input_versions.contains_key("object-set:customers"));

        let db = svc.db.runtime();
        db.register_transform_runtime("ops", "plain", &Default::default(), "local", 1)
            .unwrap();
        assert!(
            db.claim_transform_work("ops", "plain", "", 60_000, 2)
                .unwrap()
                .is_none()
        );
        let labels = std::collections::BTreeMap::from([(
            OBJECT_SET_INPUT_LABEL.to_string(),
            "v1".to_string(),
        )]);
        db.register_transform_runtime("ops", "sets", &labels, "local", 1)
            .unwrap();
        let (work, _) = db
            .claim_transform_work("ops", "sets", "", 60_000, 2)
            .unwrap()
            .expect("claimable work");
        let streamed = db
            .read_transform_run_input(
                &crate::sekai::governed_transform::WriteTransformRunCommand {
                    run_id: work.run_id,
                    runtime_id: work.claim_owner,
                    claim_generation: work.claim_generation,
                    fencing_token: work.fencing_token,
                    ..Default::default()
                },
                "customers",
                "",
                0,
                100,
                3,
            )
            .unwrap();
        let mut streamed: Vec<String> = streamed
            .iter()
            .map(|row| row.values["id"].clone())
            .collect();
        streamed.sort();
        let evaluated = svc
            .evaluate_object_set(with_named_principal(
                EvaluateObjectSetRequest {
                    descriptor: Some(eu()),
                    page_token: String::new(),
                    required_freshness_ms: 0,
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        let mut expected: Vec<String> = evaluated
            .members
            .iter()
            .map(|object| object.id.clone())
            .collect();
        expected.sort();
        assert!(!expected.is_empty());
        assert_eq!(streamed, expected);
    }

    /// #1977: a transform joins a dataset with an object set read as its
    /// principal; the run pins the set; markings follow; partial access
    /// narrows the rows; no access refuses put, preview and run.
    #[tokio::test]
    async fn object_set_inputs_read_as_the_principal_and_pin() {
        use crate::sekai::dataset::{ColumnDef, Dataset};
        use crate::sekai::governed_transform::{ANALYTICAL_CLASS, CONTRACT_VERSION};
        let svc = service();
        let digest = seed_sales_definition(&svc);
        seed_customers_and_orders(&svc);
        let mut marked = svc.db.runtime().get_object("c-eu-3").unwrap().unwrap();
        marked.properties.insert(
            crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            "internal".into(),
        );
        marked.updated += 1;
        svc.db.runtime().update_object(&marked).unwrap();
        // A marked input needs an output bound to an object.
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: "ops-out-object".into(),
                kind: "artifact".into(),
                name: "out".into(),
                namespace: "ops".into(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        for (id, object_id) in [("ops-orders", ""), ("ops-out", "ops-out-object")] {
            svc.db
                .runtime()
                .create_dataset(&Dataset {
                    id: id.into(),
                    name: id.into(),
                    columns: vec![ColumnDef {
                        name: "customer".into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    }],
                    object_id: object_id.into(),
                    created: 1,
                    partition_keys: Vec::new(),
                })
                .unwrap();
        }
        let order = |customer: &str, amount: &str| {
            HashMap::from([
                ("customer".to_string(), customer.to_string()),
                ("amount".to_string(), amount.to_string()),
            ])
        };
        svc.db
            .runtime()
            .append_rows(
                "ops-orders",
                &[
                    order("c-eu-2", "5"),
                    order("c-eu-3", "9"),
                    order("c-us-2", "7"),
                ],
            )
            .unwrap();
        let customers = serde_json::to_string(&crate::sekai::object_set::ObjectSetDescriptor {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: digest.clone(),
            property_filters: vec![domain::PropertyFilter {
                key: "region".into(),
                op: "eq".into(),
                value: "eu".into(),
            }],
            ..Default::default()
        })
        .unwrap();
        let definition = |transform_id: &str| GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: transform_id.into(),
            output_dataset_id: "ops-out".into(),
            profile: ANALYTICAL_CLASS.into(),
            sql: "SELECT o.customer, o.amount, c.name FROM orders o \
                  JOIN customers c ON c.id = o.customer ORDER BY o.customer"
                .into(),
            inputs: vec![
                TransformInput {
                    alias: "orders".into(),
                    dataset_id: "ops-orders".into(),
                    object_set: String::new(),
                },
                TransformInput {
                    alias: "customers".into(),
                    dataset_id: String::new(),
                    object_set: customers.clone(),
                },
            ],
            ..GovernedTransform::default()
        };
        let adhoc = |principal: &'static str, key: &'static str| {
            svc.run_ad_hoc_governed_transform(with_named_principal(
                RunAdHocGovernedTransformRequest {
                    transform: Some(definition("adhoc")),
                    session_label: "join".into(),
                    idempotency_key: key.into(),
                },
                principal,
            ))
        };

        // Joined with the eu customers, read as the caller and pinned.
        let joined = adhoc("local", "k1").await.unwrap().into_inner();
        let run = joined.run.unwrap();
        assert!(run.input_versions.contains_key("object-set:customers"));
        assert!(run.input_versions.contains_key("ops-orders"));
        let rows = svc
            .db
            .runtime()
            .query_rows(&joined.scratch_dataset_id, &Default::default())
            .unwrap();
        let mut names: Vec<_> = rows.iter().map(|row| row["name"].clone()).collect();
        names.sort();
        assert_eq!(names, ["North", "South"]);
        // A retry replays while the caller still reads the rows it pinned.
        assert!(adhoc("local", "k1").await.unwrap().into_inner().replayed);

        // A restricted property stays out of the rows, even for a reader
        // allowed to see it: no marking carries its classification out.
        let property = |name: &str, classification: &str| PropertyDef {
            name: name.into(),
            r#type: "string".into(),
            classification: classification.into(),
            ..Default::default()
        };
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(ObjectType {
                    kind: "Customer".into(),
                    properties: vec![property("region", "public"), property("tier", "internal")],
                    ..Default::default()
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        let everything = svc
            .run_ad_hoc_governed_transform(with_named_principal(
                RunAdHocGovernedTransformRequest {
                    transform: Some(GovernedTransform {
                        sql: "SELECT c.* FROM customers c JOIN orders o ON o.customer = c.id"
                            .into(),
                        ..definition("adhoc")
                    }),
                    session_label: "all".into(),
                    idempotency_key: "k-restricted".into(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        let rows = svc
            .db
            .runtime()
            .query_rows(&everything.scratch_dataset_id, &Default::default())
            .unwrap();
        assert!(!rows.is_empty());
        assert!(
            rows.iter()
                .all(|row| row.contains_key("region") && !row.contains_key("tier")),
            "{rows:?}"
        );
        // A filter on the restricted property is refused, as it would shape
        // public output by values no marking carries.
        let by_tier = serde_json::to_string(&crate::sekai::object_set::ObjectSetDescriptor {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: digest.clone(),
            property_filters: vec![domain::PropertyFilter {
                key: "tier".into(),
                op: "eq".into(),
                value: "3".into(),
            }],
            ..Default::default()
        })
        .unwrap();
        let mut filtered = definition("adhoc");
        filtered.inputs[1].object_set = by_tier;
        let refused = svc
            .run_ad_hoc_governed_transform(with_named_principal(
                RunAdHocGovernedTransformRequest {
                    transform: Some(filtered),
                    session_label: "tier".into(),
                    idempotency_key: "k-tier".into(),
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::InvalidArgument, "{refused:?}");
        assert!(refused.message().contains("restricted"), "{refused:?}");
        assert!(
            run.markings_out.contains("internal"),
            "{}",
            run.markings_out
        );

        // A stored definition reads as its putter.
        svc.put_governed_transform(with_named_principal(
            PutGovernedTransformRequest {
                transform: Some(definition("stored")),
            },
            "local",
        ))
        .await
        .unwrap();
        let stored = svc
            .run_governed_transform(with_named_principal(
                RunGovernedTransformRequest {
                    namespace: "ops".into(),
                    transform_id: "stored".into(),
                    incremental: false,
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner()
            .run
            .unwrap();
        assert!(stored.input_versions.contains_key("object-set:customers"));
        assert_eq!(
            svc.db.runtime().transform_reader("ops", "stored").unwrap(),
            Some(("local".to_string(), stored.definition_digest.clone()))
        );
        assert_eq!(stored.rows_out, 2);

        // An object the principal may not read is left out.
        let owner = security::Grant {
            id: "owner-c-eu-2".into(),
            object_id: "c-eu-2".into(),
            principal: "bob".into(),
            role: security::Role::Admin,
            created: 0,
            ..Default::default()
        };
        svc.db.runtime().create_grant(&owner).unwrap();
        svc.security.add_grant(&owner);
        let narrowed = adhoc("alice", "k2").await.unwrap().into_inner();
        let rows = svc
            .db
            .runtime()
            .query_rows(&narrowed.scratch_dataset_id, &Default::default())
            .unwrap();
        assert!(
            rows.iter().all(|row| row["customer"] != "c-eu-2"),
            "{rows:?}"
        );
        // A pinned member the caller can no longer read refuses the replay.
        assert_eq!(
            adhoc("local", "k1").await.unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );

        // A namespace the principal may not read refuses put, preview and run.
        grant_namespace(&svc, "sales", "bob");
        assert_eq!(
            adhoc("alice", "k3").await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        let preview = svc
            .preview_governed_transform(with_named_principal(
                PreviewGovernedTransformRequest {
                    transform: Some(definition("preview")),
                    row_cap: 0,
                    preview_id: String::new(),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(preview.code(), tonic::Code::PermissionDenied);
        svc.db
            .runtime()
            .set_transform_reader("ops", "stored", "alice", &stored.definition_digest)
            .unwrap();
        let refused = svc
            .run_governed_transform(with_named_principal(
                RunGovernedTransformRequest {
                    namespace: "ops".into(),
                    transform_id: "stored".into(),
                    incremental: false,
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);

        // A reader recorded for another definition is no reader.
        svc.db
            .runtime()
            .set_transform_reader("ops", "stored", "local", "sha256:another")
            .unwrap();
        let mismatched = svc
            .run_governed_transform(with_named_principal(
                RunGovernedTransformRequest {
                    namespace: "ops".into(),
                    transform_id: "stored".into(),
                    incremental: false,
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(mismatched.code(), tonic::Code::PermissionDenied);

        // A set larger than the input budget stops while it is read.
        let tiny = svc
            .put_governed_transform(with_named_principal(
                PutGovernedTransformRequest {
                    transform: Some(GovernedTransform {
                        memory_limit_bytes: 64,
                        ..definition("tiny")
                    }),
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(tiny.code(), tonic::Code::ResourceExhausted);
        assert!(
            svc.db
                .runtime()
                .get_governed_transform("ops", "tiny")
                .unwrap()
                .is_none()
        );

        // A put without object-set inputs clears the reader in its own write.
        let mut plain = definition("stored");
        plain.inputs.truncate(1);
        plain.sql = "SELECT customer, amount FROM orders".into();
        svc.put_governed_transform(with_named_principal(
            PutGovernedTransformRequest {
                transform: Some(plain),
            },
            "local",
        ))
        .await
        .unwrap();
        assert_eq!(
            svc.db.runtime().transform_reader("ops", "stored").unwrap(),
            None
        );

        // Object-set pins share the run's input keys; datasets beside them,
        // and new datasets, may not take their prefix.
        let mut prefixed = definition("prefixed");
        prefixed.inputs[0].dataset_id = "object-set:customers".into();
        let refused = svc
            .put_governed_transform(with_named_principal(
                PutGovernedTransformRequest {
                    transform: Some(prefixed),
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        let refused = svc
            .create_dataset(with_named_principal(
                CreateDatasetRequest {
                    dataset: Some(crate::grpc::pb::sekai::Dataset {
                        id: "object-set:customers".into(),
                        name: "shadow".into(),
                        ..Default::default()
                    }),
                },
                "local",
            ))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);

        // A committed identity is refused, like a new one, once its sets no
        // longer read.
        svc.db
            .runtime()
            .register_object_type_datasource(
                &crate::sekai::object_type_index::ObjectTypeDatasource {
                    contract_version: "v1".into(),
                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    definition_digest: digest.clone(),
                    dataset_id: "ops-orders".into(),
                    key_column: "customer".into(),
                    property_mapping: Default::default(),
                    hidden_column: String::new(),
                    edits_only: false,
                    conflict_rule: String::new(),
                    source_timestamp_property: String::new(),
                },
                99,
            )
            .unwrap();
        for key in ["k1", "k-new"] {
            assert_eq!(
                adhoc("local", key).await.unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
        }
    }

    fn set_read(
        svc: &SekaiServiceImpl,
        object_set: ObjectSetDescriptor,
        snapshot: &str,
        last_digest: &str,
        experimental: bool,
    ) -> Result<ReadObjectChangeSubscriptionResponse, Status> {
        svc.read_gated_object_change_subscription(
            with_named_principal(
                ReadObjectChangeSubscriptionRequest {
                    subscription_id: "eu-customers".into(),
                    scope: None,
                    snapshot_revision: snapshot.into(),
                    limit: 32,
                    retention_ms: 0,
                    last_page_digest: last_digest.into(),
                    revoke: false,
                    object_set: Some(object_set),
                },
                "alice",
            ),
            experimental,
        )
        .map(Response::into_inner)
    }

    fn set_ops(page: &ReadObjectChangeSubscriptionResponse) -> Vec<(&str, &str)> {
        page.events
            .iter()
            .map(|event| (event.object_id.as_str(), event.op.as_str()))
            .collect()
    }

    fn retier(svc: &SekaiServiceImpl, id: &str, key: &str, value: &str, actor: &str) {
        let mut object = svc.db.runtime().get_object(id).unwrap().unwrap();
        object.properties.insert(key.into(), value.into());
        svc.db
            .runtime()
            .update_object_with_audit(&object, actor)
            .unwrap();
    }

    /// #3038: a membership subscription delivers its snapshot as enters,
    /// then reports each enter and leave once; a replica continues from the
    /// stored cursor, and a member the reader can no longer see leaves with
    /// nothing but its id.
    #[tokio::test]
    async fn object_set_subscription_reports_enter_and_leave_as_the_reader() {
        use crate::sekai::object_change_subscription::{
            OP_ENTER, OP_LEAVE, OUTCOME_PAGE, OUTCOME_REPLAYED, OUTCOME_RESNAPSHOT,
        };
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(
            db.clone(),
        ));
        grant_namespace(&svc, "sales", "alice");
        let digest = seed_sales_definition(&svc);
        seed_customers_and_orders(&svc);
        let set = ObjectSetDescriptor {
            traversal: None,
            order_by: String::new(),
            ..descriptor(&digest, 0)
        };

        let first = set_read(&svc, set.clone(), "", "", true).unwrap();
        assert_eq!(first.outcome, OUTCOME_RESNAPSHOT);
        let revision = first.snapshot_revision;
        // A write between the resnapshot and the first page: the snapshot is
        // delivered as enters, and the history scan after it reconciles the
        // write, so the client never holds a set the subscription missed.
        retier(&svc, "c-eu-1", "tier", "2", "alice");
        let snapshot = set_read(&svc, set.clone(), &revision, "", true).unwrap();
        assert_eq!(snapshot.outcome, OUTCOME_PAGE);
        assert_eq!(
            set_ops(&snapshot),
            [("c-eu-2", OP_ENTER), ("c-eu-3", OP_ENTER)]
        );
        let reconciled = set_read(&svc, set.clone(), &revision, "", true).unwrap();
        assert_eq!(set_ops(&reconciled), [("c-eu-1", OP_ENTER)]);
        let settled = set_read(&svc, set.clone(), &revision, "", true).unwrap();
        assert!(settled.events.is_empty());

        retier(&svc, "c-us-2", "region", "eu", "alice");
        retier(&svc, "c-eu-3", "tier", "1", "alice");
        retier(&svc, "c-eu-1", "region", "us", "alice");
        let page = set_read(&svc, set.clone(), &revision, "", true).unwrap();
        assert_eq!(page.outcome, OUTCOME_PAGE);
        assert_eq!(
            set_ops(&page),
            [
                ("c-us-2", OP_ENTER),
                ("c-eu-3", OP_LEAVE),
                ("c-eu-1", OP_LEAVE)
            ]
        );
        let replay = set_read(&svc, set.clone(), &revision, &page.page_digest, true).unwrap();
        assert_eq!(replay.outcome, OUTCOME_REPLAYED);

        // A replica on the same store continues from the committed cursor.
        let replica = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db));
        grant_namespace(&replica, "sales", "alice");
        assert!(
            set_read(&replica, set.clone(), &revision, "", true)
                .unwrap()
                .events
                .is_empty()
        );
        svc.db
            .runtime()
            .delete_object_with_audit("c-us-2", "alice")
            .unwrap();
        let deleted = set_read(&replica, set.clone(), &revision, "", true).unwrap();
        assert_eq!(set_ops(&deleted), [("c-us-2", OP_LEAVE)]);

        // Another principal's grant hides the member from alice; its next
        // change makes it leave, naming no field or operation.
        let grant = security::Grant {
            id: "c-eu-2-bob".into(),
            object_id: "c-eu-2".into(),
            principal: "bob".into(),
            role: security::Role::Admin,
            created: 0,
            ..Default::default()
        };
        svc.db.runtime().create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
        retier(&svc, "c-eu-2", "tier", "3", "bob");
        let hidden = set_read(&svc, set, &revision, "", true).unwrap();
        assert_eq!(set_ops(&hidden), [("c-eu-2", OP_LEAVE)]);
        assert!(hidden.events[0].field.is_empty());
        assert!(hidden.events[0].operation_id.is_empty());
    }

    #[tokio::test]
    async fn object_set_subscription_refuses_unsupported_descriptors() {
        let svc = service();
        grant_namespace(&svc, "sales", "alice");
        let digest = seed_sales_definition(&svc);
        let filtered = ObjectSetDescriptor {
            traversal: None,
            ..descriptor(&digest, 0)
        };
        let disabled = set_read(&svc, filtered.clone(), "", "", false).unwrap_err();
        assert_eq!(disabled.code(), tonic::Code::Unimplemented);
        let traversal = set_read(&svc, descriptor(&digest, 0), "", "", true).unwrap_err();
        assert_eq!(traversal.code(), tonic::Code::FailedPrecondition);

        // Another principal reusing alice's subscription id writes no baseline.
        let revision = set_read(&svc, filtered.clone(), "", "", true)
            .unwrap()
            .snapshot_revision;
        set_read(&svc, filtered.clone(), &revision, "", true).unwrap();
        grant_namespace(&svc, "sales", "mallory");
        let intruder = svc
            .read_gated_object_change_subscription(
                with_named_principal(
                    ReadObjectChangeSubscriptionRequest {
                        subscription_id: "eu-customers".into(),
                        object_set: Some(filtered),
                        ..Default::default()
                    },
                    "mallory",
                ),
                true,
            )
            .unwrap_err();
        assert_eq!(intruder.code(), tonic::Code::NotFound);
    }
}
