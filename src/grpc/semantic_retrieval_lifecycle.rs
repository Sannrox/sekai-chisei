//! Semantic retrieval reasoning behind one private interface.
//!
//! The gRPC adapter owns authentication, catalog metadata, and protocol-specific
//! projections for expansion and explanation. This module owns retrieval-query
//! parsing, the authorization-filtered ontology snapshot, bounded reasoning,
//! denial normalization, computed properties, and the canonical result projection.

use super::*;

impl SekaiServiceImpl {
    pub(super) fn execute_retrieve_context(
        &self,
        principals: &[String],
        policy_context: &crate::sekai::object_security::PrincipalPolicyContext,
        inner: RetrieveContextRequest,
    ) -> Result<RetrieveContextResponse, Status> {
        let reasoning_started = std::time::Instant::now();
        let roots = inner
            .roots
            .into_iter()
            .map(from_proto_context_root)
            .collect::<Result<Vec<_>, _>>()?;
        let direction =
            retrieval::RetrievalDirection::parse(&inner.direction).map_err(map_retrieval_error)?;
        let reasoning_mode =
            retrieval::ReasoningMode::parse(&inner.reasoning_mode).map_err(map_retrieval_error)?;
        let mut query = retrieval::RetrievalQuery {
            roots,
            relations: inner.relations,
            direction,
            max_depth: inner.max_depth,
            max_objects: inner.max_objects,
            max_links: inner.max_links,
            kind_filter: inner.kind_filter,
            reasoning_mode,
            max_source_rows: inner.max_source_rows,
            max_derived_rows: inner.max_derived_rows,
            max_derivation_steps: inner.max_derivation_steps,
            max_time_ms: inner.max_time_ms,
            max_explanation_bytes: inner.max_explanation_bytes,
            initial_source_rows: 0,
            source_rows_truncated: false,
            policy_context: Some(policy_context.clone()),
        };
        let reasoning_timeout =
            std::time::Duration::from_millis(u64::from(if query.max_time_ms == 0 {
                retrieval::DEFAULT_MAX_TIME_MS
            } else {
                query.max_time_ms.min(retrieval::MAX_TIME_MS)
            }));
        let reasoning_deadline = reasoning_started + reasoning_timeout;
        let ontology_row_limit = if query.max_source_rows == 0 {
            retrieval::DEFAULT_MAX_SOURCE_ROWS
        } else {
            query.max_source_rows.min(retrieval::MAX_SOURCE_ROWS)
        };
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();

        // Hidden definitions cannot influence closure, counts, explanations,
        // errors, or truncation metadata.
        let mut ontology_source_rows = 0u32;
        let mut ontology_source_truncated = false;
        let ontology = if reasoning_mode == retrieval::ReasoningMode::Entailment {
            if self.db.backend_name() == "postgres" {
                return Err(Status::failed_precondition(
                    "sekai.context.retrieve entailment is unavailable on the PostgreSQL community runtime; use asserted_only",
                ));
            }
            let mut classes = match self.db.list_readable_ontology_classes(
                principals,
                reasoning_deadline,
                ontology_row_limit.saturating_add(1),
            ) {
                Ok(classes) => classes,
                Err(_) if reasoning_started.elapsed() >= reasoning_timeout => Vec::new(),
                Err(error) => return Err(Status::internal(error)),
            };
            if classes.len() > ontology_row_limit as usize {
                classes.truncate(ontology_row_limit as usize);
                ontology_source_truncated = true;
            }
            ontology_source_rows = classes.len().min(u32::MAX as usize) as u32;
            let mut classes = classes
                .into_iter()
                .take_while(|_| reasoning_started.elapsed() < reasoning_timeout)
                .filter(|class| {
                    check_read(
                        &self.security,
                        &ontology_class_object_id(&class.name),
                        principals,
                    )
                    .is_ok()
                })
                .collect::<Vec<_>>();
            let visible_class_names = classes
                .iter()
                .map(|class| class.name.clone())
                .collect::<std::collections::HashSet<_>>();
            for class in &mut classes {
                class
                    .superclasses
                    .retain(|name| visible_class_names.contains(name));
                class
                    .equivalent_classes
                    .retain(|name| visible_class_names.contains(name));
                class
                    .disjoint_classes
                    .retain(|name| visible_class_names.contains(name));
            }
            let remaining_rows = ontology_row_limit.saturating_sub(ontology_source_rows);
            let mut relation_rows =
                if !ontology_source_truncated && reasoning_started.elapsed() < reasoning_timeout {
                    self.db
                        .list_readable_ontology_relations(
                            principals,
                            reasoning_deadline,
                            remaining_rows.saturating_add(1),
                        )
                        .or_else(|error| {
                            if reasoning_started.elapsed() >= reasoning_timeout {
                                Ok(Vec::new())
                            } else {
                                Err(error)
                            }
                        })
                        .map_err(Status::internal)?
                } else {
                    Vec::new()
                };
            if relation_rows.len() > remaining_rows as usize {
                relation_rows.truncate(remaining_rows as usize);
                ontology_source_truncated = true;
            }
            ontology_source_rows = ontology_source_rows
                .saturating_add(relation_rows.len().min(u32::MAX as usize) as u32);
            let mut relations = relation_rows
                .into_iter()
                .take_while(|_| reasoning_started.elapsed() < reasoning_timeout)
                .filter(|relation| {
                    check_read(
                        &self.security,
                        &ontology_relation_object_id(&relation.name),
                        principals,
                    )
                    .is_ok()
                })
                .filter(|relation| {
                    visible_class_names.contains(&relation.domain)
                        && visible_class_names.contains(&relation.range)
                })
                .collect::<Vec<_>>();
            let visible_relation_names = relations
                .iter()
                .map(|relation| relation.name.clone())
                .collect::<std::collections::HashSet<_>>();
            for relation in &mut relations {
                if !relation.inverse.is_empty()
                    && !visible_relation_names.contains(&relation.inverse)
                {
                    relation.inverse.clear();
                }
            }
            Some(ontology::OntologyRegistry::from_parts(classes, relations))
        } else {
            None
        };

        query.initial_source_rows = ontology_source_rows;
        query.source_rows_truncated = ontology_source_truncated;
        let mut result = retrieval::retrieve_with_ontology_started(
            &self.db,
            &query,
            ontology.as_ref(),
            reasoning_started,
            |object| {
                self.security.can_access(&object.id, &principal_refs)
                    && check_team_namespace(&self.db, principals, &object.namespace, false).is_ok()
                    && object_passes_marking(&self.db, object, principals).unwrap_or(false)
            },
            |object| is_reserved_governance_kind(&object.kind),
        )
        .map_err(map_retrieval_error)?;

        // A denied root remains observationally equivalent to a missing root.
        let denied_roots = result.denied_roots;
        result.denied_objects = 0;
        result.unresolved_roots = result.unresolved_roots.saturating_add(denied_roots);
        result.denied_roots = 0;
        if reasoning_mode == retrieval::ReasoningMode::Entailment
            && reasoning_started.elapsed() >= reasoning_timeout
            && !result
                .truncation_reasons
                .iter()
                .any(|reason| reason == "time")
        {
            result.truncation_reasons.push("time".into());
            result.truncated = true;
        }
        for candidate in &mut result.candidates {
            candidate.object = self.resolve_computed_for_response_with_policy(
                candidate.object.clone(),
                principals,
                Some(policy_context),
                None,
            )?;
        }

        Ok(RetrieveContextResponse {
            candidates: result
                .candidates
                .iter()
                .map(|candidate| ContextCandidate {
                    object: Some(to_proto_obj(&candidate.object)),
                    depth: candidate.depth,
                    via_relation: candidate.via_relation.clone(),
                    affinity: candidate.affinity,
                    explanation: Some(ContextExplanation {
                        steps: candidate
                            .explanation
                            .steps
                            .iter()
                            .map(|step| ContextDerivationStep {
                                kind: step.kind.into(),
                                relation: step.relation.clone(),
                                from_id: step.from_id.clone(),
                                to_id: step.to_id.clone(),
                                source_fact_ids: step.source_fact_ids.clone(),
                                ontology_revision: step.ontology_revision.clone(),
                                rule: step.rule.into(),
                            })
                            .collect(),
                        source_fact_ids: candidate.explanation.source_fact_ids.clone(),
                        ontology_revision: candidate.explanation.ontology_revision.clone(),
                        derived: candidate.explanation.derived,
                    }),
                    descriptor: Some(to_proto_epistemic_descriptor(
                        &DomainEpistemicDescriptor::from_graph_explanation(
                            &candidate.explanation,
                            result
                                .truncation_reasons
                                .iter()
                                .any(|reason| reason == "source_rows"),
                        ),
                    )),
                })
                .collect(),
            links: result.links.iter().map(to_proto_link).collect(),
            truncated: result.truncated,
            unresolved_roots: result.unresolved_roots,
            denied_objects: result.denied_objects,
            truncated_objects: result.truncated_objects,
            truncated_links: result.truncated_links,
            truncation_reasons: result.truncation_reasons,
            source_rows: result.source_rows,
            derived_rows: result.derived_rows,
            ontology_revision: result.ontology_revision,
            epistemic_descriptor_version: EPISTEMIC_DESCRIPTOR_VERSION.into(),
        })
    }
}
