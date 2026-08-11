//! Runtime Ontology definition mutation behind one private domain interface.
//!
//! The gRPC adapter owns caller authentication and protocol translation. This
//! module owns reference visibility, mapped schema-kind ensure, deterministic
//! definition validation, audited persistence, and grant-cache cleanup.

use super::*;

impl SekaiServiceImpl {
    pub(super) fn create_ontology_class_definition(
        &self,
        principals: &[String],
        parsed: ontology::OntologyClass,
    ) -> Result<ontology::OntologyClass, Status> {
        check_ontology_admin(
            &self.security,
            &ontology_class_object_id(&parsed.name),
            principals,
        )?;
        for reference in parsed
            .superclasses
            .iter()
            .chain(&parsed.equivalent_classes)
            .chain(&parsed.disjoint_classes)
        {
            check_read(
                &self.security,
                &ontology_class_object_id(reference),
                principals,
            )?;
        }
        self.ensure_mapped_kind(&parsed, principals)?;
        let mut registry = self.db.load_ontology_registry().map_err(Status::internal)?;
        let existing = registry.get_class(&parsed.name).cloned();
        registry.remove_class(&parsed.name);
        ontology::validate_class_definition(&parsed, existing.as_ref(), &registry)
            .map_err(Status::invalid_argument)?;
        self.db
            .upsert_ontology_class_with_audit(&parsed, actor(principals))
            .map_err(Status::internal)?;
        Ok(parsed)
    }

    pub(super) fn delete_ontology_class_definition(
        &self,
        principals: &[String],
        name: &str,
    ) -> Result<(), Status> {
        check_ontology_admin(&self.security, &ontology_class_object_id(name), principals)?;
        let registry = self.db.load_ontology_registry().map_err(Status::internal)?;
        for class in registry.classes() {
            if class.name != name
                && class
                    .superclasses
                    .iter()
                    .chain(&class.equivalent_classes)
                    .chain(&class.disjoint_classes)
                    .any(|reference| reference == name)
            {
                return Err(Status::failed_precondition(format!(
                    "class '{}' still references '{name}'",
                    class.name
                )));
            }
        }
        for relation in registry.relations() {
            if relation.domain == name || relation.range == name {
                return Err(Status::failed_precondition(format!(
                    "relation '{}' still uses '{name}' as domain or range",
                    relation.name
                )));
            }
        }
        let object_id = ontology_class_object_id(name);
        let grants = self.db.list_grants(&object_id).map_err(Status::internal)?;
        if !self
            .db
            .delete_ontology_class_with_audit(name, actor(principals))
            .map_err(Status::internal)?
        {
            return Err(Status::not_found("ontology class not found"));
        }
        for grant in grants {
            self.security.remove_grant(&object_id, &grant.principal);
        }
        Ok(())
    }

    pub(super) fn create_ontology_relation_definition(
        &self,
        principals: &[String],
        parsed: ontology::OntologyRelation,
    ) -> Result<ontology::OntologyRelation, Status> {
        check_ontology_admin(
            &self.security,
            &ontology_relation_object_id(&parsed.name),
            principals,
        )?;
        for endpoint in [&parsed.domain, &parsed.range] {
            check_read(
                &self.security,
                &ontology_class_object_id(endpoint),
                principals,
            )?;
        }
        if !parsed.inverse.is_empty() {
            check_read(
                &self.security,
                &ontology_relation_object_id(&parsed.inverse),
                principals,
            )?;
        }
        let mut registry = self.db.load_ontology_registry().map_err(Status::internal)?;
        let existing = registry.get_relation(&parsed.name).cloned();
        registry.remove_relation(&parsed.name);
        ontology::validate_relation_definition(&parsed, existing.as_ref(), &registry)
            .map_err(Status::invalid_argument)?;
        for referencing in registry
            .relations()
            .into_iter()
            .filter(|relation| relation.inverse == parsed.name)
        {
            if referencing.domain != parsed.range || referencing.range != parsed.domain {
                return Err(Status::invalid_argument(format!(
                    "relation '{}' would no longer reverse inverse '{}'",
                    referencing.name, parsed.name
                )));
            }
        }
        self.db
            .upsert_ontology_relation_with_audit(&parsed, actor(principals))
            .map_err(Status::internal)?;
        Ok(parsed)
    }

    pub(super) fn delete_ontology_relation_definition(
        &self,
        principals: &[String],
        name: &str,
    ) -> Result<(), Status> {
        check_ontology_admin(
            &self.security,
            &ontology_relation_object_id(name),
            principals,
        )?;
        let registry = self.db.load_ontology_registry().map_err(Status::internal)?;
        if let Some(referencing) = registry
            .relations()
            .into_iter()
            .find(|relation| relation.name != name && relation.inverse == name)
        {
            return Err(Status::failed_precondition(format!(
                "relation '{}' still uses '{name}' as its inverse",
                referencing.name
            )));
        }
        let object_id = ontology_relation_object_id(name);
        let grants = self.db.list_grants(&object_id).map_err(Status::internal)?;
        if !self
            .db
            .delete_ontology_relation_with_audit(name, actor(principals))
            .map_err(Status::internal)?
        {
            return Err(Status::not_found("ontology relation not found"));
        }
        for grant in grants {
            self.security.remove_grant(&object_id, &grant.principal);
        }
        Ok(())
    }

    fn ensure_mapped_kind(
        &self,
        parsed: &ontology::OntologyClass,
        principals: &[String],
    ) -> Result<(), Status> {
        if parsed.mapped_kind.is_empty() {
            return Ok(());
        }
        let kind = parsed.mapped_kind.as_str();
        let needs_ensure = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .get(kind)
            .is_none();
        if !needs_ensure {
            return check_read(&self.security, &schema_object_id(kind), principals);
        }
        if schema::is_builtin_schema_kind(kind) {
            return Err(Status::invalid_argument(
                "mapped schema kind not found for builtin kind",
            ));
        }
        let object_type = schema::ObjectType {
            kind: kind.to_string(),
            description: format!("Object kind ensured for ontology class {}", parsed.name),
            properties: Vec::new(),
            is_builtin: false,
            implements: Vec::new(),
        };
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            schema::validate_object_type_definition(
                &object_type,
                registry.get(&object_type.kind),
                &registry,
            )
            .map_err(Status::invalid_argument)?;
        }
        validate_computed_property_functions(&self.db, &object_type)?;
        self.db
            .upsert_object_type(&object_type)
            .map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .register(object_type);
        self.schema_load_errors
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove(kind);
        Ok(())
    }
}

fn actor(principals: &[String]) -> &str {
    principals.first().map(String::as_str).unwrap_or_default()
}
