use std::collections::HashMap;

use sekai_chisei::grpc::pb::sekai::{Link, Object};

fn main() {
    let (objects, links) = incident_response_graph();

    println!("incident response expressed through core contracts:");
    for object in &objects {
        println!("- {:<12} {}", object.kind, object.name);
    }
    println!("relations:");
    for link in &links {
        println!("- {} --{}--> {}", link.from_id, link.relation, link.to_id);
    }
}

fn incident_response_graph() -> (Vec<Object>, Vec<Link>) {
    let namespace = object("namespace", "operations", "production");
    let actor = object("actor", "actor:on-call", "incident commander");
    let operation = object("operation", "operation:restore-service", "restore service");
    let attempt = object(
        "attempt",
        "attempt:restore-service:1",
        "first response attempt",
    );
    let action = object("action", "action:shift-traffic", "shift traffic");
    let artifact = object(
        "artifact",
        "artifact:status-update",
        "operator status update",
    );
    let verification = object(
        "verification",
        "verification:service-health",
        "service health check",
    );
    let outcome = object("outcome", "outcome:service-restored", "service restored");

    let links = vec![
        link(&namespace, &operation, "contains"),
        link(&actor, &attempt, "performed"),
        link(&attempt, &operation, "attempted"),
        link(&attempt, &action, "produced"),
        link(&action, &artifact, "produced"),
        link(&verification, &attempt, "verified"),
        link(&verification, &outcome, "supports"),
        link(&outcome, &operation, "resolved"),
    ];

    (
        vec![
            namespace,
            actor,
            operation,
            attempt,
            action,
            artifact,
            verification,
            outcome,
        ],
        links,
    )
}

fn object(kind: &str, id: &str, name: &str) -> Object {
    Object {
        id: id.into(),
        kind: kind.into(),
        name: name.into(),
        namespace: "operations".into(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 0,
        updated: 0,
    }
}

fn link(from: &Object, to: &Object, relation: &str) -> Link {
    Link {
        id: format!("{}:{relation}:{}", from.id, to.id),
        from_id: from.id.clone(),
        to_id: to.id.clone(),
        relation: relation.into(),
        created: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_uses_only_domain_neutral_object_kinds() {
        let (objects, links) = incident_response_graph();
        let kinds = objects
            .iter()
            .map(|object| object.kind.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            kinds,
            [
                "namespace",
                "actor",
                "operation",
                "attempt",
                "action",
                "artifact",
                "verification",
                "outcome",
            ]
        );
        assert_eq!(links.len(), 8);
        assert!(
            objects
                .iter()
                .all(|object| object.namespace == "operations")
        );
    }
}
