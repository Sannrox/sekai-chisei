-- Forget redaction looks up writer Actions and decision memory by object_id
-- (#2048). Without these indexes the predicates seq-scan every writer row
-- in the namespace.
CREATE INDEX IF NOT EXISTS idx_action_instances_writer_object
    ON sekai_action_instances (
        namespace,
        ((parameters_json::jsonb ->> 'object_id'))
    )
    WHERE type_id IN (
        'site_agent.memory.create',
        'site_agent.memory.update',
        'site_agent.memory.forget'
    );

CREATE INDEX IF NOT EXISTS idx_decision_memory_writer_parameters_object
    ON sekai_action_decision_memory (
        namespace,
        ((
            CASE
                WHEN coalesce(body_json::jsonb ->> 'parameters_json', '') IN ('', 'null')
                    THEN NULL
                ELSE (body_json::jsonb ->> 'parameters_json')::jsonb ->> 'object_id'
            END
        ))
    )
    WHERE type_id IN (
        'site_agent.memory.create',
        'site_agent.memory.update',
        'site_agent.memory.forget'
    );

CREATE INDEX IF NOT EXISTS idx_decision_memory_writer_facts_object
    ON sekai_action_decision_memory (
        namespace,
        ((
            CASE
                WHEN coalesce(body_json::jsonb ->> 'facts_json', '') IN ('', 'null')
                    THEN NULL
                ELSE (body_json::jsonb ->> 'facts_json')::jsonb ->> 'object_id'
            END
        ))
    )
    WHERE type_id IN (
        'site_agent.memory.create',
        'site_agent.memory.update',
        'site_agent.memory.forget'
    );
