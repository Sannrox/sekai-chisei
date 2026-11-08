-- Live working-memory list by instance (#2034). list_all_objects scanned
-- every site_agent_memory row in the namespace; this index matches the
-- keyset query (namespace, instance_id, id) for one instance.
CREATE INDEX IF NOT EXISTS idx_sekai_objects_site_agent_memory_instance
    ON sekai_objects (
        namespace,
        (sekai_jsonb_object(properties) ->> 'instance_id'),
        id
    )
    WHERE kind = 'site_agent_memory';
