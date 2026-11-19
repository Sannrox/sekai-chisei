-- Drop the search index of planes from before #2250 (#2255). Migration 0154
-- seeded the *_v2 tables from it, and rollback below the release that
-- shipped them is unsupported, so nothing reads these tables any more. Their
-- full-text indexes and id sequences go with them.
DROP TABLE IF EXISTS
    sekai_search_checkpoint,
    sekai_search_object,
    sekai_search_object_text,
    sekai_search_dataset,
    sekai_search_dataset_text;
