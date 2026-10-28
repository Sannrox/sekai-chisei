-- Default per-work-unit budget limits (#1862). A row on a scope applies to
-- every `work_unit:` scope directly under it that has no limit of its own;
-- each work unit counts its own usage. No row keeps work units unlimited.
CREATE TABLE IF NOT EXISTS chisei_budget_work_unit_defaults (
    scope_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    max_amount BIGINT NOT NULL,
    period_type TEXT NOT NULL,
    home_site_id TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scope_id, metric)
);
