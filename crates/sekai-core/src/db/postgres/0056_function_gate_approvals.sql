-- Function revisions (by digest) whose evaluation gate allowed publish (#1384).
CREATE TABLE IF NOT EXISTS sekai_function_gate_approvals (
    function_digest TEXT PRIMARY KEY,
    name TEXT NOT NULL
);
