-- Execution-evidence lifecycle state and conflict alerts (#1318).
-- Evidence rows live in 0012; these tables finish reject/record/resolve parity.
CREATE TABLE IF NOT EXISTS sekai_external_action_execution_state (
 redemption_id TEXT PRIMARY KEY,
 execution_id TEXT NOT NULL,
 permit_id TEXT NOT NULL,
 source_type TEXT NOT NULL,
 source_instance TEXT NOT NULL,
 source_record_id TEXT NOT NULL,
 lifecycle_state TEXT NOT NULL,
 source_sequence BIGINT NOT NULL,
 terminal BOOLEAN NOT NULL,
 updated_at_ms BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS sekai_external_action_execution_alerts (
 alert_id TEXT PRIMARY KEY,
 kind TEXT NOT NULL,
 permit_id TEXT NOT NULL,
 redemption_id TEXT NOT NULL,
 execution_id TEXT NOT NULL,
 observed_at_ms BIGINT NOT NULL,
 summary TEXT NOT NULL);
