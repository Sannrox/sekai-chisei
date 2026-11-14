# Sample observation recording

Sample observations are admitted internally through `put_sample_observation`
during trusted `RecordUsage` and execution-lifecycle scoring. There is no
public write or read RPC for this queue.

The bounded scoring-admission row is an internal worker input. After the
scoring worker consumes a row, it is gone from this surface. Durable scored
evidence is owned by evaluation and receipt records.
