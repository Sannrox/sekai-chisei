#!/usr/bin/env bash
set -euo pipefail

row_count="${1:-100000}"
case "$row_count" in
  ''|*[!0-9]*) echo "row count must be a positive integer" >&2; exit 2 ;;
esac
row_count="$((10#$row_count))"
if [ "$row_count" -eq 0 ]; then
  echo "row count must be a positive integer" >&2
  exit 2
fi

spike_dir="$(mktemp -d "${TMPDIR:-/tmp}/sekai-temporal-spike.XXXXXX")"
trap 'rm -rf "$spike_dir"' EXIT
current_db="$spike_dir/current.db"
temporal_db="$spike_dir/temporal.db"
lookup_id="$(printf 'object-%08d' "$(((row_count + 1) / 2))")"

sqlite3 "$current_db" <<SQL
PRAGMA journal_mode=OFF;
PRAGMA synchronous=OFF;
CREATE TABLE objects (
  id TEXT PRIMARY KEY,
  namespace TEXT NOT NULL,
  properties TEXT NOT NULL
);
WITH RECURSIVE n(i) AS (
  VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < $row_count
)
INSERT INTO objects
SELECT printf('object-%08d', i), 'default', json_object('value', i) FROM n;
CREATE INDEX objects_namespace ON objects(namespace, id);
VACUUM;
SQL

sqlite3 "$temporal_db" <<SQL
PRAGMA journal_mode=OFF;
PRAGMA synchronous=OFF;
CREATE TABLE assertions (
  assertion_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  namespace TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  predicate TEXT NOT NULL,
  object_json TEXT NOT NULL,
  valid_from_kind TEXT NOT NULL CHECK (valid_from_kind IN ('known', 'unbounded', 'unknown')),
  valid_from_ms INTEGER,
  valid_to_kind TEXT NOT NULL CHECK (valid_to_kind IN ('known', 'unbounded', 'unknown')),
  valid_to_ms INTEGER,
  recorded_from_revision INTEGER NOT NULL,
  recorded_to_revision INTEGER,
  recorded_at_ms INTEGER NOT NULL,
  source_observed_at_ms INTEGER,
  source_id TEXT NOT NULL,
  PRIMARY KEY (assertion_id, version),
  CHECK ((valid_from_kind = 'known') = (valid_from_ms IS NOT NULL)),
  CHECK ((valid_to_kind = 'known') = (valid_to_ms IS NOT NULL)),
  CHECK (valid_to_kind != 'known' OR valid_from_kind != 'known' OR valid_from_ms < valid_to_ms),
  CHECK (recorded_to_revision IS NULL OR recorded_from_revision < recorded_to_revision)
);
WITH RECURSIVE n(i) AS (
  VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < $row_count
)
INSERT INTO assertions
SELECT printf('assertion-%08d', i), 1, 'default', printf('object-%08d', i),
       'example:value', json_object('value', i), 'known', 0, 'unbounded', NULL,
       1, NULL, 1000, 900,
       printf('source-%08d', i)
FROM n;
CREATE INDEX assertions_current
  ON assertions(namespace, subject_id, predicate, valid_from_kind, valid_from_ms,
                valid_to_kind, valid_to_ms)
  WHERE recorded_to_revision IS NULL;
CREATE INDEX assertions_as_of
  ON assertions(namespace, subject_id, predicate, recorded_from_revision,
                recorded_to_revision,
                valid_from_kind, valid_from_ms, valid_to_kind, valid_to_ms);
VACUUM;
SQL

current_bytes="$(stat -f %z "$current_db" 2>/dev/null || stat -c %s "$current_db")"
temporal_bytes="$(stat -f %z "$temporal_db" 2>/dev/null || stat -c %s "$temporal_db")"
printf 'rows=%s current_bytes=%s temporal_bytes=%s ratio=' "$row_count" "$current_bytes" "$temporal_bytes"
awk -v temporal="$temporal_bytes" -v current="$current_bytes" 'BEGIN { printf "%.2f\n", temporal / current }'

printf 'current lookup plan: '
sqlite3 "$current_db" "EXPLAIN QUERY PLAN SELECT properties FROM objects WHERE id='$lookup_id';" | tail -1
printf 'bitemporal as-of plan: '
sqlite3 "$temporal_db" "EXPLAIN QUERY PLAN SELECT object_json FROM assertions WHERE namespace='default' AND subject_id='$lookup_id' AND predicate='example:value' AND recorded_from_revision<=1 AND (recorded_to_revision IS NULL OR recorded_to_revision>1) AND (valid_from_kind='unbounded' OR (valid_from_kind='known' AND valid_from_ms<=500)) AND (valid_to_kind='unbounded' OR (valid_to_kind='known' AND valid_to_ms>500));" | tail -1

printf 'current lookup x1000: '
/usr/bin/time -p sh -c "i=0; while [ \$i -lt 1000 ]; do sqlite3 '$current_db' \"SELECT properties FROM objects WHERE id='$lookup_id';\" >/dev/null; i=\$((i+1)); done" 2>&1 | awk '/^real / { print $2 "s" }'
printf 'bitemporal as-of x1000: '
/usr/bin/time -p sh -c "i=0; while [ \$i -lt 1000 ]; do sqlite3 '$temporal_db' \"SELECT object_json FROM assertions WHERE namespace='default' AND subject_id='$lookup_id' AND predicate='example:value' AND recorded_from_revision<=1 AND (recorded_to_revision IS NULL OR recorded_to_revision>1) AND (valid_from_kind='unbounded' OR (valid_from_kind='known' AND valid_from_ms<=500)) AND (valid_to_kind='unbounded' OR (valid_to_kind='known' AND valid_to_ms>500));\" >/dev/null; i=\$((i+1)); done" 2>&1 | awk '/^real / { print $2 "s" }'
