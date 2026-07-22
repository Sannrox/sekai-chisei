#!/usr/bin/env bash
set -euo pipefail

row_count="${1:-100000}"
coverage_percent="${2:-10}"
for value in "$row_count" "$coverage_percent"; do
  case "$value" in
    ''|*[!0-9]*) echo "row count and coverage must be positive integers" >&2; exit 2 ;;
  esac
done
row_count="$((10#$row_count))"
coverage_percent="$((10#$coverage_percent))"
if [ "$row_count" -eq 0 ] || [ "$coverage_percent" -eq 0 ] || [ "$coverage_percent" -gt 100 ]; then
  echo "row count must be positive and coverage must be between 1 and 100" >&2
  exit 2
fi

spike_dir="$(mktemp -d "${TMPDIR:-/tmp}/sekai-temporal-spike.XXXXXX")"
trap 'rm -rf "$spike_dir"' EXIT
current_db="$spike_dir/current.db"
selective_db="$spike_dir/selective.db"
lookup_id="object-00000001"

create_current_sql="CREATE TABLE objects (
  id TEXT PRIMARY KEY,
  namespace TEXT NOT NULL,
  properties TEXT NOT NULL
);
WITH RECURSIVE n(i) AS (
  VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < $row_count
)
INSERT INTO objects
SELECT printf('object-%08d', i), 'default', json_object('value', i) FROM n;
CREATE INDEX objects_namespace ON objects(namespace, id);"

sqlite3 "$current_db" <<SQL
PRAGMA journal_mode=OFF;
PRAGMA synchronous=OFF;
$create_current_sql
VACUUM;
SQL

sqlite3 "$selective_db" <<SQL
PRAGMA journal_mode=OFF;
PRAGMA synchronous=OFF;
$create_current_sql
CREATE TABLE temporal_assertions (
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
INSERT INTO temporal_assertions
SELECT printf('assertion-%08d', CAST(substr(id, 8) AS INTEGER)), 1, namespace, id,
       'example:value', properties, 'known', 0, 'unbounded', NULL,
       1, NULL, 1000, 900, printf('source-%08d', CAST(substr(id, 8) AS INTEGER))
FROM objects
WHERE CAST(substr(id, 8) AS INTEGER) <= (($row_count * $coverage_percent + 99) / 100);
CREATE INDEX assertions_as_of
  ON temporal_assertions(namespace, subject_id, predicate, recorded_from_revision,
                         recorded_to_revision, valid_from_kind, valid_from_ms,
                         valid_to_kind, valid_to_ms);
VACUUM;
SQL

current_bytes="$(stat -f %z "$current_db" 2>/dev/null || stat -c %s "$current_db")"
selective_bytes="$(stat -f %z "$selective_db" 2>/dev/null || stat -c %s "$selective_db")"
history_rows="$(sqlite3 "$selective_db" "SELECT COUNT(*) FROM temporal_assertions;")"
printf 'rows=%s coverage=%s%% history_rows=%s current_bytes=%s selective_bytes=%s ratio=' \
  "$row_count" "$coverage_percent" "$history_rows" "$current_bytes" "$selective_bytes"
awk -v selective="$selective_bytes" -v current="$current_bytes" \
  'BEGIN { printf "%.2f\n", selective / current }'

printf 'current lookup plan: '
sqlite3 "$selective_db" \
  "EXPLAIN QUERY PLAN SELECT properties FROM objects WHERE id='$lookup_id';" | tail -1
printf 'historical lookup plan: '
sqlite3 "$selective_db" "EXPLAIN QUERY PLAN SELECT object_json FROM temporal_assertions WHERE namespace='default' AND subject_id='$lookup_id' AND predicate='example:value' AND recorded_from_revision<=1 AND (recorded_to_revision IS NULL OR recorded_to_revision>1) AND (valid_from_kind='unbounded' OR (valid_from_kind='known' AND valid_from_ms<=500)) AND (valid_to_kind='unbounded' OR (valid_to_kind='known' AND valid_to_ms>500));" | tail -1

printf 'current lookup x1000: '
/usr/bin/time -p sh -c "i=0; while [ \$i -lt 1000 ]; do sqlite3 '$selective_db' \"SELECT properties FROM objects WHERE id='$lookup_id';\" >/dev/null; i=\$((i+1)); done" 2>&1 | awk '/^real / { print $2 "s" }'
printf 'historical lookup x1000: '
/usr/bin/time -p sh -c "i=0; while [ \$i -lt 1000 ]; do sqlite3 '$selective_db' \"SELECT object_json FROM temporal_assertions WHERE namespace='default' AND subject_id='$lookup_id' AND predicate='example:value' AND recorded_from_revision<=1 AND (recorded_to_revision IS NULL OR recorded_to_revision>1) AND (valid_from_kind='unbounded' OR (valid_from_kind='known' AND valid_from_ms<=500)) AND (valid_to_kind='unbounded' OR (valid_to_kind='known' AND valid_to_ms>500));\" >/dev/null; i=\$((i+1)); done" 2>&1 | awk '/^real / { print $2 "s" }'
