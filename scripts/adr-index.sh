#!/bin/sh
# Generate the decision record index in docs/decisions/README.md from each
# record's header: the number from the filename, the title from the first
# heading, and the status from the `- Status:` line. Statuses other than
# accepted are shown after the link. Only the lines between the adr-index
# markers are generated; prose outside them is kept.
#
#   sh scripts/adr-index.sh          rewrite the index
#   sh scripts/adr-index.sh --check  exit 1 with a diff when the index is stale
set -eu

cd "$(dirname "$0")/.."
DIR=docs/decisions
README="$DIR/README.md"
START='<!-- adr-index:start -->'
END='<!-- adr-index:end -->'

case "${1:-}" in
  "") mode="write" ;;
  --check) mode="check" ;;
  *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

index=$(mktemp)
generated=$(mktemp)
trap 'rm -f "$index" "$generated"' EXIT

for file in "$DIR"/[0-9][0-9][0-9][0-9]-*.md; do
  name=${file##*/}
  number=${name%%-*}
  [ "$number" = 0000 ] && continue
  awk -v number="$number" -v name="$name" '
    title == "" && /^# / {
      title = substr($0, 3)
      sub("^(ADR )?" number ": ", "", title)
    }
    status == "" && /^- Status: / { status = substr($0, 11) }
    END {
      if (title == "" || status == "") {
        printf "%s: needs a first heading and a \"- Status:\" line\n", name > "/dev/stderr"
        exit 1
      }
      suffix = tolower(status) ~ /^accepted/ ? "" : " (" status ")"
      printf "- [ADR %s: %s](%s)%s\n", number, title, name, suffix
    }
  ' "$file" >>"$index"
done

if ! grep -Fqx "$START" "$README" || ! grep -Fqx "$END" "$README"; then
  echo "$README: missing $START / $END markers" >&2
  exit 1
fi

awk -v start="$START" -v end="$END" -v index_file="$index" '
  $0 == start { print; while ((getline line < index_file) > 0) print line; skip = 1; next }
  $0 == end { skip = 0 }
  !skip { print }
' "$README" >"$generated"

if [ "$mode" = check ]; then
  diff -u "$README" "$generated" || {
    echo "$README is stale; run sh scripts/adr-index.sh" >&2
    exit 1
  }
else
  cp "$generated" "$README"
fi
