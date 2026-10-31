#!/usr/bin/env bash
# Print a Keep a Changelog section for the pull requests squash-merged to main
# since the last v* tag. Release prep pastes it into CHANGELOG.md, edits it,
# and commits it with the version bump; pull requests never edit CHANGELOG.md.
# The v* workflow takes the GitHub Release body from that section via
# scripts/changelog-notes.py.
#
#   bash scripts/changelog-draft.sh <version> [since-ref]
#
# Squash subjects are Conventional Commits: feat -> Added, fix -> Fixed,
# refactor/perf -> Changed; other types are omitted. A pull request is listed
# under Breaking when its subject is `type!:`, its body has a `BREAKING CHANGE`
# line or a `Breaking` heading, or it carries `risk:breaking`; under Upgrade
# when its body has an `Upgrade` heading or it carries `risk:migration`.
# Each pull request appears once. Labels are read with `gh`.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: bash scripts/changelog-draft.sh <version> [since-ref]" >&2
  exit 2
fi
version="${1#v}"

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT_PATH}"

git fetch --quiet --tags origin main
since="${2:-$(git describe --tags --abbrev=0 --match 'v*' origin/main)}"
since_date="$(git log -1 --format=%cI "${since}")"

# labeled <label> prints the numbers of PRs with that label merged since the tag.
labeled() {
  gh pr list --state merged --base main --label "$1" --limit 1000 \
    --search "merged:>=${since_date}" --json number --jq '.[].number'
}
breaking_prs=" $(labeled risk:breaking | tr '\n' ' ') "
upgrade_prs=" $(labeled risk:migration | tr '\n' ' ') "

header_re='^([a-z]+)(\([^)]*\))?(!?): (.*)$'
pr_re='\(#([0-9]+)\)$'
added=() fixed=() changed=() breaking=() upgrade=()
while read -r sha; do
  subject="$(git log -1 --format=%s "${sha}")"
  body="$(git log -1 --format=%b "${sha}")"
  type="" bang="" text="${subject}" pr=""
  if [[ "${subject}" =~ ${header_re} ]]; then
    type="${BASH_REMATCH[1]}" bang="${BASH_REMATCH[3]}" text="${BASH_REMATCH[4]}"
  fi
  [[ "${subject}" =~ ${pr_re} ]] && pr="${BASH_REMATCH[1]}"
  line="- ${text}"
  if [[ -n "${bang}" || ( -n "${pr}" && "${breaking_prs}" == *" ${pr} "* ) ]] ||
    grep -qE '^(BREAKING[ -]CHANGE|#+ *Breaking)' <<<"${body}"; then
    breaking+=("${line}")
  elif [[ -n "${pr}" && "${upgrade_prs}" == *" ${pr} "* ]] ||
    grep -qE '^#+ *Upgrade' <<<"${body}"; then
    upgrade+=("${line}")
  else
    case "${type}" in
      feat) added+=("${line}") ;;
      fix) fixed+=("${line}") ;;
      refactor | perf) changed+=("${line}") ;;
    esac
  fi
done < <(git log --first-parent --reverse --format=%H "${since}..origin/main")

# section <title> <lines...> prints a ### block when it has entries.
section() {
  local title="$1"
  shift
  if [[ $# -eq 0 ]]; then return 0; fi
  printf '\n### %s\n\n' "${title}"
  printf '%s\n' "$@"
}

echo "## ${version}"
section "Breaking" ${breaking[@]+"${breaking[@]}"}
section "Upgrade" ${upgrade[@]+"${upgrade[@]}"}
section "Added" ${added[@]+"${added[@]}"}
section "Changed" ${changed[@]+"${changed[@]}"}
section "Fixed" ${fixed[@]+"${fixed[@]}"}
