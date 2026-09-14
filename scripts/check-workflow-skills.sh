#!/bin/sh
# Guard deliver-ready-issue, advance-issue-frontier, and the parallel-lane
# claim contract so they stay linked to the project operating system.
set -eu

SKILLS_ROOT=".agents/skills"

fail() {
  printf 'workflow skill parity check failed: %s\n' "$1" >&2
  exit 1
}

require_file() {
  [ -f "$1" ] || fail "missing $1"
}

require_line() {
  grep -Fqx "$2" "$1" || fail "$1 is missing canonical line: $2"
}

require_fragment() {
  grep -Fq "$2" "$1" || fail "$1 is missing required metadata: $2"
}

for skill in \
  shape-work-item \
  advance-issue-frontier \
  assess-change-impact \
  deliver-ready-issue \
  verify-change \
  capture-project-decision \
  prepare-release
do
  skill_file="$SKILLS_ROOT/$skill/SKILL.md"
  metadata_file="$SKILLS_ROOT/$skill/agents/openai.yaml"
  require_file "$skill_file"
  require_file "$metadata_file"
  require_line "$skill_file" "name: $skill"
  require_fragment "$metadata_file" "default_prompt: \"Use \$$skill "
done

for stage in \
  '## Establish authority and scope' \
  '## Build the dependency graph' \
  '## Compute the frontier' \
  '## Apply authorized status changes' \
  '## Report the frontier' \
  '## Boundaries'
do
  require_line "$SKILLS_ROOT/advance-issue-frontier/SKILL.md" "$stage"
done

for stage in \
  '## Establish the authority ceiling' \
  '## Deliver the Issue' \
  '### 1. Prove readiness' \
  '### 2. Isolate the work' \
  '### 3. Bound the implementation' \
  '### 4. Verify and review' \
  '### 5. Publish when authorized' \
  '### 6. Land when authorized' \
  '## Report completion' \
  '## Boundaries'
do
  require_line "$SKILLS_ROOT/deliver-ready-issue/SKILL.md" "$stage"
done

# Parallel lanes: the lead procedure lives with deliver-ready-issue, the policy
# lives in the project operating system, and both must stay linked.
PARALLEL_REFERENCE="$SKILLS_ROOT/deliver-ready-issue/references/parallel-delivery.md"
LANE_SCRIPT="$SKILLS_ROOT/deliver-ready-issue/scripts/issue-lane.sh"
require_file "$PARALLEL_REFERENCE"
require_file "$LANE_SCRIPT"
require_fragment "$SKILLS_ROOT/deliver-ready-issue/SKILL.md" "references/parallel-delivery.md"
require_fragment "$SKILLS_ROOT/deliver-ready-issue/SKILL.md" "scripts/issue-lane.sh"
require_fragment "$SKILLS_ROOT/advance-issue-frontier/SKILL.md" "issue-lane.sh check"
require_line "docs/project-operating-system.md" "## Parallel delivery lanes"
require_fragment "$PARALLEL_REFERENCE" "docs/project-operating-system.md"
require_fragment "docs/project-operating-system.md" "issue-lane.sh claim"
grep -Fq "/.worktrees/" .gitignore || fail ".gitignore does not ignore the /.worktrees/ lane directory"

printf 'workflow skill parity check passed\n'
