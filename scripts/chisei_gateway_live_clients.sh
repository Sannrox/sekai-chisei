#!/usr/bin/env bash
set -euo pipefail

GATEWAY_BASE_URL="${GATEWAY_BASE_URL:-http://127.0.0.1:8788/v1}"
GATEWAY_ROOT_URL="${GATEWAY_ROOT_URL:-${GATEWAY_BASE_URL%/v1}}"
CODEX_KEY="${CHISEI_CODEX_API_KEY:-sk-chisei-codex-app}"
CLAUDE_KEY="${CHISEI_CLAUDE_API_KEY:-sk-chisei-claude-code}"
CLAUDE_MODEL="${CHISEI_CLAUDE_MODEL:-}"
CODEX_CONFIG="${CODEX_CONFIG:-$HOME/.codex/config.toml}"
CODEX_PROFILE="${CHISEI_CODEX_PROFILE:-chisei}"
CODEX_MODEL="${CHISEI_CODEX_MODEL:-gpt-5.5}"
CODEX_LAST_OUTPUT="${CHISEI_CODEX_LAST_OUTPUT:-/tmp/chisei-codex-last.txt}"
CHISEI_AGENT="${CHISEI_AGENT:-claude-code}"
CHISEI_PROJECT="${CHISEI_PROJECT:-$(basename "$PWD")}"
CHISEI_CODEX_AGENT="${CHISEI_CODEX_AGENT:-codex-app}"
CHISEI_CODEX_PROJECT="${CHISEI_CODEX_PROJECT:-$(basename "$PWD")}"
CODEX_SMOKE_EXPECTED="${CHISEI_CODEX_SMOKE_EXPECTED:-chisei gateway codex smoke ok}"
REPORT_SINCE="${CHISEI_GATEWAY_REPORT_SINCE:-10m}"

usage() {
  cat <<'EOF'
Usage: scripts/chisei_gateway_live_clients.sh <command>

Commands:
  check-codex-config      Verify ~/.codex/config.toml contains a chisei provider stanza.
  check-codex-profile     Verify the chisei Codex CLI profile exists.
  install-codex-profile   Write/update ~/.codex/chisei.config.toml for CLI smoke.
  print-codex-config      Print the Codex local-login provider stanza to add manually.
  print-codex-key-config  Print the Codex virtual-key provider stanza to add manually.
  doctor                  Check local readiness for real Codex-through-gateway proof.
  launch-codex-app        Launch Codex.app through the Chisei provider using config overrides.
  codex-smoke [prompt]    Run `codex exec` through the configured chisei provider.
  codex-live-smoke        Run Codex smoke and require exact output plus report visibility.
  claude-smoke [prompt]   Run `claude -p` through the gateway using local Claude login.
  claude-key-smoke [prompt]
                           Run `claude -p` through the gateway using a virtual Anthropic key.

Environment:
  GATEWAY_BASE_URL        Gateway /v1 URL. Default: http://127.0.0.1:8788/v1
  GATEWAY_ROOT_URL        Gateway root URL for Claude. Default: GATEWAY_BASE_URL without /v1
  CHISEI_CODEX_API_KEY    Codex virtual key. Default: sk-chisei-codex-app
  CHISEI_CLAUDE_API_KEY   Claude Code virtual key. Default: sk-chisei-claude-code
  CHISEI_CLAUDE_MODEL     Optional Claude Code model for smoke runs, e.g. claude-fable-5
  CHISEI_AGENT            Local-login attribution agent. Default: claude-code
  CHISEI_PROJECT          Local-login attribution project. Default: current directory name
  CHISEI_CODEX_AGENT      Codex local-login attribution agent. Default: codex-app
  CHISEI_CODEX_PROJECT    Codex local-login attribution project. Default: current directory name
  CHISEI_CODEX_PROFILE    Codex profile to use for codex-smoke. Default: chisei
  CHISEI_CODEX_MODEL      Codex model for profile/app launches. Default: gpt-5.5
  CHISEI_CODEX_LAST_OUTPUT
                          Path for codex-smoke last-message output.
                          Default: /tmp/chisei-codex-last.txt
  CHISEI_CODEX_SMOKE_EXPECTED
                          Exact text required by codex-live-smoke.
                          Default: chisei gateway codex smoke ok
  CHISEI_GATEWAY_REPORT_SINCE
                          Report lookback for codex-live-smoke. Default: 10m
  CHISEI_SKIP_REPORT_CHECK
                          If set to 1, codex-live-smoke skips report verification.
  CHISEI_LAUNCH_DRY_RUN   If set to 1, print the Codex app launch command.
  CODEX_CONFIG            Codex config path. Default: ~/.codex/config.toml
EOF
}

require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "required command not found: $cmd" >&2
    exit 127
  fi
}

check_codex_config() {
  local config_path="${1:-$CODEX_CONFIG}"
  if [ ! -f "$config_path" ]; then
    echo "missing Codex config: $config_path" >&2
    exit 2
  fi
  if ! grep -q '^\[model_providers\.chisei\]' "$config_path"; then
    echo "missing [model_providers.chisei] in $config_path" >&2
    echo "Run: scripts/chisei_gateway_live_clients.sh print-codex-config" >&2
    exit 2
  fi
  if ! grep -q 'wire_api *= *"responses"' "$config_path"; then
    echo "chisei provider exists, but wire_api is not responses" >&2
    exit 2
  fi
  echo "Codex chisei provider appears configured in $config_path"
}

gateway_models_check() {
  require_command curl
  curl -fsS --max-time 5 \
    -H "authorization: Bearer $CODEX_KEY" \
    -H "x-chisei-agent: $CHISEI_CODEX_AGENT" \
    -H "x-chisei-project: $CHISEI_CODEX_PROJECT" \
    "$GATEWAY_BASE_URL/models" >/dev/null
}

doctor() {
  local failures=0
  echo "Checking Chisei/Codex live readiness."

  if command -v codex >/dev/null 2>&1; then
    echo "ok: codex command found"
  else
    echo "missing: codex command not found" >&2
    failures=$((failures + 1))
  fi

  if check_codex_config "$(codex_profile_config)" >/dev/null 2>&1; then
    echo "ok: Codex profile exists: $(codex_profile_config)"
  else
    echo "missing: Codex profile is not installed: $(codex_profile_config)" >&2
    echo "       run: scripts/chisei_gateway_live_clients.sh install-codex-profile" >&2
    failures=$((failures + 1))
  fi

  if command -v curl >/dev/null 2>&1 && gateway_models_check; then
    echo "ok: gateway answers $GATEWAY_BASE_URL/models"
  else
    echo "missing: gateway did not answer $GATEWAY_BASE_URL/models" >&2
    echo "       start it with OPENAI_API_KEY and CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH=1 for real Codex/OpenAI proof" >&2
    failures=$((failures + 1))
  fi

  if [ -n "${OPENAI_API_KEY:-}" ]; then
    echo "ok: OPENAI_API_KEY is set in this shell"
  else
    echo "warn: OPENAI_API_KEY is not set in this shell; the running gateway may still have it from its own environment" >&2
  fi

  if [ "${CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH:-0}" = "1" ]; then
    echo "ok: CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH=1 in this shell"
  else
    echo "warn: CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH is not 1 in this shell; the running gateway may still have it from its own environment" >&2
  fi

  if [ "$failures" -gt 0 ]; then
    echo "doctor failed with $failures missing requirement(s)" >&2
    return 1
  fi
  echo "doctor passed"
}

codex_profile_config() {
  printf '%s/%s.config.toml\n' "${CODEX_HOME:-$HOME/.codex}" "$CODEX_PROFILE"
}

codex_local_login_provider_inline() {
  printf '{name="Chisei Gateway", base_url="%s", wire_api="responses", requires_openai_auth=true, env_http_headers={"x-chisei-agent"="CHISEI_CODEX_AGENT", "x-chisei-project"="CHISEI_CODEX_PROJECT"}}' "$GATEWAY_BASE_URL"
}

codex_profile_body() {
  cat <<EOF
model = "$CODEX_MODEL"
model_provider = "chisei"

[model_providers.chisei]
name = "Chisei Gateway"
base_url = "$GATEWAY_BASE_URL"
wire_api = "responses"
requires_openai_auth = true
env_http_headers = { "x-chisei-agent" = "CHISEI_CODEX_AGENT", "x-chisei-project" = "CHISEI_CODEX_PROJECT" }
EOF
}

print_codex_config() {
  cat <<EOF
# Add this to $CODEX_CONFIG, then set model_provider = "chisei" where desired.
# This mode preserves your normal Codex/OpenAI login and adds Chisei attribution headers.
[model_providers.chisei]
name = "Chisei Gateway"
base_url = "$GATEWAY_BASE_URL"
wire_api = "responses"
requires_openai_auth = true
env_http_headers = { "x-chisei-agent" = "CHISEI_CODEX_AGENT", "x-chisei-project" = "CHISEI_CODEX_PROJECT" }
EOF
}

print_codex_key_config() {
  cat <<EOF
# Add this to $CODEX_CONFIG, then set model_provider = "chisei" where desired.
# This mode uses a Chisei virtual key instead of local Codex/OpenAI login.
[model_providers.chisei]
name = "Chisei Gateway"
base_url = "$GATEWAY_BASE_URL"
wire_api = "responses"
env_key = "CHISEI_CODEX_API_KEY"
EOF
}

install_codex_profile() {
  local profile_path
  profile_path="$(codex_profile_config)"
  mkdir -p "$(dirname "$profile_path")"
  local tmp
  tmp="$(mktemp)"
  codex_profile_body >"$tmp"
  if [ -f "$profile_path" ] && cmp -s "$tmp" "$profile_path"; then
    rm -f "$tmp"
    echo "Codex profile already up to date: $profile_path"
    return 0
  fi
  if [ -f "$profile_path" ]; then
    local backup="${profile_path}.$(date +%Y%m%d%H%M%S).bak"
    cp "$profile_path" "$backup"
    echo "Backed up existing profile to $backup"
  fi
  mv "$tmp" "$profile_path"
  echo "Installed Codex Chisei profile: $profile_path"
}

launch_codex_app() {
  require_command codex
  echo "Launching Codex.app through $GATEWAY_BASE_URL with Chisei attribution env set."
  local provider_inline
  provider_inline="$(codex_local_login_provider_inline)"
  local cmd=(
    codex app
    -c "model=\"$CODEX_MODEL\""
    -c 'model_provider="chisei"'
    -c "model_providers.chisei=$provider_inline"
    "$PWD"
  )
  if [ "${CHISEI_LAUNCH_DRY_RUN:-0}" = "1" ]; then
    printf 'CHISEI_CODEX_AGENT=%q CHISEI_CODEX_PROJECT=%q CHISEI_CODEX_API_KEY=<redacted>' \
      "$CHISEI_CODEX_AGENT" "$CHISEI_CODEX_PROJECT"
    printf ' %q' "${cmd[@]}"
    printf '\n'
    return 0
  fi
  CHISEI_CODEX_AGENT="$CHISEI_CODEX_AGENT" \
  CHISEI_CODEX_PROJECT="$CHISEI_CODEX_PROJECT" \
  CHISEI_CODEX_API_KEY="$CODEX_KEY" \
    "${cmd[@]}"
  echo "After one model call, verify usage with:"
  echo "  SEKAI_SOCKET=./data/sekai.sock cargo run --bin chisei-gateway -- report --by agent --since 10m"
}

codex_smoke() {
  require_command codex
  check_codex_config "$(codex_profile_config)"
  local prompt="${1:-Reply with exactly: $CODEX_SMOKE_EXPECTED}"
  rm -f "$CODEX_LAST_OUTPUT"
  echo "Running Codex CLI through profile '$CODEX_PROFILE' using $GATEWAY_BASE_URL."
  CHISEI_CODEX_AGENT="$CHISEI_CODEX_AGENT" \
  CHISEI_CODEX_PROJECT="$CHISEI_CODEX_PROJECT" \
  CHISEI_CODEX_API_KEY="$CODEX_KEY" \
    codex -p "$CODEX_PROFILE" \
      --ask-for-approval never \
      exec \
      -C "$PWD" \
      --skip-git-repo-check \
      --sandbox read-only \
      --output-last-message "$CODEX_LAST_OUTPUT" \
      "$prompt"
  if [ -f "$CODEX_LAST_OUTPUT" ]; then
    echo "Codex last message:"
    cat "$CODEX_LAST_OUTPUT"
  fi
}

codex_live_smoke() {
  local prompt="Reply with exactly: $CODEX_SMOKE_EXPECTED"
  codex_smoke "$prompt"
  if [ ! -f "$CODEX_LAST_OUTPUT" ]; then
    echo "codex-live-smoke failed: missing Codex last-message output at $CODEX_LAST_OUTPUT" >&2
    return 1
  fi
  if ! grep -Fq "$CODEX_SMOKE_EXPECTED" "$CODEX_LAST_OUTPUT"; then
    echo "codex-live-smoke failed: Codex output did not contain expected text: $CODEX_SMOKE_EXPECTED" >&2
    return 1
  fi
  echo "ok: Codex output contains expected text"

  if [ "${CHISEI_SKIP_REPORT_CHECK:-0}" = "1" ]; then
    echo "skipping report check because CHISEI_SKIP_REPORT_CHECK=1"
    return 0
  fi
  if [ ! -f Cargo.toml ]; then
    echo "codex-live-smoke failed: run from the sekai-chisei repo root or set CHISEI_SKIP_REPORT_CHECK=1" >&2
    return 1
  fi
  require_command cargo
  local report_file
  report_file="$(mktemp)"
  if ! cargo run --quiet --bin chisei-gateway -- report --by agent --since "$REPORT_SINCE" --limit 100 >"$report_file"; then
    cat "$report_file" >&2 || true
    rm -f "$report_file"
    echo "codex-live-smoke failed: could not read gateway report" >&2
    return 1
  fi
  echo "Recent gateway report:"
  cat "$report_file"
  if ! grep -Fq "$CHISEI_CODEX_AGENT" "$report_file"; then
    rm -f "$report_file"
    echo "codex-live-smoke failed: report did not include recent agent '$CHISEI_CODEX_AGENT'" >&2
    return 1
  fi
  rm -f "$report_file"
  echo "ok: report includes recent agent '$CHISEI_CODEX_AGENT'"
}

claude_smoke() {
  require_command claude
  local prompt="${1:-Reply with exactly: chisei gateway claude smoke ok}"
  local model_args=()
  if [ -n "$CLAUDE_MODEL" ]; then
    model_args=(--model "$CLAUDE_MODEL")
  fi
  echo "Running Claude Code through $GATEWAY_ROOT_URL using local Claude login."
  ANTHROPIC_BASE_URL="$GATEWAY_ROOT_URL" \
  ANTHROPIC_CUSTOM_HEADERS=$'x-chisei-agent: '"$CHISEI_AGENT"$'\nx-chisei-project: '"$CHISEI_PROJECT" \
  ENABLE_TOOL_SEARCH=true \
    claude --no-session-persistence "${model_args[@]}" -p "$prompt"
}

claude_key_smoke() {
  require_command claude
  local prompt="${1:-Reply with exactly: chisei gateway claude smoke ok}"
  local model_args=()
  if [ -n "$CLAUDE_MODEL" ]; then
    model_args=(--model "$CLAUDE_MODEL")
  fi
  echo "Running Claude Code through $GATEWAY_ROOT_URL using a Chisei virtual key."
  ANTHROPIC_BASE_URL="$GATEWAY_ROOT_URL" \
  ANTHROPIC_API_KEY="$CLAUDE_KEY" \
    claude "${model_args[@]}" -p "$prompt"
}

cmd="${1:-}"
case "$cmd" in
  check-codex-config)
    check_codex_config
    ;;
  check-codex-profile)
    check_codex_config "$(codex_profile_config)"
    ;;
  install-codex-profile)
    install_codex_profile
    ;;
  print-codex-config)
    print_codex_config
    ;;
  print-codex-key-config)
    print_codex_key_config
    ;;
  doctor)
    doctor
    ;;
  launch-codex-app)
    launch_codex_app
    ;;
  codex-smoke)
    shift
    codex_smoke "${1:-}"
    ;;
  codex-live-smoke)
    codex_live_smoke
    ;;
  claude-smoke)
    shift
    claude_smoke "${1:-}"
    ;;
  claude-key-smoke)
    shift
    claude_key_smoke "${1:-}"
    ;;
  --help|-h|"")
    usage
    ;;
  *)
    echo "unknown command: $cmd" >&2
    usage >&2
    exit 2
    ;;
esac
