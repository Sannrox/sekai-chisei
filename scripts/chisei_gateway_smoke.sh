#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/chisei-gateway-smoke.XXXXXX")"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

wait_for_file() {
  local path="$1"
  for _ in $(seq 1 600); do
    if [ -e "$path" ]; then
      return 0
    fi
    sleep 0.05
  done
  echo "timed out waiting for $path" >&2
  return 1
}

wait_for_http() {
  local url="$1"
  for _ in $(seq 1 600); do
    if curl -sS -o /dev/null "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  echo "timed out waiting for $url" >&2
  return 1
}

wait_for_http_or_exit() {
  local url="$1"
  local pid="$2"
  local log="$3"
  for _ in $(seq 1 600); do
    if curl -sS -o /dev/null "$url" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "process $pid exited while waiting for $url" >&2
      sed -n '1,120p' "$log" >&2 || true
      return 1
    fi
    sleep 0.05
  done
  echo "timed out waiting for $url" >&2
  sed -n '1,120p' "$log" >&2 || true
  return 1
}

live_client_enabled() {
  local client="$1"
  case "${CHISEI_GATEWAY_SMOKE_LIVE_CLIENTS:-0}" in
    1|all|true|yes) return 0 ;;
    codex) [ "$client" = "codex" ] ;;
    claude) [ "$client" = "claude" ] ;;
    *) return 1 ;;
  esac
}

cat >"$TMPDIR/fake_provider.py" <<'PY'
import http.server
import json
import sys

requests_path = sys.argv[1]
port_path = sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/v1/models") or self.path.startswith("/models"):
            payload = {
                "object": "list",
                "data": [{"id": "gpt-5.5", "object": "model"}],
                "models": [{
                    "base_instructions": "",
                    "context_window": 131072,
                    "default_verbosity": "low",
                    "experimental_supported_tools": [],
                    "id": "gpt-5.5",
                    "input_modalities": ["text"],
                    "priority": 0,
                    "shell_type": "default",
                    "slug": "gpt-5.5",
                    "name": "gpt-5.5",
                    "display_name": "gpt-5.5",
                    "support_verbosity": True,
                    "supported_in_api": True,
                    "supported_reasoning_levels": [],
                    "supports_parallel_tool_calls": False,
                    "supports_reasoning_summaries": False,
                    "truncation_policy": {"limit": 10000, "mode": "tokens"},
                    "visibility": "list",
                }],
            }
            data = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        parsed = json.loads(body) if body.strip() else {}
        with open(requests_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "path": self.path,
                "authorization": self.headers.get("authorization"),
                "x_api_key": self.headers.get("x-api-key"),
                "body": body,
            }) + "\n")

        if parsed.get("stream") and self.path.startswith("/v1/messages"):
            chunks = [
                'event: message_start\n'
                'data: {"type":"message_start","message":{"usage":{"input_tokens":13,"output_tokens":0}}}\n\n',
                'event: content_block_start\n'
                'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n',
                'event: content_block_delta\n'
                'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"chisei gateway claude smoke ok"}}\n\n',
                'event: content_block_stop\n'
                'data: {"type":"content_block_stop","index":0}\n\n',
                'event: message_delta\n'
                'data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":7}}\n\n',
                'event: message_stop\n'
                'data: {"type":"message_stop"}\n\n',
            ]
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(chunk.encode("utf-8"))
                self.wfile.flush()
            return

        if parsed.get("stream") and self.path.startswith("/v1/responses"):
            chunks = [
                'event: response.created\n'
                'data: {"type":"response.created","response":{"id":"resp_smoke","object":"response","status":"in_progress","model":"gpt-5.5","output":[]}}\n\n',
                'event: response.output_item.added\n'
                'data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_smoke","type":"message","status":"in_progress","role":"assistant","content":[]}}\n\n',
                'event: response.content_part.added\n'
                'data: {"type":"response.content_part.added","item_id":"msg_smoke","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}\n\n',
                'event: response.output_text.delta\n'
                'data: {"type":"response.output_text.delta","item_id":"msg_smoke","output_index":0,"content_index":0,"delta":"chisei gateway codex smoke ok"}\n\n',
                'event: response.output_text.done\n'
                'data: {"type":"response.output_text.done","item_id":"msg_smoke","output_index":0,"content_index":0,"text":"chisei gateway codex smoke ok"}\n\n',
                'event: response.content_part.done\n'
                'data: {"type":"response.content_part.done","item_id":"msg_smoke","output_index":0,"content_index":0,"part":{"type":"output_text","text":"chisei gateway codex smoke ok","annotations":[]}}\n\n',
                'event: response.output_item.done\n'
                'data: {"type":"response.output_item.done","output_index":0,"item":{"id":"msg_smoke","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"chisei gateway codex smoke ok","annotations":[]}]}}\n\n',
                'event: response.completed\n'
                'data: {"type":"response.completed","response":{"id":"resp_smoke","object":"response","status":"completed","model":"gpt-5.5","output":[{"id":"msg_smoke","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"chisei gateway codex smoke ok","annotations":[]}]}],"usage":{"input_tokens":11,"output_tokens":13,"total_tokens":24}}}\n\n',
            ]
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(chunk.encode("utf-8"))
                self.wfile.flush()
            return

        if self.path.startswith("/v1/messages/count_tokens"):
            payload = {"input_tokens": 11}
        elif self.path.startswith("/v1/messages"):
            payload = {
                "id": "msg_smoke",
                "type": "message",
                "role": "assistant",
                "model": parsed.get("model", "claude-sonnet-4-8"),
                "content": [{"type": "text", "text": "chisei gateway claude smoke ok"}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 5, "output_tokens": 3},
            }
        elif self.path.startswith("/v1/chat/completions"):
            payload = {
                "id": "chatcmpl_smoke",
                "object": "chat.completion",
                "usage": {"prompt_tokens": 6, "completion_tokens": 4, "total_tokens": 10},
            }
        else:
            payload = {
                "id": "resp_smoke",
                "object": "response",
                "status": "completed",
                "model": parsed.get("model", "gpt-5.5"),
                "output": [{
                    "id": "msg_smoke",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{
                        "type": "output_text",
                        "text": "chisei gateway codex smoke ok",
                        "annotations": [],
                    }],
                }],
                "usage": {"input_tokens": 7, "output_tokens": 5, "total_tokens": 12},
            }

        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(port_path, "w", encoding="utf-8") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
PY

cd "$ROOT"

if [ "${CHISEI_GATEWAY_SMOKE_SKIP_BUILD:-0}" != "1" ]; then
  cargo build --locked --bins
fi

BIN_DIR="${CHISEI_GATEWAY_SMOKE_BIN_DIR:-$ROOT/target/debug}"
SEKAI_CHISEI_BIN="${SEKAI_CHISEI_BIN:-$BIN_DIR/sekai-chisei}"
SEKAICTL_BIN="${SEKAICTL_BIN:-$BIN_DIR/sekaictl}"
CHISEI_GATEWAY_BIN="${CHISEI_GATEWAY_BIN:-$BIN_DIR/chisei-gateway}"

PROVIDER_REQUESTS="$TMPDIR/provider-requests.jsonl"
PROVIDER_PORT_FILE="$TMPDIR/provider-port"
python3 "$TMPDIR/fake_provider.py" "$PROVIDER_REQUESTS" "$PROVIDER_PORT_FILE" &
PIDS+=("$!")
wait_for_file "$PROVIDER_PORT_FILE"
PROVIDER_PORT="$(cat "$PROVIDER_PORT_FILE")"

SOCKET="$TMPDIR/sekai.sock"
DB_PATH="$TMPDIR/sekai.db"
SEKAI_INSECURE=1 \
GRPC_PORT=0 \
SEKAI_SOCKET="$SOCKET" \
DB_PATH="$DB_PATH" \
OPENAI_API_KEY="control-plane-openai-smoke-key" \
ANTHROPIC_API_KEY="control-plane-anthropic-smoke-key" \
"$SEKAI_CHISEI_BIN" >"$TMPDIR/sekai.log" 2>&1 &
PIDS+=("$!")
wait_for_file "$SOCKET"

SEKAI_SOCKET="$SOCKET" "$SEKAICTL_BIN" gateway setup \
  --agent codex-app \
  --project sekai-chisei \
  --gateway-key-name codex-app \
  --gateway-key sk-chisei-codex-app \
  --budget 500000 \
  --budget-period day \
  --default-runtime openai \
  --default-model gpt-5.5 \
  --allowed-model gpt-5.5 >"$TMPDIR/setup-codex.log" 2>&1

SEKAI_SOCKET="$SOCKET" "$SEKAICTL_BIN" gateway setup \
  --agent claude-code \
  --project default \
  --gateway-key-name claude-code \
  --gateway-key sk-chisei-claude-code \
  --budget 500000 \
  --budget-period day \
  --default-runtime anthropic \
  --default-model claude-sonnet-4-8 \
  --allowed-model claude-sonnet-4-8 \
  --allowed-model claude-sonnet-4-6 \
  --allowed-model claude-sonnet-4-20250514 \
  --allowed-model claude-haiku-4-5-20251001 \
  --allowed-model claude-opus-4-8 \
  --allowed-model claude-fable-5 \
  --allowed-model sonnet \
  --allowed-model haiku \
  --allowed-model opus \
  --allowed-model fable >"$TMPDIR/setup-claude.log" 2>&1

GATEWAY_PORT=""
for attempt in $(seq 1 10); do
  candidate_port="$(free_port)"
  gateway_log="$TMPDIR/gateway-$attempt.log"
  SEKAI_SOCKET="$SOCKET" \
  GATEWAY_BIND="127.0.0.1:$candidate_port" \
  CHISEI_OPENAI_BASE_URL="http://127.0.0.1:$PROVIDER_PORT/v1" \
  CHISEI_ANTHROPIC_BASE_URL="http://127.0.0.1:$PROVIDER_PORT/v1" \
  CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH=1 \
  CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH=1 \
  CHISEI_GATEWAY_PRICING="gpt-5.5=1:2,claude-sonnet-4-8=3:15,claude-sonnet-4-6=3:15" \
  OPENAI_API_KEY="real-openai-smoke-key" \
  ANTHROPIC_API_KEY="real-anthropic-smoke-key" \
  "$CHISEI_GATEWAY_BIN" >"$gateway_log" 2>&1 &
  gateway_pid="$!"
  if wait_for_http_or_exit "http://127.0.0.1:$candidate_port/v1/responses" "$gateway_pid" "$gateway_log"; then
    PIDS+=("$gateway_pid")
    GATEWAY_PORT="$candidate_port"
    cp "$gateway_log" "$TMPDIR/gateway.log"
    break
  fi
  kill "$gateway_pid" >/dev/null 2>&1 || true
  wait "$gateway_pid" >/dev/null 2>&1 || true
done
if [ -z "$GATEWAY_PORT" ]; then
  echo "failed to start chisei-gateway after retrying candidate ports" >&2
  exit 1
fi

curl -fsS "http://127.0.0.1:$GATEWAY_PORT/v1/responses" \
  -H "authorization: Bearer sk-chisei-codex-app" \
  -H "content-type: application/json" \
  -d '{"model":"gpt-5.5","input":"hello from smoke"}' >"$TMPDIR/openai-response.json"

curl -fsS "http://127.0.0.1:$GATEWAY_PORT/v1/responses" \
  -H "authorization: Bearer codex-local-login-smoke-token" \
  -H "x-chisei-agent: codex-app" \
  -H "x-chisei-project: sekai-chisei" \
  -H "content-type: application/json" \
  -d '{"model":"gpt-5.5","input":"hello codex local-login smoke"}' >"$TMPDIR/openai-codex-local-login-response.json"

curl -fsS "http://127.0.0.1:$GATEWAY_PORT/v1/responses" \
  -H "authorization: Bearer sk-chisei-codex-app" \
  -H "content-type: application/json" \
  -d '{"model":"gpt-5.5","input":"hello streaming smoke","stream":true}' >"$TMPDIR/openai-stream.sse"

curl -fsS "http://127.0.0.1:$GATEWAY_PORT/v1/messages" \
  -H "x-api-key: sk-chisei-claude-code" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-8","max_tokens":16,"messages":[{"role":"user","content":"hello from smoke"}]}' >"$TMPDIR/anthropic-response.json"

curl -fsS "http://127.0.0.1:$GATEWAY_PORT/v1/messages" \
  -H "x-api-key: sk-chisei-claude-code" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-8","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hello streaming smoke"}]}' >"$TMPDIR/anthropic-stream.sse"

if live_client_enabled claude; then
  if command -v claude >/dev/null 2>&1; then
    set +e
    ANTHROPIC_BASE_URL="http://127.0.0.1:$GATEWAY_PORT" \
    ANTHROPIC_CUSTOM_HEADERS=$'x-chisei-agent: claude-code\nx-chisei-project: default' \
    ENABLE_TOOL_SEARCH=true \
      claude --no-session-persistence --model "${CHISEI_GATEWAY_SMOKE_CLAUDE_MODEL:-sonnet}" \
        -p "Reply with exactly: chisei gateway claude smoke ok" \
      >"$TMPDIR/claude-live.txt"
    echo "$?" >"$TMPDIR/claude-live.status"
    set -e
  else
    echo "claude command not found" >"$TMPDIR/claude-live.txt"
    echo "127" >"$TMPDIR/claude-live.status"
  fi
fi

if live_client_enabled codex; then
  if command -v codex >/dev/null 2>&1; then
    set +e
    CHISEI_CODEX_API_KEY="sk-chisei-codex-app" \
      codex exec \
        --ignore-user-config \
        --skip-git-repo-check \
        --ephemeral \
        -C "$TMPDIR" \
        -s read-only \
        -m gpt-5.5 \
        -o "$TMPDIR/codex-last.txt" \
        -c 'model_provider="chisei"' \
        -c "model_providers.chisei={name=\"Chisei Gateway\", base_url=\"http://127.0.0.1:$GATEWAY_PORT/v1\", wire_api=\"responses\", env_key=\"CHISEI_CODEX_API_KEY\"}" \
        "Reply with exactly: chisei gateway codex smoke ok" \
      >"$TMPDIR/codex-live.txt" 2>&1
    echo "$?" >"$TMPDIR/codex-live.status"
    set -e
  else
    echo "codex command not found" >"$TMPDIR/codex-live.txt"
    echo "127" >"$TMPDIR/codex-live.status"
  fi
fi

SEKAI_SOCKET="$SOCKET" "$CHISEI_GATEWAY_BIN" \
  report --by agent --since 24h >"$TMPDIR/report.txt"

SEKAI_SOCKET="$SOCKET" "$CHISEI_GATEWAY_BIN" \
  report --since 24h --html "$TMPDIR/dashboard.html" >"$TMPDIR/dashboard-command.txt"

python3 - "$PROVIDER_REQUESTS" "$TMPDIR/report.txt" "$TMPDIR/dashboard.html" "$TMPDIR/openai-stream.sse" "$TMPDIR/anthropic-stream.sse" <<'PY'
import json
import sys

requests_path, report_path, dashboard_path, openai_stream_path, anthropic_stream_path = sys.argv[1:6]
with open(requests_path, encoding="utf-8") as f:
    requests = [json.loads(line) for line in f if line.strip()]

assert len(requests) >= 5, f"expected at least five upstream requests, got {len(requests)}"
assert any(r["authorization"] == "Bearer real-openai-smoke-key" for r in requests), requests
assert any(r["x_api_key"] == "real-anthropic-smoke-key" for r in requests), requests
assert not any("sk-chisei-" in json.dumps(r) for r in requests), requests
assert not any("codex-local-login-smoke-token" in json.dumps(r) for r in requests), requests
assert any(json.loads(r["body"]).get("stream") for r in requests), requests
assert any(
    r["authorization"] == "Bearer real-openai-smoke-key"
    and json.loads(r["body"]).get("input") == "hello codex local-login smoke"
    for r in requests
), requests

openai_stream = open(openai_stream_path, encoding="utf-8").read()
assert "event: response.completed" in openai_stream, openai_stream
assert '"total_tokens":24' in openai_stream, openai_stream

anthropic_stream = open(anthropic_stream_path, encoding="utf-8").read()
assert "event: message_delta" in anthropic_stream, anthropic_stream
assert '"output_tokens":7' in anthropic_stream, anthropic_stream

report = open(report_path, encoding="utf-8").read()
assert "codex-app" in report, report
assert "claude-code" in report, report
assert "est_cost_usd" in report, report

dashboard = open(dashboard_path, encoding="utf-8").read()
assert "Chisei Gateway Usage" in dashboard, dashboard
assert "By Agent" in dashboard, dashboard
assert "Estimated cost" in dashboard, dashboard
assert "codex-app" in dashboard, dashboard
assert "claude-code" in dashboard, dashboard
PY

if live_client_enabled claude; then
  python3 - "$TMPDIR/claude-live.txt" "$TMPDIR/claude-live.status" <<'PY'
import sys

claude_path, claude_status_path = sys.argv[1:3]
claude = open(claude_path, encoding="utf-8").read()
claude_status = open(claude_status_path, encoding="utf-8").read().strip()
assert claude_status == "0", claude
assert "chisei gateway claude smoke ok" in claude, claude
PY
fi

if live_client_enabled codex; then
  python3 - "$TMPDIR/codex-live.txt" "$TMPDIR/codex-last.txt" "$TMPDIR/codex-live.status" <<'PY'
import sys

codex_path, codex_last_path, codex_status_path = sys.argv[1:4]
codex = open(codex_path, encoding="utf-8").read()
codex_last = open(codex_last_path, encoding="utf-8").read()
codex_status = open(codex_status_path, encoding="utf-8").read().strip()
assert codex_status == "0", codex
assert "chisei gateway codex smoke ok" in codex_last or "chisei gateway codex smoke ok" in codex, codex + codex_last
PY
fi

echo "chisei gateway smoke passed"
echo "logs: $TMPDIR"
