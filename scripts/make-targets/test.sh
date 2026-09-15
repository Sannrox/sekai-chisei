#!/usr/bin/env bash

set -euo pipefail

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "${ROOT_PATH}"

if [ $# -gt 0 ]; then
  cargo test --locked "$@"
  exit 0
fi

cargo build --workspace --locked

python3 - <<'PY'
import subprocess
import sys
import time

start = time.perf_counter()
for _ in range(20):
    subprocess.run(
        ["target/debug/sekai", "--help"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
average_ms = (time.perf_counter() - start) / 20 * 1000
print(f"sekai average cold-start subprocess time: {average_ms:.0f} ms")
if average_ms >= 250:
    sys.exit(1)
PY

cargo test --workspace --locked
