#!/usr/bin/env bash

set -euo pipefail

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "${ROOT_PATH}"

cargo build --locked --workspace --bins
CHISEI_GATEWAY_SMOKE_SKIP_BUILD=1 "${ROOT_PATH}/scripts/chisei_gateway_smoke.sh"
