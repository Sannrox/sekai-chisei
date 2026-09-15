#!/usr/bin/env bash

set -euo pipefail

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "${ROOT_PATH}"

VCS_REF="${VCS_REF:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"

docker build --build-arg VCS_REF="${VCS_REF}" -t sekai-chisei-ci .
docker run --rm sekai-chisei-ci sekaictl --help
