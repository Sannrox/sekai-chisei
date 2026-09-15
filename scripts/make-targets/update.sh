#!/usr/bin/env bash

set -euo pipefail

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

mapfile -t update_scripts < <(
  find "${ROOT_PATH}/scripts" -maxdepth 1 -type f -name 'update-*.sh' -print \
    | LC_ALL=C sort
)

if [ "${#update_scripts[@]}" -eq 0 ]; then
  echo "No update scripts found under ${ROOT_PATH}/scripts" >&2
  exit 1
fi

for script in "${update_scripts[@]}"; do
  echo "Updating $(basename "${script}")"
  "${script}"
done
