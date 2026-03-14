#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -eq 0 ]]; then
  set -- linux-x64
fi

exec "$SCRIPT_DIR/publish-binexplore.sh" "$@"
