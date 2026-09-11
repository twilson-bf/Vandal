#!/usr/bin/env bash
set -euo pipefail
VANDAL_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "${VANDAL_PYTHON:-python3}" "$VANDAL_ROOT/scripts/dependencies.py" "$@"

