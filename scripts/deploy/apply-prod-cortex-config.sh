#!/usr/bin/env bash

set -euo pipefail

APP_DIR="${APP_DIR:-/opt/phishing}"
CURRENT_ENV_PATH="${CURRENT_ENV_PATH:-${APP_DIR}/current/.env}"
SHARED_ENV_PATH="${SHARED_ENV_PATH:-${APP_DIR}/shared/.env}"

CORTEX_ENABLED_VALUE="${CORTEX_ENABLED:-false}"
CORTEX_BASE_URL_VALUE="${CORTEX_BASE_URL:-}"
CORTEX_API_KEY_VALUE="${CORTEX_API_KEY:-}"
CORTEX_TIMEOUT_MS_VALUE="${CORTEX_TIMEOUT_MS:-15000}"
CORTEX_ANALYZERS_EML_VALUE="${CORTEX_ANALYZERS_EML:-}"
CORTEX_ANALYZERS_URL_VALUE="${CORTEX_ANALYZERS_URL:-}"
CORTEX_ANALYZERS_DOMAIN_VALUE="${CORTEX_ANALYZERS_DOMAIN:-}"
CORTEX_ANALYZERS_FILE_HASH_VALUE="${CORTEX_ANALYZERS_FILE_HASH:-}"

upsert_env_file() {
  local env_path="$1"
  mkdir -p "$(dirname "$env_path")"
  touch "$env_path"

  python3 - "$env_path" \
    "$CORTEX_ENABLED_VALUE" \
    "$CORTEX_BASE_URL_VALUE" \
    "$CORTEX_API_KEY_VALUE" \
    "$CORTEX_TIMEOUT_MS_VALUE" \
    "$CORTEX_ANALYZERS_EML_VALUE" \
    "$CORTEX_ANALYZERS_URL_VALUE" \
    "$CORTEX_ANALYZERS_DOMAIN_VALUE" \
    "$CORTEX_ANALYZERS_FILE_HASH_VALUE" <<'PY'
from pathlib import Path
import sys

env_path = Path(sys.argv[1])
updates = {
    'CORTEX_ENABLED': sys.argv[2],
    'CORTEX_BASE_URL': sys.argv[3],
    'CORTEX_API_KEY': sys.argv[4],
    'CORTEX_TIMEOUT_MS': sys.argv[5],
    'CORTEX_ANALYZERS_EML': sys.argv[6],
    'CORTEX_ANALYZERS_URL': sys.argv[7],
    'CORTEX_ANALYZERS_DOMAIN': sys.argv[8],
    'CORTEX_ANALYZERS_FILE_HASH': sys.argv[9],
}

lines = env_path.read_text().splitlines() if env_path.exists() else []
filtered = [line for line in lines if not any(line.startswith(f'{key}=') for key in updates)]
for key, value in updates.items():
    filtered.append(f'{key}={value}')
env_path.write_text('\n'.join(filtered) + '\n')
PY
}

if [ "$CORTEX_ENABLED_VALUE" = "true" ] && { [ -z "$CORTEX_BASE_URL_VALUE" ] || [ -z "$CORTEX_API_KEY_VALUE" ]; }; then
  echo "CORTEX_BASE_URL and CORTEX_API_KEY are required when CORTEX_ENABLED=true" >&2
  exit 1
fi

upsert_env_file "$SHARED_ENV_PATH"
upsert_env_file "$CURRENT_ENV_PATH"

echo "Applied Cortex configuration to:"
echo " - $SHARED_ENV_PATH"
echo " - $CURRENT_ENV_PATH"