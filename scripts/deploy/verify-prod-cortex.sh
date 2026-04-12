#!/usr/bin/env bash

set -euo pipefail

APP_DIR="${APP_DIR:-/opt/phishing}"
CURRENT_ENV_PATH="${CURRENT_ENV_PATH:-${APP_DIR}/current/.env}"
APP_URL="${APP_URL:-http://127.0.0.1:4000}"

if [ ! -f "$CURRENT_ENV_PATH" ]; then
  echo "Current app env file missing: $CURRENT_ENV_PATH" >&2
  exit 1
fi

get_env_value() {
  local key="$1"
  sed -n "s/^${key}=//p" "$CURRENT_ENV_PATH" | tail -n 1
}

CORTEX_ENABLED_VALUE="$(get_env_value CORTEX_ENABLED)"
CORTEX_BASE_URL_VALUE="$(get_env_value CORTEX_BASE_URL)"
CORTEX_API_KEY_VALUE="$(get_env_value CORTEX_API_KEY)"

echo "APP_HEALTH:"
curl -sS -o /dev/null -w '%{http_code}\n' "$APP_URL/api/health"

echo "CORTEX_ENABLED:${CORTEX_ENABLED_VALUE:-unset}"
echo "CORTEX_BASE_URL:${CORTEX_BASE_URL_VALUE:-unset}"

if [ "${CORTEX_ENABLED_VALUE:-false}" != "true" ]; then
  echo "Cortex integration is disabled; skipping remote API verification."
  exit 0
fi

if [ -z "$CORTEX_BASE_URL_VALUE" ] || [ -z "$CORTEX_API_KEY_VALUE" ]; then
  echo "Cortex is enabled but CORTEX_BASE_URL or CORTEX_API_KEY is missing." >&2
  exit 1
fi

echo "CORTEX_BASE_REACHABILITY:"
curl -ksS -o /dev/null -w '%{http_code}\n' "$CORTEX_BASE_URL_VALUE/"

echo "CORTEX_ANALYZER_API:"
curl -ksS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $CORTEX_API_KEY_VALUE" \
  "$CORTEX_BASE_URL_VALUE/api/analyzer"