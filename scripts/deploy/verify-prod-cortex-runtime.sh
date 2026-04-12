#!/usr/bin/env bash

set -euo pipefail

APP_NAME="${APP_NAME:-phishing}"
APP_DIR="${APP_DIR:-/opt/phishing}"
APP_SHARED_DIR="${APP_SHARED_DIR:-${APP_DIR}/shared}"
CORTEX_RUNTIME_DIR="${CORTEX_RUNTIME_DIR:-${APP_SHARED_DIR}/cortex-runtime}"
CORTEX_RUNTIME_ENV_FILE="${CORTEX_RUNTIME_ENV_FILE:-${CORTEX_RUNTIME_DIR}/runtime.env}"
CORTEX_RUNTIME_COMPOSE_FILE="${CORTEX_RUNTIME_COMPOSE_FILE:-${CORTEX_RUNTIME_DIR}/docker-compose.yml}"

if [ ! -f "${CORTEX_RUNTIME_ENV_FILE}" ] || [ ! -f "${CORTEX_RUNTIME_COMPOSE_FILE}" ]; then
  echo "Cortex runtime files are missing under ${CORTEX_RUNTIME_DIR}." >&2
  exit 1
fi

cortex_port="$(sed -n 's/^CORTEX_RUNTIME_PORT=//p' "${CORTEX_RUNTIME_ENV_FILE}" | tail -n 1)"
cortex_port="${cortex_port:-9001}"

docker compose --env-file "${CORTEX_RUNTIME_ENV_FILE}" -f "${CORTEX_RUNTIME_COMPOSE_FILE}" ps

if ! curl --fail --silent "http://127.0.0.1:${cortex_port}" >/dev/null 2>&1; then
  echo "Cortex runtime is not reachable on http://127.0.0.1:${cortex_port}." >&2
  exit 1
fi

echo "Cortex runtime is reachable on http://127.0.0.1:${cortex_port}."