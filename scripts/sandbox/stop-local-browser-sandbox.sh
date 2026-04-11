#!/usr/bin/env bash

set -euo pipefail

JOB_ID="${1:?job id required}"
SESSION_DIR="${2:?session directory required}"
RUNTIME_DIR="${SESSION_DIR}/runtime"

stop_pid_file() {
  local pid_file="$1"
  if [ -f "${pid_file}" ]; then
    local pid
    pid="$(cat "${pid_file}")"
    if kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
    fi
    rm -f "${pid_file}"
  fi
}

stop_pid_file "${RUNTIME_DIR}/websockify.pid"
stop_pid_file "${RUNTIME_DIR}/x11vnc.pid"
stop_pid_file "${RUNTIME_DIR}/chromium.pid"
stop_pid_file "${RUNTIME_DIR}/xvfb.pid"

rm -f "${RUNTIME_DIR}/session.env"
echo "Stopped local browser sandbox for ${JOB_ID}"