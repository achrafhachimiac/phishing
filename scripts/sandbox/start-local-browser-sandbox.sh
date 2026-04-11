#!/usr/bin/env bash

set -euo pipefail

JOB_ID="${1:?job id required}"
TARGET_URL="${2:?target url required}"
DISPLAY_NUMBER="${3:?display number required}"
VNC_PORT="${4:?vnc port required}"
NOVNC_PORT="${5:?novnc port required}"
SESSION_DIR="${6:?session directory required}"

DISPLAY=":${DISPLAY_NUMBER}"
RUNTIME_DIR="${SESSION_DIR}/runtime"
mkdir -p "${RUNTIME_DIR}"

XVFB_PID_FILE="${RUNTIME_DIR}/xvfb.pid"
CHROMIUM_PID_FILE="${RUNTIME_DIR}/chromium.pid"
X11VNC_PID_FILE="${RUNTIME_DIR}/x11vnc.pid"
WEBSOCKIFY_PID_FILE="${RUNTIME_DIR}/websockify.pid"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

resolve_chromium() {
  if command -v chromium >/dev/null 2>&1; then
    command -v chromium
    return
  fi
  if command -v chromium-browser >/dev/null 2>&1; then
    command -v chromium-browser
    return
  fi
  if [ -x "node_modules/.bin/playwright" ]; then
    node -e "const { chromium } = require('playwright'); console.log(chromium.executablePath());"
    return
  fi
  echo "Missing Chromium executable" >&2
  exit 1
}

start_if_missing() {
  local pid_file="$1"
  shift

  if [ -f "${pid_file}" ] && kill -0 "$(cat "${pid_file}")" 2>/dev/null; then
    return
  fi

  "$@" > /dev/null 2>&1 &
  echo $! > "${pid_file}"
}

require_command Xvfb
require_command x11vnc
require_command websockify

CHROMIUM_BIN="$(resolve_chromium)"

start_if_missing "${XVFB_PID_FILE}" Xvfb "${DISPLAY}" -screen 0 1440x900x24 -nolisten tcp
sleep 1

start_if_missing "${CHROMIUM_PID_FILE}" env DISPLAY="${DISPLAY}" "${CHROMIUM_BIN}" \
  --user-data-dir="${RUNTIME_DIR}/chromium-profile" \
  --no-first-run \
  --disable-dev-shm-usage \
  --disable-gpu \
  --window-size=1440,900 \
  --new-window \
  --no-default-browser-check \
  --app="${TARGET_URL}"

start_if_missing "${X11VNC_PID_FILE}" x11vnc -display "${DISPLAY}" -rfbport "${VNC_PORT}" -shared -forever -nopw
NOVNC_WEB_ROOT="/usr/share/novnc"
if [ ! -d "${NOVNC_WEB_ROOT}" ]; then
  echo "Missing noVNC web assets in ${NOVNC_WEB_ROOT}" >&2
  exit 1
fi
start_if_missing "${WEBSOCKIFY_PID_FILE}" websockify --web "${NOVNC_WEB_ROOT}" "${NOVNC_PORT}" "127.0.0.1:${VNC_PORT}"

cat > "${RUNTIME_DIR}/session.env" <<EOF
JOB_ID=${JOB_ID}
TARGET_URL=${TARGET_URL}
DISPLAY=${DISPLAY}
VNC_PORT=${VNC_PORT}
NOVNC_PORT=${NOVNC_PORT}
EOF