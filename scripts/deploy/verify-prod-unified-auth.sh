#!/usr/bin/env bash

set -euo pipefail

BASE_URL="${BASE_URL:-https://fred.syntrix.ae}"
APP_URL="${APP_URL:-http://127.0.0.1:4000}"
PASSWORD="${PASSWORD:-Fr&dCl@ssic}"
SCREENSHOT_PATH="${SCREENSHOT_PATH:-/storage/sandbox-sessions/c1bc3da9-2c08-44ee-b3ea-8628bbdb0f58/google.com.png}"
NOVNC_PATH="${NOVNC_PATH:-/novnc/7610/vnc.html?autoconnect=1&resize=remote}"
COOKIE_JAR="/tmp/phish-hunter-auth-cookie.txt"

cleanup() {
  rm -f "$COOKIE_JAR"
}

trap cleanup EXIT

echo "LOGIN:"
curl -s -o /dev/null -w '%{http_code}\n' \
  -c "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d "{\"password\":\"$PASSWORD\"}" \
  "$APP_URL/api/auth/login"

echo "SESSION:"
curl -s -o /dev/null -w '%{http_code}\n' \
  -b "$COOKIE_JAR" \
  "$APP_URL/api/auth/session"

echo "ROOT_NO_COOKIE:"
curl -s -o /dev/null -w '%{http_code}\n' \
  "$BASE_URL/"

echo "ROOT_WITH_COOKIE:"
curl -s -o /dev/null -w '%{http_code}\n' \
  -b "$COOKIE_JAR" \
  "$BASE_URL/"

echo "STORAGE_NO_COOKIE:"
curl -s -o /dev/null -w '%{http_code}\n' \
  "$BASE_URL$SCREENSHOT_PATH"

echo "STORAGE_WITH_COOKIE:"
curl -s -o /dev/null -w '%{http_code}\n' \
  -b "$COOKIE_JAR" \
  "$BASE_URL$SCREENSHOT_PATH"

echo "NOVNC_NO_COOKIE:"
curl -s -o /dev/null -w '%{http_code}\n' \
  "$BASE_URL$NOVNC_PATH"

echo "NOVNC_WITH_COOKIE:"
curl -s -o /dev/null -w '%{http_code}\n' \
  -b "$COOKIE_JAR" \
  "$BASE_URL$NOVNC_PATH"