#!/usr/bin/env bash

set -euo pipefail

BASE_URL="${BASE_URL:-https://fred.syntrix.ae}"
PASSWORD="${PASSWORD:-Fr&dCl@ssic}"
TARGET_URL="${TARGET_URL:-https://example.com}"
COOKIE_JAR="/tmp/phish-hunter-sandbox-cookie.txt"
JOB_JSON="/tmp/phish-hunter-sandbox-job.json"

cleanup() {
  rm -f "$COOKIE_JAR" "$JOB_JSON"
}

trap cleanup EXIT

curl -s \
  -c "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d "{\"password\":\"$PASSWORD\"}" \
  "$BASE_URL/api/auth/login" >/dev/null

curl -s \
  -b "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d "{\"url\":\"$TARGET_URL\"}" \
  "$BASE_URL/api/sandbox/browser" > "$JOB_JSON"

job_id="$(python3 - <<'PY' "$JOB_JSON"
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    payload = json.load(fh)
print(payload['jobId'])
PY
)"

for _ in $(seq 1 120); do
  curl -s -b "$COOKIE_JAR" "$BASE_URL/api/sandbox/browser/$job_id" > "$JOB_JSON"
  status="$(python3 - <<'PY' "$JOB_JSON"
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    payload = json.load(fh)
print(payload['status'])
PY
)"
  if [ "$status" = "completed" ] || [ "$status" = "failed" ] || [ "$status" = "stopped" ]; then
    break
  fi
  sleep 1
done

echo "JOB_STATUS:"
python3 - <<'PY' "$JOB_JSON"
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    payload = json.load(fh)
print(payload['status'])
print(payload.get('result', {}).get('session', {}).get('status'))
print(payload.get('result', {}).get('screenshotPath'))
print(payload.get('result', {}).get('access', {}).get('url'))
PY

screenshot_path="$(python3 - <<'PY' "$JOB_JSON"
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    payload = json.load(fh)
print(payload.get('result', {}).get('screenshotPath') or '')
PY
)"

access_url="$(python3 - <<'PY' "$JOB_JSON"
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    payload = json.load(fh)
print(payload.get('result', {}).get('access', {}).get('url') or '')
PY
)"

if [ -n "$screenshot_path" ]; then
  case "$screenshot_path" in
    storage/*) screenshot_path="/$screenshot_path" ;;
  esac
  echo "SCREENSHOT_WITH_COOKIE:"
  curl -s -o /dev/null -w '%{http_code}\n' -b "$COOKIE_JAR" "$BASE_URL$screenshot_path"
fi

if [ -n "$access_url" ]; then
  echo "NOVNC_WITH_COOKIE:"
  curl -s -o /dev/null -w '%{http_code}\n' -b "$COOKIE_JAR" "$access_url"
fi