#!/usr/bin/env bash

set -euo pipefail

APP_DIR="${APP_DIR:-/opt/phishing}"
APP_URL="${APP_URL:-http://127.0.0.1:4000}"
JOB_ID="${1:-${JOB_ID:-}}"
COOKIE_JAR="/tmp/phish-debug-cookie.txt"

if [ -z "$JOB_ID" ]; then
  echo "Usage: $0 <job-id>" >&2
  exit 1
fi

cleanup() {
  rm -f "$COOKIE_JAR"
}

trap cleanup EXIT

get_env_value() {
  local key="$1"
  local env_path
  for env_path in "$APP_DIR/current/.env" "$APP_DIR/shared/.env"; do
    if [ -f "$env_path" ]; then
      sed -n "s/^${key}=//p" "$env_path" | tail -n 1
    fi
  done | tail -n 1 | tr -d '\r'
}

print_key_status() {
  local key="$1"
  local value
  value="$(get_env_value "$key")"
  if [ -n "$value" ]; then
    echo "$key=set"
  else
    echo "$key=missing"
  fi
}

PASSWORD="$(get_env_value APP_ACCESS_PASSWORD)"
if [ -z "$PASSWORD" ]; then
  PASSWORD="$(get_env_value APP_AUTH_PASSWORD)"
fi

echo "APP_DIR:$APP_DIR"
echo "APP_URL:$APP_URL"
echo "JOB_ID:$JOB_ID"
echo "CURRENT_RELEASE:$(readlink -f "$APP_DIR/current")"

echo "ENV_STATUS:"
print_key_status APP_ACCESS_PASSWORD
print_key_status APP_SESSION_SECRET
print_key_status CORTEX_ENABLED
print_key_status CORTEX_BASE_URL
print_key_status CORTEX_API_KEY
print_key_status CORTEX_ANALYZERS_EML
print_key_status CORTEX_ANALYZERS_URL
print_key_status CORTEX_ANALYZERS_DOMAIN
print_key_status CORTEX_ANALYZERS_FILE_HASH
print_key_status FILE_ANALYSIS_YARA_COMMAND
print_key_status FILE_ANALYSIS_CLAMAV_COMMAND

echo "HEALTH_STATUS:$(curl -sS -o /dev/null -w '%{http_code}' "$APP_URL/api/health")"

if [ -z "$PASSWORD" ]; then
  echo "LOGIN_SKIPPED:missing_password"
else
  echo "LOGIN_RESPONSE:"
  curl -sS -D - -o /tmp/phish-login-body.txt \
    -c "$COOKIE_JAR" \
    -H 'Content-Type: application/json' \
    -d "{\"password\":\"$PASSWORD\"}" \
    "$APP_URL/api/auth/login" | sed -n '1,20p'
  echo "LOGIN_BODY:$(cat /tmp/phish-login-body.txt)"
  rm -f /tmp/phish-login-body.txt

  echo "SESSION_RESPONSE:"
  curl -sS -b "$COOKIE_JAR" "$APP_URL/api/auth/session"
  echo

  echo "JOB_RESPONSE:"
  curl -sS -b "$COOKIE_JAR" "$APP_URL/api/analyze/eml/$JOB_ID"
  echo
fi

echo "RECENT_JOURNAL_MATCHES:"
journalctl -u phishing --no-pager -n 400 \
  | grep -Ei "$JOB_ID|eml_attachment_analysis_failed|Attachment analysis failed before completion|eml_analysis_failed|file_analysis_failed|ZodError|Invalid input|cortex|clamav|yara|7z|rar" \
  || true