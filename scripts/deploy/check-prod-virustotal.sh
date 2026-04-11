#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/phishing}"
SERVICE_NAME="${SERVICE_NAME:-phishing}"
DOMAIN="${DOMAIN:-lbpam.com}"

mask_value() {
  local value="${1:-}"
  if [ -z "$value" ]; then
    echo "missing"
    return
  fi

  local length=${#value}
  if [ "$length" -le 8 ]; then
    echo "set(length=${length})"
    return
  fi

  echo "${value:0:4}...${value:length-4:4} (length=${length})"
}

report_env_file() {
  local file_path="$1"
  if [ ! -f "$file_path" ]; then
    echo "ENV_FILE $file_path missing"
    return
  fi

  echo "ENV_FILE $file_path present"
  local vt_key=""
  local urlhaus_key=""
  vt_key="$(grep -E '^VIRUSTOTAL_API_KEY=' "$file_path" | head -n 1 | cut -d '=' -f2- || true)"
  urlhaus_key="$(grep -E '^URLHAUS_AUTH_KEY=' "$file_path" | head -n 1 | cut -d '=' -f2- || true)"
  echo "  VIRUSTOTAL_API_KEY=$(mask_value "$vt_key")"
  echo "  URLHAUS_AUTH_KEY=$(mask_value "$urlhaus_key")"
}

echo "== SERVICE STATUS =="
systemctl is-active "$SERVICE_NAME" || true
systemctl status "$SERVICE_NAME" --no-pager -l | sed -n '1,18p' || true

echo
echo "== SERVICE UNIT =="
systemctl cat "$SERVICE_NAME" || true

echo
echo "== APP PATHS =="
ls -la "$APP_DIR" || true
ls -la "$APP_DIR/shared" || true
ls -la "$APP_DIR/current" || true

echo
echo "== ENV FILES =="
report_env_file "$APP_DIR/shared/.env"
report_env_file "$APP_DIR/current/.env"

echo
echo "== BUILT CONFIG CHECK =="
if [ -f "$APP_DIR/current/dist-server/backend/config.js" ]; then
  grep -nE 'dotenv|loadBackendEnvironment|\.env.local|\.env' "$APP_DIR/current/dist-server/backend/config.js" || true
else
  echo "config.js missing"
fi

echo
echo "== LOCAL API RESPONSE =="
curl --silent --show-error --fail -H 'Content-Type: application/json' -d "{\"domain\":\"$DOMAIN\"}" http://127.0.0.1:4000/api/analyze/domain > /tmp/prod-domain-analysis.json
node -e "const fs=require('fs'); const data=JSON.parse(fs.readFileSync('/tmp/prod-domain-analysis.json','utf8')); console.log(JSON.stringify({ summary:data.summary, virustotal:data.reputation?.virustotal, urlhausHost:data.reputation?.urlhausHost }, null, 2));"

echo
echo "== DONE =="
