#!/usr/bin/env bash

set -euo pipefail

APP_DIR="${APP_DIR:-/opt/phishing}"
SITE_CONF="${SITE_CONF:-/etc/nginx/sites-enabled/phishing}"
ACCESS_PASSWORD="${ACCESS_PASSWORD:-Fr&dCl@ssic}"
SESSION_SECRET="${SESSION_SECRET:-$ACCESS_PASSWORD}"

update_env_file() {
  local file_path="$1"
  python3 - "$file_path" "$ACCESS_PASSWORD" "$SESSION_SECRET" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
access_password = sys.argv[2]
session_secret = sys.argv[3]
text = path.read_text() if path.exists() else ""
lines = []
for line in text.splitlines():
    if line.startswith(("APP_AUTH_USERNAME=", "APP_AUTH_PASSWORD=", "APP_ACCESS_PASSWORD=", "APP_SESSION_SECRET=")):
        continue
    lines.append(line)
lines.append(f"APP_ACCESS_PASSWORD={access_password}")
lines.append(f"APP_SESSION_SECRET={session_secret}")
path.write_text("\n".join(lines).rstrip() + "\n")
PY
}

update_nginx_site() {
  python3 - "$SITE_CONF" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()

internal_block = """
    location = /_auth_session {
        internal;
        proxy_pass http://127.0.0.1:4000/api/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Cookie $http_cookie;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
"""

if "location = /_auth_session" not in text:
    marker = "    client_max_body_size 10m;\n"
    text = text.replace(marker, marker + internal_block, 1)

target = """    location ~ ^/novnc/(7[67][0-9][0-9])/(.*)$ {
        proxy_pass http://127.0.0.1:$1/$2$is_args$args;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection upgrade;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
"""

replacement = """    location ~ ^/novnc/(7[67][0-9][0-9])/(.*)$ {
        auth_request /_auth_session;
        proxy_pass http://127.0.0.1:$1/$2$is_args$args;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection upgrade;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
"""

if target in text:
    text = text.replace(target, replacement, 1)

path.write_text(text)
PY
}

update_env_file "$APP_DIR/shared/.env"
cp "$APP_DIR/shared/.env" "$APP_DIR/current/.env"
update_nginx_site

nginx -t >/dev/null
systemctl reload nginx
systemctl restart phishing
systemctl is-active phishing

echo "Unified auth config applied."