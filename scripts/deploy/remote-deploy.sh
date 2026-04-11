#!/usr/bin/env bash

set -euo pipefail

APP_NAME="${APP_NAME:-phishing}"
APP_DIR="${APP_DIR:-/opt/phishing}"
SERVICE_NAME="${SERVICE_NAME:-phishing}"
PORT="${PORT:-4000}"
RELEASE_ARCHIVE="${RELEASE_ARCHIVE:-/tmp/${APP_NAME}-release.tgz}"
ENV_FILE_PATH="${ENV_FILE_PATH:-}"
ENABLE_LOCAL_BROWSER_SANDBOX="${ENABLE_LOCAL_BROWSER_SANDBOX:-0}"

install_node() {
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    return
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl gnupg

  install -d -m 0755 /etc/apt/keyrings

  if [ ! -f /etc/apt/keyrings/nodesource.gpg ]; then
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
      | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  fi

  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list

  apt-get update
  apt-get install -y nodejs
}

write_service() {
  local node_path
  node_path="$(command -v node)"

  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=${APP_NAME} service
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}/current
Environment=NODE_ENV=production
Environment=PORT=${PORT}
ExecStart=${node_path} dist-server/backend/server.js
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
}

setup_novnc_proxy() {
  if ! command -v nginx >/dev/null 2>&1; then
    echo "Nginx not found; skipping noVNC reverse-proxy setup."
    return
  fi

  local snippet="scripts/deploy/nginx-novnc-proxy.conf"
  if [ ! -f "${snippet}" ]; then
    return
  fi

  mkdir -p /etc/nginx/snippets
  cp "${snippet}" /etc/nginx/snippets/novnc-proxy.conf

  # Check whether the snippet is already included in an enabled server block.
  local already_included=0
  for conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
    [ -f "${conf}" ] || continue
    if grep -q 'novnc-proxy\.conf' "${conf}"; then
      already_included=1
      break
    fi
  done

  if [ "${already_included}" = "0" ]; then
    # Try to auto-inject into the server block that proxies the app.
    for conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
      [ -f "${conf}" ] || continue
      if grep -qE "proxy_pass.*127\\.0\\.0\\.1.*${PORT}" "${conf}" 2>/dev/null; then
        sed -i '0,/server_name/{/server_name/a\    include /etc/nginx/snippets/novnc-proxy.conf;' "${conf}" && \
          echo "Injected noVNC proxy snippet into ${conf}"
        break
      fi
    done
  fi

  if nginx -t 2>/dev/null; then
    systemctl reload nginx
    echo "Nginx reloaded with noVNC WebSocket proxy support."
  else
    echo "Warning: nginx config test failed; removing injected snippet line." >&2
    for conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
      [ -f "${conf}" ] || continue
      sed -i '/novnc-proxy\.conf/d' "${conf}"
    done
    nginx -t 2>/dev/null && systemctl reload nginx
  fi
}

main() {
  install_node

  mkdir -p "${APP_DIR}/releases" "${APP_DIR}/shared"

  local release_dir
  release_dir="${APP_DIR}/releases/$(date +%Y%m%d%H%M%S)"
  mkdir -p "${release_dir}"

  tar -xzf "${RELEASE_ARCHIVE}" -C "${release_dir}"

  if [ -n "${ENV_FILE_PATH}" ] && [ -f "${ENV_FILE_PATH}" ]; then
    cp "${ENV_FILE_PATH}" "${APP_DIR}/shared/.env"
  fi

  if [ -f "${APP_DIR}/shared/.env" ]; then
    cp "${APP_DIR}/shared/.env" "${release_dir}/.env"
  fi

  mkdir -p "${release_dir}/storage"

  cd "${release_dir}"
  npm ci --omit=dev

  if [ "${ENABLE_LOCAL_BROWSER_SANDBOX}" = "1" ] && [ -f "scripts/deploy/install-local-browser-sandbox.sh" ]; then
    bash "scripts/deploy/install-local-browser-sandbox.sh"
  fi

  if [ "${ENABLE_LOCAL_BROWSER_SANDBOX}" = "1" ]; then
    setup_novnc_proxy
  fi

  ln -sfn "${release_dir}" "${APP_DIR}/current"

  write_service
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"

  # Wait for the Node process to bind its port
  local retries=10
  while [ $retries -gt 0 ]; do
    if curl --fail --silent "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
      break
    fi
    retries=$((retries - 1))
    sleep 2
  done

  if [ $retries -eq 0 ]; then
    echo "Health check failed after waiting" >&2
    exit 1
  fi

  rm -f "${RELEASE_ARCHIVE}"

  if [ -n "${ENV_FILE_PATH}" ]; then
    rm -f "${ENV_FILE_PATH}"
  fi

  ls -1dt "${APP_DIR}"/releases/* 2>/dev/null | tail -n +6 | xargs -r rm -rf
}

main "$@"