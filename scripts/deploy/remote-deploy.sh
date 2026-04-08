#!/usr/bin/env bash

set -euo pipefail

APP_NAME="${APP_NAME:-phishing}"
APP_DIR="${APP_DIR:-/opt/phishing}"
SERVICE_NAME="${SERVICE_NAME:-phishing}"
PORT="${PORT:-4000}"
RELEASE_ARCHIVE="${RELEASE_ARCHIVE:-/tmp/${APP_NAME}-release.tgz}"
ENV_FILE_PATH="${ENV_FILE_PATH:-}"

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

  ln -sfn "${release_dir}" "${APP_DIR}/current"

  write_service
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"

  if command -v curl >/dev/null 2>&1; then
    curl --fail --silent "http://127.0.0.1:${PORT}/api/health" >/dev/null
  fi

  rm -f "${RELEASE_ARCHIVE}"

  if [ -n "${ENV_FILE_PATH}" ]; then
    rm -f "${ENV_FILE_PATH}"
  fi

  ls -1dt "${APP_DIR}"/releases/* 2>/dev/null | tail -n +6 | xargs -r rm -rf
}

main "$@"