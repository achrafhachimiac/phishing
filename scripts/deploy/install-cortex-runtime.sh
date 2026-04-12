#!/usr/bin/env bash

set -euo pipefail

APP_NAME="${APP_NAME:-phishing}"
APP_DIR="${APP_DIR:-/opt/phishing}"
APP_SHARED_DIR="${APP_SHARED_DIR:-${APP_DIR}/shared}"
APP_ENV_FILE="${APP_ENV_FILE:-${APP_SHARED_DIR}/.env}"
CORTEX_RUNTIME_DIR="${CORTEX_RUNTIME_DIR:-${APP_SHARED_DIR}/cortex-runtime}"
CORTEX_RUNTIME_ENV_FILE="${CORTEX_RUNTIME_ENV_FILE:-${CORTEX_RUNTIME_DIR}/runtime.env}"
CORTEX_RUNTIME_COMPOSE_FILE="${CORTEX_RUNTIME_COMPOSE_FILE:-${CORTEX_RUNTIME_DIR}/docker-compose.yml}"

read_env_value() {
  local key="$1"

  if [ ! -f "${APP_ENV_FILE}" ]; then
    return 1
  fi

  sed -n "s/^${key}=//p" "${APP_ENV_FILE}" | tail -n 1
}

bool_from_value() {
  local value="${1:-}"
  case "${value,,}" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    return
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl gnupg

  install -d -m 0755 /etc/apt/keyrings

  if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  fi

  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

configure_elasticsearch_kernel_settings() {
  cat > /etc/sysctl.d/99-${APP_NAME}-cortex-elasticsearch.conf <<EOF
vm.max_map_count=262144
EOF

  sysctl -w vm.max_map_count=262144 >/dev/null
}

ensure_runtime_directories() {
  mkdir -p \
    "${CORTEX_RUNTIME_DIR}" \
    "${CORTEX_RUNTIME_DIR}/jobs" \
    "${CORTEX_RUNTIME_DIR}/elasticsearch-data"

  # Elasticsearch runs as uid 1000 in the official container and needs write access
  # to the mounted data directory to create node.lock and shard data.
  chown -R 1000:0 "${CORTEX_RUNTIME_DIR}/elasticsearch-data"
  chmod 0770 "${CORTEX_RUNTIME_DIR}/elasticsearch-data"
}

ensure_runtime_secret() {
  local secret_file="${CORTEX_RUNTIME_DIR}/secret"

  if [ -s "${secret_file}" ]; then
    cat "${secret_file}"
    return
  fi

  local secret
  secret="$(openssl rand -hex 32)"
  printf '%s\n' "${secret}" > "${secret_file}"
  printf '%s' "${secret}"
}

write_runtime_env() {
  local cortex_port="$1"
  local cortex_image="$2"
  local elasticsearch_image="$3"
  local es_java_opts="$4"
  local secret="$5"
  local analyzer_urls="$6"
  local responder_urls="$7"
  local elasticsearch_port="$8"

  cat > "${CORTEX_RUNTIME_ENV_FILE}" <<EOF
CORTEX_IMAGE=${cortex_image}
CORTEX_ELASTICSEARCH_IMAGE=${elasticsearch_image}
CORTEX_SECRET=${secret}
CORTEX_RUNTIME_PORT=${cortex_port}
CORTEX_RUNTIME_ELASTICSEARCH_PORT=${elasticsearch_port}
CORTEX_RUNTIME_ES_JAVA_OPTS=${es_java_opts}
CORTEX_JOB_DIRECTORY_HOST=${CORTEX_RUNTIME_DIR}/jobs
CORTEX_ANALYZER_URLS=${analyzer_urls}
CORTEX_RESPONDER_URLS=${responder_urls}
EOF
}

write_compose_file() {
  cat > "${CORTEX_RUNTIME_COMPOSE_FILE}" <<'EOF'
services:
  elasticsearch:
    image: ${CORTEX_ELASTICSEARCH_IMAGE}
    container_name: phishing-cortex-elasticsearch
    restart: unless-stopped
    environment:
      discovery.type: single-node
      xpack.security.enabled: "false"
      ES_JAVA_OPTS: ${CORTEX_RUNTIME_ES_JAVA_OPTS}
    ports:
      - 127.0.0.1:${CORTEX_RUNTIME_ELASTICSEARCH_PORT}:9200
    volumes:
      - ./elasticsearch-data:/usr/share/elasticsearch/data

  cortex:
    image: ${CORTEX_IMAGE}
    container_name: phishing-cortex
    restart: unless-stopped
    depends_on:
      - elasticsearch
    environment:
      es_uri: http://elasticsearch:9200
      secret: ${CORTEX_SECRET}
      job_directory: /opt/cortex/jobs
      docker_job_directory: ${CORTEX_JOB_DIRECTORY_HOST}
      analyzer_urls: ${CORTEX_ANALYZER_URLS}
      responder_urls: ${CORTEX_RESPONDER_URLS}
    ports:
      - 127.0.0.1:${CORTEX_RUNTIME_PORT}:9001
    volumes:
      - ./jobs:/opt/cortex/jobs
      - /var/run/docker.sock:/var/run/docker.sock
EOF
}

start_runtime() {
  local elasticsearch_port="$1"

  docker compose \
    --env-file "${CORTEX_RUNTIME_ENV_FILE}" \
    -f "${CORTEX_RUNTIME_COMPOSE_FILE}" \
    up -d elasticsearch

  local es_attempts=30
  while [ "${es_attempts}" -gt 0 ]; do
    if curl --fail --silent "http://127.0.0.1:${elasticsearch_port}" >/dev/null 2>&1; then
      break
    fi

    es_attempts=$((es_attempts - 1))
    sleep 5
  done

  if [ "${es_attempts}" -eq 0 ]; then
    echo "Elasticsearch did not become reachable on port ${elasticsearch_port}." >&2
    docker compose --env-file "${CORTEX_RUNTIME_ENV_FILE}" -f "${CORTEX_RUNTIME_COMPOSE_FILE}" ps >&2 || true
    exit 1
  fi

  docker compose \
    --env-file "${CORTEX_RUNTIME_ENV_FILE}" \
    -f "${CORTEX_RUNTIME_COMPOSE_FILE}" \
    up -d cortex
}

wait_for_cortex() {
  local cortex_port="$1"
  local attempts=30

  while [ "${attempts}" -gt 0 ]; do
    if curl --fail --silent "http://127.0.0.1:${cortex_port}" >/dev/null 2>&1; then
      return
    fi

    attempts=$((attempts - 1))
    sleep 5
  done

  echo "Cortex runtime did not become reachable on port ${cortex_port}." >&2
  docker compose --env-file "${CORTEX_RUNTIME_ENV_FILE}" -f "${CORTEX_RUNTIME_COMPOSE_FILE}" ps >&2 || true
  exit 1
}

main() {
  local runtime_enabled
  runtime_enabled="$(read_env_value CORTEX_RUNTIME_ENABLED 2>/dev/null || true)"

  if [ -n "${runtime_enabled}" ] && ! bool_from_value "${runtime_enabled}"; then
    echo "Cortex runtime install skipped because CORTEX_RUNTIME_ENABLED is disabled in ${APP_ENV_FILE}."
    return
  fi

  local cortex_port
  local cortex_image
  local elasticsearch_image
  local es_java_opts
  local analyzer_urls
  local responder_urls
  local elasticsearch_port

  cortex_port="$(read_env_value CORTEX_RUNTIME_PORT 2>/dev/null || true)"
  cortex_image="$(read_env_value CORTEX_RUNTIME_IMAGE 2>/dev/null || true)"
  elasticsearch_image="$(read_env_value CORTEX_RUNTIME_ELASTICSEARCH_IMAGE 2>/dev/null || true)"
  es_java_opts="$(read_env_value CORTEX_RUNTIME_ES_JAVA_OPTS 2>/dev/null || true)"
  analyzer_urls="$(read_env_value CORTEX_RUNTIME_ANALYZER_URLS 2>/dev/null || true)"
  responder_urls="$(read_env_value CORTEX_RUNTIME_RESPONDER_URLS 2>/dev/null || true)"
  elasticsearch_port="$(read_env_value CORTEX_RUNTIME_ELASTICSEARCH_PORT 2>/dev/null || true)"

  cortex_port="${cortex_port:-9001}"
  cortex_image="${cortex_image:-thehiveproject/cortex:4.0.1}"
  elasticsearch_image="${elasticsearch_image:-docker.elastic.co/elasticsearch/elasticsearch:8.19.0}"
  es_java_opts="${es_java_opts:--Xms1g -Xmx1g}"
  analyzer_urls="${analyzer_urls:-https://catalogs.download.strangebee.com/latest/json/analyzers.json}"
  responder_urls="${responder_urls:-https://catalogs.download.strangebee.com/latest/json/responders.json}"
  elasticsearch_port="${elasticsearch_port:-9201}"

  install_docker
  configure_elasticsearch_kernel_settings
  ensure_runtime_directories

  local secret
  secret="$(ensure_runtime_secret)"

  write_runtime_env \
    "${cortex_port}" \
    "${cortex_image}" \
    "${elasticsearch_image}" \
    "${es_java_opts}" \
    "${secret}" \
    "${analyzer_urls}" \
    "${responder_urls}" \
    "${elasticsearch_port}"
  write_compose_file
  start_runtime "${elasticsearch_port}"
  wait_for_cortex "${cortex_port}"

  cat <<EOF
Cortex runtime is installed under ${CORTEX_RUNTIME_DIR}.
Containers are managed by docker compose and survive app release rotations.
If you enable app-side Cortex integration, set CORTEX_BASE_URL=http://127.0.0.1:${cortex_port} and provide a valid CORTEX_API_KEY in ${APP_ENV_FILE}.
EOF
}

main "$@"