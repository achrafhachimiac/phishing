#!/usr/bin/env bash

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y xvfb x11vnc novnc websockify clamav clamav-freshclam yara

npx playwright install --with-deps chromium

mkdir -p storage/sandbox-sessions storage/downloads storage/uploads storage/file-reports /opt/yara/rules

if [ ! -f /opt/yara/rules/index.yar ]; then
	cat > /opt/yara/rules/index.yar <<'EOF'
rule placeholder_never_match {
	condition:
		false
}
EOF
fi

freshclam || true

echo "Local browser sandbox runtime and file scanners installed."