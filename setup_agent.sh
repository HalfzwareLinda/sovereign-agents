#!/bin/bash
# =============================================================================
# setup_vps.sh — Sovereign Agent VPS Setup
#
# This script is executed over SSH on a fresh LNVPS Ubuntu VM.
# provision_agent.py uploads this script, the config, workspace files, and
# keys, then runs it remotely.
#
# It expects the following files to already be uploaded to /tmp/agent-setup/:
#   - openclaw.json         (OpenClaw config)
#   - keys.json             (private keys — moved to secure location)
#   - workspace/*.md        (inherited memory / workspace files)
# =============================================================================
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

SETUP_DIR="/tmp/agent-setup"
LOG="/var/log/agent-provision.log"
exec > >(tee -a "$LOG") 2>&1

echo "========================================"
echo "  Sovereign Agent VPS Setup"
echo "  Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "========================================"

# ------------------------------------------------------------------
# 1. System packages
# ------------------------------------------------------------------
echo "[1/8] Installing system packages..."
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    docker.io \
    docker-compose-v2 \
    curl \
    jq \
    ufw \
    git \
    unattended-upgrades

# Enable automatic security updates
dpkg-reconfigure -f noninteractive unattended-upgrades

# ------------------------------------------------------------------
# 2. Firewall
# ------------------------------------------------------------------
echo "[2/8] Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment 'SSH'
ufw allow 3000/tcp  comment 'OpenClaw webchat'
ufw allow 443/tcp   comment 'HTTPS'
ufw allow 80/tcp    comment 'HTTP'
ufw --force enable
echo "  Firewall: SSH(22) Webchat(3000) HTTP(80) HTTPS(443)"

# ------------------------------------------------------------------
# 3. Create agent user
# ------------------------------------------------------------------
echo "[3/8] Creating agent user..."
useradd -m -s /bin/bash agent 2>/dev/null || true
usermod -aG docker agent

# ------------------------------------------------------------------
# 4. Secure key storage
# ------------------------------------------------------------------
echo "[4/8] Securing private keys..."
mkdir -p /opt/agent-keys
cp "${SETUP_DIR}/keys.json" /opt/agent-keys/keys.json
chmod 700 /opt/agent-keys
chmod 600 /opt/agent-keys/keys.json
chown -R root:root /opt/agent-keys

# ------------------------------------------------------------------
# 5. Install OpenClaw
# ------------------------------------------------------------------
echo "[5/9] Installing OpenClaw..."

# Install OpenClaw via the official install script
# This sets up the Docker container and CLI
curl -fsSL https://get.openclaw.ai | bash || {
    echo "  OpenClaw installer failed — trying manual Docker setup"
    cd /opt
    if [ ! -d "openclaw" ]; then
        git clone --depth 1 https://github.com/openclaw/openclaw.git
    fi
}

# Determine OpenClaw directory
OPENCLAW_DIR="${HOME}/.openclaw"
mkdir -p "${OPENCLAW_DIR}/workspace"

# ------------------------------------------------------------------
# 6. Write config + workspace
# ------------------------------------------------------------------
echo "[6/9] Writing configuration and workspace..."
cp "${SETUP_DIR}/openclaw.json" "${OPENCLAW_DIR}/openclaw.json"
chmod 600 "${OPENCLAW_DIR}/openclaw.json"

if [ -d "${SETUP_DIR}/workspace" ]; then
    cp "${SETUP_DIR}/workspace/"*.md "${OPENCLAW_DIR}/workspace/" 2>/dev/null || true
fi

# Write API key to auth-profiles.json (OpenClaw stores keys here, not in config)
PAYPERQ_KEY=$(jq -r '.payperq_api_key // empty' "${SETUP_DIR}/keys.json" 2>/dev/null || echo "")
if [ -n "${PAYPERQ_KEY}" ]; then
    mkdir -p "${OPENCLAW_DIR}/agents/main/agent"
    cat > "${OPENCLAW_DIR}/agents/main/agent/auth-profiles.json" << AUTHEOF
{
  "openai:default": {
    "provider": "openai",
    "mode": "token",
    "token": "${PAYPERQ_KEY}",
    "baseUrl": "https://api.ppq.ai"
  }
}
AUTHEOF
    chmod 600 "${OPENCLAW_DIR}/agents/main/agent/auth-profiles.json"
fi

chown -R agent:agent "${OPENCLAW_DIR}"

# ------------------------------------------------------------------
# 7. Install Nostr plugin
# ------------------------------------------------------------------
echo "[7/9] Installing Nostr plugin..."
# Extract Nostr nsec from keys.json for plugin config
NOSTR_NSEC=$(jq -r '.nostr.nsec // empty' "${SETUP_DIR}/keys.json" 2>/dev/null || echo "")
if [ -n "${NOSTR_NSEC}" ]; then
    sudo -u agent openclaw plugins install @openclaw/nostr 2>/dev/null || echo "  Nostr plugin install skipped (may need manual setup)"
    # TODO: Configure Nostr plugin with nsec, relays, dmPolicy
    # This requires openclaw nostr configure or editing the plugin config directly
    echo "  Nostr plugin installed — configure manually if needed"
fi

# ------------------------------------------------------------------
# 8. Start OpenClaw
# ------------------------------------------------------------------
echo "[8/9] Starting OpenClaw..."
sudo -u agent openclaw gateway start 2>/dev/null || {
    echo "  openclaw CLI not available — trying Docker compose"
    cd /opt/openclaw 2>/dev/null && sudo -u agent docker compose up -d
}

# ------------------------------------------------------------------
# 9. Health check
# ------------------------------------------------------------------
echo "[9/9] Health check..."
HEALTH_OK=false
for i in $(seq 1 12); do
    if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
        echo "  Health check PASSED (attempt $i)"
        HEALTH_OK=true
        break
    fi
    echo "  Waiting for OpenClaw... ($i/12)"
    sleep 10
done

if [ "$HEALTH_OK" = false ]; then
    echo "  WARNING: Health check failed — agent may still be booting"
    echo "  Debug: cd /opt/openclaw && docker compose logs"
fi

# ------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------
rm -rf "${SETUP_DIR}"

PUBLIC_IP=$(curl -sf ifconfig.me || echo "unknown")
echo ""
echo "========================================"
echo "  Setup Complete"
echo "  Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Webchat:  http://${PUBLIC_IP}:3000"
echo "========================================"
