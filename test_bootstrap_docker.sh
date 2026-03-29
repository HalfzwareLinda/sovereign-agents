#!/bin/bash
# test_bootstrap_docker.sh — Docker-compatible wrapper for bootstrap_agent.sh
#
# Patches commands that don't work in Docker containers (ufw, systemctl)
# without modifying the production bootstrap script.

set -euo pipefail

echo "========================================"
echo "  Docker Bootstrap Test Wrapper"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "========================================"
echo ""

# Stub out ufw — Docker lacks iptables kernel modules
echo "  Stubbing ufw for Docker..."
cat > /usr/local/bin/ufw << 'EOF'
#!/bin/bash
echo "  [DOCKER STUB] ufw $*"
exit 0
EOF
chmod +x /usr/local/bin/ufw

# Stub out systemctl — Docker has no systemd
echo "  Stubbing systemctl for Docker..."
cat > /usr/local/bin/systemctl << 'EOF'
#!/bin/bash
echo "  [DOCKER STUB] systemctl $*"
exit 0
EOF
chmod +x /usr/local/bin/systemctl

# Stub out systemd-related commands
cat > /usr/local/bin/dpkg-reconfigure << 'DPKGEOF'
#!/bin/bash
echo "  [DOCKER STUB] dpkg-reconfigure $*"
exit 0
DPKGEOF
chmod +x /usr/local/bin/dpkg-reconfigure

# Ensure /usr/local/bin is first in PATH so stubs take precedence
export PATH="/usr/local/bin:$PATH"

echo ""
echo "  Starting bootstrap_agent.sh..."
echo "========================================"
echo ""

# Run the real bootstrap script
exec bash /tmp/agent-bootstrap/bootstrap_agent.sh
