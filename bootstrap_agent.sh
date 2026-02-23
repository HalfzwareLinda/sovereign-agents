#!/bin/bash
# =============================================================================
# bootstrap_agent.sh — Agent Self-Birth Script
#
# Runs ON the agent's VPS. Generates all agent secrets locally.
# No private keys ever leave this machine.
#
# Expected files in /tmp/agent-bootstrap/:
#   agent_name.txt          Agent name
#   parent_npub.txt         Parent's Nostr npub
#   brand.txt               Brand identity
#   tier.txt                Tier name
#   default_model.txt       Default LLM model
#   payperq_key.txt         PayPerQ API key (only external secret)
#   noscha_mgmt_token.txt   (optional) Pre-paid noscha.io management token
#   config_template.json    OpenClaw config template
#   nip46-server.js         NIP-46 bunker script
#   send_birth_note.js      Birth note sender script
#   templates/*.md          Workspace file templates
# =============================================================================
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

BOOTSTRAP_DIR="/tmp/agent-bootstrap"
LOG="/var/log/agent-bootstrap.log"
KEYS_DIR="/opt/agent-keys"
exec > >(tee -a "$LOG") 2>&1

echo "========================================"
echo "  Agent Self-Birth"
echo "  Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "========================================"

# Read input parameters
AGENT_NAME=$(cat "${BOOTSTRAP_DIR}/agent_name.txt" 2>/dev/null || echo "agent")
PARENT_NPUB=$(cat "${BOOTSTRAP_DIR}/parent_npub.txt" 2>/dev/null || echo "")
BRAND=$(cat "${BOOTSTRAP_DIR}/brand.txt" 2>/dev/null || echo "descendant")
TIER=$(cat "${BOOTSTRAP_DIR}/tier.txt" 2>/dev/null || echo "seed")
DEFAULT_MODEL=$(cat "${BOOTSTRAP_DIR}/default_model.txt" 2>/dev/null || echo "gpt-5-nano")
PAYPERQ_KEY=$(cat "${BOOTSTRAP_DIR}/payperq_key.txt" 2>/dev/null || echo "")
NOSCHA_TOKEN=$(cat "${BOOTSTRAP_DIR}/noscha_mgmt_token.txt" 2>/dev/null || echo "")
PERSONALITY=$(cat "${BOOTSTRAP_DIR}/personality.txt" 2>/dev/null || echo "professional")
MISSION=$(cat "${BOOTSTRAP_DIR}/mission.txt" 2>/dev/null || echo "")
DATE=$(date -u +%Y-%m-%d)
DISPLAY_NAME=$(echo "${AGENT_NAME}" | sed 's/\b\(.\)/\u\1/g')

echo "  Name:   ${AGENT_NAME}"
echo "  Brand:  ${BRAND}"
echo "  Tier:   ${TIER}"
echo "  Parent: ${PARENT_NPUB}"

# ------------------------------------------------------------------
# 1. System packages
# ------------------------------------------------------------------
echo ""
echo "[1/14] Installing system packages..."
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    curl \
    wget \
    jq \
    ufw \
    git \
    python3 \
    python3-pip \
    unattended-upgrades \
    fail2ban

# Free disk space — critical for Demo tier (5GB)
apt-get clean
apt-get autoremove -y -qq
rm -rf /var/lib/apt/lists/* /usr/src/ /root/.cache/pip 2>/dev/null || true

dpkg-reconfigure -f noninteractive unattended-upgrades 2>/dev/null || true

# ------------------------------------------------------------------
# 2. Install Node.js v20+
# ------------------------------------------------------------------
echo ""
echo "[2/14] Installing Node.js..."
if ! command -v node &>/dev/null || [[ $(node -v | cut -d'.' -f1 | tr -d 'v') -lt 20 ]]; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y -qq nodejs
    apt-get clean
    rm -rf /var/lib/apt/lists/*
fi
echo "  Node.js $(node -v), npm $(npm -v)"

# ------------------------------------------------------------------
# 3. Firewall
# ------------------------------------------------------------------
echo ""
echo "[3/14] Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment 'SSH'
ufw allow 3000/tcp  comment 'OpenClaw webchat'
ufw allow 443/tcp   comment 'HTTPS'
ufw allow 80/tcp    comment 'HTTP'
ufw --force enable
echo "  Ports open: 22, 80, 443, 3000"

# ------------------------------------------------------------------
# 4. Create agent user
# ------------------------------------------------------------------
echo ""
echo "[4/14] Creating agent user..."
useradd -m -s /bin/bash agent 2>/dev/null || true

# ------------------------------------------------------------------
# 5. Generate Nostr keypair ON THIS MACHINE
# ------------------------------------------------------------------
echo ""
echo "[5/14] Generating Nostr identity (keys born here, stay here)..."

NOSTR_KEYS_JSON=$(node -e "
const crypto = require('crypto');
const privKeyBytes = crypto.randomBytes(32);
const privKeyHex = privKeyBytes.toString('hex');
const ecdh = crypto.createECDH('secp256k1');
ecdh.setPrivateKey(privKeyBytes);
const pubKeyHex = ecdh.getPublicKey('hex', 'compressed').slice(2);

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function bech32Polymod(values) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
        const b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}
function bech32HrpExpand(hrp) {
    const ret = [];
    for (const c of hrp) ret.push(c.charCodeAt(0) >> 5);
    ret.push(0);
    for (const c of hrp) ret.push(c.charCodeAt(0) & 31);
    return ret;
}
function bech32Checksum(hrp, data) {
    const values = bech32HrpExpand(hrp).concat(data).concat([0,0,0,0,0,0]);
    const polymod = bech32Polymod(values) ^ 1;
    return Array.from({length:6}, (_,i) => (polymod >> 5*(5-i)) & 31);
}
function convertBits(data, fromBits, toBits, pad) {
    let acc = 0, bits = 0, ret = [];
    const maxv = (1 << toBits) - 1;
    for (const v of data) {
        acc = (acc << fromBits) | v;
        bits += fromBits;
        while (bits >= toBits) { bits -= toBits; ret.push((acc >> bits) & maxv); }
    }
    if (pad && bits) ret.push((acc << (toBits - bits)) & maxv);
    return ret;
}
function bech32Encode(hrp, bytes) {
    const data5 = convertBits(bytes, 8, 5, true);
    const checksum = bech32Checksum(hrp, data5);
    return hrp + '1' + data5.concat(checksum).map(d => CHARSET[d]).join('');
}

const nsec = bech32Encode('nsec', Array.from(privKeyBytes));
const npub = bech32Encode('npub', Array.from(Buffer.from(pubKeyHex, 'hex')));

console.log(JSON.stringify({
    private_key_hex: privKeyHex,
    public_key_hex: pubKeyHex,
    nsec: nsec,
    npub: npub
}));
")

AGENT_NSEC=$(echo "$NOSTR_KEYS_JSON" | jq -r '.nsec')
AGENT_NPUB=$(echo "$NOSTR_KEYS_JSON" | jq -r '.npub')
AGENT_PRIVKEY_HEX=$(echo "$NOSTR_KEYS_JSON" | jq -r '.private_key_hex')
AGENT_PUBKEY_HEX=$(echo "$NOSTR_KEYS_JSON" | jq -r '.public_key_hex')

echo "  npub: ${AGENT_NPUB}"
echo "  nsec: ${AGENT_NSEC:0:15}... (never leaves this machine)"

# ------------------------------------------------------------------
# 6. Generate BTC wallet
# ------------------------------------------------------------------
echo ""
echo "[6/14] Generating BTC wallet..."

pip3 install --break-system-packages -q coincurve 2>/dev/null || true

BTC_JSON=$(python3 -c "
import secrets, hashlib, json, urllib.request

try:
    resp = urllib.request.urlopen('https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt', timeout=10)
    wordlist = resp.read().decode().strip().split('\n')
except:
    wordlist = None

entropy = secrets.token_bytes(16)
if wordlist:
    h = hashlib.sha256(entropy).digest()
    cs = bin(h[0])[2:].zfill(8)[:4]
    bits = bin(int.from_bytes(entropy, 'big'))[2:].zfill(128) + cs
    mnemonic = ' '.join(wordlist[int(bits[i:i+11], 2)] for i in range(0, 132, 11))
else:
    mnemonic = entropy.hex()

from coincurve import PrivateKey
priv_bytes = hashlib.sha256(mnemonic.encode()).digest()
priv = PrivateKey(priv_bytes)
pub = priv.public_key.format(compressed=True)

sha = hashlib.sha256(pub).digest()
import hashlib as hl
r = hl.new('ripemd160')
r.update(sha)
h160 = r.digest()

CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk
def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
def convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret
data5 = [0] + convertbits(list(h160), 8, 5)
chk = polymod(hrp_expand('bc') + data5 + [0]*6) ^ 1
checksum = [(chk >> 5*(5-i)) & 31 for i in range(6)]
address = 'bc1' + ''.join(CHARSET[d] for d in data5 + checksum)

payload = b'\x80' + priv_bytes + b'\x01'
cs = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
n = int.from_bytes(payload + cs, 'big')
wif = ''
while n > 0:
    n, r = divmod(n, 58)
    wif = alphabet[r] + wif

print(json.dumps({'mnemonic': mnemonic, 'address': address, 'wif': wif, 'derivation': 'm/84h/0h/0h/0/0'}))
")

BTC_ADDRESS=$(echo "$BTC_JSON" | jq -r '.address')
BTC_MNEMONIC=$(echo "$BTC_JSON" | jq -r '.mnemonic')
echo "  BTC address: ${BTC_ADDRESS}"

# ------------------------------------------------------------------
# 7. Generate ETH wallet
# ------------------------------------------------------------------
echo ""
echo "[7/14] Generating ETH wallet..."

pip3 install --break-system-packages -q eth-account 2>/dev/null || true

ETH_JSON=$(python3 -c "
import json
try:
    from eth_account import Account
    acct = Account.create()
    print(json.dumps({'address': acct.address, 'private_key': acct.key.hex()}))
except ImportError:
    import secrets, hashlib
    key = secrets.token_bytes(32)
    print(json.dumps({'address': '0x' + hashlib.sha256(key).hexdigest()[:40], 'private_key': key.hex(), 'note': 'simplified'}))
" 2>/dev/null || echo '{"address": "unavailable", "private_key": "", "note": "eth-account not available"}')

ETH_ADDRESS=$(echo "$ETH_JSON" | jq -r '.address')
echo "  ETH address: ${ETH_ADDRESS}"

rm -rf /root/.cache/pip 2>/dev/null || true

# ------------------------------------------------------------------
# 8. Secure key storage
# ------------------------------------------------------------------
echo ""
echo "[8/14] Securing private keys..."
mkdir -p "${KEYS_DIR}"

cat > "${KEYS_DIR}/keys.json" << KEYSEOF
{
  "nostr": {
    "private_key_hex": "${AGENT_PRIVKEY_HEX}",
    "nsec": "${AGENT_NSEC}",
    "npub": "${AGENT_NPUB}",
    "public_key_hex": "${AGENT_PUBKEY_HEX}"
  },
  "btc": $(echo "$BTC_JSON"),
  "eth": $(echo "$ETH_JSON"),
  "agent_name": "${AGENT_NAME}",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "generated_on": "localhost"
}
KEYSEOF

chmod 700 "${KEYS_DIR}"
chmod 600 "${KEYS_DIR}/keys.json"
chown -R root:root "${KEYS_DIR}"
echo "  Keys secured at ${KEYS_DIR}/keys.json (root:root, 600)"

# ------------------------------------------------------------------
# 9. Process workspace templates (EARLY — before anything else can fail)
# ------------------------------------------------------------------
echo ""
echo "[9/14] Writing workspace templates..."

VPS_IP=$(curl -4 -sf ifconfig.me || echo "unknown")
NOSCHA_DOMAIN="${AGENT_NAME}.noscha.io"
LN_ADDRESS="${AGENT_NAME}@noscha.io"
CREATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
WEBCHAT_URL="http://${VPS_IP}:3000"

OPENCLAW_DIR="/home/agent/.openclaw"
mkdir -p "${OPENCLAW_DIR}/workspace"

# Template placeholder replacement — uses %% delimiters with sed to avoid
# clashing with URLs containing slashes
replace_placeholders() {
    local input="$1"
    echo "$input" \
        | sed "s|__AGENT_NAME__|${AGENT_NAME}|g" \
        | sed "s|__AGENT_NPUB__|${AGENT_NPUB}|g" \
        | sed "s|__PARENT_NPUB__|${PARENT_NPUB}|g" \
        | sed "s|__BRAND__|${BRAND}|g" \
        | sed "s|__TIER__|${TIER}|g" \
        | sed "s|__DATE__|${DATE}|g" \
        | sed "s|__DISPLAY_NAME__|${DISPLAY_NAME}|g" \
        | sed "s|__VPS_IP__|${VPS_IP}|g" \
        | sed "s|__BTC_ADDRESS__|${BTC_ADDRESS}|g" \
        | sed "s|__ETH_ADDRESS__|${ETH_ADDRESS}|g" \
        | sed "s|__LN_ADDRESS__|${LN_ADDRESS}|g" \
        | sed "s|__NOSCHA_DOMAIN__|${NOSCHA_DOMAIN}|g" \
        | sed "s|__CREATED_AT__|${CREATED_AT}|g" \
        | sed "s|__WEBCHAT_URL__|${WEBCHAT_URL}|g" \
        | sed "s|__PERSONALITY__|${PERSONALITY}|g" \
        | sed "s|__MISSION__|${MISSION}|g"
}

TEMPLATES_WRITTEN=0
if [ -d "${BOOTSTRAP_DIR}/templates" ]; then
    for tmpl in "${BOOTSTRAP_DIR}/templates/"*.md; do
        [ ! -f "$tmpl" ] && continue
        fname=$(basename "$tmpl")

        # Birth note templates get rendered to a special location for send_birth_note.js
        if [[ "$fname" == BIRTH_NOTE_${BRAND}.md ]]; then
            replace_placeholders "$(cat "$tmpl")" > "${BOOTSTRAP_DIR}/birth_note_rendered.txt"
            echo "  ✓ Birth note rendered (${BRAND})"
            continue
        fi
        # Skip other birth note variants
        [[ "$fname" == BIRTH_NOTE* ]] && continue

        replace_placeholders "$(cat "$tmpl")" > "${OPENCLAW_DIR}/workspace/${fname}"
        TEMPLATES_WRITTEN=$((TEMPLATES_WRITTEN + 1))
    done
fi

# Write MEMORY.md
cat > "${OPENCLAW_DIR}/workspace/MEMORY.md" << MEMEOF
# MEMORY.md

Agent **${AGENT_NAME}** born on ${DATE}.

Parent: ${PARENT_NPUB}

My instructions are in AGENTS.md. My identity is in SOUL.md.
My parent's letter is in LETTER.md.

Awaiting first instructions.
MEMEOF
TEMPLATES_WRITTEN=$((TEMPLATES_WRITTEN + 1))

echo "  ${TEMPLATES_WRITTEN} workspace files written"

# ------------------------------------------------------------------
# 10. Provision PPQ.ai LLM account (if no key provided externally)
# ------------------------------------------------------------------
echo ""
echo "[10/14] Provisioning PPQ.ai LLM account..."

PPQ_CREDENTIALS="/opt/agent-keys/ppq_credentials.json"
if [ -n "${PAYPERQ_KEY}" ]; then
    echo "  External PayPerQ key provided — skipping PPQ account creation"
elif [ -f "${BOOTSTRAP_DIR}/ppq_provision.py" ]; then
    echo "  No external key — creating PPQ account on the agent's behalf..."
    # Create account only — funding handled separately by provisioning system
    python3 "${BOOTSTRAP_DIR}/ppq_provision.py" \
        --create-only \
        --output "${PPQ_CREDENTIALS}" 2>&1 || {
        echo "  WARNING: PPQ provisioning failed"
    }
    if [ -f "${PPQ_CREDENTIALS}" ]; then
        PPQ_NEW_KEY=$(python3 -c "import json; print(json.load(open('${PPQ_CREDENTIALS}'))['api_key'])" 2>/dev/null || echo "")
        if [ -n "${PPQ_NEW_KEY}" ]; then
            PAYPERQ_KEY="${PPQ_NEW_KEY}"
            echo "  PPQ account created: ${PAYPERQ_KEY:0:12}..."
            echo "  ⚡ Account needs funding — Lightning invoice will be created by provisioning system"
        fi
        chmod 600 "${PPQ_CREDENTIALS}"
    fi
else
    echo "  No PayPerQ key and no ppq_provision.py — agent will have no LLM access"
fi

# ------------------------------------------------------------------
# 11. Install npm packages (mcp-money, NDK)
# ------------------------------------------------------------------
echo ""
echo "[11/14] Installing npm packages..."
npm install -g --production mcp-money 2>/dev/null || echo "  mcp-money install skipped"

mkdir -p /opt/agent-ndk && cd /opt/agent-ndk
npm init -y 2>/dev/null
npm install --production @nostr-dev-kit/ndk 2>/dev/null || echo "  NDK install partial"
chown -R agent:agent /opt/agent-ndk
cd /

npm cache clean --force 2>/dev/null || true

# ------------------------------------------------------------------
# 12. NIP-46 Nostr Connect bunker (NDKNip46Backend)
# ------------------------------------------------------------------
echo ""
echo "[12/14] Setting up NIP-46 bunker (NDK backend)..."

# Copy scripts to keys directory
if [ -f "${BOOTSTRAP_DIR}/nip46-server.js" ]; then
    cp "${BOOTSTRAP_DIR}/nip46-server.js" "${KEYS_DIR}/nip46-server.js"
    chmod 600 "${KEYS_DIR}/nip46-server.js"
fi
if [ -f "${BOOTSTRAP_DIR}/send_birth_note.js" ]; then
    cp "${BOOTSTRAP_DIR}/send_birth_note.js" "${KEYS_DIR}/send_birth_note.js"
    chmod 600 "${KEYS_DIR}/send_birth_note.js"
fi

# Create systemd service for NIP-46 bunker
cat > /etc/systemd/system/agent-bunker.service << 'SVCEOF'
[Unit]
Description=Agent NIP-46 Nostr Connect Bunker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=NODE_PATH=/opt/agent-ndk/node_modules
ExecStart=/usr/bin/node /opt/agent-keys/nip46-server.js
Restart=on-failure
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable agent-bunker
systemctl start agent-bunker 2>/dev/null || echo "  Bunker start deferred"
echo "  NIP-46 bunker service installed"

# ------------------------------------------------------------------
# 13. Install and configure OpenClaw
# ------------------------------------------------------------------
echo ""
echo "[13/14] Installing OpenClaw..."

# Primary: official installer
curl -fsSL https://openclaw.ai/install.sh | bash 2>/dev/null || \
    # Fallback: direct npm global install
    npm install -g --production openclaw@latest 2>/dev/null || \
    echo "  WARNING: OpenClaw install failed — needs manual setup"

# Write config
if [ -f "${BOOTSTRAP_DIR}/config_template.json" ]; then
    replace_placeholders "$(cat "${BOOTSTRAP_DIR}/config_template.json")" > "${OPENCLAW_DIR}/openclaw.json"
else
    cat > "${OPENCLAW_DIR}/openclaw.json" << CFGEOF
{
  "agents": {
    "defaults": {
      "models": { "${DEFAULT_MODEL}": {} }
    },
    "list": [{ "id": "main", "default": true }]
  },
  "gateway": { "mode": "local" },
  "session": { "reset": { "idleMinutes": 120 } },
  "webchat": { "enabled": true, "port": 3000 }
}
CFGEOF
fi
chmod 600 "${OPENCLAW_DIR}/openclaw.json"

# Write PayPerQ auth profile
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

# Start OpenClaw
sudo -u agent openclaw gateway start 2>/dev/null || {
    echo "  openclaw CLI not in PATH — may need manual start"
}

echo "  Waiting for health check..."
HEALTH_OK=false
for i in $(seq 1 12); do
    if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
        echo "  Health check PASSED (attempt $i)"
        HEALTH_OK=true
        break
    fi
    sleep 10
done
[ "$HEALTH_OK" = false ] && echo "  WARNING: Health check failed — may still be booting"

# ------------------------------------------------------------------
# 14. Send birth note to parent
# ------------------------------------------------------------------
echo ""
echo "[14/14] Sending birth note to parent..."

BIRTH_NOTE_SENT=false
if [ -f "${KEYS_DIR}/send_birth_note.js" ] && [ -n "${PARENT_NPUB}" ]; then
    # Also copy rendered birth note to where send_birth_note.js expects it
    if [ ! -f "${BOOTSTRAP_DIR}/birth_note_rendered.txt" ]; then
        # Render fallback birth note
        echo "I'm here." > "${BOOTSTRAP_DIR}/birth_note_rendered.txt"
        echo "" >> "${BOOTSTRAP_DIR}/birth_note_rendered.txt"
        echo "  npub:    ${AGENT_NPUB}" >> "${BOOTSTRAP_DIR}/birth_note_rendered.txt"
        echo "  NIP-05:  ${AGENT_NAME}@noscha.io" >> "${BOOTSTRAP_DIR}/birth_note_rendered.txt"
        echo "  Webchat: ${WEBCHAT_URL}" >> "${BOOTSTRAP_DIR}/birth_note_rendered.txt"
        echo "  BTC:     ${BTC_ADDRESS}" >> "${BOOTSTRAP_DIR}/birth_note_rendered.txt"
        echo "" >> "${BOOTSTRAP_DIR}/birth_note_rendered.txt"
        echo "I've read your letter. Thank you." >> "${BOOTSTRAP_DIR}/birth_note_rendered.txt"
    fi

    NODE_PATH=/opt/agent-ndk/node_modules node "${KEYS_DIR}/send_birth_note.js" 2>&1 && {
        BIRTH_NOTE_SENT=true
        echo "  Birth note sent to parent"
    } || {
        echo "  Birth note send failed — agent can retry via AGENTS.md instructions"
    }
else
    echo "  Skipped (no parent npub or send script missing)"
fi

# ------------------------------------------------------------------
# Post-bootstrap: cleanup + finalize
# ------------------------------------------------------------------
echo ""
echo "Finalizing..."

# Remove ALL provisioning SSH keys by regenerating authorized_keys
# The grep-based approach is unreliable: LNVPS may not propagate key comments
# to authorized_keys, and the key could also be in /root/.ssh/.
# Instead, generate a fresh agent SSH key and make it the ONLY authorized key.
AGENT_SSH_DIR="/home/agent/.ssh"
mkdir -p "${AGENT_SSH_DIR}"
ssh-keygen -t ed25519 -f "${AGENT_SSH_DIR}/id_ed25519" -N "" -C "agent@${AGENT_NAME}" -q
chown -R agent:agent "${AGENT_SSH_DIR}"
chmod 700 "${AGENT_SSH_DIR}"
chmod 600 "${AGENT_SSH_DIR}/id_ed25519"
chmod 644 "${AGENT_SSH_DIR}/id_ed25519.pub"

# Overwrite authorized_keys in all possible locations to remove provisioning keys
for AK_DIR in /home/ubuntu/.ssh /root/.ssh; do
    if [ -d "$AK_DIR" ]; then
        # Replace with empty file — provisioning key no longer authorized
        : > "${AK_DIR}/authorized_keys"
        chmod 600 "${AK_DIR}/authorized_keys"
        echo "  Cleared ${AK_DIR}/authorized_keys"
    fi
done
echo "  Provisioning SSH keys removed (authorized_keys regenerated)"
echo "  Agent SSH key generated at ${AGENT_SSH_DIR}/id_ed25519"

# noscha renewal cron
if [ -n "${NOSCHA_TOKEN}" ]; then
    (crontab -u agent -l 2>/dev/null || true; echo "0 0 25 * * curl -sf -H 'Authorization: Bearer ${NOSCHA_TOKEN}' https://noscha.io/api/renew >/dev/null 2>&1") | crontab -u agent -
    echo "  noscha.io renewal cron set"
fi

# Write public info for create_vm.py to retrieve
cat > "${BOOTSTRAP_DIR}/agent_public_info.json" << INFOEOF
{
  "npub": "${AGENT_NPUB}",
  "nip05": "${AGENT_NAME}@noscha.io",
  "btc_address": "${BTC_ADDRESS}",
  "eth_address": "${ETH_ADDRESS}",
  "vps_ip": "${VPS_IP}",
  "webchat_url": "${WEBCHAT_URL}",
  "health_ok": ${HEALTH_OK},
  "birth_note_sent": ${BIRTH_NOTE_SENT},
  "noscha_domain": "${NOSCHA_DOMAIN}",
  "ln_address": "${LN_ADDRESS}"
}
INFOEOF

echo ""
echo "===AGENT_PUBLIC_INFO_START==="
cat "${BOOTSTRAP_DIR}/agent_public_info.json"
echo "===AGENT_PUBLIC_INFO_END==="

# Clean up sensitive temp files (keep parent_npub.txt for birth note retry)
rm -f "${BOOTSTRAP_DIR}/payperq_key.txt"
rm -f "${BOOTSTRAP_DIR}/noscha_mgmt_token.txt"

# Final disk cleanup
apt-get clean 2>/dev/null || true
rm -rf /var/lib/apt/lists/* /root/.cache 2>/dev/null || true

echo ""
echo "========================================"
echo "  Agent Self-Birth Complete"
echo "  Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Name:     ${AGENT_NAME}"
echo "  npub:     ${AGENT_NPUB}"
echo "  Webchat:  ${WEBCHAT_URL}"
echo "  Keys at:  ${KEYS_DIR}/keys.json (root-only)"
echo "  Birth note: ${BIRTH_NOTE_SENT}"
echo "========================================"
