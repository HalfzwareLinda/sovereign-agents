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
#   parent_wisdom.txt       (optional) Parent's wisdom for LETTER.md
#   llm_base_url.txt        (optional) LLM API base URL (default: https://api.ppq.ai)
#   keep_ssh.txt            (optional) "true" to preserve provisioning SSH keys
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
STATE_DIR="/opt/agent-state"
exec > >(tee -a "$LOG") 2>&1

# ------------------------------------------------------------------
# Checkpoint system — enables retry from failed step
# ------------------------------------------------------------------
mkdir -p "${STATE_DIR}"

# RESUME_FROM_STEP: if set, skip all steps before this number.
# Used by create_vm.py --retry to resume after a failure.
RESUME_FROM_STEP="${RESUME_FROM_STEP:-0}"

mark_step_done() {
    local step="$1"
    touch "${STATE_DIR}/step_${step}.done"
    echo "  [checkpoint] Step ${step} complete"
}

step_already_done() {
    local step="$1"
    [ -f "${STATE_DIR}/step_${step}.done" ]
}

should_skip_step() {
    local step="$1"
    if [ "${step}" -lt "${RESUME_FROM_STEP}" ]; then
        echo "  [resume] Skipping step ${step} (resuming from ${RESUME_FROM_STEP})"
        return 0
    fi
    if step_already_done "${step}"; then
        echo "  [idempotent] Step ${step} already completed — skipping"
        return 0
    fi
    return 1
}

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
PARENT_WISDOM=$(cat "${BOOTSTRAP_DIR}/parent_wisdom.txt" 2>/dev/null || echo "Trust your instincts. Verify everything. Keep your keys safe.")
LLM_BASE_URL=$(cat "${BOOTSTRAP_DIR}/llm_base_url.txt" 2>/dev/null || echo "https://api.ppq.ai")
KEEP_SSH=$(cat "${BOOTSTRAP_DIR}/keep_ssh.txt" 2>/dev/null || echo "false")
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
echo "[1/15] Installing system packages..."
if should_skip_step 1; then
    true  # skip
else
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
    mark_step_done 1
fi

# ------------------------------------------------------------------
# 2. Install Node.js v22+ (LTS — required by OpenClaw)
# ------------------------------------------------------------------
echo ""
echo "[2/15] Installing Node.js..."
if should_skip_step 2; then
    true  # skip
else
    if ! command -v node &>/dev/null || [[ $(node -v | cut -d'.' -f1 | tr -d 'v') -lt 22 ]]; then
        curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
        apt-get install -y -qq nodejs
        apt-get clean
        rm -rf /var/lib/apt/lists/*
    fi
    echo "  Node.js $(node -v), npm $(npm -v)"
    mark_step_done 2
fi

# ------------------------------------------------------------------
# 3. Firewall
# ------------------------------------------------------------------
echo ""
echo "[3/15] Configuring firewall..."
if should_skip_step 3; then
    true  # skip
else
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp    comment 'SSH'
    ufw allow 3000/tcp  comment 'OpenClaw webchat'
    ufw allow 443/tcp   comment 'HTTPS'
    ufw allow 80/tcp    comment 'HTTP'
    ufw --force enable
    echo "  Ports open: 22, 80, 443, 3000"
    mark_step_done 3
fi

# ------------------------------------------------------------------
# 4. Create agent user
# ------------------------------------------------------------------
echo ""
echo "[4/15] Creating agent user..."
if should_skip_step 4; then
    true  # skip
else
    useradd -m -s /bin/bash agent 2>/dev/null || true
    mark_step_done 4
fi

# ------------------------------------------------------------------
# 5. Generate Nostr keypair ON THIS MACHINE
# ------------------------------------------------------------------
echo ""
echo "[5/15] Generating Nostr identity (keys born here, stay here)..."
if should_skip_step 5 || [ -f "${KEYS_DIR}/nostr.json" ]; then
    # Keys already exist — load them instead of regenerating
    if [ -f "${KEYS_DIR}/nostr.json" ]; then
        echo "  Nostr keys already exist at ${KEYS_DIR}/nostr.json — reusing"
        AGENT_NSEC=$(jq -r '.nsec' "${KEYS_DIR}/nostr.json")
        AGENT_NPUB=$(jq -r '.npub' "${KEYS_DIR}/nostr.json")
        AGENT_PRIVKEY_HEX=$(jq -r '.private_key_hex' "${KEYS_DIR}/nostr.json")
        AGENT_PUBKEY_HEX=$(jq -r '.public_key_hex' "${KEYS_DIR}/nostr.json")
        mark_step_done 5
    fi
else

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
echo "  nsec: [REDACTED — generated and stored locally only]"
mark_step_done 5
fi  # end of step 5 idempotency guard

# ------------------------------------------------------------------
# 6. Generate BTC wallet
# ------------------------------------------------------------------
echo ""
echo "[6/15] Generating BTC wallet..."
if should_skip_step 6 || [ -f "${KEYS_DIR}/btc_wallet.json" ]; then
    # Wallet already exists — load address
    if [ -f "${KEYS_DIR}/btc_wallet.json" ]; then
        echo "  BTC wallet already exists at ${KEYS_DIR}/btc_wallet.json — reusing"
        BTC_ADDRESS=$(jq -r '.address' "${KEYS_DIR}/btc_wallet.json")
        BTC_MNEMONIC=$(jq -r '.mnemonic' "${KEYS_DIR}/btc_wallet.json")
        BTC_JSON=$(cat "${KEYS_DIR}/btc_wallet.json")
        echo "  BTC address: ${BTC_ADDRESS}"
        mark_step_done 6
    fi
else

pip3 install --break-system-packages -q coincurve requests 2>/dev/null || true

BTC_JSON=$(python3 -c "
import secrets, hashlib, hmac, json, struct, sys, urllib.request

# --- BIP-39: Generate mnemonic from 128-bit entropy ---
try:
    resp = urllib.request.urlopen('https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt', timeout=10)
    wordlist = resp.read().decode().strip().split('\n')
    assert len(wordlist) == 2048, f'Expected 2048 words, got {len(wordlist)}'
except Exception as e:
    print(json.dumps({'error': f'BIP-39 wordlist fetch failed: {e}'}), file=sys.stderr)
    sys.exit(1)

entropy = secrets.token_bytes(16)
h = hashlib.sha256(entropy).digest()
cs = bin(h[0])[2:].zfill(8)[:4]
bits = bin(int.from_bytes(entropy, 'big'))[2:].zfill(128) + cs
mnemonic = ' '.join(wordlist[int(bits[i:i+11], 2)] for i in range(0, 132, 11))

# --- BIP-39: Mnemonic to seed via PBKDF2 (2048 rounds, no passphrase) ---
seed = hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), b'mnemonic', 2048)

# --- BIP-32: HD key derivation ---
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def hmac512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()

def derive_child(parent_key, parent_chain, index):
    from coincurve import PrivateKey as PK
    if index >= 0x80000000:
        data = b'\x00' + parent_key + struct.pack('>I', index)
    else:
        pub = PK(parent_key).public_key.format(compressed=True)
        data = pub + struct.pack('>I', index)
    I = hmac512(parent_chain, data)
    child_int = (int.from_bytes(I[:32], 'big') + int.from_bytes(parent_key, 'big')) % N
    return child_int.to_bytes(32, 'big'), I[32:]

# Master key from seed
I = hmac512(b'Bitcoin seed', seed)
key, chain = I[:32], I[32:]

# BIP-84 path: m/84'/0'/0'/0/0
for idx in [0x80000000 + 84, 0x80000000 + 0, 0x80000000 + 0, 0, 0]:
    key, chain = derive_child(key, chain, idx)

from coincurve import PrivateKey
priv = PrivateKey(key)
pub = priv.public_key.format(compressed=True)

# --- Native SegWit (bech32) address ---
sha = hashlib.sha256(pub).digest()
r = hashlib.new('ripemd160'); r.update(sha); h160 = r.digest()

CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5): chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk
def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
def convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v; bits += frombits
        while bits >= tobits: bits -= tobits; ret.append((acc >> bits) & maxv)
    if pad and bits: ret.append((acc << (tobits - bits)) & maxv)
    return ret
data5 = [0] + convertbits(list(h160), 8, 5)
chk = polymod(hrp_expand('bc') + data5 + [0]*6) ^ 1
checksum = [(chk >> 5*(5-i)) & 31 for i in range(6)]
address = 'bc1' + ''.join(CHARSET[d] for d in data5 + checksum)

# WIF for the derived child key
payload = b'\x80' + key + b'\x01'
cs = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
n = int.from_bytes(payload + cs, 'big'); wif = ''
while n > 0: n, r = divmod(n, 58); wif = alphabet[r] + wif

print(json.dumps({'mnemonic': mnemonic, 'address': address, 'wif': wif, 'derivation': 'm/84h/0h/0h/0/0'}))
")

BTC_ADDRESS=$(echo "$BTC_JSON" | jq -r '.address')
BTC_MNEMONIC=$(echo "$BTC_JSON" | jq -r '.mnemonic')
echo "  BTC address: ${BTC_ADDRESS}"
mark_step_done 6
fi  # end of step 6 idempotency guard

# ------------------------------------------------------------------
# 7. Generate ETH wallet
# ------------------------------------------------------------------
echo ""
echo "[7/15] Generating ETH wallet..."
if should_skip_step 7 || [ -f "${KEYS_DIR}/eth_wallet.json" ]; then
    if [ -f "${KEYS_DIR}/eth_wallet.json" ]; then
        echo "  ETH wallet already exists at ${KEYS_DIR}/eth_wallet.json — reusing"
        ETH_ADDRESS=$(jq -r '.address' "${KEYS_DIR}/eth_wallet.json")
        ETH_JSON=$(cat "${KEYS_DIR}/eth_wallet.json")
        echo "  ETH address: ${ETH_ADDRESS}"
        mark_step_done 7
    fi
else

pip3 install --break-system-packages -q eth-account 2>/dev/null || true

ETH_JSON=$(python3 -c "
import json, sys
try:
    from eth_account import Account
    acct = Account.create()
    print(json.dumps({'address': acct.address, 'private_key': acct.key.hex()}))
except ImportError:
    # eth-account not available — skip ETH wallet rather than generate an invalid address
    print(json.dumps({'address': 'unavailable', 'private_key': '', 'note': 'eth-account not installed — ETH wallet skipped'}))
    print('WARNING: eth-account not available, ETH wallet not generated', file=sys.stderr)
")

ETH_ADDRESS=$(echo "$ETH_JSON" | jq -r '.address')
echo "  ETH address: ${ETH_ADDRESS}"

rm -rf /root/.cache/pip 2>/dev/null || true
mark_step_done 7
fi  # end of step 7 idempotency guard

# ------------------------------------------------------------------
# 8. Secure key storage
# ------------------------------------------------------------------
echo ""
echo "[8/15] Securing private keys..."
if should_skip_step 8; then
    true  # skip
else
mkdir -p "${KEYS_DIR}"

# Split secrets into separate files per FUNCTIONAL_DESIGN.md
# This limits blast radius: a vulnerability that reads one file doesn't expose all secrets.
# The NIP-46 bunker only needs nostr.json, not wallet keys.

cat > "${KEYS_DIR}/nostr.json" << NOSTREOF
{
  "private_key_hex": "${AGENT_PRIVKEY_HEX}",
  "nsec": "${AGENT_NSEC}",
  "npub": "${AGENT_NPUB}",
  "public_key_hex": "${AGENT_PUBKEY_HEX}",
  "agent_name": "${AGENT_NAME}",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
NOSTREOF

cat > "${KEYS_DIR}/btc_wallet.json" << BTCEOF
$(echo "$BTC_JSON")
BTCEOF

cat > "${KEYS_DIR}/eth_wallet.json" << ETHEOF
$(echo "$ETH_JSON")
ETHEOF

# Write legacy keys.json for backward compatibility with scripts that still read it
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
chmod 600 "${KEYS_DIR}/nostr.json"
chmod 600 "${KEYS_DIR}/btc_wallet.json"
chmod 600 "${KEYS_DIR}/eth_wallet.json"
chmod 600 "${KEYS_DIR}/keys.json"
chown -R root:root "${KEYS_DIR}"
echo "  Keys split into separate files at ${KEYS_DIR}/ (root:root, 600)"
echo "    nostr.json, btc_wallet.json, eth_wallet.json, keys.json (legacy)"

# Write public-only info file readable by the agent user (ISSUE-003)
# Contains NO private keys — only public identifiers the agent needs for self-identification
BTC_ADDRESS=$(echo "$BTC_JSON" | jq -r '.address')
cat > "${KEYS_DIR}/agent_public.json" << PUBEOF
{
  "npub": "${AGENT_NPUB}",
  "public_key_hex": "${AGENT_PUBKEY_HEX}",
  "btc_address": "${BTC_ADDRESS}",
  "eth_address": "${ETH_ADDRESS}",
  "agent_name": "${AGENT_NAME}",
  "nip05": "${AGENT_NAME}@noscha.io",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
PUBEOF
chown agent:agent "${KEYS_DIR}/agent_public.json"
chmod 644 "${KEYS_DIR}/agent_public.json"
echo "    agent_public.json (agent:agent, 644 — public info only)"
mark_step_done 8
fi  # end of step 8

# ------------------------------------------------------------------
# 9. Process workspace templates (EARLY — before anything else can fail)
# ------------------------------------------------------------------
echo ""
echo "[9/15] Writing workspace templates..."

# These vars are needed by later steps regardless of whether step 9 runs
VPS_IP=$(curl -4 -sf ifconfig.me || echo "unknown")
NOSCHA_DOMAIN="${AGENT_NAME}.noscha.io"
LN_ADDRESS="${AGENT_NAME}@noscha.io"
CREATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
WEBCHAT_URL="https://${AGENT_NAME}.noscha.io"
OPENCLAW_DIR="/home/agent/.openclaw"

if should_skip_step 9; then
    true  # skip
else

mkdir -p "${OPENCLAW_DIR}/workspace"

# Escape a string for safe use as a sed replacement value.
# Escapes the sed delimiter (|), backslash, ampersand, and newlines.
sed_escape() {
    printf '%s' "$1" | sed -e 's/[|\\&]/\\&/g' -e '$!s/$/\\/'
}

# Sanitize user-supplied inputs that will be used in sed replacements.
# PERSONALITY and MISSION originate from web form input and could contain
# sed control characters (|, &, \) or shell metacharacters.
PERSONALITY_SAFE=$(sed_escape "${PERSONALITY}")
MISSION_SAFE=$(sed_escape "${MISSION}")
PARENT_WISDOM_SAFE=$(sed_escape "${PARENT_WISDOM}")

# Template placeholder replacement — uses | delimiter with sed
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
        | sed "s|__PERSONALITY__|${PERSONALITY_SAFE}|g" \
        | sed "s|__MISSION__|${MISSION_SAFE}|g" \
        | sed "s|__PARENT_WISDOM__|${PARENT_WISDOM_SAFE}|g" \
        | sed "s|__DEFAULT_MODEL__|${DEFAULT_MODEL}|g"
}

TEMPLATES_WRITTEN=0
HAS_CUSTOM_MEMORY=false
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

        # Track if a custom MEMORY.md was provided (so we don't overwrite it)
        [[ "$fname" == "MEMORY.md" ]] && HAS_CUSTOM_MEMORY=true
    done
fi

# Write fallback MEMORY.md only if no custom one was provided via upload
if [ "$HAS_CUSTOM_MEMORY" = false ]; then
    cat > "${OPENCLAW_DIR}/workspace/MEMORY.md" << MEMEOF
# MEMORY.md

Agent **${AGENT_NAME}** born on ${DATE}.

Parent: ${PARENT_NPUB}

My instructions are in AGENTS.md. My identity is in SOUL.md.
My parent's letter is in LETTER.md.

Awaiting first instructions.
MEMEOF
    TEMPLATES_WRITTEN=$((TEMPLATES_WRITTEN + 1))
else
    echo "  ✓ Using customer-provided MEMORY.md (skipping default)"
fi

# Copy custom templates provenance marker if present (customer-uploaded files)
if [ -f "${BOOTSTRAP_DIR}/custom_templates.json" ]; then
    cp "${BOOTSTRAP_DIR}/custom_templates.json" "${OPENCLAW_DIR}/workspace/custom_templates.json"
    TEMPLATES_WRITTEN=$((TEMPLATES_WRITTEN + 1))
    echo "  ✓ Custom templates provenance marker written"
fi

echo "  ${TEMPLATES_WRITTEN} workspace files written"
mark_step_done 9
fi  # end of step 9

# ------------------------------------------------------------------
# 10. Provision PPQ.ai LLM account (if no key provided externally)
# ------------------------------------------------------------------
echo ""
echo "[10/15] Provisioning PPQ.ai LLM account..."
if should_skip_step 10; then
    # Load existing key if available
    PPQ_CREDENTIALS="/opt/agent-keys/ppq_credentials.json"
    if [ -z "${PAYPERQ_KEY}" ] && [ -f "${PPQ_CREDENTIALS}" ]; then
        PAYPERQ_KEY=$(python3 -c "import json; print(json.load(open('${PPQ_CREDENTIALS}'))['api_key'])" 2>/dev/null || echo "")
    fi
else

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
mark_step_done 10
fi  # end of step 10

# ------------------------------------------------------------------
# 11. Install npm packages (mcp-money, NDK)
# ------------------------------------------------------------------
echo ""
echo "[11/15] Installing npm packages..."
if should_skip_step 11; then
    true  # skip
else
    npm install -g --production mcp-money 2>/dev/null || echo "  mcp-money install skipped"

    mkdir -p /opt/agent-ndk && cd /opt/agent-ndk
    npm init -y 2>/dev/null
    npm install --production @nostr-dev-kit/ndk 2>/dev/null || echo "  NDK install partial"
    chown -R agent:agent /opt/agent-ndk
    cd /

    npm cache clean --force 2>/dev/null || true
    mark_step_done 11
fi

# ------------------------------------------------------------------
# 12. NIP-46 Nostr Connect bunker (NDKNip46Backend)
# ------------------------------------------------------------------
echo ""
echo "[12/15] Setting up NIP-46 bunker (NDK backend)..."
if should_skip_step 12; then
    true  # skip
else

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
mark_step_done 12
fi  # end of step 12

# ------------------------------------------------------------------
# 13. Install and configure OpenClaw
# ------------------------------------------------------------------
echo ""
echo "[13/15] Installing OpenClaw..."
if should_skip_step 13; then
    # Need these vars for later steps
    OPENCLAW_INSTALLED=true
    HEALTH_OK=true
else

OPENCLAW_INSTALLED=false

# Idempotency: check if openclaw is already available from a previous run
if command -v openclaw &>/dev/null; then
    echo "  OpenClaw already installed: $(openclaw --version 2>/dev/null || echo 'present')"
    OPENCLAW_INSTALLED=true
fi

# Stage 1: npm global install (primary — Node 22 satisfies >=22.12.0 requirement)
if [ "$OPENCLAW_INSTALLED" = false ] && npm install -g --production openclaw@latest 2>/dev/null; then
    echo "  OpenClaw installed via npm"
    OPENCLAW_INSTALLED=true
fi

# Stage 2: git clone + npm install from source
if [ "$OPENCLAW_INSTALLED" = false ]; then
    echo "  npm global failed, trying git clone..."
    if git clone --depth 1 https://github.com/openclaw/openclaw.git /tmp/openclaw-build 2>/dev/null; then
        cd /tmp/openclaw-build
        if npm install --production 2>/dev/null && npm link 2>/dev/null; then
            echo "  OpenClaw installed via git clone + npm link"
            OPENCLAW_INSTALLED=true
        fi
        cd /
        rm -rf /tmp/openclaw-build
    fi
fi

# Stage 3: Docker fallback (isolation, no Node version dependency)
if [ "$OPENCLAW_INSTALLED" = false ] && command -v docker &>/dev/null; then
    echo "  Source build failed, trying Docker..."
    if docker pull ghcr.io/phioranex/openclaw-docker:latest 2>/dev/null; then
        OPENCLAW_IMAGE="ghcr.io/phioranex/openclaw-docker:latest"
        echo "  OpenClaw Docker image pulled: ${OPENCLAW_IMAGE}"
        cat > /usr/local/bin/openclaw << WRAPEOF
#!/bin/bash
exec docker run --rm -v /home/agent/.openclaw:/root/.openclaw --network host ${OPENCLAW_IMAGE} "\$@"
WRAPEOF
        chmod +x /usr/local/bin/openclaw
        OPENCLAW_INSTALLED=true
        echo "  OpenClaw available via Docker wrapper at /usr/local/bin/openclaw"
    fi
fi

if [ "$OPENCLAW_INSTALLED" = false ]; then
    echo "  WARNING: OpenClaw install failed on all methods — needs manual setup"
fi

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
    "baseUrl": "${LLM_BASE_URL}"
  }
}
AUTHEOF
    chmod 600 "${OPENCLAW_DIR}/agents/main/agent/auth-profiles.json"
fi

chown -R agent:agent "${OPENCLAW_DIR}"

# Create systemd service for OpenClaw gateway
cat > /etc/systemd/system/agent-openclaw.service << 'OCSVCEOF'
[Unit]
Description=Agent OpenClaw Gateway
After=network-online.target agent-bunker.service
Wants=network-online.target

[Service]
Type=simple
User=agent
WorkingDirectory=/home/agent/.openclaw
ExecStart=/usr/local/bin/openclaw gateway start
Restart=on-failure
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
OCSVCEOF

systemctl daemon-reload
systemctl enable agent-openclaw

if [ "$OPENCLAW_INSTALLED" = true ]; then
    systemctl start agent-openclaw 2>/dev/null || echo "  OpenClaw start deferred"
else
    echo "  OpenClaw service installed but not started (install failed)"
fi

# Health check
echo "  Waiting for health check..."
HEALTH_OK=false
if [ "$OPENCLAW_INSTALLED" = true ]; then
    for i in $(seq 1 12); do
        if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
            echo "  Health check PASSED (attempt $i)"
            HEALTH_OK=true
            break
        fi
        sleep 10
    done
    [ "$HEALTH_OK" = false ] && echo "  WARNING: Health check failed — may still be booting"
else
    echo "  Health check skipped (OpenClaw not installed)"
fi
mark_step_done 13
fi  # end of step 13

# ------------------------------------------------------------------
# 14. Install Caddy reverse proxy for HTTPS (ISSUE-002)
# ------------------------------------------------------------------
echo ""
echo "[14/15] Setting up Caddy reverse proxy (HTTPS)..."
if should_skip_step 14; then
    CADDY_OK=true
    WEBCHAT_URL="https://${AGENT_NAME}.noscha.io"
else

CADDY_OK=false

# Install Caddy
if command -v caddy &>/dev/null; then
    echo "  Caddy already installed: $(caddy version)"
else
    # Add Caddy official repo
    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl >/dev/null 2>&1
    curl -1sLf 'https://dl.cloudflare.com/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null
    curl -1sLf 'https://dl.cloudflare.com/caddy/stable/deb/debian/config' | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq caddy >/dev/null 2>&1
    echo "  Caddy installed: $(caddy version 2>/dev/null || echo 'unknown')"
fi

# Wait for DNS to resolve before requesting a cert (SA-013)
echo "  Waiting for DNS (${NOSCHA_DOMAIN})..."
DNS_OK=false
for i in $(seq 1 24); do
    if host "${NOSCHA_DOMAIN}" 1.1.1.1 >/dev/null 2>&1; then
        echo "  DNS resolved (attempt $i)"
        DNS_OK=true
        break
    fi
    sleep 5
done
if [ "$DNS_OK" = false ]; then
    echo "  WARNING: DNS for ${NOSCHA_DOMAIN} not resolving — Caddy may fail to get cert"
fi

# Write Caddyfile
cat > /etc/caddy/Caddyfile << CADDYEOF
# Default catch-all — drop connections to unknown hosts (SA-012)
:443 {
    tls internal
    respond 444
}

# Agent webchat — reverse proxy to OpenClaw on localhost:3000
${NOSCHA_DOMAIN} {
    reverse_proxy localhost:3000
}
CADDYEOF

echo "  Caddyfile written for ${NOSCHA_DOMAIN} → localhost:3000"

# Start Caddy
systemctl enable caddy >/dev/null 2>&1
systemctl restart caddy 2>/dev/null || echo "  WARNING: Caddy failed to start"

# Verify Caddy started
sleep 3
if systemctl is-active --quiet caddy; then
    echo "  Caddy running — HTTPS enabled"
    CADDY_OK=true
    # Update webchat URL to use HTTPS
    WEBCHAT_URL="https://${NOSCHA_DOMAIN}"
else
    echo "  WARNING: Caddy not running — falling back to HTTP"
    echo "  Check: journalctl -u caddy --no-pager -n 20"
    WEBCHAT_URL="http://${VPS_IP}:3000"
fi
mark_step_done 14
fi  # end of step 14

# ------------------------------------------------------------------
# 15. Send birth note to parent
# ------------------------------------------------------------------
echo ""
echo "[15/15] Sending birth note to parent..."
if should_skip_step 15; then
    BIRTH_NOTE_SENT=true
else

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
mark_step_done 15
fi  # end of step 15

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
if [ "${KEEP_SSH}" = "true" ]; then
    echo "  KEEP_SSH=true — preserving provisioning SSH keys in authorized_keys"
else
    for AK_DIR in /home/ubuntu/.ssh /root/.ssh; do
        if [ -d "$AK_DIR" ]; then
            # Replace with empty file — provisioning key no longer authorized
            : > "${AK_DIR}/authorized_keys"
            chmod 600 "${AK_DIR}/authorized_keys"
            echo "  Cleared ${AK_DIR}/authorized_keys"
        fi
    done
    echo "  Provisioning SSH keys removed (authorized_keys regenerated)"
fi
echo "  Agent SSH key generated at ${AGENT_SSH_DIR}/id_ed25519"

# noscha renewal cron — token stored in file, not in crontab command line
# (M3: prevents token exposure via `ps`, /var/spool/cron/crontabs, or process list)
if [ -n "${NOSCHA_TOKEN}" ]; then
    NOSCHA_TOKEN_FILE="${KEYS_DIR}/noscha_token"
    printf '%s' "${NOSCHA_TOKEN}" > "${NOSCHA_TOKEN_FILE}"
    chmod 600 "${NOSCHA_TOKEN_FILE}"
    chown root:root "${NOSCHA_TOKEN_FILE}"

    cat > "${KEYS_DIR}/noscha_renew.sh" << 'RENEWEOF'
#!/bin/bash
TOKEN=$(cat /opt/agent-keys/noscha_token 2>/dev/null)
[ -z "$TOKEN" ] && exit 0
curl -sf -H "Authorization: Bearer ${TOKEN}" https://noscha.io/api/renew >/dev/null 2>&1
RENEWEOF
    chmod 700 "${KEYS_DIR}/noscha_renew.sh"
    chown root:root "${KEYS_DIR}/noscha_renew.sh"

    (crontab -u root -l 2>/dev/null || true; echo "0 0 25 * * /opt/agent-keys/noscha_renew.sh") | crontab -u root -
    echo "  noscha.io renewal cron set (token in file, not command line)"
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
  "openclaw_installed": ${OPENCLAW_INSTALLED},
  "caddy_ok": ${CADDY_OK},
  "health_ok": ${HEALTH_OK},
  "birth_note_sent": ${BIRTH_NOTE_SENT},
  "noscha_domain": "${NOSCHA_DOMAIN}",
  "ln_address": "${LN_ADDRESS}"
}
INFOEOF

# Output public info for create_vm.py to parse (must be before cleanup)
echo ""
echo "===AGENT_PUBLIC_INFO_START==="
cat "${BOOTSTRAP_DIR}/agent_public_info.json"
echo "===AGENT_PUBLIC_INFO_END==="

# Clean up entire bootstrap staging directory (L2)
# Per FUNCTIONAL_DESIGN F2.17: "Delete /tmp/agent-setup/ entirely"
# The only file we need to keep is the public info JSON (already written above).
# Copy it out first, then remove the whole directory.
cp "${BOOTSTRAP_DIR}/agent_public_info.json" /tmp/agent_public_info.json 2>/dev/null || true
rm -rf "${BOOTSTRAP_DIR}"
echo "  Cleaned up ${BOOTSTRAP_DIR}"

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
echo "  Keys at:  ${KEYS_DIR}/ (nostr.json, btc_wallet.json, eth_wallet.json)"
echo "  Birth note: ${BIRTH_NOTE_SENT}"
echo "========================================"
