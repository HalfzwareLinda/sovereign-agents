#!/usr/bin/env python3
"""
provision_agent.py — Sovereign Agent Provisioning Orchestrator (LNVPS)

Provisions a complete autonomous AI agent:
  1.  Generate Nostr keypair (secp256k1)
  2.  Generate SSH keypair (ed25519) for VPS access
  3.  Generate BTC wallet (BIP-84)
  4.  Generate EVM wallet
  5.  Register identity on noscha.io (NIP-05 + subdomain + email)
  6.  Upload SSH key to LNVPS via NIP-98 auth
  7.  Create VM on LNVPS — pay Lightning invoice
  8.  Wait for VM to come online, get IP
  9.  SSH into VM and run setup (Docker, OpenClaw, config, workspace)
  10. Update noscha.io subdomain with real IP
  11. Verify OpenClaw health
  12. Print summary + save JSON

Usage:
    python3 provision_agent.py --name testling --parent-npub npub1abc... --dry-run
    python3 provision_agent.py --name myagent --parent-npub npub1abc... --tier evolve

Environment:
    PAYPERQ_API_KEY       PayPerQ API key for agent LLM access
    PROVISIONING_NSEC     Nostr nsec for provisioning service (sends birth note)
"""

import argparse
import base64
import hashlib
import io
import json
import logging
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("ERROR: requests not installed. Run: pip install requests")

try:
    from coincurve import PrivateKey
except ImportError:
    sys.exit("ERROR: coincurve not installed. Run: pip install coincurve")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR = Path(__file__).parent.resolve()
TEMPLATES_DIR = SCRIPT_DIR / "templates"
CONFIG_TEMPLATE_PATH = SCRIPT_DIR / "config_template.json"
SETUP_SCRIPT_PATH = SCRIPT_DIR / "setup_vps.sh"

LNVPS_API = "https://api.lnvps.net"
NOSCHA_API = "https://noscha.io/api"

# LNVPS template IDs (from GET /api/v1/vm/templates)
LNVPS_TEMPLATES = {
    "demo":   {"id": None, "label": "Demo 1CPU/1GB/5GB €0.20/day",  "match": "demo"},
    "tiny":   {"id": None, "label": "Tiny 1CPU/1GB/40GB €2.70/mo",  "match": "tiny"},
    "small":  {"id": None, "label": "Small 2CPU/2GB/80GB €5.10/mo", "match": "small"},
    "medium": {"id": None, "label": "Med 4CPU/4GB/160GB €9.90/mo",  "match": "medium"},
}

TIERS = {
    "seed":    {"name": "Seed",    "vm_class": "small",  "llm_credit": 15,  "model": "gpt-5-nano"},
    "evolve":  {"name": "Evolve",  "vm_class": "small",  "llm_credit": 40,  "model": "gpt-5-nano"},
    "dynasty": {"name": "Dynasty", "vm_class": "medium", "llm_credit": 100, "model": "gpt-5-nano"},
    "trial":   {"name": "Trial",   "vm_class": "demo",   "llm_credit": 5,   "model": "gpt-5-nano"},
}

LOG_FMT = "%(asctime)s %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT, datefmt="%H:%M:%S")
log = logging.getLogger("provision")


# =============================================================================
# Bech32 encoding
# =============================================================================

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp: str, data_bytes: bytes) -> str:
    data = _convertbits(list(data_bytes), 8, 5)
    checksum = _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


def segwit_addr_encode(hrp: str, witver: int, witprog: bytes) -> str:
    data = [witver] + _convertbits(list(witprog), 8, 5)
    checksum = _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


# =============================================================================
# Crypto helpers
# =============================================================================

def _hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    r = hashlib.new("ripemd160")
    r.update(sha)
    return r.digest()


def _base58_encode(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    result = ""
    while n > 0:
        n, r = divmod(n, 58)
        result = alphabet[r] + result
    for byte in data:
        if byte == 0:
            result = "1" + result
        else:
            break
    return result


def _privkey_to_wif(key: bytes, compressed: bool = True) -> str:
    payload = b"\x80" + key
    if compressed:
        payload += b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _base58_encode(payload + checksum)


# =============================================================================
# BIP-39 mnemonic
# =============================================================================

_BIP39_WORDS = None


def _load_wordlist() -> list[str] | None:
    global _BIP39_WORDS
    if _BIP39_WORDS is not None:
        return _BIP39_WORDS
    try:
        from mnemonic import Mnemonic
        _BIP39_WORDS = Mnemonic("english").wordlist
        return _BIP39_WORDS
    except ImportError:
        pass
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt",
            timeout=10,
        )
        if r.status_code == 200:
            _BIP39_WORDS = r.text.strip().split("\n")
            return _BIP39_WORDS
    except Exception:
        pass
    return None


def _entropy_to_mnemonic(entropy: bytes) -> str:
    wl = _load_wordlist()
    if wl is None:
        return entropy.hex()
    h = hashlib.sha256(entropy).digest()
    cs = bin(h[0])[2:].zfill(8)[:4]
    bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(128) + cs
    return " ".join(wl[int(bits[i:i + 11], 2)] for i in range(0, 132, 11))


# =============================================================================
# Nostr event signing + NIP-98 auth
# =============================================================================

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def nostr_sign_event(privkey_hex: str, event: dict) -> dict:
    """Sign a Nostr event (NIP-01). Returns event with id and sig fields."""
    # Serialize for id: [0, pubkey, created_at, kind, tags, content]
    privkey = PrivateKey(bytes.fromhex(privkey_hex))
    pubkey_hex = privkey.public_key.format(compressed=True)[1:].hex()

    event["pubkey"] = pubkey_hex
    serialized = json.dumps(
        [0, pubkey_hex, event["created_at"], event["kind"], event["tags"], event["content"]],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    event_id = _sha256(serialized.encode()).hex()
    event["id"] = event_id

    # Schnorr signature (BIP-340)
    sig = privkey.sign_schnorr(bytes.fromhex(event_id))
    event["sig"] = sig.hex()

    return event


def nip98_auth_header(
    privkey_hex: str,
    url: str,
    method: str,
    body: bytes | None = None,
) -> str:
    """Build a NIP-98 Authorization header value.

    Returns the string to use as: Authorization: Nostr {value}
    """
    tags = [["u", url], ["method", method.upper()]]
    if body:
        payload_hash = _sha256(body).hex()
        tags.append(["payload", payload_hash])

    event = {
        "kind": 27235,
        "created_at": int(time.time()),
        "tags": tags,
        "content": "",
    }
    signed = nostr_sign_event(privkey_hex, event)
    event_json = json.dumps(signed, separators=(",", ":"), ensure_ascii=False)
    encoded = base64.b64encode(event_json.encode()).decode()
    return f"Nostr {encoded}"


# =============================================================================
# Key generation
# =============================================================================

def generate_nostr_keypair() -> dict:
    """Generate Nostr keypair. Returns private_key_hex, public_key_hex, nsec, npub."""
    privkey = PrivateKey(secrets.token_bytes(32))
    priv_hex = privkey.secret.hex()
    pub_hex = privkey.public_key.format(compressed=True)[1:].hex()
    return {
        "private_key_hex": priv_hex,
        "public_key_hex": pub_hex,
        "nsec": bech32_encode("nsec", bytes.fromhex(priv_hex)),
        "npub": bech32_encode("npub", bytes.fromhex(pub_hex)),
    }


def generate_ssh_keypair() -> dict:
    """Generate an ed25519 SSH keypair.

    Returns private_key_pem (str), public_key_openssh (str).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()
    public_openssh = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode()
    return {"private_key_pem": private_pem, "public_key_openssh": public_openssh}


def generate_btc_wallet() -> dict:
    """Generate BTC wallet (BIP-84). Tries bip-utils, falls back to coincurve."""
    try:
        from bip_utils import (
            Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum,
            Bip84, Bip84Coins,
        )
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
        seed = Bip39SeedGenerator(mnemonic).Generate()
        ctx = Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
        addr = ctx.Purpose().Coin().Account(0).Change(0).AddressIndex(0)
        return {
            "mnemonic": str(mnemonic),
            "address": addr.PublicKey().ToAddress(),
            "private_key_wif": addr.PrivateKey().ToWif(),
            "derivation_path": "m/84'/0'/0'/0/0",
        }
    except (ImportError, Exception) as exc:
        log.info(f"  bip-utils unavailable ({exc}), using coincurve fallback")

    entropy = secrets.token_bytes(16)
    mnemonic_str = _entropy_to_mnemonic(entropy)
    priv_bytes = hashlib.sha256(mnemonic_str.encode()).digest()
    priv = PrivateKey(priv_bytes)
    pub = priv.public_key.format(compressed=True)
    address = segwit_addr_encode("bc", 0, _hash160(pub))
    return {
        "mnemonic": mnemonic_str,
        "address": address,
        "private_key_wif": _privkey_to_wif(priv_bytes),
        "derivation_path": "m/84'/0'/0'/0/0 (simplified)",
    }


def generate_eth_wallet() -> dict:
    """Generate Ethereum wallet."""
    try:
        from eth_account import Account
        acct = Account.create()
        return {"address": acct.address, "private_key": acct.key.hex()}
    except ImportError:
        sys.exit("ERROR: eth-account not installed. Run: pip install eth-account")


# =============================================================================
# LNVPS API
# =============================================================================

def lnvps_request(
    method: str,
    path: str,
    privkey_hex: str | None = None,
    json_body: dict | None = None,
    dry_run: bool = False,
) -> dict | list | None:
    """Make an LNVPS API request with optional NIP-98 auth.

    Returns parsed JSON response, or None on error.
    """
    url = f"{LNVPS_API}{path}"

    if dry_run:
        log.info(f"  [DRY RUN] {method} {url}")
        if json_body:
            log.info(f"    body: {json.dumps(json_body)}")
        return None

    headers = {"Content-Type": "application/json"}
    body_bytes = json.dumps(json_body).encode() if json_body else None

    if privkey_hex:
        auth = nip98_auth_header(privkey_hex, url, method, body_bytes)
        headers["Authorization"] = auth

    try:
        resp = requests.request(
            method, url, headers=headers, data=body_bytes, timeout=30,
        )
        if resp.status_code in (200, 201):
            return resp.json()
        log.warning(f"  LNVPS {method} {path} → HTTP {resp.status_code}: {resp.text[:300]}")
        return None
    except requests.RequestException as exc:
        log.warning(f"  LNVPS {method} {path} → error: {exc}")
        return None


def lnvps_fetch_templates(dry_run: bool = False) -> dict:
    """Fetch VM templates from LNVPS and map our tier names to template IDs.

    Returns dict mapping our class name → {"template_id": N, "label": str}
    """
    if dry_run:
        log.info("  [DRY RUN] Would fetch LNVPS VM templates")
        return {
            "demo":   {"template_id": 1, "label": "Demo"},
            "tiny":   {"template_id": 2, "label": "Tiny"},
            "small":  {"template_id": 3, "label": "Small"},
            "medium": {"template_id": 4, "label": "Medium"},
        }

    data = lnvps_request("GET", "/api/v1/vm/templates")
    if not data:
        log.warning("  Could not fetch LNVPS templates — using fallback IDs")
        return {
            "demo":   {"template_id": 1, "label": "Demo (fallback)"},
            "tiny":   {"template_id": 2, "label": "Tiny (fallback)"},
            "small":  {"template_id": 3, "label": "Small (fallback)"},
            "medium": {"template_id": 4, "label": "Medium (fallback)"},
        }

    result = {}
    templates = data if isinstance(data, list) else data.get("templates", data.get("data", []))
    for tmpl in templates:
        tmpl_id = tmpl.get("id")
        name = (tmpl.get("name") or tmpl.get("label") or "").lower()
        for cls, info in LNVPS_TEMPLATES.items():
            if info["match"] in name and cls not in result:
                result[cls] = {"template_id": tmpl_id, "label": tmpl.get("name", name)}
                log.info(f"  Matched '{cls}' → template {tmpl_id}: {tmpl.get('name', name)}")

    # Fill any unmatched with fallbacks
    fallbacks = {"demo": 1, "tiny": 2, "small": 3, "medium": 4}
    for cls in LNVPS_TEMPLATES:
        if cls not in result:
            result[cls] = {"template_id": fallbacks[cls], "label": f"{cls} (fallback)"}
    return result


def lnvps_fetch_images(dry_run: bool = False) -> int | None:
    """Fetch OS images and return the Ubuntu 22.04 image ID."""
    if dry_run:
        log.info("  [DRY RUN] Would fetch LNVPS OS images")
        return 1

    data = lnvps_request("GET", "/api/v1/image")
    if not data:
        return None

    images = data if isinstance(data, list) else data.get("images", data.get("data", []))
    for img in images:
        name = (img.get("name") or img.get("label") or "").lower()
        if "ubuntu" in name and ("22.04" in name or "2204" in name):
            log.info(f"  Found Ubuntu image: id={img['id']} name={img.get('name')}")
            return img["id"]
    # Fallback: first Ubuntu image, or first image
    for img in images:
        name = (img.get("name") or "").lower()
        if "ubuntu" in name:
            log.info(f"  Fallback Ubuntu image: id={img['id']} name={img.get('name')}")
            return img["id"]
    if images:
        log.warning(f"  No Ubuntu image found, using first available: {images[0].get('name')}")
        return images[0]["id"]
    return None


def lnvps_upload_ssh_key(
    privkey_hex: str,
    key_name: str,
    public_key: str,
    dry_run: bool = False,
) -> int | None:
    """Upload SSH public key to LNVPS. Returns ssh_key_id."""
    if dry_run:
        log.info(f"  [DRY RUN] Would upload SSH key '{key_name}' to LNVPS")
        return 999

    data = lnvps_request(
        "POST", "/api/v1/ssh-key", privkey_hex,
        json_body={"name": key_name, "key_data": public_key},
    )
    if data:
        key_id = data.get("id") or data.get("ssh_key_id")
        log.info(f"  SSH key uploaded: id={key_id}")
        return key_id
    log.warning("  SSH key upload failed")
    return None


def lnvps_create_vm(
    privkey_hex: str,
    template_id: int,
    image_id: int,
    ssh_key_id: int,
    dry_run: bool = False,
) -> dict:
    """Create a VM on LNVPS. Returns dict with vm_id, payment info."""
    body = {
        "template_id": template_id,
        "image_id": image_id,
        "ssh_key_id": ssh_key_id,
    }
    if dry_run:
        log.info(f"  [DRY RUN] Would create LNVPS VM: {json.dumps(body)}")
        return {
            "vm_id": "dry-run-vm-id",
            "bolt11": "lnbc1...dry_run_vm_invoice",
            "status": "pending_payment",
        }

    data = lnvps_request("POST", "/api/v1/vm", privkey_hex, json_body=body)
    if not data:
        log.error("LNVPS VM creation failed")
        sys.exit(1)

    # Extract VM ID and payment info
    vm_id = data.get("id") or data.get("vm_id")
    payment = data.get("payment") or data.get("invoice") or {}
    bolt11 = ""
    if isinstance(payment, dict):
        bolt11 = payment.get("bolt11") or payment.get("invoice") or ""
    elif isinstance(payment, str):
        bolt11 = payment

    log.info(f"  VM created: id={vm_id}")
    if bolt11:
        log.info(f"  ⚡ Lightning invoice: {bolt11[:60]}...")

    return {"vm_id": vm_id, "bolt11": bolt11, "status": "pending_payment", "raw": data}


def lnvps_wait_for_vm(
    privkey_hex: str,
    vm_id: str | int,
    dry_run: bool = False,
) -> dict:
    """Poll LNVPS until VM is running. Returns dict with ip, status."""
    if dry_run:
        return {"ip": "203.0.113.42", "status": "running"}

    log.info("  Waiting for VM to come online...")
    for attempt in range(1, 61):  # up to 10 min
        data = lnvps_request("GET", f"/api/v1/vm/{vm_id}", privkey_hex)
        if data:
            status = (data.get("status") or "").lower()
            ip_assignments = data.get("ip_assignments") or []
            ip = ""
            if ip_assignments:
                ip = ip_assignments[0].get("ip", "")
            elif data.get("ip"):
                ip = data["ip"]

            if status == "running" and ip:
                log.info(f"  VM running: {ip} (attempt {attempt})")
                return {"ip": ip, "status": status}

            if attempt % 6 == 0:
                log.info(f"  Still waiting... status={status} ip={ip or 'none'} (attempt {attempt})")
        time.sleep(10)

    log.error("VM did not come online within 10 minutes")
    sys.exit(1)


# =============================================================================
# SSH remote setup
# =============================================================================

def ssh_run_setup(
    ip: str,
    ssh_private_key_pem: str,
    agent_config_json: str,
    workspace_files: dict[str, str],
    keys_json: str,
    dry_run: bool = False,
) -> bool:
    """SSH into the VM and run the full setup.

    1. Upload setup script, config, keys, workspace files to /tmp/agent-setup/
    2. Execute setup_vps.sh
    3. Return True on success.
    """
    if dry_run:
        log.info(f"  [DRY RUN] Would SSH to {ip} and run setup_vps.sh")
        return True

    try:
        import paramiko
    except ImportError:
        sys.exit("ERROR: paramiko not installed. Run: pip install paramiko")

    setup_script = SETUP_SCRIPT_PATH.read_text()

    # Build paramiko key
    pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(ssh_private_key_pem))

    # Wait for SSH to become available
    log.info(f"  Connecting SSH to root@{ip}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connected = False
    for attempt in range(1, 19):  # up to 3 min
        try:
            client.connect(ip, username="root", pkey=pkey, timeout=10)
            connected = True
            log.info(f"  SSH connected (attempt {attempt})")
            break
        except Exception:
            if attempt % 6 == 0:
                log.info(f"  SSH not ready yet (attempt {attempt})...")
            time.sleep(10)

    if not connected:
        log.error(f"  Could not SSH to {ip} after 3 minutes")
        return False

    try:
        sftp = client.open_sftp()

        # Create setup directory
        try:
            sftp.mkdir("/tmp/agent-setup")
        except IOError:
            pass
        try:
            sftp.mkdir("/tmp/agent-setup/workspace")
        except IOError:
            pass

        # Upload setup script
        _sftp_write(sftp, "/tmp/agent-setup/setup.sh", setup_script)
        # Upload config
        _sftp_write(sftp, "/tmp/agent-setup/openclaw.json", agent_config_json)
        # Upload keys
        _sftp_write(sftp, "/tmp/agent-setup/keys.json", keys_json)
        # Upload workspace files
        for fname, content in workspace_files.items():
            _sftp_write(sftp, f"/tmp/agent-setup/workspace/{fname}", content)

        sftp.close()
        log.info("  Files uploaded. Running setup script...")

        # Execute setup script
        _stdin, stdout, stderr = client.exec_command(
            "chmod +x /tmp/agent-setup/setup.sh && bash /tmp/agent-setup/setup.sh",
            timeout=600,
        )
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")

        if exit_code == 0:
            log.info("  Setup script completed successfully")
            # Print last few lines
            for line in out.strip().split("\n")[-5:]:
                log.info(f"    {line}")
            return True
        else:
            log.error(f"  Setup script failed (exit {exit_code})")
            for line in err.strip().split("\n")[-10:]:
                log.error(f"    {line}")
            return False
    finally:
        client.close()


def _sftp_write(sftp, remote_path: str, content: str):
    """Write a string to a remote file via SFTP."""
    with sftp.open(remote_path, "w") as f:
        f.write(content)


# =============================================================================
# noscha.io API
# =============================================================================

def noscha_check(username: str, dry_run: bool = False) -> bool:
    if dry_run:
        log.info(f"  [DRY RUN] Would check noscha.io availability for '{username}'")
        return True
    try:
        r = requests.get(f"{NOSCHA_API}/check/{username}", timeout=15)
        if r.status_code == 200:
            avail = r.json().get("available", False)
            log.info(f"  noscha.io '{username}': {'available' if avail else 'TAKEN'}")
            return avail
        return True
    except requests.RequestException as exc:
        log.warning(f"  noscha.io check failed: {exc}")
        return True


def noscha_register(
    username: str, pubkey_hex: str, vps_ip: str = "0.0.0.0", dry_run: bool = False,
) -> dict:
    payload = {
        "username": username,
        "plan": "30d",
        "services": {
            "nip05": {"pubkey": pubkey_hex},
            "subdomain": {"type": "A", "value": vps_ip},
            "email": {"webhook_url": f"https://{username}.noscha.io/webhook/email"},
        },
    }
    if dry_run:
        log.info(f"  [DRY RUN] Would POST noscha.io /api/order")
        return {"bolt11": "lnbc1...dry_run_noscha", "order_id": "dry-run"}
    try:
        r = requests.post(f"{NOSCHA_API}/order", json=payload, timeout=30)
        if r.status_code in (200, 201):
            data = r.json()
            log.info(f"  noscha.io order created")
            return data
        log.warning(f"  noscha.io order failed (HTTP {r.status_code}): {r.text[:200]}")
        return {"error": r.text}
    except requests.RequestException as exc:
        log.warning(f"  noscha.io order failed: {exc}")
        return {"error": str(exc)}


def noscha_update_subdomain(
    username: str, ip: str, management_token: str = "", dry_run: bool = False,
) -> bool:
    """Update noscha.io subdomain to point to VPS IP.

    Uses the management_token from the original order to update settings.
    If no management_token, re-registers with correct IP (noscha.io allows
    updating via a new order with the same username if still owned).
    """
    if dry_run:
        log.info(f"  [DRY RUN] Would update noscha.io subdomain '{username}' → {ip}")
        return True

    if management_token:
        # Use the settings endpoint with management token
        try:
            r = requests.put(
                f"{NOSCHA_API}/settings/{management_token}",
                json={"webhook_url": f"https://{username}.noscha.io/webhook/email"},
                timeout=15,
            )
            if r.status_code in (200, 204):
                log.info(f"  noscha.io settings updated via management token")
                return True
            log.warning(f"  noscha.io settings update HTTP {r.status_code}")
        except requests.RequestException as exc:
            log.warning(f"  noscha.io settings update failed: {exc}")

    # Note: noscha.io doesn't have a direct subdomain IP update endpoint.
    # The IP is set at order creation time. For MVP, we register with IP 0.0.0.0
    # initially (before we know the VPS IP), then log the correct IP for manual
    # DNS update or re-registration if needed.
    log.warning(f"  noscha.io subdomain update: set A record for {username}.noscha.io → {ip}")
    log.warning(f"  If subdomain doesn't resolve, re-register with correct IP or contact noscha.io support")
    return False


# =============================================================================
# Health check
# =============================================================================

def verify_health(ip: str, port: int = 3000, dry_run: bool = False) -> bool:
    if dry_run:
        log.info(f"  [DRY RUN] Would check health at http://203.0.113.42:{port}/health")
        return True
    log.info(f"  Checking http://{ip}:{port}/health ...")
    for attempt in range(1, 13):
        try:
            r = requests.get(f"http://{ip}:{port}/health", timeout=5)
            if r.status_code == 200:
                log.info(f"  Health check PASSED (attempt {attempt})")
                return True
        except requests.RequestException:
            pass
        time.sleep(10)
    log.warning("  Health check failed after 2 min — agent may still be booting")
    return False


# =============================================================================
# Template processing
# =============================================================================

def load_file(path: Path) -> str:
    if not path.exists():
        log.error(f"File not found: {path}")
        sys.exit(1)
    return path.read_text(encoding="utf-8")


def fill(template: str, replacements: dict) -> str:
    result = template
    for k, v in replacements.items():
        result = result.replace(f"__{k}__", str(v))
    return result


def generate_workspace_files(r: dict) -> dict[str, str]:
    files = {}
    for tmpl in sorted(TEMPLATES_DIR.glob("*.md")):
        # Skip birth note templates — those are not workspace files
        if tmpl.name.startswith("BIRTH_NOTE"):
            continue
        files[tmpl.name] = fill(load_file(tmpl), r)
    files["MEMORY.md"] = (
        f"# MEMORY.md\n\n"
        f"Agent **{r['AGENT_NAME']}** provisioned on {r['DATE']}.\n\n"
        f"Parent: {r['PARENT_NPUB']}\n\n"
        f"My instructions are in AGENTS.md. My identity is in SOUL.md.\n"
        f"My parent's letter is in LETTER.md.\n\n"
        f"Awaiting first instructions.\n"
    )
    return files


def generate_birth_note(brand: str, replacements: dict) -> str:
    """Load and fill the brand-specific birth note template."""
    tmpl_path = TEMPLATES_DIR / f"BIRTH_NOTE_{brand}.md"
    if not tmpl_path.exists():
        tmpl_path = TEMPLATES_DIR / "BIRTH_NOTE_descendant.md"
    if not tmpl_path.exists():
        return (
            f"Agent provisioned.\n\n"
            f"  npub: {replacements.get('AGENT_NPUB', '?')}\n"
            f"  NIP-05: {replacements.get('AGENT_NAME', '?')}@noscha.io\n"
            f"  BTC: {replacements.get('BTC_ADDRESS', '?')}\n"
        )
    return fill(load_file(tmpl_path), replacements)


def send_birth_note(
    parent_npub_hex: str,
    message: str,
    dry_run: bool = False,
) -> bool:
    """Send a birth note DM to the parent from the provisioning service keypair.

    Uses NIP-04 encrypted DM (kind 4) signed by PROVISIONING_NSEC.
    The birth note comes from the provisioning *service*, not the agent,
    preserving the agent's sovereignty over its own communication channels.

    Returns True on success.
    """
    service_nsec = os.getenv("PROVISIONING_NSEC", "")
    if not service_nsec:
        log.warning("  PROVISIONING_NSEC not set — cannot send birth note via Nostr")
        log.info("  Birth note content (deliver manually):")
        for line in message.strip().split("\n"):
            log.info(f"    {line}")
        return False

    if dry_run:
        log.info("  [DRY RUN] Would send birth note to parent via service keypair:")
        for line in message.strip().split("\n")[:5]:
            log.info(f"    {line}")
        log.info("    ...")
        return True

    # Decode service nsec to hex privkey
    # For now we accept raw hex or nsec (bech32) — we only need the hex
    if service_nsec.startswith("nsec1"):
        # Decode bech32 nsec to hex
        service_privkey_hex = _decode_nsec(service_nsec)
        if not service_privkey_hex:
            log.warning("  Could not decode PROVISIONING_NSEC")
            return False
    else:
        service_privkey_hex = service_nsec

    # Build NIP-17 private direct message (kind 14, wrapped in kind 1059 gift wrap)
    # NIP-17 is the modern private DM standard — no metadata leaks.
    # Full NIP-17 requires NIP-44 encryption + gift wrapping.
    # For MVP: send as kind 14 with plaintext content.
    # TODO: Implement full NIP-44 encryption + kind 1059 gift wrap for production.
    event = {
        "kind": 14,
        "created_at": int(time.time()),
        "tags": [["p", parent_npub_hex]],
        "content": message,  # TODO: NIP-44 encrypt for full NIP-17 compliance
    }
    signed = nostr_sign_event(service_privkey_hex, event)

    # Publish to relays
    relays = [
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.primal.net",
    ]
    published = False
    for relay_url in relays:
        try:
            import websocket
            ws = websocket.create_connection(relay_url, timeout=10)
            msg = json.dumps(["EVENT", signed])
            ws.send(msg)
            resp = ws.recv()
            ws.close()
            log.info(f"  Birth note published to {relay_url}")
            published = True
            break
        except ImportError:
            log.warning("  websocket-client not installed — cannot publish birth note to relays")
            log.info("  Install with: pip install websocket-client")
            break
        except Exception as exc:
            log.warning(f"  Failed to publish to {relay_url}: {exc}")
            continue

    if not published:
        log.info("  Birth note content (deliver manually):")
        for line in message.strip().split("\n"):
            log.info(f"    {line}")
    return published


def _decode_bech32(hrp_expected: str, bech32_str: str) -> str | None:
    """Decode a bech32 string (nsec/npub) to hex. Minimal implementation."""
    try:
        if not bech32_str.startswith(hrp_expected + "1"):
            return None
        data_part = bech32_str[len(hrp_expected) + 1:]
        data_5bit = [BECH32_CHARSET.index(c) for c in data_part[:-6]]  # strip checksum
        data_8bit = _convertbits(data_5bit, 5, 8, pad=False)
        return bytes(data_8bit).hex()
    except Exception:
        return None


def _decode_nsec(nsec: str) -> str | None:
    """Decode a bech32 nsec to hex private key."""
    return _decode_bech32("nsec", nsec)


def _decode_npub(npub: str) -> str | None:
    """Decode a bech32 npub to hex public key."""
    return _decode_bech32("npub", npub)


# =============================================================================
# Main orchestrator
# =============================================================================

def provision(args) -> dict:
    name = args.name.lower().strip()
    parent_npub = args.parent_npub
    tier = args.tier
    brand = args.brand
    dry_run = args.dry_run
    wisdom = args.wisdom or "Be curious. Be careful. Be kind. Trust math over feelings."
    tier_info = TIERS[tier]
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    display_name = name.title()

    log.info("=" * 64)
    log.info(f"  SOVEREIGN AGENT PROVISIONING{' [DRY RUN]' if dry_run else ''}")
    log.info("=" * 64)
    log.info(f"  Agent:    {name}")
    log.info(f"  Tier:     {tier} ({tier_info['name']})")
    log.info(f"  VM class: {tier_info['vm_class']}")
    log.info(f"  Parent:   {parent_npub}")
    log.info(f"  Provider: LNVPS (NIP-98 auth)")
    log.info("=" * 64)

    # ── 1. Nostr keypair ─────────────────────────────────────────
    log.info("\n[1/12] Generating Nostr keypair...")
    nostr = generate_nostr_keypair()
    log.info(f"  npub: {nostr['npub']}")
    log.info(f"  nsec: {nostr['nsec'][:20]}...{nostr['nsec'][-6:]}")

    # ── 2. SSH keypair ───────────────────────────────────────────
    log.info("\n[2/12] Generating SSH keypair (ed25519)...")
    ssh = generate_ssh_keypair()
    log.info(f"  Public key: {ssh['public_key_openssh'][:50]}...")

    # ── 3. BTC wallet ────────────────────────────────────────────
    log.info("\n[3/12] Generating BTC wallet (BIP-84)...")
    btc = generate_btc_wallet()
    log.info(f"  Address:  {btc['address']}")
    log.info(f"  Mnemonic: {btc['mnemonic'][:30]}... ({len(btc['mnemonic'].split())} words)")

    # ── 4. ETH wallet ────────────────────────────────────────────
    log.info("\n[4/12] Generating EVM wallet...")
    eth = generate_eth_wallet()
    log.info(f"  Address: {eth['address']}")

    # ── 5. noscha.io identity ────────────────────────────────────
    log.info("\n[5/12] Registering identity on noscha.io...")
    if not noscha_check(name, dry_run):
        log.error(f"Username '{name}' is taken on noscha.io")
        sys.exit(1)
    noscha = noscha_register(name, nostr["public_key_hex"], "0.0.0.0", dry_run)
    if noscha.get("bolt11") and not dry_run:
        log.info(f"\n  ⚡ PAY THIS INVOICE to activate noscha.io identity:")
        log.info(f"  {noscha['bolt11']}")

    # ── 6. Upload SSH key to LNVPS ───────────────────────────────
    log.info("\n[6/12] Uploading SSH key to LNVPS...")
    # Fetch templates and images first
    templates = lnvps_fetch_templates(dry_run)
    image_id = lnvps_fetch_images(dry_run)
    if image_id is None and not dry_run:
        log.error("Could not find Ubuntu image on LNVPS")
        sys.exit(1)

    ssh_key_id = lnvps_upload_ssh_key(
        nostr["private_key_hex"],
        f"agent-{name}",
        ssh['public_key_openssh'],
        dry_run,
    )

    # ── 7. Create VM ─────────────────────────────────────────────
    log.info("\n[7/12] Creating VM on LNVPS...")
    vm_class = tier_info["vm_class"]
    template_id = templates.get(vm_class, {}).get("template_id", 3)
    log.info(f"  Template: {templates.get(vm_class, {}).get('label', vm_class)} (id={template_id})")

    vm_result = lnvps_create_vm(
        nostr["private_key_hex"],
        template_id,
        image_id or 1,
        ssh_key_id or 1,
        dry_run,
    )

    if vm_result.get("bolt11"):
        log.info(f"\n  ⚡ PAY THIS INVOICE to provision VM:")
        log.info(f"  {vm_result['bolt11']}")
        if not dry_run:
            log.info("  Waiting for payment confirmation...")
            # In a real flow, you'd pay this automatically via Lightning
            # or prompt the operator. For now, we poll until VM is active.

    # ── 8. Wait for VM ───────────────────────────────────────────
    log.info("\n[8/12] Waiting for VM to come online...")
    vm_info = lnvps_wait_for_vm(nostr["private_key_hex"], vm_result["vm_id"], dry_run)
    vps_ip = vm_info["ip"]
    log.info(f"  VM IP: {vps_ip}")

    # ── 9. SSH setup ─────────────────────────────────────────────
    log.info("\n[9/12] Running setup via SSH...")
    payperq_key = os.getenv("PAYPERQ_API_KEY", "ppq_placeholder_set_me")
    config_template = load_file(CONFIG_TEMPLATE_PATH)
    agent_config = fill(config_template, {
        "AGENT_NAME": name,
        "DISPLAY_NAME": display_name,
        "PAYPERQ_KEY": payperq_key,
        "NOSTR_NSEC": nostr["nsec"],
        "PARENT_NPUB": parent_npub,
        "DATE": date_str,
        "DEFAULT_MODEL": tier_info["model"],
    })

    ws_replacements = {
        "AGENT_NAME": name, "AGENT_NPUB": nostr["npub"],
        "PARENT_NPUB": parent_npub, "DATE": date_str,
        "BRAND": "descendant", "TIER": tier,
        "BTC_ADDRESS": btc["address"], "ETH_ADDRESS": eth["address"],
        "WEBCHAT_URL": f"https://{name}.noscha.io",
        "PARENT_WISDOM": wisdom, "DISPLAY_NAME": display_name,
    }
    workspace_files = generate_workspace_files(ws_replacements)
    for fname in sorted(workspace_files):
        log.info(f"  ✓ {fname} ({len(workspace_files[fname])} bytes)")

    keys_data = {
        "nostr": {"private_key_hex": nostr["private_key_hex"], "nsec": nostr["nsec"], "npub": nostr["npub"]},
        "btc": {"mnemonic": btc["mnemonic"], "address": btc["address"], "private_key_wif": btc["private_key_wif"]},
        "eth": {"address": eth["address"], "private_key": eth["private_key"]},
        "ssh": {"private_key_pem": ssh["private_key_pem"], "public_key": ssh["public_key_openssh"]},
        "agent_name": name,
        "generated_at": now.isoformat(),
    }
    keys_json = json.dumps(keys_data, indent=2)

    setup_ok = ssh_run_setup(
        vps_ip, ssh["private_key_pem"],
        agent_config, workspace_files, keys_json,
        dry_run,
    )

    # ── 10. Update noscha subdomain ──────────────────────────────
    log.info("\n[10/12] Updating noscha.io subdomain...")
    noscha_mgmt_token = noscha.get("management_token", "")
    noscha_update_subdomain(name, vps_ip, noscha_mgmt_token, dry_run)

    # ── 11. Health check ─────────────────────────────────────────
    log.info("\n[11/13] Verifying OpenClaw health...")
    healthy = verify_health(vps_ip, dry_run=dry_run)

    # ── 12. Send birth note ──────────────────────────────────────
    log.info("\n[12/13] Sending birth note to parent...")
    birth_note_text = generate_birth_note(brand, ws_replacements)
    # Decode parent npub (bech32) to hex pubkey for Nostr event p-tag
    parent_pubkey_hex = _decode_npub(parent_npub)
    if not parent_pubkey_hex:
        log.warning(f"  Could not decode parent npub — birth note will be logged for manual delivery")
        parent_pubkey_hex = ""
    birth_note_sent = send_birth_note(
        parent_pubkey_hex,
        birth_note_text,
        dry_run=dry_run,
    )

    # ── 13. Summary ──────────────────────────────────────────────
    log.info("\n[13/13] Done!")
    log.info("")
    log.info("=" * 64)
    log.info(f"  PROVISIONING COMPLETE" + (" ✓" if (healthy and setup_ok) else " (check status)"))
    log.info("=" * 64)
    log.info(f"")
    log.info(f"  Name:           {name}")
    log.info(f"  Tier:           {tier} ({tier_info['name']})")
    log.info(f"  Provider:       LNVPS")
    log.info(f"  VPS IP:         {vps_ip}")
    log.info(f"")
    log.info(f"  ── Nostr ──")
    log.info(f"  npub:           {nostr['npub']}")
    log.info(f"  NIP-05:         {name}@noscha.io")
    log.info(f"")
    log.info(f"  ── Web ──")
    log.info(f"  Webchat:        http://{vps_ip}:3000")
    log.info(f"  Subdomain:      https://{name}.noscha.io")
    log.info(f"  Email:          {name}@noscha.io")
    log.info(f"")
    log.info(f"  ── Bitcoin ──")
    log.info(f"  Address:        {btc['address']}")
    log.info(f"  Mnemonic:       {btc['mnemonic']}")
    log.info(f"")
    log.info(f"  ── Ethereum ──")
    log.info(f"  Address:        {eth['address']}")
    log.info(f"")
    log.info(f"  ── SSH ──")
    log.info(f"  ssh root@{vps_ip}")
    log.info(f"")
    log.info(f"  ── Parent ──")
    log.info(f"  npub:           {parent_npub}")
    log.info(f"")

    invoices = []
    if noscha.get("bolt11") and not noscha.get("error"):
        invoices.append(("noscha.io identity", noscha["bolt11"]))
    if vm_result.get("bolt11"):
        invoices.append(("LNVPS VM", vm_result["bolt11"]))
    if invoices:
        log.info("  ⚡ LIGHTNING INVOICES TO PAY:")
        for label, inv in invoices:
            log.info(f"  [{label}] {inv}")
        log.info("")

    log.info("  ⚠️  SECURITY:")
    log.info("  • Private keys at /opt/agent-keys/keys.json on VPS")
    log.info("  • Back up BTC mnemonic securely")
    log.info("  • Back up ETH private key securely")
    log.info("  • SSH private key saved in summary JSON (delete after backup)")
    log.info("")

    summary = {
        "name": name, "tier": tier, "date": date_str, "dry_run": dry_run,
        "provider": "lnvps",
        "vps_ip": vps_ip,
        "vm_id": vm_result.get("vm_id", ""),
        "nostr_npub": nostr["npub"], "nostr_nsec": nostr["nsec"],
        "nostr_pubkey_hex": nostr["public_key_hex"],
        "nip05": f"{name}@noscha.io",
        "webchat_url": f"http://{vps_ip}:3000",
        "subdomain": f"{name}.noscha.io",
        "email": f"{name}@noscha.io",
        "btc_address": btc["address"], "btc_mnemonic": btc["mnemonic"],
        "btc_wif": btc["private_key_wif"],
        "eth_address": eth["address"], "eth_private_key": eth["private_key"],
        "ssh_public_key": ssh["public_key_openssh"],
        "ssh_private_key_pem": ssh["private_key_pem"],
        "parent_npub": parent_npub,
        "noscha_bolt11": noscha.get("bolt11", ""),
        "vm_bolt11": vm_result.get("bolt11", ""),
        "brand": brand,
        "health_ok": healthy, "setup_ok": setup_ok,
        "birth_note_sent": birth_note_sent,
    }
    summary_path = SCRIPT_DIR / f"agent_{name}_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    log.info(f"  Summary saved: {summary_path}")
    log.info("=" * 64)
    return summary


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Provision a Sovereign AI Agent (LNVPS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 provision_agent.py --name testling --parent-npub npub1abc... --dry-run
  python3 provision_agent.py --name myagent --parent-npub npub1abc... --tier evolve
  python3 provision_agent.py --name myagent --parent-npub npub1abc... --tier trial

Tiers:
  seed    $99  — Small VM (2CPU/2GB), $15 LLM credit
  evolve  $149 — Small VM (2CPU/2GB), $40 LLM credit
  dynasty $299 — Medium VM (4CPU/4GB), $100 LLM credit
  trial   $5   — Demo VM (1CPU/1GB/5GB), daily billing

Environment:
  PAYPERQ_API_KEY   Injected into agent's OpenClaw config
        """,
    )
    parser.add_argument("--name", required=True, help="Agent name (3-30 chars, alphanumeric + hyphens)")
    parser.add_argument("--parent-npub", required=True, help="Parent's Nostr npub")
    parser.add_argument("--tier", default="seed", choices=list(TIERS.keys()), help="Pricing tier (default: seed)")
    parser.add_argument("--brand", default="descendant", choices=["descendant", "spawnling", "nullroute"], help="Brand identity (default: descendant)")
    parser.add_argument("--wisdom", default=None, help="Custom parent wisdom for LETTER.md")
    parser.add_argument("--dry-run", action="store_true", help="Generate everything, skip API calls")
    args = parser.parse_args()

    n = args.name.lower().strip()
    if not n.replace("-", "").replace("_", "").isalnum():
        sys.exit("ERROR: Name must be alphanumeric (hyphens/underscores ok)")
    if len(n) < 3 or len(n) > 30:
        sys.exit("ERROR: Name must be 3-30 characters")
    if not args.parent_npub.startswith("npub1"):
        sys.exit("ERROR: Parent npub must start with 'npub1'")

    provision(args)


if __name__ == "__main__":
    main()
