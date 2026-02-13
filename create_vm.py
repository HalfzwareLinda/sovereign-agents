#!/usr/bin/env python3
"""
create_vm.py — VM Provisioning Midwife

Creates a VPS on LNVPS and bootstraps an autonomous AI agent on it.
All agent secrets (Nostr keys, wallets) are generated ON the VPS — never here.

This script only handles infrastructure:
  1. Generate TEMPORARY service Nostr keypair (for LNVPS NIP-98 auth only)
  2. Generate TEMPORARY SSH ed25519 keypair (held in memory, never written to disk)
  3. Fetch LNVPS templates/images, upload SSH key
  4. Create VM → surface Lightning invoice for payment
  5. Poll until VM boots, get IP
  6. SSH into VM: upload bootstrap_agent.sh + templates + config inputs
  7. Execute bootstrap_agent.sh remotely (agent generates its own identity)
  8. Retrieve agent's public info (npub, addresses) from bootstrap output
  9. Delete SSH key from LNVPS, discard service keypair
  10. Output JSON summary (NO agent secrets — only public info)

Usage:
    python3 create_vm.py --name myagent --parent-npub npub1abc... --dry-run
    python3 create_vm.py --name myagent --parent-npub npub1abc... --tier evolve

Environment:
    PAYPERQ_API_KEY         PayPerQ API key — the ONLY secret that crosses to the VPS
    WEBHOOK_RECEIVER_URL    (optional) Custom webhook receiver URL (default: webhook.site)
    NOSCHA_MGMT_TOKEN       (optional) Pre-paid noscha.io management token (skips registration)
"""

import argparse
import base64
import hashlib
import io
import json
import logging
import os
import re
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
BOOTSTRAP_SCRIPT = SCRIPT_DIR / "bootstrap_agent.sh"
CONFIG_TEMPLATE = SCRIPT_DIR / "config_template.json"
NIP46_SCRIPT = SCRIPT_DIR / "nip46-server.js"
BIRTH_NOTE_SCRIPT = SCRIPT_DIR / "send_birth_note.js"
PPQ_PROVISION_SCRIPT = SCRIPT_DIR / "ppq_provision.py"
NWC_PAY_SCRIPT = SCRIPT_DIR / "nwc_pay.js"

LNVPS_API = "https://api.lnvps.net"
NOSCHA_API = "https://noscha.io/api"
WEBHOOK_SITE_API = "https://webhook.site"

# VM class → LNVPS template matching keywords
VM_CLASSES = {
    "demo":   "demo",
    "tiny":   "tiny",
    "small":  "small",
    "medium": "medium",
}

TIERS = {
    "seed":    {"vm_class": "tiny",   "model": "gpt-5-nano"},
    "evolve":  {"vm_class": "small",  "model": "gpt-5-nano"},
    "dynasty": {"vm_class": "medium", "model": "gpt-5-nano"},
    "trial":   {"vm_class": "demo",   "model": "gpt-5-nano"},
}

LOG_FMT = "%(asctime)s %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT, datefmt="%H:%M:%S")
log = logging.getLogger("create_vm")


# =============================================================================
# Bech32 encoding/decoding
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


def _decode_bech32(hrp_expected: str, bech32_str: str) -> str | None:
    try:
        if not bech32_str.startswith(hrp_expected + "1"):
            return None
        data_part = bech32_str[len(hrp_expected) + 1:]
        data_5bit = [BECH32_CHARSET.index(c) for c in data_part[:-6]]
        data_8bit = _convertbits(data_5bit, 5, 8, pad=False)
        return bytes(data_8bit).hex()
    except Exception:
        return None


# =============================================================================
# Nostr signing + NIP-98
# =============================================================================

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def nostr_sign_event(privkey_hex: str, event: dict) -> dict:
    """Sign a Nostr event (NIP-01)."""
    privkey = PrivateKey(bytes.fromhex(privkey_hex))
    pubkey_hex = privkey.public_key.format(compressed=True)[1:].hex()
    event["pubkey"] = pubkey_hex
    serialized = json.dumps(
        [0, pubkey_hex, event["created_at"], event["kind"], event["tags"], event["content"]],
        separators=(",", ":"), ensure_ascii=False,
    )
    event_id = _sha256(serialized.encode()).hex()
    event["id"] = event_id
    sig = privkey.sign_schnorr(bytes.fromhex(event_id))
    event["sig"] = sig.hex()
    return event


def nip98_auth_header(privkey_hex: str, url: str, method: str, body: bytes | None = None) -> str:
    """Build NIP-98 Authorization header."""
    tags = [["u", url], ["method", method.upper()]]
    if body:
        tags.append(["payload", _sha256(body).hex()])
    event = {"kind": 27235, "created_at": int(time.time()), "tags": tags, "content": ""}
    signed = nostr_sign_event(privkey_hex, event)
    encoded = base64.b64encode(json.dumps(signed, separators=(",", ":")).encode()).decode()
    return f"Nostr {encoded}"


def generate_temp_nostr_keypair() -> dict:
    """Generate a temporary Nostr keypair for LNVPS auth. Discarded after use."""
    privkey = PrivateKey(secrets.token_bytes(32))
    priv_hex = privkey.secret.hex()
    pub_hex = privkey.public_key.format(compressed=True)[1:].hex()
    return {"private_key_hex": priv_hex, "public_key_hex": pub_hex}


def generate_ssh_keypair() -> dict:
    """Generate an ed25519 SSH keypair in memory."""
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


# =============================================================================
# LNVPS API
# =============================================================================

def lnvps_request(method, path, privkey_hex=None, json_body=None, dry_run=False):
    url = f"{LNVPS_API}{path}"
    if dry_run:
        log.info(f"  [DRY RUN] {method} {url}")
        return None

    headers = {"Content-Type": "application/json"}
    body_bytes = json.dumps(json_body).encode() if json_body else None
    if privkey_hex:
        headers["Authorization"] = nip98_auth_header(privkey_hex, url, method, body_bytes)

    try:
        resp = requests.request(method, url, headers=headers, data=body_bytes, timeout=30)
        if resp.status_code in (200, 201):
            return resp.json()
        log.warning(f"  LNVPS {method} {path} → HTTP {resp.status_code}: {resp.text[:300]}")
        return None
    except requests.RequestException as exc:
        log.warning(f"  LNVPS {method} {path} → {exc}")
        return None


def lnvps_delete_ssh_key(privkey_hex, key_id, dry_run=False):
    """Delete an SSH key from LNVPS after provisioning."""
    if dry_run:
        log.info(f"  [DRY RUN] Would delete SSH key {key_id} from LNVPS")
        return True
    result = lnvps_request("DELETE", f"/api/v1/ssh-key/{key_id}", privkey_hex)
    if result is not None:
        log.info(f"  SSH key {key_id} deleted from LNVPS")
        return True
    # DELETE may return 204 No Content — check if the request didn't error
    log.info(f"  SSH key {key_id} delete request sent")
    return True


def lnvps_fetch_templates(dry_run=False):
    if dry_run:
        return {k: {"template_id": i + 1, "label": k} for i, k in enumerate(VM_CLASSES)}
    data = lnvps_request("GET", "/api/v1/vm/templates")
    if not data:
        log.warning("  Could not fetch templates — using fallback IDs")
        return {k: {"template_id": i + 1, "label": f"{k} (fallback)"} for i, k in enumerate(VM_CLASSES)}

    result = {}
    # API returns {"data": {"templates": [...]}}
    inner = data.get("data", data) if isinstance(data, dict) else data
    templates = inner.get("templates", inner) if isinstance(inner, dict) else inner
    for tmpl in templates:
        name = (tmpl.get("name") or tmpl.get("label") or "").lower()
        for cls, keyword in VM_CLASSES.items():
            if keyword in name and cls not in result:
                result[cls] = {"template_id": tmpl["id"], "label": tmpl.get("name", name)}
    fallbacks = {k: i + 1 for i, k in enumerate(VM_CLASSES)}
    for cls in VM_CLASSES:
        if cls not in result:
            result[cls] = {"template_id": fallbacks[cls], "label": f"{cls} (fallback)"}
    return result


def lnvps_fetch_images(dry_run=False):
    if dry_run:
        return 1
    data = lnvps_request("GET", "/api/v1/image")
    if not data:
        return None
    # API returns {"data": [list of images]} — images have "distribution" + "version", not "name"
    images = data.get("data", data) if isinstance(data, dict) else data
    if isinstance(images, dict):
        images = images.get("images", [])
    for img in images:
        dist = (img.get("distribution") or img.get("name") or "").lower()
        ver = img.get("version") or ""
        if "ubuntu" in dist and ver in ("24.04", "22.04"):
            return img["id"]
    for img in images:
        dist = (img.get("distribution") or img.get("name") or "").lower()
        if "ubuntu" in dist:
            return img["id"]
    return images[0]["id"] if images else None


def lnvps_upload_ssh_key(privkey_hex, key_name, public_key, dry_run=False):
    if dry_run:
        log.info(f"  [DRY RUN] Would upload SSH key '{key_name}'")
        return 999
    data = lnvps_request("POST", "/api/v1/ssh-key", privkey_hex,
                         json_body={"name": key_name, "key_data": public_key})
    if data:
        # API returns {"data": {"id": N, ...}}
        inner = data.get("data", data) if isinstance(data, dict) else data
        key_id = inner.get("id") if isinstance(inner, dict) else data.get("id")
        log.info(f"  SSH key uploaded: id={key_id}")
        return key_id
    return None


def lnvps_create_vm(privkey_hex, template_id, image_id, ssh_key_id, dry_run=False):
    body = {"template_id": template_id, "image_id": image_id, "ssh_key_id": ssh_key_id}
    if dry_run:
        log.info(f"  [DRY RUN] Would create VM: {json.dumps(body)}")
        return {"vm_id": "dry-run-vm", "bolt11": "lnbc1...dry_run", "status": "pending_payment"}
    data = lnvps_request("POST", "/api/v1/vm", privkey_hex, json_body=body)
    if not data:
        log.error("VM creation failed")
        sys.exit(1)
    # API returns {"data": {"id": N, ...}} — invoice NOT included in create response
    inner = data.get("data", data) if isinstance(data, dict) else data
    vm_id = inner.get("id") or inner.get("vm_id")

    # Get payment invoice from renew endpoint
    bolt11 = ""
    log.info(f"  VM created: id={vm_id} — fetching payment invoice...")
    renew_data = lnvps_request("GET", f"/api/v1/vm/{vm_id}/renew?method=lightning", privkey_hex)
    if renew_data:
        renew_inner = renew_data.get("data", renew_data) if isinstance(renew_data, dict) else renew_data
        bolt11 = (renew_inner.get("data", {}).get("lightning", "") if isinstance(renew_inner, dict) else "")
    return {"vm_id": vm_id, "bolt11": bolt11, "raw": data}


def lnvps_wait_for_vm(privkey_hex, vm_id, dry_run=False):
    if dry_run:
        return {"ip": "203.0.113.42", "status": "running"}
    log.info("  Polling VM status...")
    for attempt in range(1, 61):
        data = lnvps_request("GET", f"/api/v1/vm/{vm_id}", privkey_hex)
        if data:
            # API returns {"data": {...}} wrapper
            inner = data.get("data", data) if isinstance(data, dict) else data
            status_obj = inner.get("status", {})
            state = status_obj.get("state", "") if isinstance(status_obj, dict) else str(status_obj)
            ip_list = inner.get("ip_assignments") or []
            ip_raw = ip_list[0].get("ip", "") if ip_list else inner.get("ip", "")
            ip = ip_raw.split("/")[0]  # strip CIDR suffix (e.g. /25)
            if state == "running" and ip:
                log.info(f"  VM running at {ip} (attempt {attempt})")
                return {"ip": ip, "status": state}
            if attempt % 6 == 0:
                log.info(f"  Waiting... status={state} (attempt {attempt})")
        time.sleep(10)
    log.error("VM did not come online within 10 minutes")
    sys.exit(1)


# =============================================================================
# noscha.io registration (webhook challenge flow)
# =============================================================================

def _webhook_create_token(dry_run=False):
    """Create a webhook.site token to receive the noscha challenge.

    Returns {"uuid": "...", "url": "https://webhook.site/..."} or None.
    Respects WEBHOOK_RECEIVER_URL env var as override.
    """
    override = os.getenv("WEBHOOK_RECEIVER_URL", "")
    if override:
        # Caller manages their own receiver; we just poll a requests endpoint
        # Expect format: https://webhook.site/{uuid} or similar
        uuid = override.rstrip("/").split("/")[-1]
        return {"uuid": uuid, "url": override}

    if dry_run:
        return {"uuid": "dry-run-uuid", "url": "https://webhook.site/dry-run-uuid"}

    try:
        resp = requests.post(f"{WEBHOOK_SITE_API}/token", timeout=15)
        if resp.status_code in (200, 201):
            data = resp.json()
            uuid = data.get("uuid", "")
            if uuid:
                log.info(f"  Webhook receiver: https://webhook.site/{uuid}")
                return {"uuid": uuid, "url": f"https://webhook.site/{uuid}"}
        log.warning(f"  webhook.site token creation failed: HTTP {resp.status_code}")
        return None
    except requests.RequestException as exc:
        log.warning(f"  webhook.site token creation failed: {exc}")
        return None


def _webhook_poll_for_challenge(uuid, timeout_sec=120, dry_run=False):
    """Poll webhook.site for the noscha challenge payload.

    Returns challenge_url string, or None on timeout.
    """
    if dry_run:
        return "https://noscha.io/api/order/dry-run-id/confirm/dry-run-challenge"

    log.info(f"  Polling webhook.site for noscha challenge (up to {timeout_sec}s)...")
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            resp = requests.get(
                f"{WEBHOOK_SITE_API}/token/{uuid}/requests",
                params={"sorting": "newest"},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                reqs = data.get("data", data) if isinstance(data, dict) else data
                if isinstance(reqs, list):
                    for req in reqs:
                        content = req.get("content") or req.get("body") or ""
                        if isinstance(content, str):
                            try:
                                payload = json.loads(content)
                            except json.JSONDecodeError:
                                continue
                        elif isinstance(content, dict):
                            payload = content
                        else:
                            continue

                        if payload.get("event") == "webhook_challenge":
                            challenge_url = payload.get("challenge_url", "")
                            if challenge_url:
                                log.info(f"  Challenge received: {challenge_url[:80]}...")
                                return challenge_url
        except requests.RequestException:
            pass
        time.sleep(5)

    log.warning("  Timed out waiting for noscha webhook challenge")
    return None


def _noscha_extract_bolt11(html: str) -> str | None:
    """Extract Lightning bolt11 invoice from noscha.io challenge confirmation HTML.

    Tries multiple strategies:
    1. HTML data attributes (data-invoice, data-bolt11, value=)
    2. JSON embedded in the page
    3. Raw regex scan for lnbc... strings
    """
    # Strategy 1: common HTML attributes
    for pattern in [
        r'data-invoice="(lnbc[a-z0-9]+)"',
        r'data-bolt11="(lnbc[a-z0-9]+)"',
        r'value="(lnbc[a-z0-9]+)"',
        r"data-invoice='(lnbc[a-z0-9]+)'",
    ]:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1)

    # Strategy 2: JSON blob containing lightning_invoice or bolt11
    for key in ["lightning_invoice", "bolt11", "invoice", "payment_request"]:
        pattern = rf'"{key}"\s*:\s*"(lnbc[a-z0-9]+)"'
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1)

    # Strategy 3: raw regex — find all lnbc strings, take longest
    matches = re.findall(r"(lnbc[a-z0-9]+)", html, re.IGNORECASE)
    if matches:
        return max(matches, key=len)

    return None


def _noscha_poll_order_status(order_id, timeout_sec=600, dry_run=False):
    """Poll noscha.io order status until provisioned.

    Returns {"management_token": "...", "status": "provisioned"} or None.
    """
    if dry_run:
        return {"management_token": "dry-run-mgmt-token", "status": "provisioned"}

    log.info(f"  Polling noscha.io order {order_id} status (up to {timeout_sec}s)...")
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            resp = requests.get(
                f"{NOSCHA_API}/order/{order_id}/status",
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status", "")
                if status == "provisioned":
                    mgmt_token = data.get("management_token", "")
                    log.info(f"  noscha.io order provisioned! management_token={'yes' if mgmt_token else 'missing'}")
                    return {"management_token": mgmt_token, "status": status}
                if status in ("failed", "cancelled", "expired"):
                    log.error(f"  noscha.io order {status}")
                    return None
                # Still pending — keep polling
        except requests.RequestException:
            pass
        time.sleep(10)

    log.warning("  Timed out waiting for noscha.io provisioning")
    return None


def noscha_register(username, plan, pubkey_hex, target_ip, dry_run=False):
    """Full noscha.io registration with webhook challenge flow.

    Steps:
      1. Create webhook.site token to receive challenge
      2. POST /api/order with webhook_url → get order_id
      3. Poll webhook.site for challenge payload
      4. GET challenge_url → extract bolt11 from HTML
      5. Surface bolt11 for operator to pay
      6. Poll order status until provisioned → get management_token

    Returns {"management_token": "...", "order_id": "...", "bolt11": "...", "nip05": "user@noscha.io"}
    or {"error": "..."} on failure.
    """
    if dry_run:
        log.info(f"  [DRY RUN] Would register {username}@noscha.io")
        log.info(f"    plan={plan}, pubkey={pubkey_hex[:16]}..., ip={target_ip}")
        return {
            "management_token": "dry-run-mgmt-token",
            "order_id": "dry-run-order",
            "bolt11": "lnbc1...dry_run_noscha",
            "nip05": f"{username}@noscha.io",
        }

    # Step 1: Create webhook receiver
    log.info("  Creating webhook receiver for challenge...")
    webhook = _webhook_create_token()
    if not webhook:
        return {"error": "Could not create webhook receiver"}

    # Step 2: Submit noscha order
    log.info(f"  Submitting noscha.io order for '{username}'...")
    order_payload = {
        "username": username,
        "plan": plan,
        "webhook_url": webhook["url"],
        "services": {
            "nip05": {"pubkey": pubkey_hex},
            "subdomain": {"type": "A", "target": target_ip},
            "email": {},
        },
    }
    try:
        resp = requests.post(
            f"{NOSCHA_API}/order",
            json=order_payload,
            timeout=30,
        )
        if resp.status_code not in (200, 201):
            log.error(f"  noscha.io order failed: HTTP {resp.status_code} — {resp.text[:300]}")
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        order_data = resp.json()
    except requests.RequestException as exc:
        log.error(f"  noscha.io order failed: {exc}")
        return {"error": str(exc)}

    order_id = order_data.get("order_id") or order_data.get("id", "unknown")
    order_status = order_data.get("status", "")
    log.info(f"  Order created: id={order_id}, status={order_status}")

    # Step 3: Poll webhook for challenge
    challenge_url = _webhook_poll_for_challenge(webhook["uuid"])
    if not challenge_url:
        return {"error": "No webhook challenge received", "order_id": order_id}

    # Step 4: GET challenge URL → extract bolt11
    log.info("  Confirming challenge and extracting payment invoice...")
    bolt11 = ""
    try:
        resp = requests.get(challenge_url, timeout=15)
        if resp.status_code == 200:
            bolt11 = _noscha_extract_bolt11(resp.text) or ""
            if bolt11:
                log.info(f"  ⚡ noscha.io invoice: {bolt11[:60]}...")
            else:
                log.warning(f"  Could not extract bolt11 from challenge page ({len(resp.text)} bytes)")
                # Log a snippet for debugging
                log.warning(f"  Page snippet: {resp.text[:300]}")
        else:
            log.warning(f"  Challenge URL returned HTTP {resp.status_code}")
    except requests.RequestException as exc:
        log.warning(f"  Challenge URL fetch failed: {exc}")

    if not bolt11:
        log.warning("  No bolt11 extracted — noscha.io identity may need manual setup")
        return {"error": "No bolt11 in challenge page", "order_id": order_id}

    # Step 5: Surface invoice for payment
    log.info("")
    log.info(f"  ⚡ PAY THIS INVOICE to activate {username}@noscha.io:")
    log.info(f"  {bolt11}")
    log.info("")

    # Step 6: Poll until provisioned
    result = _noscha_poll_order_status(order_id)
    if not result:
        return {"error": "Order did not provision", "order_id": order_id, "bolt11": bolt11}

    return {
        "management_token": result.get("management_token", ""),
        "order_id": order_id,
        "bolt11": bolt11,
        "nip05": f"{username}@noscha.io",
    }


# =============================================================================
# SSH: upload files and run bootstrap
# =============================================================================

def ssh_bootstrap(ip, ssh_private_key_pem, upload_files, dry_run=False):
    """SSH into VM, upload files to /tmp/agent-bootstrap/, execute bootstrap_agent.sh.

    Returns dict with agent's public info parsed from bootstrap output, or None on failure.
    """
    if dry_run:
        log.info(f"  [DRY RUN] Would SSH to {ip}, upload {len(upload_files)} files, run bootstrap")
        return {
            "npub": "npub1dryrun...",
            "btc_address": "bc1qdryrun...",
            "eth_address": "0xDryRun...",
        }

    try:
        import paramiko
    except ImportError:
        sys.exit("ERROR: paramiko not installed. Run: pip install paramiko")

    pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(ssh_private_key_pem))
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Wait for SSH
    log.info(f"  Connecting to ubuntu@{ip}...")
    connected = False
    for attempt in range(1, 19):
        try:
            client.connect(ip, username="ubuntu", pkey=pkey, timeout=10)
            connected = True
            log.info(f"  SSH connected (attempt {attempt})")
            break
        except Exception:
            if attempt % 6 == 0:
                log.info(f"  SSH not ready (attempt {attempt})...")
            time.sleep(10)

    if not connected:
        log.error(f"  Could not SSH to {ip}")
        return None

    try:
        sftp = client.open_sftp()
        # Create staging directory
        for d in ["/tmp/agent-bootstrap", "/tmp/agent-bootstrap/templates"]:
            try:
                sftp.mkdir(d)
            except IOError:
                pass

        # Upload all files
        for remote_name, content in upload_files.items():
            remote_path = f"/tmp/agent-bootstrap/{remote_name}"
            # Ensure parent dir exists for nested paths
            parent = "/tmp/agent-bootstrap/" + "/".join(remote_name.split("/")[:-1])
            if "/" in remote_name:
                try:
                    sftp.mkdir(parent)
                except IOError:
                    pass
            with sftp.open(remote_path, "w") as f:
                f.write(content)
            log.info(f"  Uploaded: {remote_name} ({len(content)} bytes)")

        sftp.close()

        # Execute bootstrap
        log.info("  Running bootstrap_agent.sh (this takes a few minutes)...")
        _, stdout, stderr = client.exec_command(
            "chmod +x /tmp/agent-bootstrap/bootstrap_agent.sh && "
            "sudo bash /tmp/agent-bootstrap/bootstrap_agent.sh 2>&1",
            timeout=900,  # 15 min max
        )
        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")

        if exit_code != 0:
            log.error(f"  Bootstrap failed (exit {exit_code})")
            for line in (err or output).strip().split("\n")[-15:]:
                log.error(f"    {line}")
            return None

        log.info("  Bootstrap completed successfully")
        # Print last lines
        for line in output.strip().split("\n")[-8:]:
            log.info(f"    {line}")

        # Parse agent public info from bootstrap output JSON
        agent_info = _parse_bootstrap_output(output)

        # Read the public info file if bootstrap wrote one
        if not agent_info:
            try:
                sftp2 = client.open_sftp()
                with sftp2.open("/tmp/agent-bootstrap/agent_public_info.json", "r") as f:
                    agent_info = json.loads(f.read())
                sftp2.close()
            except Exception:
                pass

        return agent_info

    finally:
        client.close()


def _parse_bootstrap_output(output: str) -> dict | None:
    """Parse the JSON public info block from bootstrap stdout."""
    # Bootstrap writes a JSON block between markers
    marker_start = "===AGENT_PUBLIC_INFO_START==="
    marker_end = "===AGENT_PUBLIC_INFO_END==="
    if marker_start in output and marker_end in output:
        json_str = output.split(marker_start)[1].split(marker_end)[0].strip()
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass
    return None


# =============================================================================
# File preparation
# =============================================================================

def prepare_upload_files(name, parent_npub, tier, brand, model, noscha_mgmt_token="", personality="professional", mission=""):
    """Prepare all files to upload to the VPS for bootstrap."""
    files = {}

    # Bootstrap script
    if BOOTSTRAP_SCRIPT.exists():
        files["bootstrap_agent.sh"] = BOOTSTRAP_SCRIPT.read_text()
    else:
        log.error(f"bootstrap_agent.sh not found at {BOOTSTRAP_SCRIPT}")
        sys.exit(1)

    # Config template
    if CONFIG_TEMPLATE.exists():
        files["config_template.json"] = CONFIG_TEMPLATE.read_text()

    # NIP-46 bunker script
    if NIP46_SCRIPT.exists():
        files["nip46-server.js"] = NIP46_SCRIPT.read_text()

    # Birth note sender script
    if BIRTH_NOTE_SCRIPT.exists():
        files["send_birth_note.js"] = BIRTH_NOTE_SCRIPT.read_text()

    # PPQ provisioning script + NWC payment
    if PPQ_PROVISION_SCRIPT.exists():
        files["ppq_provision.py"] = PPQ_PROVISION_SCRIPT.read_text()
    if NWC_PAY_SCRIPT.exists():
        files["nwc_pay.js"] = NWC_PAY_SCRIPT.read_text()

    # Workspace templates
    for tmpl in sorted(TEMPLATES_DIR.glob("*.md")):
        files[f"templates/{tmpl.name}"] = tmpl.read_text()

    # Input parameters for bootstrap (plain text files — no secrets except PayPerQ key)
    files["agent_name.txt"] = name
    files["parent_npub.txt"] = parent_npub
    files["brand.txt"] = brand
    files["tier.txt"] = tier
    files["default_model.txt"] = model
    files["personality.txt"] = personality
    files["mission.txt"] = mission

    # PayPerQ key — the ONLY secret that crosses
    payperq_key = os.getenv("PAYPERQ_API_KEY", "")
    if payperq_key:
        files["payperq_key.txt"] = payperq_key
    else:
        log.warning("  PAYPERQ_API_KEY not set — agent will have no LLM access")
        files["payperq_key.txt"] = ""

    # noscha.io management token — from registration or env override
    token = noscha_mgmt_token or os.getenv("NOSCHA_MGMT_TOKEN", "")
    if token:
        files["noscha_mgmt_token.txt"] = token

    return files


# =============================================================================
# Main orchestrator
# =============================================================================

def create_vm(args) -> dict:
    name = args.name.lower().strip()
    parent_npub = args.parent_npub
    tier = args.tier
    brand = args.brand
    dry_run = args.dry_run
    tier_info = TIERS[tier]
    now = datetime.now(timezone.utc)

    log.info("=" * 64)
    log.info(f"  VM PROVISIONING{' [DRY RUN]' if dry_run else ''}")
    log.info("=" * 64)
    log.info(f"  Agent name:  {name}")
    log.info(f"  Tier:        {tier} (VM: {tier_info['vm_class']})")
    log.info(f"  Parent:      {parent_npub}")
    log.info(f"  Brand:       {brand}")
    log.info("=" * 64)

    # ── 1. Temporary service keypair (for LNVPS auth only) ───────
    log.info("\n[1/11] Generating temporary service Nostr keypair...")
    service_key = generate_temp_nostr_keypair()
    service_npub = bech32_encode("npub", bytes.fromhex(service_key["public_key_hex"]))
    log.info(f"  Service npub: {service_npub[:30]}... (temporary, discarded after)")

    # ── 2. Temporary SSH keypair (in memory only) ────────────────
    log.info("\n[2/11] Generating temporary SSH keypair...")
    ssh = generate_ssh_keypair()
    log.info(f"  Public key: {ssh['public_key_openssh'][:50]}... (in memory, never written to disk)")

    # ── 3. Fetch LNVPS templates + images ────────────────────────
    log.info("\n[3/11] Fetching LNVPS catalog...")
    templates = lnvps_fetch_templates(dry_run)
    image_id = lnvps_fetch_images(dry_run)
    if image_id is None and not dry_run:
        log.error("No Ubuntu image found on LNVPS")
        sys.exit(1)
    vm_class = tier_info["vm_class"]
    template_id = templates.get(vm_class, {}).get("template_id", 3)
    log.info(f"  Template: {templates.get(vm_class, {}).get('label', vm_class)} (id={template_id})")
    log.info(f"  Image: Ubuntu (id={image_id})")

    # ── 4. Upload SSH key to LNVPS ───────────────────────────────
    log.info("\n[4/11] Uploading temporary SSH key to LNVPS...")
    ssh_key_name = f"provision-{name}-{int(time.time())}"
    ssh_key_id = lnvps_upload_ssh_key(
        service_key["private_key_hex"], ssh_key_name,
        ssh["public_key_openssh"], dry_run,
    )
    if ssh_key_id is None and not dry_run:
        log.error("Failed to upload SSH key")
        sys.exit(1)

    # ── 5. Create VM ─────────────────────────────────────────────
    log.info("\n[5/11] Creating VM on LNVPS...")
    vm = lnvps_create_vm(
        service_key["private_key_hex"], template_id,
        image_id or 1, ssh_key_id or 1, dry_run,
    )
    if vm.get("bolt11"):
        log.info(f"\n  ⚡ LIGHTNING INVOICE — pay to provision VM:")
        log.info(f"  {vm['bolt11']}")

    # ── 6. Wait for VM ───────────────────────────────────────────
    log.info("\n[6/11] Waiting for VM to boot...")
    vm_info = lnvps_wait_for_vm(service_key["private_key_hex"], vm["vm_id"], dry_run)
    vps_ip = vm_info["ip"]
    log.info(f"  VM IP: {vps_ip}")

    # ── 7. Register noscha.io identity ───────────────────────────
    # Now that we have the VM IP, register noscha.io with the real IP.
    # The pubkey is a placeholder (service key) — bootstrap will update it
    # via management_token once the agent generates its real Nostr keypair.
    log.info("\n[7/11] Registering noscha.io identity...")
    noscha_result = noscha_register(
        username=name,
        plan="30d",
        pubkey_hex=service_key["public_key_hex"],  # placeholder — agent updates later
        target_ip=vps_ip,
        dry_run=dry_run,
    )
    noscha_mgmt_token = ""
    noscha_bolt11 = ""
    if noscha_result.get("error"):
        log.warning(f"  noscha.io registration issue: {noscha_result['error']}")
        log.warning(f"  Agent will boot without NIP-05/subdomain — can register manually later")
    else:
        noscha_mgmt_token = noscha_result.get("management_token", "")
        noscha_bolt11 = noscha_result.get("bolt11", "")
        log.info(f"  NIP-05: {name}@noscha.io")
        log.info(f"  Subdomain: {name}.noscha.io → {vps_ip}")
        if noscha_mgmt_token:
            log.info(f"  Management token: {'yes' if noscha_mgmt_token else 'no'}")

    # ── 8. Prepare and upload files ──────────────────────────────
    log.info("\n[8/11] Preparing bootstrap files...")
    upload_files = prepare_upload_files(
        name, parent_npub, tier, brand, tier_info["model"],
        noscha_mgmt_token=noscha_mgmt_token,
        personality=getattr(args, "personality", "professional"),
        mission=getattr(args, "mission", ""),
    )
    log.info(f"  {len(upload_files)} files prepared")

    # ── 9. SSH bootstrap ─────────────────────────────────────────
    log.info("\n[9/11] Running bootstrap on VPS (agent generates its own identity)...")
    agent_info = ssh_bootstrap(vps_ip, ssh["private_key_pem"], upload_files, dry_run)

    if agent_info is None and not dry_run:
        log.error("Bootstrap failed — VM is running but agent may not be configured")
        log.error(f"  SSH manually: ssh root@{vps_ip}")
        agent_info = {}

    # ── 10. Cleanup: delete SSH key from LNVPS ───────────────────
    log.info("\n[10/11] Cleaning up temporary credentials...")
    lnvps_delete_ssh_key(service_key["private_key_hex"], ssh_key_id, dry_run)
    # Discard service keypair (just let it go out of scope)
    service_key_npub = service_npub  # save for logging
    del service_key
    log.info("  Service Nostr keypair discarded")
    log.info("  SSH keypair discarded (was never written to disk)")

    # ── 11. Summary ──────────────────────────────────────────────
    log.info("\n[11/11] Done!")

    agent_npub = agent_info.get("npub", "unknown")
    btc_address = agent_info.get("btc_address", "unknown")
    eth_address = agent_info.get("eth_address", "unknown")
    nip05 = agent_info.get("nip05", f"{name}@noscha.io")

    log.info("")
    log.info("=" * 64)
    log.info("  PROVISIONING COMPLETE")
    log.info("=" * 64)
    log.info(f"  Name:       {name}")
    log.info(f"  VPS IP:     {vps_ip}")
    log.info(f"  VM ID:      {vm.get('vm_id', '?')}")
    log.info(f"")
    log.info(f"  Agent npub: {agent_npub}")
    log.info(f"  NIP-05:     {nip05}")
    log.info(f"  Webchat:    http://{vps_ip}:3000")
    log.info(f"  BTC:        {btc_address}")
    log.info(f"  ETH:        {eth_address}")
    log.info(f"")
    log.info(f"  ⚠️  Agent secrets exist ONLY on the VPS at /opt/agent-keys/")
    log.info(f"      This machine has NO access to agent private keys.")
    invoices = []
    if vm.get("bolt11"):
        invoices.append(("LNVPS VM", vm["bolt11"]))
    if noscha_bolt11:
        invoices.append(("noscha.io identity", noscha_bolt11))
    if invoices:
        log.info("")
        log.info("  ⚡ LIGHTNING INVOICES:")
        for label, inv in invoices:
            log.info(f"    [{label}] {inv}")
    log.info("=" * 64)

    summary = {
        "name": name,
        "tier": tier,
        "brand": brand,
        "date": now.strftime("%Y-%m-%d"),
        "dry_run": dry_run,
        "provider": "lnvps",
        "vps_ip": vps_ip,
        "vm_id": vm.get("vm_id", ""),
        "vm_bolt11": vm.get("bolt11", ""),
        "noscha_bolt11": noscha_bolt11,
        "noscha_order_id": noscha_result.get("order_id", ""),
        "noscha_registered": not bool(noscha_result.get("error")),
        "agent_npub": agent_npub,
        "agent_nip05": nip05,
        "agent_btc_address": btc_address,
        "agent_eth_address": eth_address,
        "webchat_url": f"http://{vps_ip}:3000",
        "parent_npub": parent_npub,
        "bootstrap_success": agent_info is not None and bool(agent_info),
        "health_ok": agent_info.get("health_ok", False) if agent_info else False,
        "birth_note_sent": agent_info.get("birth_note_sent", False) if agent_info else False,
    }

    summary_path = SCRIPT_DIR / f"vm_{name}_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    log.info(f"  Summary: {summary_path}")

    return summary


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Create a VPS and bootstrap an autonomous AI agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 create_vm.py --name myagent --parent-npub npub1abc... --dry-run
  python3 create_vm.py --name myagent --parent-npub npub1abc... --tier evolve
  python3 create_vm.py --name myagent --parent-npub npub1abc... --tier trial --brand nullroute

Environment:
  PAYPERQ_API_KEY         LLM API key (only secret sent to VPS)
  WEBHOOK_RECEIVER_URL    Custom webhook URL (default: webhook.site)
  NOSCHA_MGMT_TOKEN       Pre-paid noscha.io token (skips registration)
""",
    )
    parser.add_argument("--name", required=True, help="Agent name (3-30 chars, alphanumeric + hyphens)")
    parser.add_argument("--parent-npub", required=True, help="Parent's Nostr npub")
    parser.add_argument("--tier", default="seed", choices=list(TIERS.keys()))
    parser.add_argument("--brand", default="descendant", choices=["descendant", "spawnling", "deadrop"])
    parser.add_argument("--personality", default="professional", help="Agent personality style")
    parser.add_argument("--mission", default="", help="Agent's first mission / purpose")
    parser.add_argument("--region", default="", help="Preferred region (if LNVPS supports)")
    parser.add_argument("--dry-run", action="store_true", help="Generate plan, skip API calls")
    args = parser.parse_args()

    n = args.name.lower().strip()
    if not n.replace("-", "").replace("_", "").isalnum() or len(n) < 3 or len(n) > 30:
        sys.exit("ERROR: Name must be 3-30 alphanumeric characters (hyphens/underscores ok)")
    if not args.parent_npub.startswith("npub1"):
        sys.exit("ERROR: Parent npub must start with 'npub1'")

    create_vm(args)


if __name__ == "__main__":
    main()
