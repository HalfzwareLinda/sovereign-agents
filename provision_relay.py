#!/usr/bin/env python3
"""
provision_relay.py — Provision a lightweight LNVPS for the Codedeck relay.

Creates a Tiny VPS on LNVPS, saves the service keypair (so we can renew later),
and outputs SSH credentials for bootstrapping strfry + Caddy + blossom-server.

Usage:
    python3 provision_relay.py                    # create VM, print Lightning invoice
    python3 provision_relay.py --poll             # poll for VM to come online after payment
    python3 provision_relay.py --status           # check saved VM status
    python3 provision_relay.py --renew            # get renewal invoice for existing VM

State is saved to relay_state.json (keypair + VM ID) for future renewals.
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import time

try:
    import requests
except ImportError:
    sys.exit("ERROR: requests not installed. Run: pip install requests")

try:
    from coincurve import PrivateKey
except ImportError:
    sys.exit("ERROR: coincurve not installed. Run: pip install coincurve")

LNVPS_API = "https://api.lnvps.net"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(SCRIPT_DIR, "relay_state.json")


# =============================================================================
# Crypto helpers (same as create_vm.py)
# =============================================================================

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def nostr_sign_event(privkey_hex: str, event: dict) -> dict:
    privkey = PrivateKey(bytes.fromhex(privkey_hex))
    pubkey_hex = privkey.public_key.format(compressed=True)[1:].hex()
    event["pubkey"] = pubkey_hex
    serialized = json.dumps(
        [0, pubkey_hex, event["created_at"], event["kind"], event["tags"], event["content"]],
        separators=(",", ":"), ensure_ascii=False,
    )
    event["id"] = _sha256(serialized.encode()).hex()
    event["sig"] = privkey.sign_schnorr(bytes.fromhex(event["id"])).hex()
    return event


def nip98_auth_header(privkey_hex: str, url: str, method: str, body: bytes = None) -> str:
    tags = [["u", url], ["method", method.upper()]]
    if body:
        tags.append(["payload", _sha256(body).hex()])
    event = {"kind": 27235, "created_at": int(time.time()), "tags": tags, "content": ""}
    signed = nostr_sign_event(privkey_hex, event)
    encoded = base64.b64encode(json.dumps(signed, separators=(",", ":")).encode()).decode()
    return f"Nostr {encoded}"


# =============================================================================
# LNVPS API
# =============================================================================

def lnvps_request(method, path, privkey_hex, json_body=None):
    url = f"{LNVPS_API}{path}"
    body_bytes = json.dumps(json_body).encode() if json_body else None
    headers = {
        "Authorization": nip98_auth_header(privkey_hex, url, method, body_bytes),
        "Content-Type": "application/json",
    }
    resp = requests.request(method, url, headers=headers, data=body_bytes, timeout=30)
    if resp.status_code >= 400:
        print(f"ERROR: {method} {path} → HTTP {resp.status_code}: {resp.text[:500]}")
        sys.exit(1)
    try:
        return resp.json()
    except ValueError:
        return {}


def unwrap(data):
    """Unwrap LNVPS nested response."""
    if isinstance(data, dict):
        inner = data.get("data", data)
        if isinstance(inner, dict) and "data" in inner:
            return inner["data"]
        return inner
    return data


# =============================================================================
# SSH key generation
# =============================================================================

def generate_ssh_keypair():
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
    return {"private_pem": private_pem, "public_openssh": public_openssh}


# =============================================================================
# State management
# =============================================================================

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return None


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    os.chmod(STATE_FILE, 0o600)
    print(f"State saved to {STATE_FILE}")


# =============================================================================
# Commands
# =============================================================================

def cmd_create(args):
    """Create a new Tiny VPS and print Lightning invoice."""
    existing = load_state()
    if existing and existing.get("vm_id"):
        print(f"WARNING: relay_state.json already has VM {existing['vm_id']} (IP: {existing.get('ip', '?')})")
        print("Use --renew to renew, --status to check, or delete relay_state.json to start fresh.")
        sys.exit(1)

    print("=== Provisioning Codedeck Relay VPS ===\n")

    # 1. Generate service keypair (saved for future renewals)
    print("1. Generating service Nostr keypair...")
    privkey = PrivateKey(secrets.token_bytes(32))
    privkey_hex = privkey.secret.hex()
    pubkey_hex = privkey.public_key.format(compressed=True)[1:].hex()
    print(f"   Pubkey: {pubkey_hex[:16]}...")

    # 2. Generate SSH keypair
    print("2. Generating SSH keypair...")
    ssh = generate_ssh_keypair()

    # 3. Fetch templates
    print("3. Fetching LNVPS templates...")
    templates_data = lnvps_request("GET", "/api/v1/vm/templates", privkey_hex)
    templates = unwrap(templates_data)
    if isinstance(templates, dict):
        templates = templates.get("templates", [])

    # Find tiny template
    template_id = None
    for tmpl in templates:
        name = (tmpl.get("name") or "").lower()
        if "tiny" in name:
            template_id = tmpl["id"]
            print(f"   Found: {tmpl.get('name')} (id={template_id})")
            break
    if not template_id:
        print(f"   Available templates:")
        for tmpl in templates:
            print(f"     - {tmpl.get('name', '?')} (id={tmpl.get('id', '?')})")
        sys.exit(1)

    # 4. Fetch images
    print("4. Fetching OS images...")
    images_data = lnvps_request("GET", "/api/v1/image", privkey_hex)
    images = unwrap(images_data)
    if isinstance(images, dict):
        images = images.get("images", [])

    image_id = None
    for img in images:
        dist = (img.get("distribution") or img.get("name") or "").lower()
        ver = img.get("version") or ""
        if "ubuntu" in dist and ver == "24.04":
            image_id = img["id"]
            print(f"   Found: Ubuntu {ver} (id={image_id})")
            break
    if not image_id and images:
        image_id = images[0]["id"]
        print(f"   Fallback: {images[0].get('distribution', '?')} (id={image_id})")

    # 5. Upload SSH key
    print("5. Uploading SSH key to LNVPS...")
    key_data = lnvps_request("POST", "/api/v1/ssh-key", privkey_hex,
                              json_body={"name": "codedeck-relay", "key_data": ssh["public_openssh"]})
    ssh_key_id = unwrap(key_data).get("id") if isinstance(unwrap(key_data), dict) else key_data.get("id")
    print(f"   SSH key id: {ssh_key_id}")

    # 6. Create VM
    print("6. Creating VM...")
    vm_data = lnvps_request("POST", "/api/v1/vm", privkey_hex,
                             json_body={"template_id": template_id, "image_id": image_id, "ssh_key_id": ssh_key_id})
    vm_id = unwrap(vm_data).get("id") if isinstance(unwrap(vm_data), dict) else None
    print(f"   VM ID: {vm_id}")

    # 7. Get payment invoice
    print("7. Fetching Lightning invoice...")
    renew_data = lnvps_request("GET", f"/api/v1/vm/{vm_id}/renew?method=lightning", privkey_hex)
    renew_inner = unwrap(renew_data)
    bolt11 = ""
    if isinstance(renew_inner, dict):
        bolt11 = (renew_inner.get("lightning", "") or renew_inner.get("invoice", "")
                  or renew_inner.get("bolt11", ""))

    # Save state (keypair + VM ID + SSH key) for renewals and polling
    state = {
        "service_privkey_hex": privkey_hex,
        "service_pubkey_hex": pubkey_hex,
        "vm_id": vm_id,
        "ssh_key_id": ssh_key_id,
        "ssh_private_pem": ssh["private_pem"],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    save_state(state)

    print(f"\n{'='*60}")
    if bolt11:
        print(f"LIGHTNING INVOICE FOR VM {vm_id}")
        print(f"{'='*60}")
        print(f"\n{bolt11}\n")
    else:
        print(f"VM {vm_id} created — could not extract invoice from:")
        print(json.dumps(renew_data, indent=2))

    print(f"{'='*60}")
    print(f"Pay the invoice, then run:  python3 provision_relay.py --poll")
    print(f"State saved to relay_state.json (contains service keypair for renewals)")


def cmd_poll(args):
    """Poll for VM to come online after payment."""
    state = load_state()
    if not state or not state.get("vm_id"):
        print("No VM in relay_state.json. Run without flags to create one first.")
        sys.exit(1)

    privkey_hex = state["service_privkey_hex"]
    vm_id = state["vm_id"]
    print(f"Polling VM {vm_id}...")

    for attempt in range(1, 61):
        data = lnvps_request("GET", f"/api/v1/vm/{vm_id}", privkey_hex)
        inner = unwrap(data)
        status_obj = inner.get("status", {}) if isinstance(inner, dict) else {}
        vm_state = status_obj.get("state", "") if isinstance(status_obj, dict) else str(status_obj)
        ip_list = inner.get("ip_assignments", []) if isinstance(inner, dict) else []
        ip = ip_list[0].get("ip", "").split("/")[0] if ip_list else ""

        if vm_state == "running" and ip:
            print(f"\nVM {vm_id} is RUNNING at {ip}")
            state["ip"] = ip
            state["status"] = "running"
            save_state(state)

            # Write SSH key to temp file for easy access
            ssh_pem_file = os.path.join(SCRIPT_DIR, "relay_ssh.pem")
            with open(ssh_pem_file, "w") as f:
                f.write(state["ssh_private_pem"])
            os.chmod(ssh_pem_file, 0o600)
            print(f"SSH key written to {ssh_pem_file}")
            print(f"\nConnect with:")
            print(f"  ssh -i relay_ssh.pem ubuntu@{ip}")
            return

        if attempt % 3 == 0:
            print(f"  Waiting... state={vm_state}, ip={ip or 'none'} (attempt {attempt})")
        time.sleep(10)

    print("VM did not come online within 10 minutes.")
    sys.exit(1)


def cmd_status(args):
    """Check saved VM status."""
    state = load_state()
    if not state or not state.get("vm_id"):
        print("No VM in relay_state.json.")
        sys.exit(1)

    data = lnvps_request("GET", f"/api/v1/vm/{state['vm_id']}", state["service_privkey_hex"])
    inner = unwrap(data)
    status_obj = inner.get("status", {}) if isinstance(inner, dict) else {}
    vm_state = status_obj.get("state", "unknown") if isinstance(status_obj, dict) else str(status_obj)
    expires = inner.get("expires_at", "unknown") if isinstance(inner, dict) else "unknown"
    ip_list = inner.get("ip_assignments", []) if isinstance(inner, dict) else []
    ip = ip_list[0].get("ip", "").split("/")[0] if ip_list else state.get("ip", "?")

    print(f"VM {state['vm_id']}:")
    print(f"  State:   {vm_state}")
    print(f"  IP:      {ip}")
    print(f"  Expires: {expires}")
    print(f"  Created: {state.get('created_at', '?')}")


def cmd_renew(args):
    """Get renewal invoice for existing VM."""
    state = load_state()
    if not state or not state.get("vm_id"):
        print("No VM in relay_state.json.")
        sys.exit(1)

    vm_id = state["vm_id"]
    privkey_hex = state["service_privkey_hex"]

    print(f"Fetching renewal invoice for VM {vm_id}...")
    renew_data = lnvps_request("GET", f"/api/v1/vm/{vm_id}/renew?method=lightning", privkey_hex)
    renew_inner = unwrap(renew_data)
    bolt11 = ""
    if isinstance(renew_inner, dict):
        bolt11 = (renew_inner.get("lightning", "") or renew_inner.get("invoice", "")
                  or renew_inner.get("bolt11", ""))

    if bolt11:
        print(f"\n{'='*60}")
        print(f"LIGHTNING INVOICE FOR VM {vm_id} RENEWAL")
        print(f"{'='*60}")
        print(f"\n{bolt11}\n")
        print(f"{'='*60}")
    else:
        print(f"Could not extract bolt11 from response:")
        print(json.dumps(renew_data, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Provision/manage Codedeck relay VPS")
    parser.add_argument("--poll", action="store_true", help="Poll for VM to come online after payment")
    parser.add_argument("--status", action="store_true", help="Check VM status")
    parser.add_argument("--renew", action="store_true", help="Get renewal invoice")
    args = parser.parse_args()

    if args.poll:
        cmd_poll(args)
    elif args.status:
        cmd_status(args)
    elif args.renew:
        cmd_renew(args)
    else:
        cmd_create(args)


if __name__ == "__main__":
    main()
