#!/usr/bin/env python3
"""
renew_vm.py — Renew an LNVPS VM by fetching its Lightning renewal invoice.

Usage:
    python3 renew_vm.py --vm-id 1175
    python3 renew_vm.py --vm-id 1175 --status   # just check status, no renew

Generates a temporary Nostr keypair for NIP-98 auth (same as create_vm.py),
hits the LNVPS API, and prints the bolt11 invoice for manual payment.
"""

import argparse
import base64
import hashlib
import json
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


def nip98_auth_header(privkey_hex: str, url: str, method: str) -> str:
    tags = [["u", url], ["method", method.upper()]]
    event = {"kind": 27235, "created_at": int(time.time()), "tags": tags, "content": ""}
    signed = nostr_sign_event(privkey_hex, event)
    encoded = base64.b64encode(json.dumps(signed, separators=(",", ":")).encode()).decode()
    return f"Nostr {encoded}"


def lnvps_get(path: str, privkey_hex: str):
    url = f"{LNVPS_API}{path}"
    headers = {"Authorization": nip98_auth_header(privkey_hex, url, "GET")}
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code >= 400:
        print(f"ERROR: HTTP {resp.status_code}: {resp.text[:500]}")
        sys.exit(1)
    return resp.json()


def main():
    parser = argparse.ArgumentParser(description="Renew an LNVPS VM")
    parser.add_argument("--vm-id", required=True, type=int, help="LNVPS VM ID (e.g. 1175)")
    parser.add_argument("--status", action="store_true", help="Just check VM status, don't fetch renewal invoice")
    args = parser.parse_args()

    # Generate temporary keypair for NIP-98 auth
    privkey = PrivateKey(secrets.token_bytes(32))
    privkey_hex = privkey.secret.hex()

    # Check VM status
    print(f"Checking VM {args.vm_id} status...")
    vm_data = lnvps_get(f"/api/v1/vm/{args.vm_id}", privkey_hex)

    # Parse response (LNVPS nests data differently sometimes)
    inner = vm_data.get("data", vm_data) if isinstance(vm_data, dict) else vm_data
    if isinstance(inner, dict) and "data" in inner:
        inner = inner["data"]

    status = inner.get("status", {})
    state = status.get("state", "unknown") if isinstance(status, dict) else str(status)
    expires = inner.get("expires_at", "unknown")
    ip_list = inner.get("ip_assignments", [])
    ip = ip_list[0].get("ip", "").split("/")[0] if ip_list else "no IP"

    print(f"  State:   {state}")
    print(f"  IP:      {ip}")
    print(f"  Expires: {expires}")

    if args.status:
        return

    # Fetch renewal invoice
    print(f"\nFetching renewal invoice...")
    renew_data = lnvps_get(f"/api/v1/vm/{args.vm_id}/renew?method=lightning", privkey_hex)

    # Parse invoice from response
    renew_inner = renew_data.get("data", renew_data) if isinstance(renew_data, dict) else renew_data
    if isinstance(renew_inner, dict) and "data" in renew_inner:
        renew_inner = renew_inner["data"]

    bolt11 = ""
    if isinstance(renew_inner, dict):
        bolt11 = renew_inner.get("lightning", "") or renew_inner.get("invoice", "") or renew_inner.get("bolt11", "")

    if bolt11:
        print(f"\n{'='*60}")
        print(f"LIGHTNING INVOICE FOR VM {args.vm_id} RENEWAL")
        print(f"{'='*60}")
        print(f"\n{bolt11}\n")
        print(f"{'='*60}")
        print("Pay this invoice with any Lightning wallet to renew the VM.")
    else:
        print(f"\nCould not extract bolt11 from response:")
        print(json.dumps(renew_data, indent=2))


if __name__ == "__main__":
    main()
