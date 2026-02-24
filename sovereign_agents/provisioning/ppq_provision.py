#!/usr/bin/env python3
"""
ppq_provision.py — PayPerQ (PPQ.ai) Account Provisioning

Creates a PPQ account, generates a Lightning invoice for funding,
polls for payment, and saves credentials.

Usage:
    python3 ppq_provision.py --amount 5000 --currency SATS --output /tmp/ppq_credentials.json
    python3 ppq_provision.py --amount 5000 --currency SATS --nwc "nostr+walletconnect://..." --output creds.json
    python3 ppq_provision.py --check-balance --credentials /tmp/ppq_credentials.json
    python3 ppq_provision.py --dry-run --output /tmp/ppq_credentials.json
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("ERROR: requests not installed. Run: pip install requests")

PPQ_API = "https://api.ppq.ai"


def ppq_create_account(max_retries: int = 3, retry_delay: int = 10):
    """Create a new PPQ account. No auth needed.

    Retries up to max_retries times with retry_delay seconds between attempts.
    Returns {"api_key": "sk-...", "credit_id": "...", "balance": 0}
    Raises RuntimeError if all attempts fail.
    """
    last_error: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(f"{PPQ_API}/accounts/create", timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if not data.get("success") and not data.get("api_key"):
                raise RuntimeError(f"Account creation failed: {data}")
            return {
                "api_key": data["api_key"],
                "credit_id": data["credit_id"],
                "balance": data.get("balance", 0),
            }
        except Exception as exc:
            last_error = exc
            if attempt < max_retries:
                print(
                    f"  Attempt {attempt}/{max_retries} failed: {exc} "
                    f"— retrying in {retry_delay}s...",
                    file=sys.stderr,
                )
                time.sleep(retry_delay)
            else:
                print(
                    f"  All {max_retries} attempts failed: {exc}",
                    file=sys.stderr,
                )
    raise RuntimeError(
        f"PPQ account creation failed after {max_retries} attempts: {last_error}"
    )


def ppq_create_invoice(api_key, amount, currency="SATS"):
    """Create a Lightning invoice for funding.

    Returns {"invoice_id": "...", "lightning_invoice": "lnbc...",
             "checkout_url": "...", "expires_at": unix_ts}
    """
    resp = requests.post(
        f"{PPQ_API}/topup/create/btc-lightning",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"amount": amount, "currency": currency},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def ppq_poll_payment(api_key, invoice_id, expires_at=None, timeout_sec=900):
    """Poll invoice status until paid or expired.

    Returns final status dict.
    """
    deadline = expires_at or (time.time() + timeout_sec)
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            resp = requests.get(
                f"{PPQ_API}/topup/status/{invoice_id}",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status", "")
                if status.lower() not in ("new", "pending", ""):
                    return data
                # Progress indicator
                elapsed = int(time.time() - (deadline - timeout_sec)) if expires_at else attempt * 3
                remaining = max(0, int(deadline - time.time()))
                dots = "." * (attempt % 4)
                print(f"\r  Waiting for payment{dots:<4} ({remaining}s remaining)", end="", flush=True)
        except requests.RequestException:
            pass
        time.sleep(3)

    print()
    return {"status": "expired", "invoice_id": invoice_id}


def ppq_check_balance(credit_id):
    """Check account balance. No auth token needed, just credit_id.

    Returns response dict with balance info.
    """
    resp = requests.post(
        f"{PPQ_API}/credits/balance",
        json={"credit_id": credit_id},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def nwc_pay_invoice(nwc_string, bolt11):
    """Pay a Lightning invoice via NWC using nwc_pay.js.

    Returns {"success": True, "preimage": "..."} or {"success": False, "error": "..."}
    """
    script_dir = Path(__file__).parent.resolve()
    nwc_script = script_dir / "nwc_pay.js"

    if not nwc_script.exists():
        return {"success": False, "error": f"nwc_pay.js not found at {nwc_script}"}

    node_path = os.environ.get("NODE_PATH", "/opt/agent-ndk/node_modules")
    env = {**os.environ, "NODE_PATH": node_path}

    try:
        result = subprocess.run(
            ["node", str(nwc_script), nwc_string, bolt11],
            capture_output=True, text=True, timeout=90, env=env,
        )
        if result.stdout.strip():
            return json.loads(result.stdout.strip())
        return {
            "success": False,
            "error": result.stderr.strip() or f"nwc_pay.js exited with code {result.returncode}",
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "NWC payment timed out (90s)"}
    except json.JSONDecodeError:
        return {"success": False, "error": f"Invalid JSON from nwc_pay.js: {result.stdout[:200]}"}
    except FileNotFoundError:
        return {"success": False, "error": "node not found — is Node.js installed?"}


def cmd_provision(args):
    """Main provisioning flow: create account → invoice → pay → save."""
    output_path = Path(args.output)
    now = datetime.now(timezone.utc)
    nwc_string = getattr(args, "nwc", "") or ""

    # Step 1: Create account (retries 3x with 10s backoff)
    print("[1/4] Creating PPQ account...")
    try:
        account = ppq_create_account()
    except RuntimeError as exc:
        # Non-fatal when create-only / dry-run: agent starts without LLM credits,
        # can be topped up later via the provisioning system.
        if args.dry_run or args.create_only:
            print(f"  WARNING: PPQ account creation failed — {exc}", file=sys.stderr)
            print("  Agent will start without LLM credits. Top up later.", file=sys.stderr)
            result = {
                "api_key": "",
                "credit_id": "",
                "base_url": PPQ_API,
                "created_at": now.isoformat(),
                "status": "provisioning_failed",
                "error": str(exc),
            }
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(result, indent=2))
            print(f"  Placeholder credentials saved: {output_path}")
            return result
        raise
    print(f"  API key:   {account['api_key']}")
    print(f"  Credit ID: {account['credit_id']}")

    result = {
        "api_key": account["api_key"],
        "credit_id": account["credit_id"],
        "base_url": PPQ_API,
        "created_at": now.isoformat(),
        "initial_funding": None,
        "balance": account["balance"],
    }

    if args.dry_run or args.create_only:
        print("\n  Account created (no funding). API key ready for use.")
        result["initial_funding"] = {"status": "skipped"}
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2))
        print(f"\n  Credentials saved: {output_path}")
        return result

    # Step 2: Create Lightning invoice
    amount = args.amount
    currency = args.currency.upper()
    print(f"\n[2/4] Creating Lightning invoice ({amount} {currency})...")
    invoice_data = ppq_create_invoice(account["api_key"], amount, currency)

    invoice_id = invoice_data.get("invoice_id", "")
    bolt11 = invoice_data.get("lightning_invoice", "")
    checkout_url = invoice_data.get("checkout_url", "")
    expires_at = invoice_data.get("expires_at", time.time() + 900)

    print()
    print("  " + "=" * 60)
    print("  ⚡ LIGHTNING INVOICE — PAY TO FUND AGENT LLM ACCESS")
    print("  " + "=" * 60)
    if bolt11:
        print(f"  {bolt11}")
    if checkout_url:
        print(f"\n  Or pay via: {checkout_url}")
    print("  " + "=" * 60)
    print()

    # Step 3: Pay or wait for payment
    if nwc_string and bolt11:
        print("[3/4] Paying invoice via NWC (Nostr Wallet Connect)...")
        pay_result = nwc_pay_invoice(nwc_string, bolt11)
        if pay_result.get("success"):
            print(f"  ✓ Payment sent (preimage: {pay_result.get('preimage', '?')[:16]}...)")
            # Brief poll to let PPQ register the payment
            print("  Confirming with PPQ...")
            time.sleep(3)
            status_data = ppq_poll_payment(account["api_key"], invoice_id, expires_at, timeout_sec=60)
            print()
        else:
            print(f"  ✗ NWC payment failed: {pay_result.get('error', 'unknown')}")
            print("  Falling back to manual payment — pay the invoice above")
            status_data = ppq_poll_payment(account["api_key"], invoice_id, expires_at)
            print()
    else:
        print("[3/4] Waiting for payment...")
        status_data = ppq_poll_payment(account["api_key"], invoice_id, expires_at)
        print()

    payment_status = status_data.get("status", "unknown")
    if payment_status.lower() in ("expired", "cancelled"):
        print(f"  ✗ Invoice {payment_status}. Account created but unfunded.")
        result["initial_funding"] = {
            "amount": amount,
            "currency": currency,
            "invoice_id": invoice_id,
            "status": payment_status,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2))
        print(f"\n  Credentials saved: {output_path}")
        print("  Re-run without --dry-run to create a new invoice.")
        return result

    print(f"  ✓ Payment confirmed ({payment_status})")

    # Step 4: Verify balance
    print("\n[4/4] Verifying balance...")
    try:
        balance_data = ppq_check_balance(account["credit_id"])
        balance = balance_data.get("balance", balance_data.get("credits", 0))
        print(f"  Balance: ${balance}")
    except Exception as exc:
        print(f"  Balance check failed: {exc}")
        balance = None

    result["initial_funding"] = {
        "amount": amount,
        "currency": currency,
        "invoice_id": invoice_id,
        "status": payment_status,
    }
    if balance is not None:
        result["balance"] = balance

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2))

    print()
    print("  " + "=" * 60)
    print("  PPQ ACCOUNT READY")
    print("  " + "=" * 60)
    print(f"  API key:   {account['api_key']}")
    print(f"  Base URL:  {PPQ_API}")
    print(f"  Balance:   ${balance}")
    print(f"  Saved:     {output_path}")
    print("  " + "=" * 60)

    return result


def cmd_check_balance(args):
    """Check balance of existing credentials file."""
    cred_path = Path(args.credentials)
    if not cred_path.exists():
        sys.exit(f"ERROR: Credentials file not found: {cred_path}")

    creds = json.loads(cred_path.read_text())
    credit_id = creds.get("credit_id", "")
    if not credit_id:
        sys.exit("ERROR: No credit_id in credentials file")

    print(f"Checking balance for {credit_id[:12]}...")
    data = ppq_check_balance(credit_id)
    balance = data.get("balance", data.get("credits", "unknown"))
    print(f"  Balance: ${balance}")
    print(f"  Raw: {json.dumps(data, indent=2)}")
    return data


def main():
    parser = argparse.ArgumentParser(
        description="PPQ.ai account provisioning and funding",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--amount", type=float, default=5000, help="Funding amount (default: 5000)")
    parser.add_argument("--currency", default="SATS", choices=["SATS", "USD"], help="Currency (default: SATS)")
    parser.add_argument("--output", default="/opt/agent-keys/ppq_credentials.json", help="Output credentials file")
    parser.add_argument("--nwc", default="", help="NWC connection string for automatic Lightning payment")
    parser.add_argument("--create-only", action="store_true", help="Create account and save credentials, skip funding")
    parser.add_argument("--dry-run", action="store_true", help="Alias for --create-only")
    parser.add_argument("--check-balance", action="store_true", help="Check balance of existing credentials")
    parser.add_argument("--credentials", default="", help="Path to existing credentials (for --check-balance)")
    args = parser.parse_args()

    if args.check_balance:
        if not args.credentials:
            args.credentials = args.output
        cmd_check_balance(args)
    else:
        cmd_provision(args)


if __name__ == "__main__":
    main()
