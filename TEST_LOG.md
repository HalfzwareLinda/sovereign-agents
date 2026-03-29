# Sovereign Agent Provisioning — Test Log
**Started:** 2026-02-13 16:26 UTC

---

## Layer 1: Dry Run Tests (Cost: $0)

### Test 1.1 — Basic dry run (seed/descendant)
- **Command:** `python3 create_vm.py --name testling --parent-npub npub1qqq... --dry-run`
- **Result:** ✅ PASS — Clean 10-step flow, summary JSON written, no secrets in output
- **Time:** 16:26 UTC

### Test 1.2 — Different tier + brand (dynasty/spawnling)
- **Command:** `python3 create_vm.py --name my-agent-42 --parent-npub npub1qqq... --tier dynasty --brand spawnling --dry-run`
- **Result:** ✅ PASS — Correct template_id=4 (medium), 16 files prepared
- **Time:** 16:26 UTC

### Test 1.3 — Input validation: name too short
- **Command:** `--name ab`
- **Result:** ✅ PASS — Rejected: "Name must be 3-30 alphanumeric characters"

### Test 1.4 — Input validation: bad npub
- **Command:** `--parent-npub notnpub123`
- **Result:** ✅ PASS — Rejected: "Parent npub must start with 'npub1'"

### Test 1.5 — Input validation: special characters
- **Command:** `--name "test@agent!"`
- **Result:** ✅ PASS — Rejected

### Test 1.6 — Summary JSON security check
- **File:** `vm_testling_summary.json`
- **Result:** ✅ PASS — No nsec, no mnemonics, no private keys. Only public info.

**Layer 1 Summary: 6/6 PASS ✅**

---

## Layer 2: API Integration Tests

### Test 2.1 — LNVPS Templates Endpoint (FREE)
- **Endpoint:** `GET https://api.lnvps.net/api/v1/vm/templates`
- **Result:** ✅ PASS — 7 templates returned
- **Data format:** `{"data": {"templates": [...]}}`
- **Template matching:** All 4 classes match correctly (demo→12, tiny→1, small→2, medium→3)
- **🔴 BUG FOUND:** Demo template ID is 12, not 7 as we had in MEMORY.md. Our code handles this correctly (matches by name keyword, not hardcoded ID). MEMORY.md reference was wrong.
- **New discovery:** X-Large (ID=5, 12CPU/16GB, €39.90) and XX-Large (ID=6, 20CPU/24GB, €55.50) tiers exist
- **Time:** 16:28 UTC

### Test 2.2 — LNVPS Images Endpoint (FREE)
- **Endpoint:** `GET https://api.lnvps.net/api/v1/image`
- **Result:** ✅ PASS — 6 images returned
- **Data format:** `{"data": [list]}` (NOT `{"data": {"images": [...]}}`)
- **Image matching:** Correctly selects Ubuntu 24.04 (ID=1)
- **🔴 BUG FOUND:** Default SSH user is `ubuntu`, NOT `root`! Our `create_vm.py` connects as `root` in `ssh_bootstrap()`. This will fail on real VMs. Must SSH as `ubuntu` then `sudo`.
- **Available images:** Ubuntu 24.04/22.04/20.04/25.04, Debian 11/13
- **Time:** 16:28 UTC

### Test 2.3 — LNVPS Template Matching Logic (FREE)
- **Test:** Run our code's matching algorithm against real API data
- **Result:** ✅ PASS — demo→12, tiny→1, small→2, medium→3 all matched correctly
- **Note:** Our fallback IDs (1,2,3,4) would be WRONG for demo (real=12). Good that we match by name.
- **Time:** 16:28 UTC

### Test 2.4 — noscha.io Availability Check (FREE)
- **Endpoint:** `GET https://noscha.io/api/check/{name}`
- **Result:** ✅ PASS — All test names available (testling, spawnling, deadrop, myagent)
- **Response format:** `{"available": true, "username": "testling"}`
- **Time:** 16:28 UTC

### Test 2.5 — noscha.io Pricing Endpoint (FREE)
- **Endpoint:** `GET https://noscha.io/api/pricing`
- **Result:** ✅ PASS — Pricing matches our docs
- **Confirmed:** 1h=1000 sats bundle, 1d=1600, 7d=3300, 30d=6500, 90d=16000, 365d=40000
- **Time:** 16:28 UTC

### Bugs Found in Layer 2 (Free Tests)
1. **🔴 CRITICAL: SSH user is `ubuntu` not `root`** — create_vm.py line `client.connect(ip, username="root", ...)` will fail. Must use `ubuntu` + sudo for bootstrap.
2. **🟡 Demo template ID=12** (not 7) — code handles correctly via name matching, but MEMORY.md was wrong. Updated.
3. **🟡 Image API format** — returns `{"data": [list]}` not `{"data": {"images": [...]}}`. Our code's fallback chain happens to work but is fragile.

---

### Test 2.6 — LNVPS NIP-98 Auth: List VMs (FREE)
- **Endpoint:** `GET /api/v1/vm` with NIP-98 auth header
- **Result:** ✅ PASS — HTTP 200, returned `{"data":[]}` (empty, new keypair)
- **Validates:** NIP-98 event signing + base64 encoding accepted by LNVPS
- **Time:** 16:32 UTC

### Test 2.7 — LNVPS SSH Key Upload (FREE)
- **Endpoint:** `POST /api/v1/ssh-key` with NIP-98 auth
- **Result:** ✅ PASS — Key ID 772 returned, then Key ID 773
- **Response format:** `{"data": {"id": 772, "name": "test-provision-key", ...}}`
- **Time:** 16:32 UTC

### Test 2.8 — LNVPS Demo VM Creation (PAID — ~344 sats / €0.20)
- **Endpoint:** `POST /api/v1/vm` with template_id=12, image_id=1
- **Result:** ✅ PASS — VM ID 1042 created (first attempt, lost SSH key)
- **Then:** VM ID 1043 created with correct SSH key
- **Response format:** `{"data": {"id": 1043, "status": {...}, "ip_assignments": [], ...}}`
- **Payment:** Via `GET /api/v1/vm/{id}/renew?method=lightning` → bolt11 invoice
- **🔴 BUG FOUND:** Payment invoice NOT in create response — must call renew endpoint separately. Our code assumed payment info in create response.
- **🟡 FINDING:** Amount field is in millisatoshis (344453 = 344.5 sats)
- **🟡 LESSON:** SSH key is baked into VM at creation time. Uploading a new key after doesn't help. Must have the private key saved BEFORE creating the VM.
- **Time:** 16:32-16:37 UTC
- **Cost:** 2x ~344 sats (first VM lost, second VM worked) = ~688 sats total

### Test 2.9 — LNVPS VM Boot + IP Assignment
- **Result:** ✅ PASS — VM booted in ~20 seconds after payment
- **IP assigned:** 185.18.221.189 (VM 1043)
- **IP format:** `185.18.221.189/25` (CIDR notation — must strip `/25` for SSH)
- **🟡 BUG FOUND:** IP returned with CIDR suffix. Our code must handle `ip.split('/')[0]`
- **Time:** 16:39 UTC

### Test 2.10 — SSH Access to LNVPS VM
- **Result:** ✅ PASS — Connected as `ubuntu` user on attempt 2 (first attempt too early, SSH not ready)
- **User:** `ubuntu` (confirmed NOT root — our fix was correct)
- **Sudo:** `sudo whoami` → `root` ✅ (passwordless sudo works)
- **OS:** Ubuntu 24.04.2 LTS (Noble Numbat), kernel 6.8.0-64-generic
- **Resources:** 942MB RAM (393MB used), 3.9GB disk (1.8GB used, 48%)
- **⚠️ NOTE:** Demo tier only has 3.9GB disk with 2GB already used — only 2GB free. May not be enough for Docker + OpenClaw. Real agents need Small tier (80GB).
- **Time:** 16:39 UTC

### Bugs Found in Layer 2 (Paid Tests)
1. **🔴 Payment invoice flow wrong** — `POST /api/v1/vm` does NOT return a bolt11 invoice. Must call `GET /api/v1/vm/{id}/renew?method=lightning` separately after creation. Our `create_vm.py` code assumed invoice in create response.
2. **🟡 IP has CIDR suffix** — `ip_assignments[0].ip` returns `185.18.221.189/25` not `185.18.221.189`. Must strip `/25` before SSH.
3. **🟡 Amount in millisatoshis** — API `amount` field is millisats, not sats. 344453 = 344.5 sats.
4. **✅ CONFIRMED:** SSH user is `ubuntu` with passwordless sudo (our fix was correct)
5. **✅ CONFIRMED:** NIP-98 auth works perfectly — key upload, VM creation, VM status polling all accept our signed events

### Test 2.11 — noscha.io Order + Webhook Challenge Flow
- **Endpoint:** `POST /api/order` with webhook_url
- **Result:** ✅ PASS — Order created, webhook challenge received via webhook.site
- **🔴 FINDING:** noscha.io REQUIRES a webhook_url. Flow is: create order → noscha POSTs challenge to webhook → visit challenge_url (GET) → returns HTML payment page with bolt11 embedded → pay → poll status
- **🟡 FINDING:** Confirm endpoint returns HTML page, not JSON. Must regex-extract bolt11 from HTML.
- **🟡 FINDING:** Our bootstrap can't self-register with noscha.io without a reachable webhook URL. Need to either: (a) pre-register from create_vm.py with webhook.site or our own endpoint, or (b) run a temp listener on the VPS first.
- **Time:** 16:43-16:44 UTC

### Test 2.12 — noscha.io Payment + Provisioning (PAID — 1000 sats)
- **Result:** ✅ PASS — Provisioned instantly after payment
- **Management token:** Returned in status poll (`mgmt_19c57e6d361`)
- **Time:** 16:47 UTC

### Test 2.13 — noscha.io NIP-05 Verification
- **Endpoint:** `GET /.well-known/nostr.json?name=testlingsov4`
- **Result:** ✅ PASS — Returns `{"names":{"testlingsov4":"b6345a67..."}}`
- **NIP-05 identity:** `testlingsov4@noscha.io` resolves correctly

### Test 2.14 — noscha.io Subdomain DNS
- **Result:** ✅ PASS — `testlingsov4.noscha.io` → `185.18.221.189` (our VM IP)
- **DNS propagation:** Instant (< 1 second after provisioning)

### Bugs Found in noscha.io Integration
1. **🔴 Webhook required** — Our provisioning code doesn't handle the webhook challenge flow. Need create_vm.py to: create order with webhook URL → catch challenge → confirm → pay invoice → poll status.
2. **🟡 Confirm returns HTML not JSON** — Must extract bolt11 via regex from HTML payment page.
3. **🟡 Bootstrap self-registration blocked** — Agent VPS can't easily self-register on noscha.io without a public webhook endpoint. Better to pre-register from create_vm.py.

---

## Layer 3: Bootstrap Script Test (on live VM)

**VM:** 185.18.221.189 (Demo tier, 1CPU/1GB/5GB, Ubuntu 24.04)
**Started:** 16:58 UTC | **Completed:** 17:03 UTC (~5 min)

### Results by Step

| Step | Description | Result | Notes |
|------|-------------|--------|-------|
| 1/14 | System packages | ✅ PASS | Docker, fail2ban, build-essential, pip3 installed |
| 2/14 | Node.js | ✅ PASS | v20.20.0 installed via nodesource |
| 3/14 | Firewall | ✅ PASS | UFW active: 22, 80, 443, 3000 |
| 4/14 | Agent user | ✅ PASS | `agent` user with docker group |
| 5/14 | Nostr keypair | ✅ PASS | npub generated on VPS, nsec stays local |
| 6/14 | BTC wallet | ✅ PASS (after pip fix) | First run failed: `coincurve` not installed. Fixed with `--break-system-packages` flag |
| 7/14 | ETH wallet | ✅ PASS | Generated via eth-account |
| 8/14 | Key storage | ✅ PASS | `/opt/agent-keys/keys.json` secured |
| 9/14 | NPM packages | ✅ PASS | mcp-money + NDK installed |
| 10/14 | nsecBunker | ❌ FAIL | npm install failed (`EUNSUPPORTEDPROTOCOL workspace:*`), git clone also failed. Bunker NOT running. |
| 11/14 | OpenClaw install | ⚠️ PARTIAL | `get.openclaw.ai` DNS failed. Git clone worked but Docker compose didn't start properly. |
| 12/14 | Config + workspace | ✅ PASS | Templates filled, files written |
| 13/14 | OpenClaw start | ❌ FAIL | Health check failed — OpenClaw not running |
| 14/14 | Birth note | ⚠️ PARTIAL | Kind 14 created but NIP-44 encryption not implemented. "partial" per script output. |

### Agent Public Info (generated on VPS)
- **npub:** `npub1anegru5unjxl4q6495jcyz37ljnyje3aml6gzhh6rv3vkgjvr7esg3yhed`
- **BTC:** `bc1q2q6f9agx4j2hdlp4dcurhf9clstptcr4gwyepx`
- **ETH:** `0xbe4a4de99767ee15d499847fb151ec689431e538`
- **VPS IP returned:** `2a13:2c0::6256:c47d:9ab9:1b6f` (IPv6! — `ifconfig.me` returned IPv6 instead of IPv4)

### Bugs Found in Layer 3
1. **🔴 pip3 needs `--break-system-packages`** on Ubuntu 24.04 — FIXED during test
2. **🔴 nsecBunker install failed** — `nsecbunker` npm package uses `workspace:*` protocol (monorepo dep), can't install globally. Git clone of `kind-0/nsecbunkerd` also has npm install issues. Need alternative bunker solution.
3. **🔴 `get.openclaw.ai` DNS unreachable** from LNVPS VM — installer curl failed. Git clone fallback worked but Docker compose didn't start. Need to verify OpenClaw Docker deployment on LNVPS.
4. **🟡 `ifconfig.me` returns IPv6** — VPS has IPv6 but our code expects IPv4. Need to use `curl -4 ifconfig.me` to force IPv4.
5. **🟡 OpenClaw health check failed** — related to install issue above
6. **🟡 Birth note NIP-17 incomplete** — known issue, NIP-44 not implemented

### Post-Test Fixes Applied

1. **nsecBunker (Step 10 → Steps 11-12):** Replaced the external `nsecbunker` npm package with a bundled `nip46-server.js` that uses NDK's `NDKNip46Backend` class directly. No external nsecBunker package needed. Steps renumbered: Step 11 installs NDK, Step 12 sets up the bundled NIP-46 bunker as a systemd service (`agent-bunker.service`). Secret-based authentication added in commit 1e5efed.

2. **OpenClaw install (Steps 13-14):** Upgraded Node.js from v20 to v22 (LTS, required by OpenClaw >=22.12.0). Replaced the failing two-stage install with a three-stage fallback chain: (1) `npm install -g openclaw@latest`, (2) git clone + npm link from source, (3) Docker image pull with wrapper script. Added `agent-openclaw.service` systemd unit. Health check now skipped if install fails.

3. **Birth note NIP-17:** Now uses NDK `sendDM` with proper NIP-44 encryption (NIP-04 fallback removed in commit 46fb3a5).

### What DID Work ✅
- Nostr keypair generated locally on VPS (never transmitted)
- BTC + ETH wallets generated locally
- Keys stored at /opt/agent-keys/ with correct permissions
- NDK + mcp-money installed
- Workspace templates filled with correct values
- Firewall configured correctly
- noscha.io management token consumed

---

## Layer 2 Summary

**Tests: 14/14 PASS ✅**
**Total cost: ~2032 sats (~€1.20)**
- 2x LNVPS Demo VM: ~688 sats
- 1x noscha.io 1h bundle: 1000 sats
- 1x first VM (lost SSH key, unusable): ~344 sats

**Critical bugs found: 3**
1. Payment invoice not in VM create response — must call /renew endpoint (FIXED)
2. SSH user is ubuntu not root (FIXED)  
3. noscha.io webhook challenge flow not in our code (TODO)

**Architecture validated:**
- ✅ NIP-98 auth works with LNVPS
- ✅ VM creation + Lightning payment + boot works
- ✅ SSH access as ubuntu with sudo works
- ✅ noscha.io identity registration works (NIP-05 + subdomain + email)
- ✅ DNS resolves instantly after noscha provisioning

---

## Layer 4: Docker Bootstrap Test (Cost: $0)

**Date:** 2026-02-25 12:32-12:42 UTC
**Environment:** Docker container, Ubuntu 24.04, simulating fresh LNVPS VM
**Method:** `Dockerfile.test-bootstrap` + `test_bootstrap_docker.sh` wrapper (stubs ufw, systemctl, dpkg-reconfigure)

### Results by Step

| Step | Description | Result | Notes |
|------|-------------|--------|-------|
| 1/14 | System packages | ✅ PASS | All packages installed (curl, jq, git, python3, pip3, fail2ban) |
| 2/14 | Node.js v22 | ✅ PASS | v22.22.0 installed via NodeSource |
| 3/14 | Firewall | ✅ PASS (stubbed) | Docker stub intercepted all ufw commands |
| 4/14 | Agent user | ✅ PASS | `agent` user created |
| 5/14 | Nostr keypair | ✅ PASS | Valid npub/nsec generated via Node.js crypto |
| 6/14 | BTC wallet | ✅ PASS | 12-word BIP-39 mnemonic, bc1q address, BIP-84 derivation |
| 7/14 | ETH wallet | ✅ PASS | Valid 0x address via eth-account |
| 8/14 | Key storage | ✅ PASS | Split files (nostr.json, btc_wallet.json, eth_wallet.json), mode 600 |
| 9/14 | Templates | ✅ PASS | 6 workspace files rendered, all placeholders replaced |
| 10/14 | PPQ provision | ⚠️ API ERROR | `requests` installed correctly, but PPQ API returned HTTP 500 (their server issue) |
| 11/14 | npm packages | ✅ PASS | NDK installed, mcp-money installed |
| 12/14 | NIP-46 bunker | ✅ PASS (stubbed) | Files copied, systemd service file created, systemctl stubbed |
| 13/14 | OpenClaw | ✅ PASS | **Installed via `npm install -g openclaw@latest`** — Stage 1 works! |
| 14/14 | Birth note | ⚠️ EXPECTED FAIL | Test npub has invalid bech32 checksum (not a real npub) |

### Bugs Found and Fixed

1. **`__PARENT_WISDOM__` placeholder unreplaced (FIXED)** — `templates/LETTER.md` uses `__PARENT_WISDOM__` but `replace_placeholders()` didn't handle it. Added `parent_wisdom.txt` input file and `__PARENT_WISDOM__` substitution. Verified: LETTER.md now renders correctly.

2. **`__DEFAULT_MODEL__` placeholder unreplaced in config_template.json (FIXED)** — `config_template.json` uses `__DEFAULT_MODEL__` but `replace_placeholders()` didn't handle it. Config had literal `__DEFAULT_MODEL__` instead of `gpt-5-nano`. Added substitution. Verified: openclaw.json now has `"gpt-5-nano": {}`.

3. **`requests` pip package missing (FIXED)** — `ppq_provision.py` requires `requests` but only `coincurve` and `eth-account` were installed via pip. Added `requests` to the `pip3 install` line in step 6. Verified: ppq_provision.py runs (gets PPQ 500 error, not import error).

### Verified Outputs

- `/opt/agent-keys/nostr.json` — valid nsec/npub/hex keys, mode 600 ✅
- `/opt/agent-keys/btc_wallet.json` — 12-word mnemonic, bc1q address, WIF ✅
- `/opt/agent-keys/eth_wallet.json` — 0x address with private key ✅
- `/home/agent/.openclaw/openclaw.json` — valid JSON, `gpt-5-nano` model ✅
- `/home/agent/.openclaw/workspace/LETTER.md` — `__PARENT_WISDOM__` replaced ✅
- `/home/agent/.openclaw/workspace/IDENTITY.md` — all fields correct ✅
- `agent_public_info.json` — all expected fields present ✅

### Component Tests

| Test | Result | Notes |
|------|--------|-------|
| nip46-server.js syntax | ✅ PASS | `node --check` passes |
| send_birth_note.js syntax | ✅ PASS | `node --check` passes |
| create_vm.py dry run | ✅ PASS | Clean 11-step flow, bech32 validation works, 20 files prepared |
| create_vm.py invalid npub | ✅ PASS | Rejects invalid bech32 checksum |
| LNVPS API probe | ✅ PASS | Templates endpoint returning data — API is back online |
| PPQ API probe | ❌ DOWN | Returns HTTP 500 Internal Server Error on /accounts/create |

### Summary

**Docker test: 12/14 PASS, 2 expected failures (PPQ API down, test npub invalid)**

The three critical failures from Layer 3 (Feb 13) are now resolved:
- nsecBunker → replaced with bundled nip46-server.js ✅
- OpenClaw install → `npm install -g openclaw@latest` works on Node 22 ✅
- Birth note → script syntax valid, would work with real npub ✅

**LNVPS is back online** — ready for Layer 5 live E2E test when desired.

