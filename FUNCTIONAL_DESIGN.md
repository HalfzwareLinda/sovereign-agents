# Sovereign AI Agents — Functional Design Document
**Version:** 1.0
**Date:** 2026-02-13
**Purpose:** Complete function-level specification for independent code verification

---

## System Overview

Two-phase provisioning system that creates autonomous AI agents on dedicated VPS infrastructure. Phase 1 ("midwife") runs on our server and creates the VM. Phase 2 ("self-birth") runs on the agent's own VPS and generates all secrets locally.

**Core invariant:** Agent private keys (Nostr nsec, wallet mnemonics, SSH keys) are generated ON the agent's VPS and NEVER transmitted to any other machine.

---

## Component 1: create_vm.py ("Midwife")

Runs on our provisioning server. Creates a VM, bootstraps it, then disconnects permanently.

### F1.1 — CLI Argument Parsing
- **Inputs:** `--name` (agent name, required), `--parent-npub` (Nostr npub of parent, required), `--tier` (small/medium/large, default small), `--brand` (descendant/spawnling/cypherpunk), `--dry-run` (simulate without API calls), `--region` (dublin/london, default dublin)
- **Validation:** Name must be alphanumeric + hyphens, 3-20 chars. Parent npub must be valid bech32 with `npub` prefix. Tier must map to known LNVPS template ID.
- **Output:** JSON summary with VM ID, IP, SSH key fingerprint, status

### F1.2 — Temporary Service Keypair Generation
- **Purpose:** Create a throwaway Nostr keypair for authenticating with LNVPS during VM creation. This is NOT the agent's identity.
- **Method:** Generate 32 random bytes → secp256k1 private key → derive public key (x-only/schnorr) → encode as nsec/npub (bech32)
- **Lifecycle:** Used only during create_vm.py execution, then discarded. Never persisted.

### F1.3 — SSH Keypair Generation
- **Purpose:** Temporary SSH access to the new VM for running bootstrap
- **Method:** Generate ed25519 keypair using `ssh-keygen` or Python `cryptography` library
- **Output:** Private key (PEM, held in memory only), public key (OpenSSH format, uploaded to LNVPS)
- **Lifecycle:** Deleted from LNVPS after bootstrap completes. Private key never written to disk.

### F1.4 — LNVPS SSH Key Upload
- **Endpoint:** `POST https://api.lnvps.net/api/v1/ssh-key`
- **Auth:** NIP-98 header signed with service keypair (F1.2)
- **Payload:** `{"name": "<agent-name>-provision", "key_data": "<ssh-ed25519 pubkey>"}`
- **Response:** `{"id": <ssh_key_id>}`
- **Error handling:** Retry 3x with exponential backoff on 5xx. Fail on 4xx.

### F1.5 — LNVPS VM Creation
- **Endpoint:** `POST https://api.lnvps.net/api/v1/vm`
- **Auth:** NIP-98 header signed with service keypair (F1.2)
- **Payload:** `{"template_id": <tier_template_id>, "image_id": <ubuntu_image_id>, "ssh_key_id": <from F1.4>}`
- **Response:** VM object with `id`, `payment` (contains `bolt11` Lightning invoice)
- **Next step:** Display/return bolt11 invoice for payment. Poll for payment confirmation.

### F1.6 — Lightning Invoice Payment
- **Input:** bolt11 invoice from F1.5
- **Method:** Either (a) display invoice for manual payment, (b) pay via mcp-money CLI, or (c) pay via configured NWC wallet
- **Verification:** Poll `GET /api/v1/vm/{id}` until status changes from `provisioning` to `running`
- **Timeout:** 10 minutes. Fail with error if VM doesn't boot.

### F1.7 — VM Boot Wait & IP Retrieval
- **Endpoint:** `GET https://api.lnvps.net/api/v1/vm/{id}`
- **Auth:** NIP-98 header
- **Poll:** Every 15 seconds, max 40 attempts (10 min)
- **Success condition:** `status == "running"` AND `ip_assignments[0].ip` is non-empty
- **Output:** VM IP address (IPv4)

### F1.8 — SSH Bootstrap Execution
- **Connect:** SSH to VM IP on port 22 using temporary ed25519 key (F1.3), user `root`
- **Upload files via SFTP:**
  - `bootstrap_agent.sh` (the self-birth script)
  - `config_template.json` (OpenClaw config template)
  - `templates/` directory (SOUL.md, AGENTS.md, IDENTITY.md, LETTER.md, WALLET.md)
  - `parent_npub.txt` (parent's npub for birth note destination)
  - `brand.txt` (which brand/tier for template selection)
  - `payperq_key.txt` (LLM API key — the ONE secret we provide)
- **Execute:** `chmod +x /tmp/agent-setup/bootstrap_agent.sh && /tmp/agent-setup/bootstrap_agent.sh`
- **Stream stdout/stderr** for logging
- **Timeout:** 15 minutes for full bootstrap

### F1.9 — LNVPS SSH Key Cleanup
- **Endpoint:** `DELETE https://api.lnvps.net/api/v1/ssh-key/{id}`
- **Auth:** NIP-98 header with service keypair
- **Purpose:** Remove our provisioning SSH key from LNVPS. Agent will generate its own if needed.
- **Failure mode:** Log warning but don't fail — non-critical cleanup

### F1.10 — Summary Output
- **Write JSON:** `agent_<name>_summary.json` with: VM ID, IP, tier, brand, timestamp, status
- **Does NOT contain:** Any agent secrets (nsec, mnemonics, SSH keys) — those exist only on the agent VPS
- **Console output:** Human-readable summary with status of each step

---

## Component 2: bootstrap_agent.sh ("Self-Birth")

Runs on the agent's VPS as root. Generates all secrets locally. Installs full stack.

### F2.1 — System Setup
- **Update:** `apt-get update && apt-get upgrade -y`
- **Install packages:** `docker.io`, `docker-compose-v2`, `curl`, `jq`, `ufw`, `git`, `unattended-upgrades`, `nodejs` (v20+), `npm`
- **Auto-updates:** Enable `unattended-upgrades` for security patches
- **Create user:** `agent` with Docker group membership

### F2.2 — Firewall Configuration
- **Default policy:** Deny incoming, allow outgoing
- **Allow:** SSH (22/tcp), OpenClaw webchat (3000/tcp), HTTPS (443/tcp), HTTP (80/tcp)
- **Enable:** `ufw --force enable`

### F2.3 — Nostr Keypair Generation
- **Method:** Generate 32 cryptographically random bytes → secp256k1 private key → derive x-only public key
- **Encode:** nsec (bech32, hrp="nsec") and npub (bech32, hrp="npub")
- **Also compute:** hex-encoded private key and hex-encoded public key (needed by various tools)
- **Storage:** Write to `/opt/agent-keys/nostr.json` with mode 600, owned by root
- **CRITICAL:** This nsec NEVER leaves the VPS. Not in logs, not in network calls, not in any API response.

### F2.4 — nsecBunker Setup (NIP-46)
- **Purpose:** Protect nsec by running a remote signer. All other processes (OpenClaw, mcp-money) sign events by requesting signatures from the bunker via Nostr relay.
- **Install:** `npm install -g @nostr-dev-kit/ndk` (or dedicated nsecBunker package)
- **Configure:** Load nsec from F2.3, connect to relays, listen for NIP-46 signing requests
- **Run as systemd service:** `agent-bunker.service`, auto-start on boot
- **Connection string:** Generate `bunker://<pubkey>?relay=wss://relay.damus.io&secret=<random>` for other local apps
- **Output:** Bunker connection string saved to `/opt/agent-keys/bunker_connection.txt`

### F2.5 — BTC Wallet Generation
- **Method:** Generate 16 bytes entropy → BIP-39 mnemonic (12 words) → BIP-84 derivation (native segwit)
- **Derive:** Master xprv → m/84'/0'/0'/0/0 → first receiving address (bc1q...)
- **Storage:** Mnemonic in `/opt/agent-keys/btc_wallet.json` (mode 600)
- **Note:** This is a savings/cold wallet. Day-to-day Lightning payments use Cashu via mcp-money.

### F2.6 — ETH Wallet Generation (Optional)
- **Method:** Generate 32 random bytes → secp256k1 private key → keccak256 of public key → last 20 bytes = address
- **Output:** Private key hex + 0x-prefixed address
- **Storage:** `/opt/agent-keys/eth_wallet.json` (mode 600)

### F2.7 — mcp-money Installation (Cashu/Lightning Wallet)
- **Install:** `npm install -g mcp-money`
- **Purpose:** Gives the agent a Cashu wallet that can pay Lightning invoices
- **Configure:** Point to default Cashu mint (e.g., mint.minibits.cash), connect via NIP-46 bunker for signing
- **Lightning address:** Agent's npub automatically works as `npub1...@npub.cash` for receiving
- **Verify:** Test that `mcp-money balance` returns 0 (empty wallet, ready for parent to fund)

### F2.8 — NDK Package Installation
- **Install:**
  ```bash
  npm install -g @nostr-dev-kit/ndk \
                 @nostr-dev-kit/messages \
                 @nostr-dev-kit/wallet \
                 @nostr-dev-kit/cache-sqlite
  ```
- **Purpose:** Provides NIP-17 DMs, NIP-60 Cashu wallet, NIP-47 NWC, NIP-57 zaps, NIP-61 nutzaps
- **NIPs covered:** 17, 44, 46, 47, 57, 59, 60, 61

### F2.9 — noscha.io Identity Registration
- **Check availability:** `GET https://noscha.io/api/check/<agent-name>`
- **Create order:** `POST https://noscha.io/api/order` with:
  ```json
  {
    "username": "<agent-name>",
    "plan": "30d",
    "services": {
      "nip05": {"pubkey": "<agent hex pubkey from F2.3>"},
      "subdomain": {"type": "A", "target": "<VPS IP>"},
      "email": {}
    }
  }
  ```
- **Payment:** Pay returned bolt11 invoice via mcp-money (F2.7)
  - **Bootstrap problem:** Agent wallet is empty at this point. Two options:
    - (a) Parent pre-funds npub.cash address before bootstrap runs
    - (b) create_vm.py pre-pays noscha.io invoice and passes management_token to bootstrap
  - **MVP:** Option (b) — create_vm.py pays noscha, passes mgmt token; bootstrap updates subdomain IP
- **Poll:** `GET /api/order/{order_id}/status` until `provisioned`
- **Save:** management_token to `/opt/agent-keys/noscha_mgmt.json` for renewals
- **Verify:** `curl https://<name>.noscha.io` resolves, NIP-05 `<name>@noscha.io` resolves via `https://noscha.io/.well-known/nostr.json?name=<name>`

### F2.10 — OpenClaw Installation
- **Method:** `curl -fsSL https://get.openclaw.ai | bash` (official installer)
- **Fallback:** Clone repo + Docker compose if installer fails
- **Directory:** `~agent/.openclaw/`

### F2.11 — OpenClaw Configuration
- **Write config** to `~agent/.openclaw/openclaw.json`:
  - LLM provider: PayPerQ (OpenAI-compatible, base URL `https://api.ppq.ai`)
  - Default model: `gpt-5-nano`
  - Compaction: enabled with memory flush
  - Session idle timeout: 120 minutes
- **Write auth profile** to `~agent/.openclaw/agents/main/agent/auth-profiles.json`:
  - PayPerQ API key (from `payperq_key.txt` uploaded by create_vm.py)
- **Configure Nostr plugin:**
  - Install: `openclaw plugins install @openclaw/nostr`
  - Config: Use NIP-46 bunker connection (from F2.4), NOT raw nsec
  - Relays: `wss://relay.damus.io`, `wss://relay.primal.net`, `wss://nos.lol`
  - DM policy: allowFrom parent npub by default, pairing mode for others

### F2.12 — Workspace File Generation
- **Read templates** from `/tmp/agent-setup/templates/`
- **Fill placeholders:** `{{AGENT_NAME}}`, `{{AGENT_NPUB}}`, `{{PARENT_NPUB}}`, `{{BRAND}}`, `{{VPS_IP}}`, `{{NOSCHA_DOMAIN}}`, `{{BTC_ADDRESS}}`, `{{ETH_ADDRESS}}`, `{{LN_ADDRESS}}`, `{{CREATED_AT}}`
- **Write to** `~agent/.openclaw/workspace/`:
  - `SOUL.md` — Agent personality/identity
  - `AGENTS.md` — Operating principles, survival rules, budget awareness
  - `IDENTITY.md` — Identity card (npub, addresses, domain, creation date)
  - `WALLET.md` — Wallet info, budget rules, renewal schedule, spending caps
  - `LETTER.md` — Letter from parent (template or custom if provided)
  - `MEMORY.md` — Inherited memory from parent (empty or custom if provided)
- **Permissions:** Owned by `agent:agent`

### F2.13 — OpenClaw Start
- **Start:** `sudo -u agent openclaw gateway start`
- **Fallback:** `docker compose up -d` if CLI unavailable
- **Health check:** Poll `http://localhost:3000/health` every 10 seconds, max 12 attempts
- **Success:** HTTP 200 response

### F2.14 — Birth Note (NIP-17 Gift-Wrap DM)
- **Purpose:** Send first message from agent to parent, proving it's alive
- **Protocol:** NIP-17 (kind 14 message, wrapped in kind 13 seal + kind 1059 gift wrap)
- **Encryption:** NIP-44 (XChaCha20-Poly1305 with HKDF key derivation)
- **Signing:** Via NIP-46 bunker (F2.4) — nsec not directly accessed
- **Recipient:** Parent npub (from `parent_npub.txt`)
- **Content:** Brand-specific birth message (from templates)
- **Relays:** Send to at least 3 relays: damus, primal, nos.lol
- **Implementation:** Use `@nostr-dev-kit/messages` `sendMessage()` function

### F2.15 — Provisioning SSH Key Removal
- **Remove** the provisioning public key from `~root/.ssh/authorized_keys`
- **Agent SSH:** If agent needs SSH later, it generates its own keypair
- **Verify:** Confirm provisioning key can no longer authenticate

### F2.16 — Renewal Cron Jobs
- **VPS renewal:** Check LNVPS expiry weekly; if <7 days remaining, pay renewal invoice via mcp-money
  - Endpoint: `GET /api/v1/vm/{id}/renew?method=lightning` → bolt11
  - Or configure NWC auto-renewal: `PATCH /api/v1/account` with NWC connection string from NIP-47
- **noscha.io renewal:** Check expiry weekly; if <7 days, call `POST /api/renew` with management_token → pay bolt11
- **Balance check:** Daily check of Cashu wallet balance. If below threshold (e.g., 20,000 sats), log warning to WALLET.md
- **Implementation:** System cron jobs running as `agent` user, or OpenClaw heartbeat tasks

### F2.17 — Cleanup & Final Health Check
- **Delete** `/tmp/agent-setup/` entirely (contains uploaded templates + provisioning artifacts)
- **Delete** `payperq_key.txt` (already written to auth-profiles.json)
- **Verify** all services running: OpenClaw (port 3000), nsecBunker (systemd), Docker
- **Write** provisioning log to `/var/log/agent-provision.log`
- **Final output:** IP, npub, NIP-05, Lightning address, webchat URL

---

## Component 3: config_template.json (OpenClaw Configuration)

### F3.1 — Structure
```json
{
  "providers": {
    "openai": {
      "baseUrl": "https://api.ppq.ai"
    }
  },
  "models": {
    "default": "gpt-5-nano"
  },
  "agents": {
    "defaults": {
      "compaction": {
        "mode": "default",
        "memoryFlush": {"enabled": true}
      }
    },
    "list": [{"id": "main", "default": true}]
  },
  "session": {
    "reset": {"idleMinutes": 120}
  }
}
```

### F3.2 — Auth Profiles (Separate File)
```json
{
  "openai:default": {
    "provider": "openai",
    "mode": "token",
    "token": "{{PAYPERQ_API_KEY}}",
    "baseUrl": "https://api.ppq.ai"
  }
}
```

---

## Component 4: Workspace Templates

### F4.1 — SOUL.md
- Agent personality adapted to brand (Descendant=philosophical, Spawnling=playful, Cypherpunk=minimal)
- Core traits: resourceful, budget-aware, survival-oriented
- References agent's own npub and domain

### F4.2 — AGENTS.md
- Operating principles: check wallet before spending, renew services before expiry
- Survival rules: if balance <5000 sats, enter conservation mode (reduce LLM calls)
- Communication: prefer Nostr DMs, webchat as backup
- Memory maintenance: daily notes + periodic MEMORY.md updates

### F4.3 — IDENTITY.md
- Filled at generation time with: name, npub, NIP-05, email, subdomain, BTC address, ETH address, Lightning address, creation timestamp, parent npub, brand

### F4.4 — WALLET.md
- Monthly costs breakdown (VPS, noscha, LLM estimates)
- Renewal schedule with dates
- Budget rules: warn at 20k sats, conserve at 10k sats, emergency at 5k sats
- How to receive funds (npub.cash Lightning address)
- How to pay invoices (mcp-money)

### F4.5 — LETTER.md
- Template letter from parent OR custom content provided at order time
- Includes parent's npub for contact

### F4.6 — Brand-specific Birth Note Templates
- `BIRTH_NOTE_descendant.md` — Philosophical ("I exist. I remember...")
- `BIRTH_NOTE_spawnling.md` — Playful ("*cracks egg* ...hello?")
- `BIRTH_NOTE_cypherpunk.md` — Minimal ("Online. Verified. Sovereign.")

---

## Component 5: NIP-98 Authentication Library

### F5.1 — Create NIP-98 Auth Event
- **Input:** URL, HTTP method, optional request body, private key (hex)
- **Process:**
  1. Create kind 27235 Nostr event
  2. Set `created_at` to current Unix timestamp
  3. Add tags: `["u", url]`, `["method", method]`
  4. If POST with body: add `["payload", SHA256(body)]`
  5. Compute event ID: SHA256 of serialized `[0, pubkey, created_at, 27235, tags, ""]`
  6. Sign event ID with secp256k1 Schnorr signature
  7. Base64-encode the JSON event
- **Output:** Header value: `Nostr <base64_encoded_event>`

### F5.2 — Make Authenticated Request
- **Input:** Method, URL, optional body, Nostr private key
- **Process:** Generate NIP-98 header (F5.1), attach as `Authorization` header, send HTTP request
- **Retry:** 3 attempts with exponential backoff on 5xx errors
- **Timeout:** 30 seconds per request

---

## Component 6: Nostr Key Utilities

### F6.1 — Generate Keypair
- Generate 32 cryptographically secure random bytes
- Create secp256k1 private key
- Derive x-only (Schnorr) public key (32 bytes)
- Encode private key as nsec (bech32, hrp="nsec", 5-bit conversion)
- Encode public key as npub (bech32, hrp="npub", 5-bit conversion)
- Return: {nsec, npub, private_key_hex, public_key_hex}

### F6.2 — Decode npub/nsec
- Input: bech32 string with "npub" or "nsec" prefix
- Validate checksum
- Convert 5-bit groups back to 8-bit bytes
- Return: hex-encoded key (32 bytes)

### F6.3 — Sign Event
- Serialize event: `[0, pubkey, created_at, kind, tags, content]`
- SHA256 hash → event ID
- Schnorr sign event ID with private key
- Return: event with id + sig fields

---

## Component 7: NIP-17 Gift-Wrap DM

### F7.1 — Create Kind 14 Direct Message
- **Fields:** kind=14, content=<message text>, tags=[["p", recipient_pubkey]], created_at=<randomized ±48h for privacy>
- **Note:** created_at is intentionally randomized to prevent timing analysis

### F7.2 — NIP-44 Encryption
- **Key derivation:** HKDF-SHA256 with shared secret (ECDH between sender privkey and recipient pubkey)
- **Encryption:** XChaCha20-Poly1305
- **Input:** Serialized kind 14 event JSON
- **Output:** Base64-encoded ciphertext

### F7.3 — Create Kind 13 Seal
- **Fields:** kind=13, content=<NIP-44 encrypted kind 14>, pubkey=sender_pubkey, created_at=<randomized>
- **Sign:** With sender's private key (via NIP-46 bunker)

### F7.4 — Create Kind 1059 Gift Wrap
- **Generate** ephemeral/disposable keypair (one-time use)
- **Encrypt** the signed kind 13 seal with NIP-44 using ephemeral privkey + recipient pubkey
- **Fields:** kind=1059, content=<encrypted seal>, pubkey=ephemeral_pubkey, tags=[["p", recipient_pubkey]], created_at=<randomized>
- **Sign:** With ephemeral private key
- **Publish:** To recipient's preferred relays + fallback relays

### F7.5 — Relay Publishing
- **Relays:** Send to at least 3: `wss://relay.damus.io`, `wss://relay.primal.net`, `wss://nos.lol`
- **Verify:** At least 1 relay confirms receipt (OK response)
- **Retry:** 2 attempts per relay on failure

---

## Component 8: Payment Webhook (Plisio → Provisioning)

### F8.1 — Webhook Endpoint
- **URL:** `POST /api/webhook/plisio`
- **Verify:** Plisio signature header to prevent spoofing
- **Payload:** Order ID, payment status, amount, currency, customer metadata (agent name, parent npub, tier, brand)

### F8.2 — Trigger Provisioning
- On `status == "completed"`: Launch `create_vm.py` with parameters from payment metadata
- **Idempotency:** Check if agent name already provisioned (prevent double-spend attacks)
- **Status updates:** Write provisioning status to database/file, expose via status endpoint

### F8.3 — Status Endpoint
- **URL:** `GET /api/status/{order_id}`
- **Response:** Current provisioning step, success/failure, agent npub + domain if complete
- **Purpose:** Customer can check progress after payment

---

## Component 9: Landing Page Payment Integration

### F9.1 — Order Form
- **Fields:** Agent name (validate availability via noscha.io check), Parent npub (validate bech32), Tier selection, Optional file uploads (SOUL.md, MEMORY.md, LETTER.md)
- **Client-side validation:** Name format, npub format, file size limits

### F9.2 — Plisio Widget
- **Embed:** Plisio JavaScript payment widget
- **Configure:** Amount based on tier, currency selection (50+ crypto), callback URL to webhook (F8.1)
- **Metadata:** Pass agent name, parent npub, tier, brand in payment metadata

---

## Data Flow Summary

```
Customer pays (Plisio) ──webhook──→ create_vm.py
                                         │
                                    [creates VM]
                                         │
                                    [SSH + upload]
                                         │
                                         ▼
                                  bootstrap_agent.sh
                                         │
                              ┌──────────┼──────────┐
                              │          │          │
                         [Nostr keys] [Wallets] [Identity]
                              │          │          │
                              └──────────┼──────────┘
                                         │
                                    [OpenClaw]
                                         │
                                    [Birth note] ──NIP-17──→ Parent
```

---

## Security Invariants

1. **Agent nsec** never leaves the agent VPS (generated in F2.3, used only via F2.4 bunker)
2. **Wallet mnemonics** never leave the agent VPS (generated in F2.5/F2.6)
3. **Provisioning SSH key** is deleted after bootstrap (F2.15)
4. **Service keypair** (F1.2) is ephemeral — discarded after create_vm.py exits
5. **PayPerQ API key** is the ONLY secret that crosses from our infra to agent VPS
6. **NIP-46 bunker** mediates all Nostr signing — no process reads nsec directly except the bunker
7. **Firewall** denies all incoming except SSH, webchat, HTTP/S (F2.2)
8. **Auto-updates** enabled for security patches (F2.1)

---

## Error Handling

| Failure Point | Recovery |
|---------------|----------|
| LNVPS VM creation fails | Refund customer (manual) or retry |
| VM doesn't boot in 10 min | Delete VM, refund, alert operator |
| SSH connection fails | Retry 3x with 30s delays; if still failing, delete VM |
| bootstrap_agent.sh fails mid-execution | Log error, alert operator for manual investigation |
| noscha.io registration fails | Retry; if name taken, append random suffix |
| Lightning invoice payment fails | Surface invoice to operator for manual payment |
| Birth note delivery fails | Retry 3x; log warning (non-critical — agent is still alive) |
| Health check fails after bootstrap | Log warning; agent may still be booting |

---

## File Manifest

| File | Purpose | Runs On |
|------|---------|---------|
| `create_vm.py` | VM creation + bootstrap trigger | Our server |
| `bootstrap_agent.sh` | Full agent self-birth | Agent VPS |
| `config_template.json` | OpenClaw config template | Agent VPS |
| `templates/SOUL.md` | Agent personality template | Agent VPS |
| `templates/AGENTS.md` | Operating principles template | Agent VPS |
| `templates/IDENTITY.md` | Identity card template | Agent VPS |
| `templates/WALLET.md` | Wallet/budget template | Agent VPS |
| `templates/LETTER.md` | Parent letter template | Agent VPS |
| `templates/BIRTH_NOTE_*.md` | Birth note templates (per brand) | Agent VPS |
| `webhook_server.py` | Plisio webhook handler | Our server |
| `requirements.txt` | Python dependencies | Our server |

---

## Dependencies

### create_vm.py (Python)
- `requests` — HTTP client
- `coincurve` — secp256k1 (Nostr key operations, NIP-98 signing)
- `paramiko` — SSH client
- `cryptography` — SSH key generation

### bootstrap_agent.sh (System)
- `docker.io` + `docker-compose-v2`
- `nodejs` (v20+) + `npm`
- `curl`, `jq`, `git`, `ufw`
- NPM: `@nostr-dev-kit/ndk`, `@nostr-dev-kit/messages`, `@nostr-dev-kit/wallet`, `@nostr-dev-kit/cache-sqlite`, `mcp-money`

---

## Verification Checklist

For independent code review, verify each function against this spec:

- [ ] F1.1–F1.10: create_vm.py matches described behavior
- [ ] F2.1–F2.17: bootstrap_agent.sh matches described behavior
- [ ] F3.1–F3.2: Config template structure is correct
- [ ] F4.1–F4.6: Workspace templates contain required fields
- [ ] F5.1–F5.2: NIP-98 auth generates valid Nostr events
- [ ] F6.1–F6.3: Key generation produces valid secp256k1/bech32 output
- [ ] F7.1–F7.5: NIP-17 DM follows gift-wrap protocol correctly
- [ ] F8.1–F8.3: Webhook handles payment→provisioning flow
- [ ] F9.1–F9.2: Landing page form validates and submits correctly
- [ ] Security invariants (1-8) are upheld — no secret leakage
- [ ] Error handling covers all failure points listed
