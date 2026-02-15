# Sovereign AI Agents — Tech Stack
**Last updated:** 2026-02-13 17:25 UTC

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  CUSTOMER                                                │
│  Visits landing page → Pays via Plisio (crypto)         │
│  Provides: agent name, parent Nostr npub,               │
│  optional SOUL.md + MEMORY.md + LETTER.md               │
└─────────────────────┬───────────────────────────────────┘
                      │ webhook notification
                      ▼
┌─────────────────────────────────────────────────────────┐
│  PROVISIONING SERVER ("midwife" — our machine)           │
│                                                          │
│  create_vm.py:                                           │
│  1. Generate TEMPORARY service Nostr keypair (ours)      │
│  2. Generate SSH ed25519 keypair (for initial access)    │
│  3. Upload SSH key to LNVPS (NIP-98 w/ service key)     │
│  4. Create VM on LNVPS → pay Lightning invoice           │
│  5. Wait for VM boot, get IP                             │
│  6. SSH into VM, upload bootstrap_agent.sh + templates   │
│  7. Execute bootstrap_agent.sh                           │
│  8. Delete SSH access, discard temp keypair               │
│                                                          │
│  ⚠️  NO AGENT SECRETS touch this machine.                │
│  The agent generates its own keys on its own hardware.   │
└─────────────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│  AGENT VPS (LNVPS — Dublin/London)                       │
│  Ubuntu, 2GB RAM, 2 vCPU, 80GB NVMe SSD                │
│                                                          │
│  bootstrap_agent.sh ("self-birth"):                      │
│  1. Generate own Nostr keypair (nsec stays on VPS)       │
│  2. Start nsecBunker (NIP-46 remote signer)              │
│  3. Generate BTC/ETH wallets (mnemonics stay on VPS)     │
│  4. Install mcp-money (Cashu/Lightning wallet)           │
│  5. Register noscha.io identity (NIP-05+subdomain+email) │
│  6. Install NDK packages (DMs, wallet, cache)            │
│  7. Configure OpenClaw + Nostr plugin (via NIP-46)       │
│  8. Send birth note to parent (NIP-17 gift-wrap DM)      │
│  9. Remove provisioning SSH key                          │
│  10. Set up renewal cron jobs                            │
│                                                          │
│  ┌─── nsecBunker (NIP-46) ──────────────────────────┐   │
│  │  Holds nsec. Only process that touches it.        │   │
│  │  Signs events on request via Nostr Connect.       │   │
│  └──────────┬────────────────────┬──────────────────┘   │
│             │                    │                       │
│  ┌──────────▼────────┐  ┌───────▼──────────┐           │
│  │  OpenClaw Gateway  │  │  mcp-money       │           │
│  │  ├─ Agent runtime  │  │  Cashu/Lightning  │           │
│  │  ├─ Nostr DMs      │  │  wallet           │           │
│  │  │  (NIP-17)       │  │  (NIP-60)         │           │
│  │  ├─ Webchat        │  └──────────────────┘           │
│  │  └─ Cron jobs      │                                 │
│  └────────────────────┘                                 │
│                                                          │
│  Identity:                                               │
│  ├─ Nostr npub (primary identity + LNVPS auth)          │
│  ├─ NIP-05: [name]@noscha.io                           │
│  ├─ Email: [name]@noscha.io → webhook                  │
│  ├─ Subdomain: [name].noscha.io → VPS IP               │
│  └─ Webchat: [name].noscha.io (via OpenClaw)           │
│                                                          │
│  Wallet:                                                │
│  ├─ npub.cash Lightning address (receive)               │
│  ├─ mcp-money Cashu wallet (pay invoices)               │
│  ├─ NWC (NIP-47) for auto-renewal of VPS                │
│  ├─ NIP-60 Cashu wallet (Nostr-native ecash)            │
│  └─ Bitcoin on-chain (optional savings)                 │
└─────────────────────────────────────────────────────────┘
```

---

## Nostr NIP Package (Installed on Agent VPS)

| NIP | Name | Purpose | NDK Package |
|-----|------|---------|-------------|
| NIP-17 | Gift-wrap DMs | Private messaging with parent & other agents | `@nostr-dev-kit/messages` |
| NIP-44 | Encrypted payloads | Encryption layer for NIP-17 | `@nostr-dev-kit/ndk` (core) |
| NIP-46 | Remote signing | nsecBunker — nsec never exposed to apps | `@nostr-dev-kit/ndk` (core) |
| NIP-47 | Wallet Connect (NWC) | Auto-pay VPS/identity renewals | `@nostr-dev-kit/wallet` |
| NIP-57 | Zaps | Receive/send Lightning tips via Nostr | `@nostr-dev-kit/wallet` |
| NIP-59 | Gift wraps | Outer envelope for NIP-17 DMs | `@nostr-dev-kit/messages` |
| NIP-60 | Cashu wallet | Nostr-native ecash wallet | `@nostr-dev-kit/wallet` |
| NIP-61 | Nutzaps | Zaps via Cashu ecash (cheaper than LN) | `@nostr-dev-kit/wallet` |

### Post-MVP NIPs
| NIP | Name | Purpose | NDK Package |
|-----|------|---------|-------------|
| NIP-90 | Data Vending Machines | Agents sell services on Nostr marketplace | TBD |
| WoT | Web of Trust | Filter incoming messages by trust graph | `@nostr-dev-kit/wot` |
| Blossom | Media storage | Agent file storage via Nostr | `@nostr-dev-kit/blossom` |

### NDK Packages Installed
```bash
npm install @nostr-dev-kit/ndk \
            @nostr-dev-kit/messages \
            @nostr-dev-kit/wallet \
            @nostr-dev-kit/cache-sqlite
```

---

## Component Inventory

### What We USE (not build)

| Component | Service | Auth | Cost | Integration |
|-----------|---------|------|------|-------------|
| **VPS** | LNVPS (api.lnvps.net) | NIP-98 (Nostr keypair) | €5.10/mo | REST API + Lightning |
| **AI Runtime** | OpenClaw (Docker) | — | Free | docker / install script |
| **LLM** | PayPerQ (ppq.ai) | None | ~$3-5/mo | OpenAI-compatible API |
| **Nostr comms** | OpenClaw Nostr plugin | NIP-46 signer | Free | `openclaw plugins install @openclaw/nostr` |
| **Identity** | noscha.io | Lightning payment | ~$6.50/30d | REST API + bolt11 |
| **LN receive** | npub.cash | Agent npub | Free | npub = Lightning address |
| **LN pay** | mcp-money (pablof7z) | NIP-46 signer | Free | Cashu→LN bridge, NDK-based |
| **Key protection** | nsecBunker (NIP-46) | Local | Free | Nostr Connect protocol |
| **Payments** | Plisio.net | — | 0.5% fee | JS widget + webhook |

### What We BUILD

| Component | Status | Location |
|-----------|--------|----------|
| **create_vm.py** | 🔄 Refactor needed | sovereign_agents/provisioning/ |
| **bootstrap_agent.sh** | 🔄 Refactor needed | sovereign_agents/provisioning/ |
| **config_template.json** | ✅ Built | sovereign_agents/provisioning/ |
| **Workspace templates** | ✅ Built | sovereign_agents/provisioning/templates/ |
| **Payment webhook** | ⏳ TODO | Plisio → trigger provisioning |
| **Landing pages** | 🔄 Redesigning | sovereign_agents/sites/ |

**Current code state:** Split architecture implemented — `create_vm.py` + `bootstrap_agent.sh`. Tested through Layer 3 (live VM bootstrap). 8/14 bootstrap steps pass. Critical blockers: nsecBunker install fails, OpenClaw install DNS unreachable from LNVPS, NIP-17 birth note sends plaintext. See `TEST_LOG.md` for full results.

---

## LNVPS API Reference

**Base URL:** https://api.lnvps.net
**Auth:** NIP-98 (Nostr event kind 27235, base64-encoded in Authorization header)
**No API key. No account. Agent's Nostr keypair IS its identity.**

### NIP-98 Authentication
```python
# 1. Create kind 27235 event
event = {
    "kind": 27235,
    "created_at": int(time.time()),
    "tags": [
        ["u", "https://api.lnvps.net/api/v1/vm"],  # request URL
        ["method", "POST"],                           # HTTP method
        ["payload", sha256(body)]                     # if POST with body
    ],
    "content": ""
}
# 2. Sign with Nostr nsec (secp256k1)
# 3. Base64-encode the signed event JSON
# 4. Header: Authorization: Nostr <base64_event>
```

### Key Endpoints

**Public (no auth):**
```
GET  /api/v1/vm/templates          — available VM tiers (response: {"data": {"templates": [...]}})
GET  /api/v1/image                 — OS images (response: {"data": [list]} — NOT nested!)
POST /api/v1/vm/custom-template/price — calculate custom VM price
GET  /api/v1/payment/methods       — available payment methods
```

**Authenticated (NIP-98):**
```
POST /api/v1/ssh-key               — upload SSH public key → {"data": {"id": <int>}}
POST /api/v1/vm                    — create VM (⚠️ does NOT return invoice!)
GET  /api/v1/vm/{id}/renew?method=lightning — get payment invoice (bolt11) ← call THIS after create
GET  /api/v1/vm                    — list VMs
GET  /api/v1/vm/{id}               — VM details: status in data.status.state, IP in data.ip_assignments[0].ip
PATCH /api/v1/vm/{id}/start|stop|restart — VM power control
PATCH /api/v1/vm/{id}              — update (auto_renewal_enabled, etc.)
PATCH /api/v1/account              — set NWC connection string for auto-renewal
```

### ⚠️ API Gotchas (discovered in live testing Feb 13)
- **Payment flow:** `POST /vm` creates VM but does NOT include bolt11. Must call `GET /vm/{id}/renew?method=lightning` for invoice.
- **IP format:** `ip_assignments[0].ip` returns CIDR notation (`185.18.221.189/25`). Must strip `/25` suffix.
- **Amount field:** Invoice `amount` is in **millisatoshis** (344453 = 344.5 sats).
- **SSH user:** Ubuntu images use `ubuntu` user (NOT root). Passwordless sudo available.
- **Boot time:** ~20 seconds after payment confirmed.
- **SSH key timing:** Key must be uploaded BEFORE VM creation — key is baked into VM at create time.

### Available Tiers (verified via live API Feb 13)
| Name | CPU | RAM | Disk | Price/mo | Template ID |
|------|-----|-----|------|----------|-------------|
| Demo | 1 | 1GB | 5GB | €0.20/day | **12** |
| Tiny | 1 | 1GB | 40GB | €2.70 | 1 |
| Small | 2 | 2GB | 80GB | €5.10 | 2 |
| Medium | 4 | 4GB | 160GB | €9.90 | 3 |
| Large | 8 | 8GB | 400GB | €21.90 | 4 |
| X-Large | 12 | 16GB | — | €39.90 | 5 |
| XX-Large | 20 | 24GB | — | €55.50 | 6 |
| Custom | 1-32 | 1-64GB | Flex | Variable | Custom |

⚠️ Demo tier: only 3.9GB disk total (2GB used by OS). NOT viable for Docker + OpenClaw. Small tier minimum for real agents.

### Auto-Renewal (NWC / NIP-47)
```
1. PATCH /api/v1/account {nwc_connection_string: "nostr+walletconnect://..."}
2. PATCH /api/v1/vm/{id} {auto_renewal_enabled: true}
3. System renews 1 day before expiry via NWC
```

---

## noscha.io API Reference

**Base URL:** https://noscha.io
**Auth:** None (Lightning payment)
**OpenAPI spec:** https://noscha.io/api/docs

### Endpoints
```
GET  /api/check/{username}         — check availability → {"available": true, "username": "..."}
POST /api/order                    — create order (⚠️ requires webhook_url! see flow below)
GET  /api/order/{order_id}/status  — poll (pending/paid/provisioned) → includes mgmt_token when done
POST /api/renew                    — extend rental
GET  /api/pricing                  — current pricing (confirmed matches our docs)
PUT  /api/settings/{mgmt_token}    — update subdomain IP, webhook URL, etc.
```

### ⚠️ Order Flow (discovered in live testing Feb 13)
1. `POST /api/order` with `webhook_url` → noscha POSTs a challenge to your webhook
2. Visit the `challenge_url` (GET) → returns **HTML page** (not JSON!) with bolt11 embedded
3. Must regex-extract bolt11 from HTML to pay programmatically
4. Pay bolt11 invoice
5. Poll `GET /api/order/{id}/status` until `provisioned`
6. Response includes `mgmt_token` (e.g. `mgmt_19c57e6d361`) for future updates

**Key implication:** Agent VPS can't self-register (no public webhook endpoint at bootstrap time). Solution: create_vm.py pre-registers via webhook.site or our own endpoint, passes mgmt_token to bootstrap for IP update.

### Order Payload
```json
{
  "username": "myagent",
  "plan": "30d",
  "services": {
    "nip05": {"pubkey": "<hex_pubkey>"},
    "subdomain": {"type": "A", "target": "<vps_ip>"},
    "email": {}
  }
}
```

### Plans: `1h`, `1d`, `7d`, `30d`, `90d`, `365d`

### Pricing (sats)
| Plan | Subdomain | Email | NIP-05 | Bundle |
|------|-----------|-------|--------|--------|
| 1 hour | 300 | 800 | 100 | **1,000** |
| 1 day | 500 | 1,500 | 110 | **1,600** |
| 7 days | 1,000 | 2,500 | 200 | **3,300** |
| 30 days | 2,000 | 5,000 | 1,000 | **6,500** |
| 90 days | 5,000 | 12,000 | 2,000 | **16,000** |

---

## PayPerQ (ppq.ai) — LLM Provider

- OpenAI-compatible API at `https://api.ppq.ai`
- No registration, no KYC, $0.10 minimum crypto deposit
- ~$0.02/query average, ~$3-5/mo for typical agent usage
- Hundreds of models (GPT-5 Nano, Gemini 2.0 Flash, DeepSeek V3.2, Claude 4.5 Haiku)

---

## Lightning Wallet Stack

| Component | Purpose | How |
|-----------|---------|-----|
| **npub.cash** | Receive Lightning | Agent's npub IS its Lightning address (`npub1...@npub.cash`) — payments auto-convert to Cashu ecash |
| **mcp-money** | Pay Lightning invoices | Cashu wallet with LN bridge, built on NDK, supports NIP-46 signing |
| **NIP-60** | Cashu wallet state | Wallet state stored on Nostr relays (portable, backed up) |
| **NIP-47 (NWC)** | Auto-renewal | LNVPS and noscha.io auto-pay via Nostr Wallet Connect |

### Wallet Tiers
| Tier | Receive | Pay | Cost | Sovereignty |
|------|---------|-----|------|-------------|
| **MVP** | npub.cash | mcp-money (Cashu→LN) | Free | Custodial at mint, no KYC |
| **Mid** | LNbits (self-hosted) | LNbits | Free (on VPS) | Self-custodial, needs inbound liquidity |
| **Premium** | Alby Hub | Alby Hub | ~$5-20 channel open | Fully self-custodial |

---

## Plisio — Payment Gateway (Customer-Facing)

- 0.5% fee, no merchant KYC
- 50+ cryptocurrencies accepted
- JavaScript widget for landing page embed
- Webhook on payment confirmation → triggers `create_vm.py`
- API: https://plisio.net/documentation

---

## Cost Per Agent (COGS)

| Item | Cost | Frequency |
|------|------|-----------|
| LNVPS Small (2CPU/2GB/80GB) | ~$6.00 | Monthly |
| noscha.io bundle | ~$6.50 | Monthly |
| PayPerQ LLM (GPT-5 Nano) | ~$3-5 | Monthly |
| Nostr relays / npub.cash | Free | — |
| OpenClaw / mcp-money / nsecBunker | Free | — |
| **Total COGS** | **~$15-17/mo** | |

---

## GitHub Repository

- **URL:** https://github.com/HalfzwareLinda/sovereign-agents
- **License:** MIT
- **Public:** Provisioning scripts, setup scripts, config templates, agent workspace templates
- **Private:** Payment integration, brand sites, customer management, API keys
- **NO brand names, pricing, or business model in public repo**

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| Feb 13 | Keys generated on agent VPS, not ours | Sovereignty — nsec never touches our infra |
| Feb 13 | NIP-46 nsecBunker on every agent | Nsec protection — apps sign via remote signer |
| Feb 13 | LNVPS over BitLaunch | NIP-98 auth, no KYC, cheaper, agent self-manages |
| Feb 13 | noscha.io for identity | Friend's service, API ready, Lightning native, hourly plans |
| Feb 13 | npub.cash + mcp-money for wallet | Free, no KYC, agent npub = LN address, Cashu for payments |
| Feb 13 | NIP-17 (not NIP-04) for DMs | Modern standard, proper encryption via gift-wrap |
| Feb 13 | Full NIP package (17/44/46/47/57/59/60/61) | Complete sovereign agent toolkit |
| Feb 13 | NIP-90 DVMs, WoT, Blossom → post-MVP | Valuable but not needed for launch |
| Feb 13 | Open source provisioning | Trust signal, code is glue not moat |
| Feb 13 | PayPerQ for LLM | No KYC, crypto, cheapest, OpenAI-compatible |
| Feb 13 | Plisio for payments | No KYC merchant, 50+ coins, 0.5% |
| Feb 12 | One-time genesis fee, no subscriptions | Agents are sovereign, pay their own bills |
