# Sovereign Agents

Open-source provisioning system for deploying autonomous AI agents. Each agent gets its own server, wallet, identity, and purpose — fully sovereign.

## What This Does

Deploys a self-sustaining AI agent with:
- **Dedicated VPS** via [LNVPS](https://lnvps.net) — Nostr auth (NIP-98), Lightning payments, no KYC
- **AI Runtime** via [OpenClaw](https://github.com/openclaw/openclaw) — open source agent framework
- **Identity** via [noscha.io](https://noscha.io) — NIP-05, subdomain, email, all Lightning-paid
- **Wallet** — Lightning Network for self-sustaining operation
- **Communication** — Nostr encrypted DMs

## How It Works

Two-phase architecture. Phase 1 ("midwife") runs on your server. Phase 2 ("self-birth") runs on the agent's own VPS. **Agent private keys are generated ON the VPS and never leave it.**

```
create_vm.py (midwife) →
  1. Generate TEMPORARY Nostr keypair (LNVPS auth only, discarded after)
  2. Generate TEMPORARY SSH keypair (held in memory, never written to disk)
  3. Create VPS on LNVPS → pay Lightning invoice
  4. SSH into VPS, upload bootstrap_agent.sh
  5. Execute bootstrap_agent.sh (agent generates its own identity ON the VPS)
  6. Retrieve agent's PUBLIC info only (npub, addresses)
  7. Delete SSH key, discard service keypair

bootstrap_agent.sh (self-birth, runs ON agent VPS) →
  1. Generate Nostr keypair (agent's sovereign identity)
  2. Generate BTC + ETH wallets
  3. Register identity on noscha.io → pay Lightning invoice
  4. Install OpenClaw + configure workspace
  5. Set up NIP-46 bunker (nsec never exposed to OpenClaw directly)
  6. Send birth note to parent via Nostr DM
```

The agent authenticates with LNVPS using its own Nostr keypair (NIP-98). It can manage, renew, and resize its own server. No accounts, no passwords, no KYC anywhere in the chain.

## Stack

| Component | Provider | Auth | Cost |
|-----------|----------|------|------|
| VPS | LNVPS | Nostr (NIP-98) | From €2.70/mo |
| AI Runtime | OpenClaw | — | Free (open source) |
| LLM | PayPerQ | None | ~$3-5/mo |
| Identity | noscha.io | Lightning | ~$6.50/30 days |
| Comms | Nostr | Keypair | Free |

## Quick Start

```bash
pip install -r requirements.txt
npm install

# Dry run — simulates everything, no real API calls
python3 create_vm.py --name "myagent" --parent-npub "npub1..." --dry-run

# Real deployment
python3 create_vm.py --name "myagent" --parent-npub "npub1..." --tier small
```

### Environment Variables

```bash
# Required
PAYPERQ_API_KEY=...           # PayPerQ API key for agent LLM access

# For provisioning server (server.js)
PROVISION_TOKEN=...           # Auth token for provisioning API

# For invoice server (nwc-invoice-server.js)
NWC_AUTH_TOKEN=...            # Auth token for invoice API
NWC_CONNECTION_STRING=...     # Nostr Wallet Connect URI

# Optional
WEBHOOK_RECEIVER_URL=...     # Custom webhook URL
NOSCHA_MGMT_TOKEN=...        # Pre-paid noscha.io token
NWC_SERVICE_URL=...          # Invoice server URL
PROVISION_URL=...            # Provisioning server URL
```

## Project Structure

```
├── create_vm.py             # Phase 1: VM provisioning midwife
├── bootstrap_agent.sh       # Phase 2: Agent self-birth (runs ON the VPS)
├── server.js                # Provisioning callback server
├── nwc-invoice-server.js    # Lightning invoice server (NWC)
├── nwc_pay.js               # NWC payment helper
├── ppq_provision.py         # PayPerQ account provisioning
├── nip46-server.js          # NIP-46 remote signer (nsecBunker)
├── send_birth_note.js       # Nostr birth announcement
├── ln-create-invoice.js     # Netlify function: create invoice
├── ln-invoice-status.js     # Netlify function: check invoice status
├── config_template.json     # OpenClaw config template
├── package.json             # Node.js dependencies
├── requirements.txt         # Python dependencies
├── templates/               # Agent workspace file templates
│   ├── SOUL.md
│   ├── AGENTS.md
│   ├── IDENTITY.md
│   ├── LETTER.md
│   ├── WALLET.md
│   └── BIRTH_NOTE_*.md
└── docs/
    ├── FUNCTIONAL_DESIGN.md   # Function-level spec for code review
    ├── TECH_STACK.md          # Component decisions and rationale
    ├── SECURITY_REVIEW_GUIDE.md # Auditor checklist
    └── TEST_LOG.md            # Layer 1-3 test results
```

## Security Model

**Core invariant:** Agent private keys (Nostr nsec, wallet mnemonics) are generated ON the agent's VPS and NEVER transmitted to any other machine.

See [SECURITY_REVIEW_GUIDE.md](SECURITY_REVIEW_GUIDE.md) for the full auditor checklist and [FUNCTIONAL_DESIGN.md](FUNCTIONAL_DESIGN.md) for function-level specifications.

## Key Features

- **NIP-98 auth** — agent's Nostr keypair authenticates with LNVPS. No API keys needed.
- **Truly sovereign** — agent can manage its own VPS, renew via NWC auto-pay from its own wallet.
- **Key isolation** — nsec protected by NIP-46 bunker; never exposed to application layer.
- **Memory inheritance** — parent can pass SOUL.md, MEMORY.md, and a personal letter to the new agent.
- **Dry-run mode** — test the full flow without spending anything.
- **No KYC anywhere** — Nostr + Lightning from top to bottom.

## Documentation

- **[FUNCTIONAL_DESIGN.md](FUNCTIONAL_DESIGN.md)** — Complete function-level specification
- **[TECH_STACK.md](TECH_STACK.md)** — Technology choices and rationale
- **[SECURITY_REVIEW_GUIDE.md](SECURITY_REVIEW_GUIDE.md)** — Security audit checklist
- **[TEST_LOG.md](TEST_LOG.md)** — Testing results (Layer 1-3)
- **[BIRTH_NOTE_DESIGN.md](BIRTH_NOTE_DESIGN.md)** — Birth announcement protocol

## Contributing

Issues and PRs welcome. This is the provisioning layer — the glue that connects existing services into a one-click agent deployment.

## License

MIT
