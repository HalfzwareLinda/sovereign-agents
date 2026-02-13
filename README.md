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

```
provision_agent.py runs →
  1. Generate Nostr keypair (agent's sovereign identity)
  2. Generate SSH keypair (VPS access)
  3. Register identity on noscha.io → pay Lightning invoice
  4. Create VPS on LNVPS (agent's own Nostr key = auth) → pay Lightning invoice
  5. SSH in, install OpenClaw, configure agent
  6. Agent comes online, contacts parent via Nostr DM
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

# Dry run — simulates everything, no real API calls
python provision_agent.py --name "myagent" --parent-npub "npub1..." --dry-run

# Real deployment
python provision_agent.py --name "myagent" --parent-npub "npub1..." --tier small
```

## VPS Tiers (via LNVPS)

| Tier | Specs | Monthly Cost |
|------|-------|-------------|
| demo | 1CPU, 1GB, 5GB | €0.20/day |
| tiny | 1CPU, 1GB, 40GB | €2.70/mo |
| small | 2CPU, 2GB, 80GB | €5.10/mo |
| medium | 4CPU, 4GB, 160GB | €9.90/mo |

## Project Structure

```
├── provision_agent.py      # Main provisioning orchestrator
├── setup_vps.sh            # Remote setup script (runs on VPS via SSH)
├── config_template.json    # OpenClaw config template
├── templates/              # Agent workspace file templates
│   ├── SOUL.md
│   ├── AGENTS.md
│   ├── IDENTITY.md
│   ├── LETTER.md
│   └── WALLET.md
└── requirements.txt
```

## Key Features

- **NIP-98 auth** — agent's Nostr keypair authenticates with LNVPS. No API keys needed.
- **Truly sovereign** — agent can manage its own VPS, renew via NWC auto-pay from its own wallet.
- **Memory inheritance** — parent can pass SOUL.md, MEMORY.md, and a personal letter to the new agent.
- **Dry-run mode** — test the full flow without spending anything.
- **No KYC anywhere** — Nostr + Lightning from top to bottom.

## Contributing

Issues and PRs welcome. This is the provisioning layer — the glue that connects existing services into a one-click agent deployment.

## License

MIT
