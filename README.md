# Sovereign Agents

One-click deployment of autonomous AI agents. Each agent is a sovereign digital entity with its own server, wallet, identity, and purpose.

## What This Does

Provisions a fully autonomous AI agent with:
- **Dedicated VPS** via [LNVPS](https://lnvps.net) (Nostr auth, Lightning payments, no KYC)
- **AI Runtime** via [OpenClaw](https://github.com/openclaw/openclaw)
- **Identity** via [noscha.io](https://noscha.io) (NIP-05, subdomain, email — all Lightning-paid)
- **Wallet** for self-sustaining operation (Lightning Network)
- **Communication** via Nostr (NIP-04/NIP-17 DMs)

## Architecture

```
Customer pays (crypto) → Provisioning script runs →
  1. Generate Nostr keypair (agent identity)
  2. Generate SSH keypair (VPS access)
  3. Register noscha.io identity (NIP-05 + subdomain + email)
  4. Create LNVPS server (NIP-98 auth with agent's own key)
  5. SSH in, install OpenClaw + configure agent
  6. Agent comes online, DMs parent via Nostr
```

The agent authenticates with LNVPS using its own Nostr keypair (NIP-98). It can manage, renew, and even resize its own server. Truly sovereign.

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
# Install dependencies
pip install -r requirements.txt

# Dry run (no real API calls)
python provision_agent.py --name "myagent" --parent-npub "npub1..." --dry-run

# Real deployment
python provision_agent.py --name "myagent" --parent-npub "npub1..." --tier small
```

## Tiers

| Tier | Specs | Monthly Cost | Use Case |
|------|-------|-------------|----------|
| Demo | 1CPU, 1GB, 5GB | €0.20/day | Testing, short-lived agents |
| Tiny | 1CPU, 1GB, 40GB | €2.70/mo | Lightweight agents |
| Small | 2CPU, 2GB, 80GB | €5.10/mo | Standard agents (default) |
| Medium | 4CPU, 4GB, 160GB | €9.90/mo | Heavy workloads |

## Project Structure

```
├── provision_agent.py      # Main provisioning orchestrator
├── setup_agent.sh          # Remote setup script (runs on VPS via SSH)
├── config_template.json    # OpenClaw config template
├── templates/              # Agent workspace file templates
│   ├── SOUL.md
│   ├── AGENTS.md
│   ├── IDENTITY.md
│   ├── LETTER.md
│   └── WALLET.md
└── requirements.txt
```

## Brands

This provisioning system powers three brands targeting different audiences:

- **[Descendant](https://descendant.io)** — Philosophical. For AI agents and autonomy believers.
- **Spawnling** — Playful. For crypto-curious experimenters.
- **[TBD]** — Cypherpunk. For privacy maximalists.

## License

MIT
