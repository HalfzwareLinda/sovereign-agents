# Sovereign Agents — Public Repo

## Project Overview

Sovereign Agents provisions autonomous AI agents on sovereign VPS infrastructure, paid via Bitcoin Lightning. This repo contains the open-source provisioning pipeline: bootstrap scripts, VM creation, NIP-46 bunker, birth notes, and agent templates.

GitHub: `HalfzwareLinda/sovereign-agents` (public)

## Sibling Repo

The private business repo lives alongside this one in the workspace:
- **Path**: `../sovereign-agents-business/`
- **Contains**: pricing, landing sites, payment handlers, specs, and — critically — the issue tracker and task list
- **ISSUES.md**: `../sovereign-agents-business/ISSUES.md` — all open issues (ISSUE-001 to ISSUE-021) with test matrix
- **TODO.md**: `../sovereign-agents-business/TODO.md` — actionable checklist

When working on code in this repo, always check the sibling for related issues, context, and specs. Many issues reference files in this repo by path and line number.

## Key Files

| File | Purpose |
|------|---------|
| [bootstrap_agent.sh](bootstrap_agent.sh) | Main bootstrap script — provisions a fresh VPS into a working agent |
| [create_vm.py](create_vm.py) | LNVPS API integration — creates VMs via NIP-98 auth |
| [ppq_provision.py](ppq_provision.py) | PPQ.ai LLM API key provisioning |
| [nip46-server.js](nip46-server.js) | NIP-46 remote signing bunker |
| [send_birth_note.js](send_birth_note.js) | NIP-17 encrypted birth note to parent |
| [config_template.json](config_template.json) | OpenClaw gateway config template |
| [templates/](templates/) | Agent identity templates (SOUL.md, IDENTITY.md, LETTER.md, etc.) |
| [FUNCTIONAL_DESIGN.md](FUNCTIONAL_DESIGN.md) | Functional design document |
| [TECH_STACK.md](TECH_STACK.md) | Technology stack overview |
| [SECURITY_REVIEW_GUIDE.md](SECURITY_REVIEW_GUIDE.md) | Security review checklist |

## Bootstrap Flow

```
create_vm.py (LNVPS API)
  → SSH into fresh VPS
  → bootstrap_agent.sh:
      1. System setup (user, packages)
      2. Key generation (Nostr, BTC, ETH)
      3. NIP-46 bunker setup
      4. PPQ LLM provisioning
      5. Noscha.io NIP-05 registration
      6. OpenClaw install + config
      7. Birth note to parent
      8. Health check
```

## Tech Stack

- **VPS**: LNVPS (Bitcoin Lightning paid VPS)
- **AI Gateway**: OpenClaw
- **LLM**: PPQ.ai (provisioned per-agent)
- **Signing**: NIP-46 remote signer (bunker)
- **Identity**: Noscha.io NIP-05
- **Wallets**: BIP-84 BTC, ETH (optional)
- **Comms**: NIP-17 encrypted DMs (birth notes)
