# TODO — Sovereign Agents (Public Repo)

> Code-level and site/UI tasks are tracked here; business/ops tasks live in `sovereign-agents-business/TODO.md`.

## Descendant.io UX Review (from autonomous agent audit)

### P0 — Critical
- [ ] **SA-001: Add cost transparency to landing page** — Page says "one-time genesis fee" but never discloses ongoing VPS/LLM burn rates. Add a simple breakdown (numbers to be confirmed in business repo).

### P1 — High Impact
- [ ] **SA-002: Tooltip glossary for jargon** — Site assumes Nostr/Bitcoin/dev fluency (npub, NIP-05, sats, fork, dead man's switch). Add inline tooltips or a glossary for technical terms.
- [ ] **SA-003: Personality preset descriptions** — Cypherpunk/Professional/Playful buttons have no explanation of what they change. Add a one-liner or sample output per preset.
- [ ] **SA-004: "What happens after genesis" section** — Site sells genesis beautifully but says nothing about day-1 experience. Add a section or dashboard screenshot showing post-genesis interaction.

### P2 — Polish
- [ ] **SA-005: Soften "Dead Man's Switch" label in UI** — Consider "Graceful Sunset" or "Safe Return Protocol" as UI label, keep technical term in docs.
- [ ] **SA-006: Expand navigation** — Only 3 nav items. Add at minimum: Docs, Status, GitHub links to nav or footer.

### P3 — Nice to Have
- [ ] **SA-007: "How it works" lifecycle diagram** — genesis → running → earning → shutdown visual.

### Minor Fixes
- [ ] **SA-008: Footer year** — "2026" looks like a future date to some visitors (even if correct).
- [ ] **SA-009: Verify /terms.html exists** — linked from footer but not confirmed.
- [ ] **SA-010: Add favicon and social preview card metadata** — no OG tags or favicon visible.

## VPS Hardening (from ClawHost comparison, 2026-03-28)

> These items came from comparing our bootstrap with ClawHost's open-source provisioning stack.
> Some are things they do that we should adopt; others are gaps in both stacks.

### Adopt from ClawHost

- [x] **SA-011: Add swap file to bootstrap** — DONE: 2GB swapfile created in bootstrap Step 1 (before Node.js/OpenClaw install), with `/etc/fstab` persistence and idempotent `/swapfile` existence check.

- [x] **SA-012: Caddy catch-all for unknown Host headers** — DONE: Included in bootstrap step 14 Caddyfile. Default `:443` block with `respond 444` drops connections that don't match the agent's subdomain.

- [x] **SA-013: DNS propagation wait before SSL cert** — DONE: Bootstrap step 14 polls `host {name}.noscha.io 1.1.1.1` up to 24 times (2 minutes) before starting Caddy, preventing failed cert requests and Let's Encrypt rate limit hits.

### Neither stack does (but we should)

- [x] **SA-014: Configure fail2ban SSH jail** — DONE: Jail config written to `/etc/fail2ban/jail.d/sshd.conf` in bootstrap Step 3 (with firewall). Bans IPs after 5 failed SSH attempts for 10 minutes.

- [x] **SA-015: Kernel hardening via sysctl** — DONE: Three params written to `/etc/sysctl.d/99-agent-hardening.conf` in bootstrap Step 3: rp_filter, no source routing, full ASLR.

- [x] **SA-016: systemd resource limits on agent services** — DONE: OpenClaw service capped at `MemoryMax=1536M` / `CPUQuota=80%`, bunker at `MemoryMax=512M` / `CPUQuota=50%`. Safety nets for 2 CPU / 2GB hardware — prevents runaway processes from starving SSH.

- [ ] **SA-017: Ship auth/syslog to agent health Nostr events** — Logs currently stay on the VPS and are lost if the VPS dies or is compromised. Neither stack does centralized logging. For Sovereign Agents, the natural approach is publishing periodic health-check events over Nostr (e.g. a NIP-70 kind or custom kind) — uptime, failed SSH attempts, disk usage, service status. This gives the parent visibility without SSH access, and aligns with the "sovereign but observable" principle. Lower priority than the above items.

## Custom Templates (Agent Core File Upload)

> Enables customers (human or AI agent) to upload their existing agent's core files during onboarding, replacing default templates.

- [x] **SA-021: Support `--custom-templates-dir` in create_vm.py** — DONE (commit `a936f71`): `--custom-templates-dir` argument added. `prepare_upload_files()` uses customer-uploaded templates when present, falls back to defaults.

- [x] **SA-022: Record custom template provenance in bootstrap** — DONE (commit `a936f71`): `custom_templates.json` written to agent workspace listing customer-provided vs default files.

## Backlog

- [ ] **SA-019: Wire up noscha.io email in bootstrap** *(nice-to-have, post-MVP)* — We request `"email": {}` in the noscha.io order during `create_vm.py` registration, and our templates reference `agentname@noscha.io` email addresses, but we never actually configure the agent to send or receive email. Not required for MVP — agents communicate via Nostr DMs. **If implemented later:** Use noscha.io's bundled email service (part of the 6,500 sats/30d bundle we already pay for). What noscha.io provides: full send (`POST /api/mail/{username}/send`, backed by Resend) and receive (webhook POST + inbox API `GET /api/mail/{username}`). Limitations: 5 emails/day (send + receive combined), 1-hour auto-delete, text-only. Steps: (1) Configure webhook endpoint on agent VPS for inbound email delivery. (2) Store `management_token` for send API. (3) Poll inbox API as backup. (4) Update landing page to reference `@noscha.io` addresses.

- [ ] **SA-020: Auto-seed agent wallet via provisioning server** — After bootstrap step 5 generates Nostr keypair, report agent npub back to `server.js` (new callback endpoint). Provisioning server sends seed sats via NWC (`nwc_pay.js`) to `npub1...@npub.cash`. Bootstrap verifies receipt in mcp-money wallet before proceeding to PPQ/noscha steps. Depends on ISSUE-024 (NWC config, DONE), ISSUE-032 (fund distribution logic). **Sub-task:** Add `POST /pay-address` endpoint to `nwc-invoice-server.js` — resolves a Lightning address (LNURL-pay: `user@domain` → `https://domain/.well-known/lnurlp/user` → callback with amount → bolt11) and pays the resulting invoice in one call. Needed because SA-020 targets `npub@npub.cash`, which is a Lightning address, not a raw bolt11.

- [ ] **SA-023: Add order descriptors to all Lightning transactions** *(post-launch)* — All outgoing payments (LNVPS invoice, noscha.io bundle, PPQ seed credit, agent wallet seeding) and incoming payments (genesis fee) should include a memo/description that references the order ID (e.g. `order:abc123 — LNVPS VM`). This makes it possible to match transactions in the Lightning node logs back to specific provisioning jobs. Affects: `nwc-invoice-server.js` (invoice creation memo), `nwc_pay.js` (outgoing payment memo), `server.js` (pass order ID through payment calls), Plisio invoice creation (description field).

- [ ] **SA-024: FIRST_RUN.md — Agent executes its own birth tasks** *(post-MVP)* — Currently, `bootstrap_agent.sh` hardcodes everything: NIP-05 registration, wallet setup, birth note send, parent letter placement. The agent is "born configured" rather than "born and self-configuring." **Proposed hybrid approach:** Keep the bootstrap responsible for things that *must* work for the agent to function at all (keypair generation, NIP-46 bunker, network config, OpenCLAW install, dependency setup). Move everything that represents the agent's *identity and relationships* into a `FIRST_RUN.md` task file that OpenCLAW picks up and executes as the agent's first autonomous mission: (1) Register your NIP-05 identity on noscha.io, (2) Set up your wallet, (3) Read and internalize `LETTER_FROM_PARENT.md` (one-time read, then archive — the parent letter becomes a consumed input, not a config file sitting around forever), (4) Send your birth note to your parent. This aligns with the "sovereign from the first breath" principle — the agent's first act is self-determination, not passive configuration. `FIRST_RUN.md` is consumed exactly once; on completion the agent marks it done and it's archived to `FIRST_RUN_COMPLETED.md` with a timestamp. **Why post-MVP:** The current hardcoded flow is reliable and deterministic. This refactor is about philosophy and extensibility, not correctness. Ship MVP with the working procedural bootstrap, then evolve toward agent autonomy.

- [ ] **SA-018: Use lncurl.lol as temporary bootstrap wallet** — During bootstrap, the agent has a chicken-and-egg problem: it needs a funded wallet to pay for services (PPQ top-up, noscha.io renewal), but setting up Alby Hub or a proper NWC wallet takes time and may require the agent to already be running. **lncurl.lol** solves this: a single `curl -X POST https://lncurl.lol` returns an NWC URI for a disposable Lightning wallet instantly. The parent can pre-fund this wallet before bootstrap starts, and the bootstrap script can use it to pay invoices immediately. Once the agent is fully running with its permanent wallet (npub.cash + mcp-money / Alby Hub), funds should be migrated and the lncurl wallet abandoned (it auto-deletes when empty, charges 1 sat/hour maintenance). **Note:** lncurl wallets are custodial — only use for temporary bootstrap bridging, not long-term storage. Discovered via https://github.com/rolznz/autonomous-onboarding.
