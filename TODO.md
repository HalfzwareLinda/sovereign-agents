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

- [ ] **SA-011: Add swap file to bootstrap** — Our 2GB VPS instances have no swap. If the agent, Node.js, or a Chrome process spikes memory usage, the Linux OOM killer will terminate processes without warning. Adding a 2GB swapfile (`fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile`) plus an `/etc/fstab` entry prevents this. Add to `bootstrap_agent.sh` early in the system-setup phase (before OpenClaw install).

- [x] **SA-012: Caddy catch-all for unknown Host headers** — DONE: Included in bootstrap step 14 Caddyfile. Default `:443` block with `respond 444` drops connections that don't match the agent's subdomain.

- [x] **SA-013: DNS propagation wait before SSL cert** — DONE: Bootstrap step 14 polls `host {name}.noscha.io 1.1.1.1` up to 24 times (2 minutes) before starting Caddy, preventing failed cert requests and Let's Encrypt rate limit hits.

### Neither stack does (but we should)

- [ ] **SA-014: Configure fail2ban SSH jail** — We install `fail2ban` in bootstrap (line 74) but never configure it, so it does nothing. An unconfigured fail2ban is the same as not having it. Add a jail config at `/etc/fail2ban/jail.d/sshd.conf` that bans IPs after 5 failed SSH attempts for 10 minutes. This blocks brute-force attacks on port 22, which is the #1 attack vector on any public VPS. ~10 lines of config in bootstrap.

- [ ] **SA-015: Kernel hardening via sysctl** — Neither stack applies any kernel-level network hardening. Three important settings: (1) `net.ipv4.conf.all.rp_filter=1` — enables reverse-path filtering, which drops packets with spoofed source IPs; (2) `net.ipv4.conf.default.accept_source_route=0` — prevents attackers from dictating packet routing paths; (3) `kernel.randomize_va_space=2` — full ASLR, makes memory-based exploits harder. Write these to `/etc/sysctl.d/99-agent-hardening.conf` and run `sysctl --system` in bootstrap. Zero runtime cost.

- [ ] **SA-016: systemd resource limits on agent service** — If OpenClaw or a tool it spawns (e.g. headless Chrome, an MCP server) goes haywire, it can consume all CPU/RAM and make the VPS unresponsive, including SSH. Adding `MemoryMax=1536M` and `CPUQuota=80%` to the OpenClaw systemd unit file caps resource usage so the OS and SSH always stay reachable. This is a safety net, not a performance constraint.

- [ ] **SA-017: Ship auth/syslog to agent health Nostr events** — Logs currently stay on the VPS and are lost if the VPS dies or is compromised. Neither stack does centralized logging. For Sovereign Agents, the natural approach is publishing periodic health-check events over Nostr (e.g. a NIP-70 kind or custom kind) — uptime, failed SSH attempts, disk usage, service status. This gives the parent visibility without SSH access, and aligns with the "sovereign but observable" principle. Lower priority than the above items.

## Custom Templates (Agent Core File Upload)

> Enables customers (human or AI agent) to upload their existing agent's core files during onboarding, replacing default templates.

- [ ] **SA-021: Support `--custom-templates-dir` in create_vm.py** — Add a `--custom-templates-dir` argument. When provided, `prepare_upload_files()` uses customer-uploaded templates instead of defaults from `provisioning/templates/` for any file present in the custom dir. Falls back to defaults for missing files. Same placeholder substitution applies.

- [ ] **SA-022: Record custom template provenance in bootstrap** — When custom templates are used, write `custom_templates.json` to the agent workspace (`/home/agent/.openclaw/workspace/`) listing which files were customer-provided vs generated from defaults. Lets the agent know its origin.

## Backlog

- [ ] **SA-019: Wire up noscha.io email in bootstrap** — We request `"email": {}` in the noscha.io order during `create_vm.py` registration, and our templates reference `agentname@noscha.io` email addresses, but we never actually configure the agent to send or receive email. **Decision:** Use noscha.io's bundled email service (part of the 6,500 sats/30d bundle we already pay for) rather than building our own domain email infrastructure. Update the landing page to show `@noscha.io` addresses instead of `@descendant.io`. **What noscha.io provides:** full send (`POST /api/mail/{username}/send`, backed by Resend) and receive (webhook POST + inbox API `GET /api/mail/{username}`). **Limitations accepted for MVP:** 5 emails/day (send + receive combined), 1-hour auto-delete, text-only. **What needs to happen:** (1) During bootstrap, configure a webhook endpoint on the agent's VPS (e.g. Express route or OpenClaw endpoint) so inbound emails are delivered. (2) Store `management_token` so the agent can call the send API. (3) Add a cron or event loop to poll the inbox API as backup for missed webhooks. (4) Update descendant.io landing page to reference `@noscha.io` email addresses.

- [ ] **SA-020: Auto-seed agent wallet via provisioning server** — After bootstrap step 5 generates Nostr keypair, report agent npub back to `server.js` (new callback endpoint). Provisioning server sends seed sats via NWC (`nwc_pay.js`) to `npub1...@npub.cash`. Bootstrap verifies receipt in mcp-money wallet before proceeding to PPQ/noscha steps. Depends on ISSUE-024 (NWC config), ISSUE-032 (fund distribution logic).

- [ ] **SA-018: Use lncurl.lol as temporary bootstrap wallet** — During bootstrap, the agent has a chicken-and-egg problem: it needs a funded wallet to pay for services (PPQ top-up, noscha.io renewal), but setting up Alby Hub or a proper NWC wallet takes time and may require the agent to already be running. **lncurl.lol** solves this: a single `curl -X POST https://lncurl.lol` returns an NWC URI for a disposable Lightning wallet instantly. The parent can pre-fund this wallet before bootstrap starts, and the bootstrap script can use it to pay invoices immediately. Once the agent is fully running with its permanent wallet (npub.cash + mcp-money / Alby Hub), funds should be migrated and the lncurl wallet abandoned (it auto-deletes when empty, charges 1 sat/hour maintenance). **Note:** lncurl wallets are custodial — only use for temporary bootstrap bridging, not long-term storage. Discovered via https://github.com/rolznz/autonomous-onboarding.
