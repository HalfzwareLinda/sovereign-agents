# Done — Sovereign Agents (Public Repo)

## Bootstrap & Provisioning

- [x] **OpenClaw interactive wizard hang fix** — config pre-written before installer (commit `7e2e570`)
- [x] **PPQ retry logic** — 3x retry + graceful skip if down (commit `7e2e570`)
- [x] **Gateway log path** — changed from /var/log/ to /home/agent/ (commit `a811502`)
- [x] **Birth note relay timeout** — added timeout wrapper (commit `a811502`)
- [x] **Node 20 to 22 upgrade** — OpenClaw requires >=22.12.0, bootstrap now installs Node 22 LTS (2026-02-25)
- [x] **OpenClaw 3-stage install fallback** — npm global, git clone, Docker image replaces broken curl installer (2026-02-25)
- [x] **OpenClaw systemd service** — `agent-openclaw.service` replaces ad-hoc startup (2026-02-25)
- [x] **`__DEFAULT_MODEL__` placeholder** — added to `replace_placeholders()`, openclaw.json renders correctly (2026-02-25)
- [x] **`__PARENT_WISDOM__` placeholder** — added input file + sed substitution for LETTER.md (2026-02-25)
- [x] **`requests` pip package missing** — added to pip3 install line for ppq_provision.py (2026-02-25)

## HTTPS & Reverse Proxy (2026-03-28)

- [x] **SA-012: Caddy catch-all for unknown Host headers** — Default `:443` block with `respond 444` in bootstrap Caddyfile (step 14).
- [x] **SA-013: DNS propagation wait before SSL cert** — Bootstrap polls `host {name}.noscha.io 1.1.1.1` up to 24 times (2 min) before starting Caddy.
- [x] **ISSUE-002: HTTPS on agent webchat** — Caddy reverse proxy added as bootstrap step 14/15. Auto-provisions Let's Encrypt TLS, `WEBCHAT_URL` set to `https://{name}.noscha.io`.

## Security

- [x] **BTC wallet derivation** — proper BIP-84 (PBKDF2 -> HMAC-SHA512 -> m/84'/0'/0'/0/0)
- [x] **ETH wallet fallback** — skips ETH wallet instead of generating invalid address
- [x] **NIP-17 birth note encryption** — uses NDK sendDM() with NIP-17 gift wrapping
- [x] **NIP-46 bunker auth** — validates shared secret on every request
- [x] **Input sanitization** — sed_escape() sanitizes all user inputs before sed replacement
- [x] **nsec log leak** — redacted from bootstrap output
- [x] **SSH key removal** — properly deleted after bootstrap
- [x] **Key file permissions** — all key files chmod 600
- [x] **Cron token security** — noscha renewal token properly protected
- [x] **Hardcoded auth tokens** — replaced with env-only (2026-02-15)
- [x] **Hardcoded IPs in functions** — replaced with env vars (2026-02-15)
- [x] **Agent can't read its own keys (ISSUE-003)** — `agent_public.json` with public-only info, owned by agent user (2026-02-25)

## Reliability

- [x] **LNVPS template ID silent fallback (ISSUE-007)** — raises RuntimeError instead of guessing wrong IDs (2026-02-25)
- [x] **Demo tier OOM** — trial tier maps to "small" (2GB RAM) instead of demo (1GB)

## LNVPS Integration (2026-03-23)

- [x] **Persistent LNVPS operator keypair** — `create_vm.py` now loads a dedicated Nostr keypair from `.env` for NIP-98 auth instead of generating throwaway keys. All VMs registered under one verifiable identity (`b5b7529`, 2026-03-23)

## Foundational Build-Out (2026-02-13 — 2026-02-15)

- [x] **Provisioning system** — Full 12-step bootstrap: `provision_agent.py`, `setup_agent.sh`, templates, `config_template.json` (`e9b784e`, 2026-02-13)
- [x] **PPQ auto-provisioning, NWC payments, birth note** — `ppq_provision.py`, `nwc_pay.js`, `send_birth_note.js`, NIP-46 NDK fix, template placeholder system (`cba852a`, 2026-02-13)
- [x] **create_vm.py orchestrator** — LNVPS API integration + birth note design doc (`b819ec1`, 2026-02-13)
- [x] **Personality/mission passthrough** — Args added to `create_vm.py`, noscha bolt11 extraction fix, PPQ `--create-only` flag, `server.js` provisioning callback (`1668a49`, 2026-02-13)
- [x] **Docs and package.json** — Added `FUNCTIONAL_DESIGN.md`, `SECURITY_REVIEW_GUIDE.md`, `TECH_STACK.md`; removed deprecated `provision_agent.py` (`0db35c7`, 2026-02-15)
- [x] **External audit prep** — Renamed `setup_agent.sh` to `bootstrap_agent.sh`, removed `MASTER_SPEC.md` from public repo, README rewrite (`b0771bd`, 2026-02-15)
