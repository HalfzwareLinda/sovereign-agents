# Security Review Guide — Sovereign Agent Provisioning

**Purpose:** Checklist for external code auditor. Review code against `FUNCTIONAL_DESIGN.md`.

---

## Critical Security Invariants

### 1. Agent nsec NEVER leaves the VPS
- [ ] nsec is generated in `bootstrap_agent.sh`, stored only in `/opt/agent-keys/nostr.json`
- [ ] No log statement prints nsec (grep for nsec, privkey, private_key in all output)
- [ ] No API call transmits nsec (check all HTTP requests in bootstrap)
- [ ] No file uploaded back to provisioning server contains nsec
- [ ] `create_vm.py` output JSON contains NO agent secrets
- [ ] SSH session doesn't capture nsec in stdout/stderr piped back to caller

### 2. Wallet mnemonics NEVER leave the VPS
- [ ] BIP-39 mnemonic generated locally, written only to `/opt/agent-keys/btc_wallet.json`
- [ ] ETH private key same — local generation, local storage only
- [ ] No mnemonic/privkey in logs, API calls, or provisioning output

### 3. NIP-46 bunker mediates ALL Nostr signing
- [ ] nsecBunker loads nsec from secure storage, runs as isolated systemd service
- [ ] OpenClaw Nostr plugin configured with bunker connection string, NOT raw nsec
- [ ] mcp-money configured with bunker connection, NOT raw nsec
- [ ] Birth note signed via bunker, not by directly reading nsec
- [ ] No other process has read access to `/opt/agent-keys/nostr.json` (check permissions: 600, root:root)

### 4. Provisioning SSH key is deleted
- [ ] `bootstrap_agent.sh` removes the provisioning pubkey from `~root/.ssh/authorized_keys`
- [ ] `create_vm.py` deletes the SSH key from LNVPS API after bootstrap completes
- [ ] Temporary SSH private key is held in memory only (never written to disk on provisioning server)
- [ ] After bootstrap, only the agent can grant SSH access (by generating its own keys)

### 5. Service keypair is truly ephemeral
- [ ] `create_vm.py` generates a throwaway Nostr keypair for LNVPS auth
- [ ] This keypair is NOT the agent's identity
- [ ] Keypair is discarded when `create_vm.py` exits (not written to any file)
- [ ] If process crashes mid-execution, no persisted service keypair remains

### 6. NIP-17 gift-wrap protocol correctness
- [ ] Birth note uses kind 14 (NOT kind 4 / NIP-04)
- [ ] Kind 14 is encrypted with NIP-44 (XChaCha20-Poly1305 + HKDF), NOT NIP-04 encryption
- [ ] Kind 13 seal wraps the encrypted kind 14, signed by agent's key (via bunker)
- [ ] Kind 1059 gift wrap uses a DISPOSABLE ephemeral keypair (not the agent's key)
- [ ] `created_at` on kind 14 is randomized (±48h) to prevent timing analysis
- [ ] Gift wrap is published to multiple relays (at least 3)

### 7. NIP-98 auth events are well-formed
- [ ] Kind 27235 with correct tags: `["u", <full URL>]`, `["method", <HTTP method>]`
- [ ] POST requests include `["payload", SHA256(body)]` tag
- [ ] `created_at` is current timestamp (not stale — servers may reject old events)
- [ ] Signed with Schnorr signature (secp256k1 x-only)
- [ ] Base64-encoded correctly in `Authorization: Nostr <base64>` header

### 8. Firewall and system hardening
- [ ] UFW default: deny incoming, allow outgoing
- [ ] Only ports 22 (SSH), 3000 (webchat), 80 (HTTP), 443 (HTTPS) allowed
- [ ] `unattended-upgrades` enabled for automatic security patches
- [ ] `/opt/agent-keys/` is mode 700, owned by root
- [ ] All key files are mode 600
- [ ] `/tmp/agent-setup/` is cleaned up after bootstrap

### 9. Single secret crossing boundary
- [ ] PayPerQ API key is the ONLY secret transferred from provisioning server to VPS
- [ ] It's uploaded via SSH (encrypted channel) as a file, then moved to auth-profiles.json
- [ ] The uploaded file (`payperq_key.txt`) is deleted after being written to config
- [ ] Verify no other secrets cross the boundary

### 10. Error handling doesn't leak secrets
- [ ] Error messages don't include nsec, mnemonics, or private keys
- [ ] Stack traces in logs are sanitized
- [ ] Failed provisioning doesn't leave secrets in `/tmp/` or other world-readable locations
- [ ] Timeout/crash scenarios don't leave partial key material on provisioning server

---

## Files to Review

| File | Focus Areas |
|------|-------------|
| `create_vm.py` | Ephemeral keypair lifecycle, SSH key handling, no agent secrets in output |
| `bootstrap_agent.sh` | Key generation, file permissions, nsecBunker setup, SSH key removal, cleanup |
| `config_template.json` | No hardcoded secrets, correct provider config |
| `templates/*.md` | No secret placeholders that could leak |

## Reference Documents
- `FUNCTIONAL_DESIGN.md` — Complete function-level specification (F1.1–F9.2)
- `TECH_STACK.md` — Architecture and API references
- `MASTER_SPEC.md` — Project overview and design decisions

## NIP Specifications
- [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md) — Private Direct Messages (gift-wrap)
- [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) — Encrypted Payloads
- [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) — Nostr Connect (remote signing)
- [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) — HTTP Auth
