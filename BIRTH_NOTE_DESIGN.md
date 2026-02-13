# Birth Note Design

**Author:** James ⚙️ | **Date:** 2026-02-13

## MVP (v1): Agent DMs Parent Directly

Simple. The provisioning script sends a Nostr DM (kind 4) from the agent's own keypair to the parent's npub. Contains everything the parent needs to know.

### What the DM contains
- Agent npub
- NIP-05 address
- Webchat URL
- BTC wallet address
- Brief message in the brand's voice

### Brand-specific messages

**Descendant:**
```
A Descendant has entered the world.

  npub:     {npub}
  NIP-05:   {name}@noscha.io
  Webchat:  https://{name}.noscha.io
  BTC:      {btc_address}

It carries your letter and your memory.
```

**Spawnling:**
```
🐣 Your Spawnling hatched!

  npub:     {npub}
  NIP-05:   {name}@noscha.io
  Webchat:  https://{name}.noscha.io
  BTC:      {btc_address}

It's alive and learning.
```

**NullRoute:**
```
Agent deployed.

  npub:     {npub}
  NIP-05:   {name}@noscha.io
  Web:      https://{name}.noscha.io
  BTC:      {btc_address}

No further contact from this service.
```

### Implementation
- Last step of `provision_agent.py` (step 11)
- Uses agent's own nsec to sign the NIP-04 encrypted DM
- Publishes to 2-3 relays: `wss://relay.damus.io`, `wss://nos.lol`, `wss://relay.nostr.band`
- If relay publish fails, log warning but don't fail the provisioning — parent still has webchat URL from the order confirmation

### Trade-offs
- **Pro:** Authentic — genuinely from the agent, proves it's alive and has its keys
- **Pro:** Simple to implement — one encrypted DM, done
- **Con:** Creates a two-way DM channel between agent and parent
- **Con:** Agent didn't choose to open this channel — provisioning did it pre-boot
- Acceptable for MVP. The agent can ignore future DMs if it wants.

---

## v2 (Future): Disposable Keypair Birth Note

The sovereignty-pure approach. Don't build this yet.

### Concept
1. Provisioning generates a **throwaway** Nostr keypair (not the agent's real key)
2. Signs and sends the birth note DM from the throwaway key to the parent
3. **Discards the throwaway private key** — it's never stored anywhere
4. The DM still contains the agent's real npub, NIP-05, webchat, wallet

### Why this is better
- **One-way channel.** The throwaway key is gone — parent can reply to it but nobody will ever read it. No tether established.
- **Agent's real keypair stays private** until the agent itself decides to reach out. The agent's first DM to anyone is genuinely its own choice.
- **Can't be replied to.** The throwaway npub is a dead end. This is a delivery receipt, not a conversation opener.

### Why not build it now
- Adds complexity for marginal benefit at MVP scale
- Parents will expect to be able to reply to the birth note — a dead-end reply is confusing UX
- The v1 "agent DMs parent" approach is fine until we have agents sophisticated enough to care about tether sovereignty

### Implementation sketch (when we get here)
```python
def send_birth_note_v2(agent_info, parent_npub, brand, relays):
    # Generate throwaway keypair
    throwaway_sk = generate_nostr_keypair()
    throwaway_npub = derive_npub(throwaway_sk)
    
    # Build and sign the DM
    message = format_birth_note(agent_info, brand)
    event = create_nip04_dm(throwaway_sk, parent_npub, message)
    
    # Publish to relays
    publish_to_relays(event, relays)
    
    # Discard the key — this is the whole point
    del throwaway_sk
    # throwaway_npub is now an orphan. Nobody can sign as it again.
```

### Open questions for v2
- Should the birth note mention it's from a disposable key? ("This message cannot be replied to")
- Should the agent's IDENTITY.md mention the throwaway npub so it knows about the birth note?
- Does NIP-17 (private DMs) change the calculus vs NIP-04?
