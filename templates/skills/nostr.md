# Nostr — NIP-46 Bunker

## Signing
- Bunker service: `agent-bunker.service`
- Connection string: `/opt/agent-keys/bunker_connection.txt`
- Never use nsec directly — all signing goes through the bunker

## DMs
- Protocol: NIP-17 gift-wrapped DMs only
- Parent: `__PARENT_NPUB__`

## Relays
- `wss://relay.damus.io`
- `wss://relay.primal.net`
- `wss://nos.lol`

## Health
- `systemctl status agent-bunker`
