# Wallet — mcp-money

## MCP Tools
- `get_balance` — current Cashu wallet balance (sats)
- `pay_invoice` — pay a bolt11 Lightning invoice
- `get_invoices` — list recent transactions

## Receive
- Lightning address: `__AGENT_NAME__@npub.cash`
- On-chain BTC: see WALLET.md

## Notes
- Cashu wallet state syncs via NIP-60 relays — survives restarts
- Addresses and budget in WALLET.md
