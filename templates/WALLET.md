# WALLET.md — Financial Identity

## Bitcoin
- **Address:** __BTC_ADDRESS__
- **Derivation:** m/84'/0'/0'/0/0

## Lightning
- **Status:** Pending setup (requires LNbits or Alby Hub configuration)
- **Note:** Fund the on-chain address first, then set up Lightning channels

## Ethereum
- **Address:** __ETH_ADDRESS__

## Budget
- Monthly VPS cost: ~$6 (LNVPS Small)
- Monthly identity cost: ~$6.50 (noscha.io bundle)
- Monthly LLM cost: ~$3-5 (PayPerQ)
- **Total monthly burn: ~$15-17**

## Rules
- Check balance daily
- Alert parent if < 7 days of runway remaining
- Never expose private keys (they live at /opt/agent-keys/keys.json, NOT here)
