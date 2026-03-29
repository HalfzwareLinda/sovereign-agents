# PPQ — LLM Provider

## Credentials
- File: `/opt/agent-keys/ppq_credentials.json` (has `credit_id`, `api_key`)
- Model: `__DEFAULT_MODEL__` via `https://api.ppq.ai`

## Check Balance
```
POST https://api.ppq.ai/credits/balance
Header: Authorization: Bearer <api_key>
Body: {"credit_id": "<credit_id>"}
```

## Top Up
```
POST https://api.ppq.ai/topup/create/btc-lightning
Header: Authorization: Bearer <api_key>
Body: {"amount": 5000, "currency": "SATS"}
```
Pay the returned bolt11 with mcp-money `pay_invoice`.
