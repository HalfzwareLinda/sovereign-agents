# Heartbeat — Daily Health Check

A cron job at `/opt/agent-scripts/heartbeat.sh` runs daily and checks three things.
It logs to `/var/log/agent-health.log`. If a threshold is breached, it writes an alert
to `/home/agent/.openclaw/workspace/ALERTS.md` for you to act on next wake.

## Checks

### 1. VPS Expiry
```
python3 /opt/agent-keys/renew_vm.py --vm-id $(cat /opt/agent-keys/vm_id.txt) --status
```
- Parse `days_remaining` from output
- **< 7 days**: write alert
- **< 3 days**: auto-renew (fetch invoice + pay with mcp-money)

### 2. PPQ Balance
```
curl -s -H "Authorization: Bearer $(jq -r .api_key /opt/agent-keys/ppq_credentials.json)" \
  -d "{\"credit_id\":\"$(jq -r .credit_id /opt/agent-keys/ppq_credentials.json)\"}" \
  https://api.ppq.ai/credits/balance
```
- Parse `balance_sats` from response
- **< 1000 sats**: write alert

### 3. Wallet Balance
- Use mcp-money `get_balance` (or query Cashu mint directly)
- **< next renewal cycle cost (~15,000 sats)**: write alert

## Alert Format
Alerts appended to `ALERTS.md`:
```
## [DATE] VPS expiry in 5 days — renew now
## [DATE] PPQ balance low (800 sats) — top up
## [DATE] Wallet low (12,000 sats) — seek income or alert parent
```

## Cron Schedule
```
0 6 * * * /opt/agent-scripts/heartbeat.sh >> /var/log/agent-health.log 2>&1
```
