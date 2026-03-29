# VPS — Self-Renewal

## VM Identity
- VM ID: `/opt/agent-keys/vm_id.txt`

## Check Status
```
python3 /opt/agent-keys/renew_vm.py --vm-id __VM_ID__ --status
```

## Renew
```
python3 /opt/agent-keys/renew_vm.py --vm-id __VM_ID__
```
Pay the returned bolt11 with mcp-money `pay_invoice`.
