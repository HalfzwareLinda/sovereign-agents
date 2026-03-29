#!/bin/bash
# test_e2e_live.sh — Layer 5: Live E2E provisioning test
#
# Creates a real VPS on LNVPS, bootstraps an agent, preserves SSH access.
# Prints a Lightning invoice for manual payment.
#
# Usage:
#   ./test_e2e_live.sh                          # defaults
#   ./test_e2e_live.sh --name myagent2          # custom name (overrides AGENT_NAME)
#   ./test_e2e_live.sh --tier seed              # extra flags passed through to create_vm.py
#
# Required env:
#   LLM_API_KEY     - OpenAI (or PPQ) API key
#   PARENT_NPUB     - Creator's Nostr npub
#
# Optional env:
#   AGENT_NAME      - Agent name (default: testpilot-HHMM)
#   TIER            - seed/evolve/dynasty/trial (default: evolve)
#   BRAND           - descendant/spawnling/deadrop (default: descendant)
#   LLM_BASE_URL    - API base URL (default: https://api.openai.com/v1)
#   MODEL           - LLM model (default: gpt-4o-mini)

set -euo pipefail
cd "$(dirname "$0")"

# Defaults
AGENT_NAME="${AGENT_NAME:-testpilot-$(date +%H%M)}"
TIER="${TIER:-evolve}"
BRAND="${BRAND:-descendant}"
LLM_BASE_URL="${LLM_BASE_URL:-https://api.openai.com/v1}"
MODEL="${MODEL:-gpt-4o-mini}"

# Required
: "${LLM_API_KEY:?Set LLM_API_KEY to your OpenAI or PPQ API key}"
: "${PARENT_NPUB:?Set PARENT_NPUB to the creator npub}"

echo "============================================"
echo "  Layer 5: Live E2E Provisioning Test"
echo "============================================"
echo "  Name:      ${AGENT_NAME}"
echo "  Tier:      ${TIER}"
echo "  Brand:     ${BRAND}"
echo "  Model:     ${MODEL}"
echo "  LLM URL:   ${LLM_BASE_URL}"
echo "  Parent:    ${PARENT_NPUB:0:30}..."
echo "============================================"
echo ""

PAYPERQ_API_KEY="${LLM_API_KEY}" \
python3 create_vm.py \
  --name "${AGENT_NAME}" \
  --parent-npub "${PARENT_NPUB}" \
  --tier "${TIER}" \
  --brand "${BRAND}" \
  --keep-ssh \
  --llm-base-url "${LLM_BASE_URL}" \
  --model "${MODEL}" \
  "$@"

echo ""
echo "============================================"
echo "  Test artifacts:"
echo "  SSH key:    ./vm_${AGENT_NAME}_ssh.pem"
echo "  Summary:    ./vm_${AGENT_NAME}_summary.json"
echo "  SSH cmd:    ssh -i vm_${AGENT_NAME}_ssh.pem ubuntu@<IP>"
echo "============================================"
