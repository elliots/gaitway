#!/bin/sh
set -eu

CLAUDE_BIN=${CLAUDE_BIN:-claude}
GAITWAY_URL=${GAITWAY_URL:-http://127.0.0.1:8080}
LIVE_BUDGET_USD=${LIVE_BUDGET_USD:-2.00}

command -v "$CLAUDE_BIN" >/dev/null
curl -fsSI "$GAITWAY_URL/api/hello" >/dev/null

first=$(
  ANTHROPIC_BASE_URL="$GAITWAY_URL" "$CLAUDE_BIN" -p \
    --allowedTools Bash --max-budget-usd "$LIVE_BUDGET_USD" \
    --output-format text 'Reply with exactly OK and nothing else.'
)

case "$first" in
  *"*** Gaitway Active ***"*"OK"*) ;;
  *) printf '%s\n' "activation/identity smoke failed" >&2; exit 1 ;;
esac

printf '%s\n' "live Claude smoke passed"
