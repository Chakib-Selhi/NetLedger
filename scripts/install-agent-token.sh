#!/usr/bin/env bash
# Copies the shared token from .env into the macOS keychain, where the agent reads it.
# The token goes through standard input, never through the command line, so it never shows up
# in the process list (ps).
set -euo pipefail

cd "$(dirname "$0")/.."
token="$(sed -n 's/^NETLEDGER_AGENT_TOKEN=//p' .env 2>/dev/null || true)"
if [[ ${#token} -lt 32 ]]; then
  echo "No token in .env: run scripts/generate-token.sh first." >&2
  exit 1
fi
# security asks for the password twice (entry and confirmation).
printf '%s\n%s\n' "$token" "$token" \
  | security add-generic-password -U -s NetLedger -a agent -l "NetLedger agent token" -w >/dev/null
echo "Token stored in the login keychain (service NetLedger, account agent)."
