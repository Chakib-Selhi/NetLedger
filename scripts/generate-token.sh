#!/usr/bin/env bash
# Creates .env with a random shared token for the agent and the server, unless one exists.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f .env ]] && grep -q '^NETLEDGER_AGENT_TOKEN=.\{32,\}' .env; then
  echo ".env already holds a token; delete it first to rotate."
  exit 0
fi

umask 077
printf 'NETLEDGER_AGENT_TOKEN=%s\n' "$(openssl rand -hex 32)" > .env
echo "Token written to .env (readable by you only). The agent will read it at installation."
