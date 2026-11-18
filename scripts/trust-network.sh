#!/usr/bin/env bash
# Temporary until the dashboard (phase 4): list networks or set their trust.
#   ./scripts/trust-network.sh list
#   ./scripts/trust-network.sh trust 1 owned
set -euo pipefail
exec docker exec netledger-server java \
  -Dorg.sqlite.lib.path=/app/native -Dorg.sqlite.lib.name=libsqlitejdbc.so \
  -Dloader.main=io.github.chakibselhi.netledger.server.admin.NetworkAdmin \
  -cp /app/app.jar org.springframework.boot.loader.launch.PropertiesLauncher "$@"
