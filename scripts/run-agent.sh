#!/usr/bin/env bash
# Builds and runs the agent from the terminal (the menu bar app comes in phase 4).
# Needs read access to /dev/bpf* (brew install --cask wireshark-chmodbpf).
set -euo pipefail

cd "$(dirname "$0")/.."
if [[ ! -r /dev/bpf0 ]]; then
  echo "No read access to /dev/bpf*: install Wireshark's ChmodBPF and restart." >&2
  exit 1
fi
mvn -q -pl agent -am -DskipTests -Dspotless.check.skip=true -Djacoco.skip=true package
exec "${JAVA_HOME:+$JAVA_HOME/bin/}java" -jar agent/target/netledger-agent.jar "$@"
