#!/usr/bin/env bash
# Phase 0 feasibility probes of the agent module.
#   ./scripts/probe.sh arp                 list capture interfaces
#   ./scripts/probe.sh arp en0 [30]        print ARP frames seen on en0 for 30 s
#   ./scripts/probe.sh notify [osascript|tray]  show a test macOS notification
# NETLEDGER_PCAP_LIB=/path/libpcap.so overrides the libpcap library (Linux only).
set -euo pipefail

cd "$(dirname "$0")/.."

case "${1:-}" in
  arp) main=io.github.chakibselhi.netledger.agent.probe.ArpCaptureProbe ;;
  notify) main=io.github.chakibselhi.netledger.agent.probe.NotificationProbe ;;
  *) sed -n '2,6p' "$0"; exit 64 ;;
esac
shift

if [[ "$main" == *ArpCaptureProbe && $# -gt 0 && "$(uname)" == "Darwin" && ! -r /dev/bpf0 ]]; then
  echo "No read access to /dev/bpf*: install Wireshark's ChmodBPF and log in again." >&2
  echo "  brew install --cask wireshark-chmodbpf" >&2
  exit 1
fi

mvn -q -pl agent -am -DskipTests compile dependency:build-classpath \
  -Dmdep.outputFile=target/probe-classpath.txt

java_bin="${JAVA_HOME:+$JAVA_HOME/bin/}java"
jvm_args=()
if [[ -n "${NETLEDGER_PCAP_LIB:-}" ]]; then
  jvm_args+=("-Dorg.pcap4j.core.pcapLibName=${NETLEDGER_PCAP_LIB}")
fi

exec "$java_bin" ${jvm_args[@]+"${jvm_args[@]}"} \
  -cp "agent/target/classes:$(cat agent/target/probe-classpath.txt)" "$main" "$@"
