#!/usr/bin/env bash
# Phase 0 capture probe.
#   ./scripts/arp-probe.sh              list interfaces
#   ./scripts/arp-probe.sh en0 [30]     print ARP frames seen on en0 for 30 s
# Environment:
#   NETLEDGER_SUDO=1        run only the java process with sudo (Maven still runs as you)
#   NETLEDGER_PCAP_LIB=...  explicit libpcap path (e.g. /usr/lib/x86_64-linux-gnu/libpcap.so.0.8)
set -euo pipefail

cd "$(dirname "$0")/.."

mvn -q -DskipTests compile dependency:build-classpath -Dmdep.outputFile=target/probe-classpath.txt

java_bin="${JAVA_HOME:+$JAVA_HOME/bin/}java"
jvm_args=()
if [[ -n "${NETLEDGER_PCAP_LIB:-}" ]]; then
  jvm_args+=("-Dorg.pcap4j.core.pcapLibName=${NETLEDGER_PCAP_LIB}")
fi

cmd=("$java_bin" ${jvm_args[@]+"${jvm_args[@]}"} -cp "target/classes:$(cat target/probe-classpath.txt)"
  io.github.chakibselhi.netledger.capture.probe.ArpCaptureProbe "$@")

if [[ "${NETLEDGER_SUDO:-0}" == "1" ]]; then
  exec sudo "${cmd[@]}"
fi
exec "${cmd[@]}"
