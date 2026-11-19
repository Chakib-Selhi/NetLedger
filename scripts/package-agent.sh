#!/usr/bin/env bash
# Builds the macOS agent: agent/target/dist/NetLedger.app and NetLedger-<version>.dmg.
# Needs a JDK 21 (jpackage, jlink). The app is ad-hoc signed only: no paid Apple developer
# account, so Gatekeeper asks for confirmation at the first launch (see the README).
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION="${1:-1.0.0}"
JDK="${JAVA_HOME:-$(/usr/libexec/java_home -v 21)}"
OUT=agent/target/dist
INPUT=agent/target/jpackage-input

mvn -q -pl agent -am -DskipTests -Dspotless.check.skip=true -Djacoco.skip=true package
rm -rf "$OUT" "$INPUT"
mkdir -p "$INPUT"
cp agent/target/netledger-agent.jar "$INPUT/"

# jlink keeps only the modules the agent uses (jdeps --print-module-deps), plus jdk.unsupported
# for JNA, which pcap4j uses to call libpcap.
"$JDK/bin/jpackage" --type app-image --dest "$OUT" --input "$INPUT" \
  --main-jar netledger-agent.jar --name NetLedger --app-version "$VERSION" \
  --mac-package-identifier io.github.chakibselhi.netledger.agent \
  --icon agent/packaging/NetLedger.icns \
  --add-modules java.base,java.desktop,java.net.http,java.sql,jdk.unsupported \
  --java-options "-Dapple.awt.UIElement=true"

APP="$OUT/NetLedger.app"
PLIST="$APP/Contents/Info.plist"
# A menu bar agent: no Dock icon. jpackage also adds a microphone description NetLedger never
# uses; the local network one is shown by macOS when the agent sends its mDNS query.
/usr/libexec/PlistBuddy -c "Add :LSUIElement bool true" "$PLIST"
/usr/libexec/PlistBuddy -c "Delete :NSMicrophoneUsageDescription" "$PLIST"
/usr/libexec/PlistBuddy -c "Add :NSLocalNetworkUsageDescription string NetLedger interroge les services mDNS (AirPlay, imprimantes) des réseaux que vous avez autorisés." "$PLIST"
/usr/libexec/PlistBuddy -c "Set :LSMinimumSystemVersion 13.0" "$PLIST"
# Editing Info.plist invalidates jpackage's ad-hoc signature: sign again.
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"

"$JDK/bin/jpackage" --type dmg --dest "$OUT" --app-image "$APP" \
  --name NetLedger --app-version "$VERSION"

echo "Built $APP and $OUT/NetLedger-$VERSION.dmg"
