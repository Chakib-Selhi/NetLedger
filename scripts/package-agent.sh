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

# jlink keeps only the modules the agent uses (jdeps --print-module-deps), plus what JNA needs
# at run time and jdeps cannot see: jdk.unsupported and java.logging. pcap4j calls libpcap
# through JNA, so without them capture fails only inside the app.
# The app's own main class only hands the agent over to launchd (see LaunchAgentInstaller), which
# runs AgentMain with the bundled runtime's bin/java: jpackage strips native commands by default,
# so the jlink options are given without --strip-native-commands.
"$JDK/bin/jpackage" --type app-image --dest "$OUT" --input "$INPUT" \
  --main-jar netledger-agent.jar --name NetLedger --app-version "$VERSION" \
  --main-class io.github.chakibselhi.netledger.agent.launch.AppLauncher \
  --jlink-options "--strip-debug --no-man-pages --no-header-files" \
  --mac-package-identifier io.github.chakibselhi.netledger.agent \
  --icon agent/packaging/NetLedger.icns \
  --add-modules java.base,java.desktop,java.net.http,java.sql,java.logging,jdk.unsupported \
  --java-options "-Dapple.awt.UIElement=true"

APP="$OUT/NetLedger.app"
PLIST="$APP/Contents/Info.plist"
# A menu bar agent: no Dock icon. jpackage also adds a microphone description NetLedger never
# uses; the local network one is shown by macOS when the agent sends its mDNS query.
/usr/libexec/PlistBuddy -c "Add :LSUIElement bool true" "$PLIST"
/usr/libexec/PlistBuddy -c "Delete :NSMicrophoneUsageDescription" "$PLIST"
/usr/libexec/PlistBuddy -c "Add :NSLocalNetworkUsageDescription string NetLedger interroge les services mDNS (AirPlay, imprimantes) des réseaux que vous avez autorisés." "$PLIST"
/usr/libexec/PlistBuddy -c "Set :LSMinimumSystemVersion 13.0" "$PLIST"
# macOS hides the local network (the gateway's ARP entry) from ad-hoc signed executables, and
# the "Local Network" switch does not lift it for them. jlink's bin/java is ad-hoc signed; the
# JDK's own one is signed by its vendor (Adoptium for Temurin) and is not hidden. It is the same
# binary build, so the original replaces the copy, keeping its signature.
cp "$JDK/bin/java" "$APP/Contents/runtime/Contents/Home/bin/java"
codesign --verify --strict "$APP/Contents/runtime/Contents/Home/bin/java"
# Editing Info.plist invalidates jpackage's signature: sign the bundle again, without --deep so
# the vendor signature of bin/java is kept.
codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP"

# Not jpackage --type dmg: it signs the app image again (ad hoc, --deep), which replaces the
# vendor signature of bin/java. hdiutil copies the app as it is.
STAGE="$OUT/dmg-stage"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -quiet -volname NetLedger -srcfolder "$STAGE" -ov -format UDZO \
  "$OUT/NetLedger-$VERSION.dmg"
rm -rf "$STAGE"

echo "Built $APP and $OUT/NetLedger-$VERSION.dmg"
