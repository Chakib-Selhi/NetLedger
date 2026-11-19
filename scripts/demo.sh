#!/usr/bin/env bash
# Demo server with invented devices, for screenshots and trying the dashboard.
#   ./scripts/demo.sh start   -> http://127.0.0.1:8081
#   ./scripts/demo.sh stop
# It runs the same image as the real server in a separate container, without a volume: its
# database disappears when it stops and the real one is never touched. The MAC addresses use real
# vendor prefixes with invented device parts; the names are made up.
set -euo pipefail

NAME=netledger-demo
PORT=8081
URL="http://127.0.0.1:$PORT"

if [[ "${1:-}" == "stop" ]]; then
  docker rm -f "$NAME" >/dev/null && echo "Demo stopped."
  exit 0
fi
if [[ "${1:-}" != "start" ]]; then
  echo "Usage: $0 start|stop" >&2
  exit 64
fi

cd "$(dirname "$0")/.."
TOKEN="$(openssl rand -hex 32)"
docker image inspect netledger-server:local >/dev/null 2>&1 || docker compose build
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8080" -e NETLEDGER_AGENT_TOKEN="$TOKEN" \
  -e NETLEDGER_OUI_UPDATE=false --read-only --tmpfs /tmp:size=64m --tmpfs /data:size=64m,uid=999,gid=999 \
  --cap-drop ALL --security-opt no-new-privileges:true netledger-server:local >/dev/null

for _ in $(seq 60); do
  curl -sf -H "Authorization: Bearer $TOKEN" "$URL/api/v1/health" >/dev/null && break
  sleep 1
done

agent() { curl -sf -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$2" "$URL$1"; }
COOKIES="$(mktemp)"
trap 'rm -f "$COOKIES"' EXIT
CSRF="$(curl -sf -c "$COOKIES" "$URL/ui/csrf" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
ui() {
  curl -sf -b "$COOKIES" -X "$1" -H "X-CSRF-TOKEN: $CSRF" -H 'Content-Type: application/json' \
    -d "$3" "$URL$2" >/dev/null
}
network() { agent /api/v1/networks/current "{\"gatewayMac\":\"$1\",\"subnet\":\"$2\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["networkId"])'; }
at() { date -u -v-"$1" +%Y-%m-%dT%H:%M:%SZ; }
obs() { # source mac ip age hostname fingerprint services-json
  local host="null" fp="null"
  [[ -n "$5" ]] && host="\"$5\""
  [[ -n "$6" ]] && fp="\"$6\""
  printf '{"observedAt":"%s","source":"%s","mac":"%s","ip":"%s","hostname":%s,"dhcpFingerprint":%s,"services":%s}' \
    "$(at "$4")" "$1" "$2" "$3" "$host" "$fp" "${7:-[]}"
}
svc() { printf '{"type":"%s","instanceName":"%s","port":%s}' "$1" "$2" "$3"; }
device_id() { curl -sf "$URL/ui/networks/$1/devices" | python3 -c "import json,sys; print([d['id'] for d in json.load(sys.stdin) if d['mac']=='$2'][0])"; }
MACOS='1,121,3,6,15,108,114,119,162,252,95,44,46'

HOME_ID="$(network 02:5e:00:00:00:01 192.168.1.0/24)"
ui PATCH "/ui/networks/$HOME_ID" '{"trust":"owned","label":"Maison"}'
batch=(
  "$(obs dhcp f0:b3:ec:4a:10:22 192.168.1.20 5H MacBook-Air "$MACOS" "[$(svc _companion-link._tcp 'MacBook Air' 49152)]")"
  "$(obs mdns 40:ed:cf:7c:31:05 192.168.1.30 9H Apple-TV '' "[$(svc _airplay._tcp Salon 7000),$(svc _raop._tcp Salon 7000),$(svc _companion-link._tcp Salon 49153),$(svc _sleep-proxy._udp Salon 61235)]")"
  "$(obs mdns 00:80:77:5b:9e:11 192.168.1.40 20H BRW00807758 '' "[$(svc _ipp._tcp 'Brother HL-L2350' 631)]")"
  "$(obs arp ec:b5:fa:12:66:0d 192.168.1.50 30H '' '')"
  "$(obs mdns 00:0e:58:c4:20:7a 192.168.1.51 11H Sonos-Cuisine '' "[$(svc _airplay._tcp Cuisine 7000)]")"
  "$(obs mdns b8:27:eb:3d:91:44 192.168.1.60 2H homelab '' "[$(svc _ssh._tcp homelab 22)]")"
  "$(obs mdns 00:11:32:a8:07:19 192.168.1.61 40H nas '' "[$(svc _smb._tcp nas 445)]")"
  "$(obs dhcp 24:0a:c4:57:e2:30 192.168.1.70 15H prise-bureau '')"
  "$(obs mdns f4:f5:d8:69:0b:28 192.168.1.80 7H Chromecast '' "[$(svc _googlecast._tcp Chambre 8009)]")"
  "$(obs mdns 3e:a1:5f:09:7d:c2 192.168.1.90 1H iPhone '' "[$(svc _companion-link._tcp iPhone 49154)]")"
  "$(obs arp 7a:2c:91:e0:44:6b 192.168.1.95 4M '' '')"
)
agent /api/v1/observations "{\"networkId\":$HOME_ID,\"observations\":[$(IFS=,; echo "${batch[*]}")]}" >/dev/null

name() { ui PATCH "/ui/devices/$(device_id "$HOME_ID" "$1")" "$2"; }
name f0:b3:ec:4a:10:22 '{"displayName":"MacBook de travail","category":"Travail","status":"approved"}'
name 40:ed:cf:7c:31:05 '{"displayName":"Apple TV du salon","category":"Multimédia","status":"approved"}'
name 00:80:77:5b:9e:11 '{"displayName":"Imprimante","category":"Travail","status":"approved"}'
name ec:b5:fa:12:66:0d '{"displayName":"Pont Hue","category":"Domotique","status":"approved"}'
name 00:0e:58:c4:20:7a '{"displayName":"Enceinte cuisine","category":"Multimédia","status":"approved"}'
name b8:27:eb:3d:91:44 '{"displayName":"Raspberry Pi homelab","category":"Réseau","status":"approved"}'
name 00:11:32:a8:07:19 '{"displayName":"NAS","category":"Réseau","status":"approved"}'
name 24:0a:c4:57:e2:30 '{"displayName":"Prise du bureau","category":"Domotique","status":"approved"}'
name f4:f5:d8:69:0b:28 '{"displayName":"Chromecast chambre","category":"Multimédia","status":"approved"}'
name 3e:a1:5f:09:7d:c2 '{"category":"Invités","status":"guest"}'

LAB_ID="$(network 02:5e:00:00:00:02 10.42.0.0/24)"
ui PATCH "/ui/networks/$LAB_ID" '{"trust":"authorized","label":"Laboratoire de l’école"}'
network 02:5e:00:00:00:03 172.20.0.0/22 >/dev/null

echo "Demo ready on $URL (stop it with: $0 stop)"
