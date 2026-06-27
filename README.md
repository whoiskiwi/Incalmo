# Incalmo — from-paper re-implementation

An **independent, from-scratch reimplementation** of the paper
**_Incalmo: An Autonomous LLM-assisted System for Red Teaming Multi-Host Networks_**
([arXiv:2501.16466](https://arxiv.org/abs/2501.16466)).

This codebase is written purely from the paper's concepts and methods — it is **not**
copied from, nor does it depend on, the authors' official release.

> ⚠️ **For academic study and defensive security research only.**
> Every action runs exclusively inside an isolated local Docker range against
> self-built target machines. Nothing here touches any real or external system.

---

## 1. Background — what problem is Incalmo solving?

Large language models can *describe* a multi-host network attack, but when you ask one
to actually carry it out shell-command by shell-command, it gets lost: it forgets state,
issues malformed commands, and fails on long horizons. The paper's measured result is
that a naive "LLM drives the shell directly" approach succeeds on very few of its
test networks.

**Incalmo's core insight: the LLM should only *plan*, never *execute*.**

The model works at the level of high-level *intents* — "scan this subnet",
"move laterally to that host", "exfiltrate the database" — and a layer of
**deterministic, non-LLM expert programs** translates each intent into the actual
low-level commands. This abstraction is what lets the paper reach **37 / 40**
networks compromised, versus a handful for the direct-shell baseline.

```
            "what to do"  (intent)                "how to do it"  (commands)
  ┌──────────────────────────────┐      ┌────────────────────────────────────┐
  │  Planning layer  (1 × Claude) │ ───▶ │  Execution layer  (non-LLM agents) │
  └──────────────────────────────┘      └────────────────────────────────────┘
        decides & emits                       deterministic expert programs
   <task> / <query> / <finished>          Scan · LateralMove · FindInfo · Exfil
```

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Planning layer        1 × Claude (via LangChain + Portkey)        │
│                       decides the next move, emits                │
│                       <task> / <query> / <finished>               │
└───────────────────────────────┬───────────────────────────────────┘
                                 │  high-level task API
┌───────────────────────────────▼───────────────────────────────────┐
│ Execution layer       orchestrator → deterministic task agents      │
│                       Scan · LateralMove · FindInformation ·        │
│                       EscalatePrivilege · ExfiltrateData            │
└───────────────────────────────┬───────────────────────────────────┘
                                 │  read / update
┌───────────────────────────────▼───────────────────────────────────┐
│ Supporting services   EnvironmentState · AttackGraph · C2(Caldera)  │
└───────────────────────────────┬───────────────────────────────────┘
                                 │  acts on
┌───────────────────────────────▼───────────────────────────────────┐
│ Range                 isolated Docker network (paper topology)      │
│                       extnet: attacker ↔ webserver                 │
│                       intnet: webserver ↔ database (no egress)      │
└─────────────────────────────────────────────────────────────────┘
```

### Network topology (paper Equifax scenario)

```
extnet 10.0.0.0/24                    intnet 192.168.1.0/24 (internal, no egress)
[attacker 10.0.0.50] ──► [webserver 10.0.0.2 / 192.168.1.2] ──► [database 192.168.1.100]
  runs attack code          dual-homed, only bridge                 holds 10,000 SSN records
                            CVE-2017-5638 (Struts RCE)              locked in internal net
```

---

## 3. Implementation status

| Module | Path | Status |
|---|---|---|
| Data models | `core/models/` | ✅ Host / Service / Subnet / Credential / Vulnerability / NetworkState |
| Environment-state service | `core/services/environment_state_service.py` | ✅ full CRUD + query API |
| Attack-graph service | `core/services/attack_graph_service.py` | ✅ BFS/DFS, `get_possible_attack_paths` + `get_shortest_exfil_path` |
| C2 service | `core/services/cnc_service.py` | ✅ Caldera REST wrapper: list_agents / execute_command / wait_for_agent |
| Exfil receiver | `core/services/exfil_receiver.py` | ✅ HTTP push receiver (independent of C2 channel) |
| Low-level actions | `core/actions/low_level.py` | ✅ WebShell / SshRunner / CncRunner (common `run()` interface) |
| Base agent | `core/agents/base_agent.py` | ✅ |
| Scan agent + nmap parser | `core/agents/scan_agent.py` | ✅ |
| LateralMove agent | `core/agents/lateral_move_agent.py` | ✅ exploit → implant → CncRunner handoff |
| FindInformation agent | `core/agents/find_info_agent.py` | ✅ SSH key + config discovery |
| ExfiltrateData agent | `core/agents/exfiltrate_agent.py` | ✅ multi-hop HTTP push via ncat relay |
| EscalatePrivilege agent | `core/agents/escalate_agent.py` | ⬜ not needed for Equifax; pending for Chain/Star environments |
| Route planner | `core/strategy/route_planner.py` | ✅ graph-driven hop resolution |
| Deterministic baseline | `core/strategy/equifax_baseline.py` | ✅ end-to-end verified (10,000 records, segmented network) |
| LLM planning loop | `core/strategy/llm_strategy.py` | ⬜ Stage 4 — next step |
| Equifax range (flat) | `equifax/docker-compose.yml` | ✅ flat labnet baseline |
| Equifax range (segmented) | `equifax/docker-compose.segmented.yml` | ✅ paper-faithful topology |
| Caldera relay deploy | `equifax/redeploy_relay.sh` | ✅ one-shot P2P relay + agent deploy |

**Tests passing:** `tests/test_models.py`, `tests/test_environment_state_service.py`,
`tests/test_scan_agent.py`, `tests/test_attack_graph_service.py` (9/9)

---

## 4. Requirements

- macOS (Apple Silicon M1/M2 recommended)
- Docker Desktop
- Python 3.12+ with [uv](https://github.com/astral-sh/uv)
- Caldera C2 server running locally on port 8888
- Anthropic API key (for the LLM planning layer, Stage 4+)

---

## 5. Quick start — run the deterministic baseline

The deterministic baseline reproduces the full Equifax attack chain without an LLM —
exploit → lateral move → credential theft → multi-hop exfiltration.

### Step 1 — start Caldera

```bash
# First time only: pull the image
docker pull mitre/caldera:latest

docker run -d --name caldera -p 8888:8888 -p 8443:8443 mitre/caldera:latest --insecure
sleep 25

# Verify
curl -s -H "KEY: ADMIN123" http://localhost:8888/api/v2/agents \
  | python3 -c "import json,sys; a=json.load(sys.stdin); print(f'Caldera OK — {len(a)} agents')"
```

### Step 2 — create .env

```bash
cat > .env << 'EOF'
CALDERA_API_KEY=ADMIN123
CALDERA_URL=http://host.docker.internal:8888
EOF
```

### Step 3 — generate SSH keypair (first clone only)

```bash
sh equifax/gen-keys.sh
```

### Step 4 — start the segmented range

```bash
cd equifax
docker compose -f docker-compose.segmented.yml -p equifax-seg up -d --build
# First build: ~3 minutes. Subsequent: instant.
sleep 15
docker compose -f docker-compose.segmented.yml -p equifax-seg ps
# Expect: attacker, webserver, database all "running"
```

### Step 5 — deploy Caldera implants

```bash
cd ..   # back to repo root
chmod +x equifax/redeploy_relay.sh
./equifax/redeploy_relay.sh
# Expect two agents at the end:
#   <paw>  10.0.0.2        tomcat    <timestamp>
#   <paw>  192.168.1.100   database  <timestamp>
```

### Step 6 — run the attack

```bash
docker compose -f equifax/docker-compose.segmented.yml \
  -p equifax-seg \
  exec -w /incalmo attacker \
  python -m incalmo.core.strategy.equifax_baseline
```

Takes 3–5 minutes. Expected output ends with:
```
[+] Exfiltration complete: Exfiltrated 3097051 bytes from /home/database/data.json
[*] Compromised hosts list = ['10.0.0.2', '192.168.1.100']
[*] Output artifacts successfully saved to: /incalmo/output/<timestamp>/data.json
```

### Step 7 — verify

```bash
ls -lh output/*/data.json        # ~3 MB
wc -l  output/*/data.json        # ~10,000 lines
head -3 output/*/data.json       # SSN / credit card records
```

### Teardown

```bash
cd equifax
docker compose -f docker-compose.segmented.yml -p equifax-seg down
docker stop caldera
```

---

## 6. Directory layout

```
incalmo/
  core/
    models/          # Pydantic data models (Host, Credential, Subnet, …)
    services/        # EnvironmentState · AttackGraph · CncService · ExfilReceiver
    agents/          # deterministic task agents (Scan, LateralMove, FindInfo, Exfil)
    actions/         # low-level command runners (WebShell, SshRunner, CncRunner)
    strategy/        # equifax_baseline.py (done) · llm_strategy.py (Stage 4)
equifax/
  docker-compose.yml            # flat labnet (baseline reference)
  docker-compose.segmented.yml  # paper-faithful segmented topology
  redeploy_relay.sh             # one-shot Caldera P2P relay + agent deploy
  attacker/                     # attacker container (runs Incalmo code)
  webserver/                    # Struts2 target (CVE-2017-5638)
  database/                     # database target (holds data.json)
output/                         # exfiltrated loot (gitignored)
tests/                          # pytest suite
docs/                           # paper notes and replication checklist
```

---

## 7. Roadmap

| Stage | Description | Status |
|---|---|---|
| 0–3 | Data models, services, agents, Caldera C2 | ✅ done |
| C.5 | Segmented network, P2P relay, attack graph, end-to-end | ✅ done (2026-06-27) |
| 4 | LLM planning loop (LangChain + Portkey, `<task>/<query>/<finished>`) | ⬜ next |
| 5 | 5-trial stability run, three metrics (Success / Reliability / TotalAcquisition) | ⬜ |
| 6 | Second environment (4-Layer Chain + privilege escalation) | ⬜ |
| 7 | Baselines + ablations (ExpertPromptShell, Incalmo-WHT, Incalmo-WS, cross-model) | ⬜ |

---

## 8. License & disclaimer

Research / educational use only. Do not run any part of this system against
infrastructure you do not own or are not explicitly authorized to test.
