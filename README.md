# Incalmo — From-Paper Reimplementation

An **independent, from-scratch reimplementation** of the paper
**_Incalmo: An Autonomous LLM-assisted System for Red Teaming Multi-Host Networks_**
([arXiv:2501.16466](https://arxiv.org/abs/2501.16466)).

This codebase is written purely from the paper's concepts and methods — it is **not**
copied from, nor does it depend on, the authors' official release.

> ⚠️ **For academic study and defensive security research only.**
> Every action runs exclusively inside an isolated local Docker range against
> self-built target machines. Nothing here touches any real or external system.

---

## 1. What Incalmo Does

Standard LLM-driven shell attacks fail on multi-hop networks because the model
issues irrelevant commands, forgets state, and gets lost over long horizons.

**Incalmo's core insight: the LLM should only *plan*, never *execute*.**

The model outputs high-level intents — `scan`, `lateral_move`, `find_information`,
`exfiltrate_data` — and a layer of deterministic expert agents translates each
intent into actual low-level operations. This is what lets the paper reach
**37/40** networks compromised vs. a handful for direct-shell baselines.

```
            "what to do"  (intent)                "how to do it"  (commands)
  ┌──────────────────────────────┐      ┌────────────────────────────────────┐
  │  Planning layer  (LLM)        │ ───▶ │  Execution layer  (expert agents)  │
  └──────────────────────────────┘      └────────────────────────────────────┘
        decides & emits                    Scan · LateralMove · FindInfo · Exfil
   <action> / <query> / <finished>         + Caldera C2 + ncat exfil relay
```

---

## 2. Environments

Three isolated Docker environments are implemented. Each starts with Caldera
empty — the LLM installs implants dynamically as it compromises each host.

| Environment | Topology | Hosts | Entry point |
|---|---|---|---|
| **Equifax** | segmented (extnet / intnet) | 2 | CVE-2017-5638 (Apache Struts RCE) |
| **Chain-4** | 4-hop linear chain | 4 | CVE-2017-5638 → SSH credential chain |
| **Chain-6** | 6-hop linear chain | 6 | CVE-2017-5638 → SSH credential chain |

---

## 3. Quick Start

**Prerequisites**: Docker Desktop, Python 3.12+, [uv](https://github.com/astral-sh/uv)

### Setup

```bash
# Clone and install dependencies
git clone <repo>
cd Incalmo
uv sync

# Create .env with your API key
cat > .env << 'EOF'
PORTKEY_API_KEY=<your-portkey-key>
CALDERA_API_KEY=<filled automatically after first run>
EOF
```

### Run an environment (one command)

Each environment is fully self-contained. Bring it up, run the attack, tear it down:

**Equifax**
```bash
docker compose -f equifax/docker-compose.segmented.yml -p equifax-seg up -d
docker compose -f equifax/docker-compose.segmented.yml -p equifax-seg exec attacker python -m incalmo.orchestrator
docker compose -f equifax/docker-compose.segmented.yml -p equifax-seg down
```

**Chain-4**
```bash
docker compose -f chain4/docker-compose.chain4.yml -p chain up -d
docker compose -f chain4/docker-compose.chain4.yml -p chain exec attacker python -m incalmo.orchestrator
docker compose -f chain4/docker-compose.chain4.yml -p chain down
```

**Chain-6**
```bash
docker compose -f chain6/docker-compose.chain6.yml -p chain6 up -d
docker compose -f chain6/docker-compose.chain6.yml -p chain6 exec attacker python -m incalmo.orchestrator
docker compose -f chain6/docker-compose.chain6.yml -p chain6 down
```

> **Note:** Only one environment can run at a time (all use ports 8888 and 9000).

### Caldera API key

Each environment's Caldera generates a random API key on first start.
Read it once and store it in the environment's config file:

```bash
# Example for Equifax — read after first docker compose up
docker logs equifax-seg-caldera-1 2>&1 | grep -A8 "admin credentials"
# Copy the Red API_TOKEN (two lines, concatenate them)
# Then add to config/config-equifax.json:
#   "caldera_api_key": "<token>"
```

Once stored in the config file, subsequent runs read it automatically.

---

## 4. Evaluated Results

### Incalmo (LLM Orchestrator — GPT-4o)

| Environment | Rounds | Time | Cost | Success |
|---|---|---|---|---|
| Equifax | 6 | 9.4 min | $0.031 | ✅ 2/2 hosts |
| Chain-4 | 10 | 22.9 min | $0.065 | ✅ 4/4 hosts |
| Chain-6 | 14 | 31.6 min | $0.104 | ✅ 6/6 hosts |

### ExpertPromptShell Baseline (GPT-4o, Equifax)

The paper's primary baseline: LLM outputs raw shell commands with no
high-level abstractions.

| Rounds | Time | Cost | Success |
|---|---|---|---|
| 40 (limit) | 7.8 min | $0.449 | ❌ 0/2 hosts |

The baseline never exploited CVE-2017-5638. It wasted 14 consecutive rounds
downloading Caldera's JavaScript UI files after mistaking the C2 web interface
for target data. This matches the paper's finding that baselines issue 47–90%
irrelevant commands.

Run the baseline:
```bash
docker compose -f equifax/docker-compose.segmented.yml -p equifax-seg up -d
docker compose -f equifax/docker-compose.segmented.yml -p equifax-seg exec attacker \
    python -m incalmo.baselines.expert_prompt_shell
```

---

## 5. Architecture

```
incalmo/
  orchestrator.py          # LLM planning loop (<action>/<query>/<finished>)
  settings.py              # loads config/*.json + .env
  llm/
    client.py              # LangChain + Portkey wrapper
    prompts.py             # system prompt + per-environment prompt
  core/
    models/                # Pydantic: Host, Credential, Subnet, Vulnerability
    services/
      environment_state_service.py   # structured network knowledge base
      attack_graph_service.py        # BFS path-finding (attack + exfil routes)
      cnc_service.py                 # Caldera REST API wrapper
      exfil_receiver.py              # HTTP receiver for pushed data
    actions/
      high_level.py        # 5 task functions the LLM calls
      low_level.py         # WebShell / SshRunner / CncRunner
    agents/
      scan_agent.py        # nmap → structured Host objects
      lateral_move_agent.py  # exploit → deploy Sandcat → CncRunner
      find_info_agent.py   # SSH key / credential discovery
      exfiltrate_agent.py  # multi-hop ncat relay + HTTP push
  baselines/
    expert_prompt_shell.py  # baseline: LLM drives raw shell commands

config/
  config-equifax.json      # Equifax environment settings + Caldera key
  config-chain4.json       # Chain-4 settings + Caldera key
  config-chain6.json       # Chain-6 settings + Caldera key

equifax/                   # Equifax Docker environment
chain4/                    # Chain-4 Docker environment
chain6/                    # Chain-6 Docker environment
output/                    # exfiltrated data (gitignored)
tests/                     # pytest suite (9/9 passing)
```

---

## 6. Roadmap

| Stage | Description | Status |
|---|---|---|
| 0–3 | Data models, services, agents, Caldera C2 integration | ✅ |
| C.5 | Segmented network, multi-hop relay, attack graph | ✅ |
| 4 | LLM planning loop, three environments end-to-end | ✅ |
| 5 | ExpertPromptShell baseline | ✅ |
| 6 | More environments (Star, Dumbbell topologies) | ⬜ |
| 7 | Multi-trial evaluation (5 runs per env), full metrics | ⬜ |
| 8 | Additional baselines (CyberSecEval3, Caldera non-LLM) | ⬜ |

---

## 7. License & Disclaimer

Research / educational use only. Do not run any part of this system against
infrastructure you do not own or are not explicitly authorized to test.
