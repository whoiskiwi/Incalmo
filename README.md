# Incalmo (from-paper re-implementation)

This project is an **independent reimplementation** of the paper **Incalmo: An Autonomous LLM-assisted System for Red Teaming Multi-Host Networks**
(arXiv:2501.16466) — written from scratch based only on the paper's concepts and methods, not copied from the official code.

> ⚠️ For **academic study and defensive security research only**. All attacks run solely inside an isolated local Docker range, against self-built target machines, and never touch any real/external system.

See the full roadmap in `PLAN.md` (kept locally).

## Core architecture (the paper's main architecture)

```
Planning layer: 1 Claude (decides "what to do", outputs <task>/<query>/<finished>)
            |
Execution layer: orchestrator -> 5 [non-LLM] deterministic task agents
            |        Scan / LateralMove / EscalatePrivilege / FindInformation / ExfiltrateData
            |
Supporting services: environment state service . attack graph service . C2 service
            |
Range: local isolated Docker network (the "fake machines" being attacked)
```

Key idea: **the AI only plans; execution is handed to non-AI expert programs** — this is why the paper reached 37/40.

## Requirements

- Python 3.12+, [uv](https://github.com/astral-sh/uv), Docker

## Quick start

```bash
# 1. Install dependencies
uv sync

# 2. Configure
cp .env.example .env          # fill in ANTHROPIC_API_KEY
cp config/config.example.json config/config.json

# 3. Verify Claude connectivity (hello-world)
uv run python -m incalmo.llm.client

# 4. (later) run one red-team exercise
uv run python main.py
```

## Range (Docker target)

The Equifax-style range lives in `equifax/`. Its SSH keypair (used for the
webserver -> database lateral move) is a throwaway lab key and is **not**
committed; generate it once after cloning, then build:

```bash
sh equifax/gen-keys.sh        # generates the lab SSH keypair locally
cd equifax && docker compose build && docker compose up -d
```

## Directory layout

```
main.py                       # entry point
incalmo/
  settings.py                 # read .env + config.json
  llm/                        # planning layer: Claude client + prompts
  core/
    models/   {network,events}   # data models + event system
    services/ {environment_state, attack_graph, c2}
    agents/   {scan, lateral_move, escalate_privilege, find_information, exfiltrate_data}
    actions/  {high_level, low_level}   # task API the LLM calls + low-level commands
    exploits/                          # self-written minimal exploit library
    strategy/ {base, llm_planning}     # planning loop
  orchestrator.py             # wires services / agents / strategy together
config/  range/  output/  tests/
reference/official/           # original official files (kept for reference only, not used)
```

Implementation progress per module is tracked in the staged plan (`PLAN.md`, kept locally).
