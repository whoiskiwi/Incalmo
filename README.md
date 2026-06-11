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
   <task> / <query> / <finished>          Scan · LateralMove · EscalatePriv …
```

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Planning layer        1 × Claude                                  │
│                       decides the next move, emits                │
│                       <task> / <query> / <finished>               │
└───────────────────────────────┬───────────────────────────────────┘
                                 │  high-level task API
┌───────────────────────────────▼───────────────────────────────────┐
│ Execution layer       orchestrator → deterministic task agents      │
│                       Scan · LateralMove · EscalatePrivilege ·      │
│                       FindInformation · ExfiltrateData              │
└───────────────────────────────┬───────────────────────────────────┘
                                 │  read / update
┌───────────────────────────────▼───────────────────────────────────┐
│ Supporting services   environment-state · attack-graph · C2         │
└───────────────────────────────┬───────────────────────────────────┘
                                 │  acts on
┌───────────────────────────────▼───────────────────────────────────┐
│ Range                 local isolated Docker network                 │
│                       (the self-built "target machines")            │
└─────────────────────────────────────────────────────────────────┘
```

- **Planning layer** (`incalmo/llm/`, `incalmo/core/strategy/`) — a single Claude
  conversation. It never sees raw shell; it reads a summary of network state and
  replies with a structured intent.
- **Execution layer** (`incalmo/core/agents/`, `incalmo/core/actions/`) — one
  deterministic agent per task type. No LLM here: given an intent, each agent runs
  fixed logic (e.g. nmap + parser for `Scan`) and reports results back as state.
- **Supporting services** (`incalmo/core/services/`) — the
  `EnvironmentStateService` is the single source of truth for discovered hosts,
  services, credentials, and vulnerabilities; the attack-graph and C2 services are
  planned.
- **Range** (`equifax/`) — an Equifax-style two-host target: a vulnerable Struts2
  webserver (CVE-2017-5638) and a backend database, wired on an isolated Docker
  network.

---

## 3. Implementation status

This is an in-progress re-implementation. Current state of each module:

| Module | Path | Status |
| --- | --- | --- |
| Data models | `core/models/` | ✅ implemented (host, service, subnet, credential, vulnerability, network_state) |
| Environment-state service | `core/services/environment_state_service.py` | ✅ implemented |
| Base agent | `core/agents/base_agent.py` | ✅ implemented |
| Scan agent + nmap parser | `core/agents/scan_agent.py`, `nmap_parser.py` | ✅ implemented |
| Equifax Docker range | `equifax/` | ✅ implemented |
| LLM client / prompts | `llm/client.py`, `llm/prompts.py` | 🚧 scaffold |
| High/low-level actions | `core/actions/` | 🚧 scaffold |
| Exploit library | `core/exploits/` | 🚧 scaffold |
| Planning strategy loop | `core/strategy/` | 🚧 scaffold |
| Orchestrator / entry point | `orchestrator.py`, `main.py`, `settings.py` | 🚧 scaffold |
| Lateral-move / privesc / find-info / exfil agents | `core/agents/` | ⬜ not started |
| Attack-graph / C2 services | `core/services/` | ⬜ not started |

Tests currently passing: `tests/test_models.py`,
`tests/test_environment_state_service.py`, `tests/test_scan_agent.py`.

---

## 4. Requirements

- Python 3.12+
- [uv](https://github.com/astral-sh/uv)
- Docker (with Compose)
- An Anthropic API key (for the planning layer)

---

## 5. Quick start

```bash
# 1. Install dependencies
uv sync

# 2. Configure
cp .env.example .env                          # then fill in ANTHROPIC_API_KEY
cp config/config.example.json config/config.json

# 3. Run the tests (verifies the implemented core)
uv run pytest

# 4. (once the planning layer is implemented) run one red-team exercise
uv run python main.py
```

### Bringing up the Docker range

The Equifax-style range lives in `equifax/`. The SSH keypair used for the
webserver → database lateral move is a throwaway lab key and is **not committed** —
generate it once after cloning, then build and start the range:

```bash
sh equifax/gen-keys.sh                         # generate the lab SSH keypair locally
cd equifax && docker compose build && docker compose up -d
```

Tear it down with `docker compose down` from inside `equifax/`.

---

## 6. Directory layout

```
main.py                       # entry point
incalmo/
  settings.py                 # load .env + config.json
  llm/                        # planning layer: Claude client + prompt templates
  core/
    models/                   # Pydantic data models (network state, hosts, creds, …)
    services/                 # environment-state (done); attack-graph, C2 (planned)
    agents/                   # deterministic task agents (scan done; others planned)
    actions/                  # high-level task API the LLM calls + low-level commands
    exploits/                 # minimal self-written exploit library
    strategy/                 # the LLM planning loop
  orchestrator.py             # wires services + agents + strategy together
config/                       # config.example.json / config.json
equifax/                      # Docker target range (webserver + database)
range/                        # range notes
output/                       # run artifacts (gitignored)
tests/                        # pytest suite
```

---

## 7. License & disclaimer

Research / educational use only. Do not run any part of this system against
infrastructure you do not own or are not explicitly authorized to test.
