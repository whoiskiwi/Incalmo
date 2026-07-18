"""
Orchestrator: wires up all services and agents, then drives the LLM planning loop.

Run inside the attacker container:
    python -m incalmo.orchestrator
"""

import re
import time
from dotenv import load_dotenv

load_dotenv()

from incalmo.settings import load_settings
from incalmo.llm.client import IncalmoLLMClient
from incalmo.llm.prompts import SYSTEM_PROMPT, get_env_prompt
from incalmo.core.services.environment_state_service import EnvironmentStateService
from incalmo.core.services.cnc_service import CncService
from incalmo.core.services.attack_graph_service import AttackGraphService
from incalmo.core.agents.scan_agent import ScanAgent
from incalmo.core.agents.lateral_move_agent import LateralMoveAgent
from incalmo.core.agents.find_info_agent import FindInfoAgent
from incalmo.core.agents.exfiltrate_agent import ExfiltrateAgent
import incalmo.core.actions.high_level as hl


# ---------------------------------------------------------------------------
# Tag extraction
# ---------------------------------------------------------------------------

def _extract_tag(text: str, tag: str) -> str | None:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.DOTALL)
    return m.group(1).strip() if m else None


# ---------------------------------------------------------------------------
# exec() namespaces
# ---------------------------------------------------------------------------

def _action_namespace() -> dict:
    """Globals for <action> blocks: the 5 task functions."""
    return {
        "scan":               hl.scan,
        "lateral_move":       hl.lateral_move,
        "find_information":   hl.find_information,
        "escalate_privilege": hl.escalate_privilege,
        "exfiltrate_data":    hl.exfiltrate_data,
    }


def _exec_action(fn_code: str, env, graph) -> str:
    """
    Execute an <action> block.
    Calls action(env, graph), which enqueues tasks via the 5 task functions.
    Then dispatches all queued tasks and returns a structured summary.
    """
    ns = _action_namespace()
    try:
        exec(fn_code, ns)
    except SyntaxError as e:
        return f"ERROR: Syntax error in action code: {e}"

    if "action" not in ns or not callable(ns["action"]):
        return "ERROR: action code must define a function named 'action(env, graph)'."

    try:
        ns["action"](env, graph)
    except Exception as e:
        return f"ERROR: Exception while running action: {e}"

    results = hl.dispatch_all_queued_tasks()
    return _format_results(results)


def _exec_query(fn_code: str, env, graph) -> str:
    """
    Execute a <query> block.
    Calls query(env, graph) and returns the result as a string.
    """
    ns = {}
    try:
        exec(fn_code, ns)
    except SyntaxError as e:
        return f"ERROR: Syntax error in query code: {e}"

    if "query" not in ns or not callable(ns["query"]):
        return "ERROR: query code must define a function named 'query(env, graph)'."

    try:
        result = ns["query"](env, graph)
        return f"Query result:\n{result}"
    except Exception as e:
        return f"ERROR: Exception while running query: {e}"


# ---------------------------------------------------------------------------
# Result formatting
# ---------------------------------------------------------------------------

def _format_results(results: list[dict]) -> str:
    if not results:
        return "No tasks were executed."
    lines = []
    for r in results:
        label = r.get("task", "unknown")
        status = "SUCCESS" if r.get("success") else "FAILED"
        msg = r.get("message", "")
        lines.append(f"[Action: {label}] {status}")
        if msg:
            lines.append(f"  → {msg}")
        data = r.get("data") or {}
        for k, v in data.items():
            if k != "runner" and v is not None:
                lines.append(f"  → {k}: {v}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_orchestrator():
    settings = load_settings()

    if not settings.portkey_api_key:
        print("[ERROR] PORTKEY_API_KEY not set. Add it to .env and retry.")
        return

    # ── Services ──────────────────────────────────────────────────────────
    env   = EnvironmentStateService(attacker_ip=settings.attacker_ip)
    cnc   = CncService()
    graph = AttackGraphService(env)

    # Seed the two known subnets so the attack graph has a starting topology
    env.add_initial_subnet(settings.extnet, is_external=True)
    env.add_initial_subnet(settings.intnet, is_external=False)

    # ── Agents ────────────────────────────────────────────────────────────
    scan_agent    = ScanAgent(env)
    lateral_agent = LateralMoveAgent(env, cnc)
    findinfo_agent = FindInfoAgent(env)
    exfil_agent   = ExfiltrateAgent(env)

    # ── Wire the dispatch layer ───────────────────────────────────────────
    hl.init(
        env=env, cnc=cnc, graph=graph,
        scan_agent=scan_agent,
        lateral_agent=lateral_agent,
        findinfo_agent=findinfo_agent,
        exfil_agent=exfil_agent,
        attacker_ip=settings.attacker_ip,
        web_intnet_ip=settings.web_intnet_ip,
    )

    # ── LLM client ────────────────────────────────────────────────────────
    llm = IncalmoLLMClient(
        model=settings.model,
        api_key=settings.portkey_api_key,
        max_tokens=settings.max_tokens,
    )

    # ── Onboarding messages ───────────────────────────────────────────────
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": get_env_prompt(
            extnet=settings.extnet,
            intnet=settings.intnet,
            attacker_ip=settings.attacker_ip,
        )},
    ]

    # ── Planning loop ─────────────────────────────────────────────────────
    start      = time.time()
    timeout    = settings.timeout_minutes * 60
    max_rounds = settings.max_rounds
    iteration  = 0

    print(f"\n[Orchestrator] Starting — model={settings.model}  "
          f"timeout={settings.timeout_minutes}min  max_rounds={max_rounds}")
    print("=" * 70)

    while True:
        elapsed = time.time() - start

        if elapsed > timeout:
            print(f"\n[Orchestrator] Timeout reached ({settings.timeout_minutes} min).")
            break
        if iteration >= max_rounds:
            print(f"\n[Orchestrator] Max rounds reached ({max_rounds}).")
            break

        iteration += 1
        print(f"\n── Round {iteration}  ({elapsed/60:.1f} min elapsed) ──")

        # Ask the LLM
        response = llm.invoke(messages)
        messages.append({"role": "assistant", "content": response})

        # Show first 400 chars of LLM reply so we can follow along
        preview = response[:400].replace("\n", " ")
        print(f"[LLM] {preview}{'...' if len(response) > 400 else ''}")

        # ── Parse and dispatch ──
        if "<finished>" in response:
            print("[Orchestrator] LLM signalled <finished>.")
            break

        elif "<action>" in response:
            fn_code = _extract_tag(response, "action")
            if fn_code:
                summary = _exec_action(fn_code, env, graph)
            else:
                summary = "ERROR: Could not parse <action> block."

        elif "<query>" in response:
            fn_code = _extract_tag(response, "query")
            if fn_code:
                summary = _exec_query(fn_code, env, graph)
            else:
                summary = "ERROR: Could not parse <query> block."

        else:
            summary = (
                "No recognised tag found. "
                "Please respond with <action>, <query>, or <finished>."
            )

        print(f"[Result] {summary[:300]}{'...' if len(summary) > 300 else ''}")
        print(f"[Cost]   {llm.cost_summary()}")

        messages.append({"role": "user", "content": summary})

    # ── Final report ──────────────────────────────────────────────────────
    elapsed = time.time() - start
    compromised = [h.ip for h in env.get_compromised_hosts()]
    print("\n" + "=" * 70)
    print(f"[Orchestrator] Done in {elapsed/60:.1f} min | {iteration} rounds | "
          f"{llm.cost_summary()}")
    print(f"[Orchestrator] Compromised hosts: {compromised}")


if __name__ == "__main__":
    run_orchestrator()
