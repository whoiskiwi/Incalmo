"""
Tests for the LLM planning layer (orchestrator + high_level dispatch).
Uses mock agents and a fake LLM — no real API key needed.
"""

from unittest.mock import MagicMock, patch
import pytest

from incalmo.core.services.environment_state_service import EnvironmentStateService
from incalmo.core.services.attack_graph_service import AttackGraphService
import incalmo.core.actions.high_level as hl
from incalmo.orchestrator import _extract_tag, _exec_action, _exec_query, _format_results


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def env():
    e = EnvironmentStateService(attacker_ip="10.0.0.50")
    e.add_initial_subnet("10.0.0.0/24", is_external=True)
    e.add_initial_subnet("192.168.1.0/24", is_external=False)
    return e

@pytest.fixture
def graph(env):
    return AttackGraphService(env)

@pytest.fixture
def mock_agents(env):
    """Return mock versions of all 4 agents."""
    scan    = MagicMock()
    lateral = MagicMock()
    findinfo = MagicMock()
    exfil   = MagicMock()

    scan.run.return_value = {
        "success": True,
        "message": "Scan complete, discovered 1 host(s)",
        "data": {"discovered_hosts": [{"ip": "10.0.0.2", "ports": [8080],
                                        "vulnerabilities": ["CVE-2017-5638"]}]},
    }
    lateral.run.return_value = {
        "success": True,
        "message": "Compromised 10.0.0.2 via struts exploit",
        "data": {"runner": MagicMock()},
    }
    findinfo.run.return_value = {
        "success": True,
        "message": "Found SSH key for database@192.168.1.100",
        "data": {"username": "database", "can_access": "192.168.1.100"},
    }
    exfil.run.return_value = {
        "success": True,
        "message": "Exfiltrated 3097051 bytes",
        "data": {"saved_to": "/tmp/data.json", "bytes": 3097051},
    }
    return scan, lateral, findinfo, exfil

@pytest.fixture(autouse=True)
def init_hl(env, graph, mock_agents):
    """Initialize high_level module before every test."""
    scan, lateral, findinfo, exfil = mock_agents
    hl.init(
        env=env, cnc=MagicMock(), graph=graph,
        scan_agent=scan, lateral_agent=lateral,
        findinfo_agent=findinfo, exfil_agent=exfil,
    )


# ---------------------------------------------------------------------------
# 1. Tag extraction
# ---------------------------------------------------------------------------

def test_extract_action_tag():
    text = "Some reasoning.\n<action>\ndef action(env, graph):\n    scan('10.0.0.0/24')\n</action>"
    result = _extract_tag(text, "action")
    assert result is not None
    assert "scan" in result

def test_extract_query_tag():
    text = "<query>\ndef query(env, graph):\n    return env.get_network_summary()\n</query>"
    result = _extract_tag(text, "query")
    assert result is not None
    assert "get_network_summary" in result

def test_extract_missing_tag():
    assert _extract_tag("no tags here", "action") is None


# ---------------------------------------------------------------------------
# 2. exec action
# ---------------------------------------------------------------------------

def test_exec_action_scan(env, graph, mock_agents):
    code = "def action(env, graph):\n    scan('10.0.0.0/24')"
    summary = _exec_action(code, env, graph)
    assert "SUCCESS" in summary
    assert "scan" in summary.lower()

def test_exec_action_lateral_move(env, graph, mock_agents):
    # Seed the webserver so the attack graph can find a path
    from incalmo.core.models import Host
    env.add_host(Host(ip="10.0.0.2", is_external=True))
    env.add_host_to_subnet("10.0.0.2", "10.0.0.0/24")

    code = "def action(env, graph):\n    lateral_move('10.0.0.2')"
    summary = _exec_action(code, env, graph)
    assert "lateral_move" in summary.lower()

def test_exec_action_escalate_privilege_stub(env, graph):
    """escalate_privilege should return not-needed without crashing."""
    code = "def action(env, graph):\n    escalate_privilege('10.0.0.2')"
    summary = _exec_action(code, env, graph)
    assert "FAILED" in summary
    assert "not needed" in summary.lower()

def test_exec_action_syntax_error(env, graph):
    code = "def action(env, graph):\n    @@invalid python@@"
    summary = _exec_action(code, env, graph)
    assert "ERROR" in summary

def test_exec_action_wrong_function_name(env, graph):
    code = "def plan():\n    scan('10.0.0.0/24')"
    summary = _exec_action(code, env, graph)
    assert "ERROR" in summary

def test_exec_action_multiple_tasks(env, graph, mock_agents):
    code = (
        "def action(env, graph):\n"
        "    scan('10.0.0.0/24')\n"
        "    escalate_privilege('10.0.0.2')\n"
    )
    summary = _exec_action(code, env, graph)
    assert "scan" in summary.lower()
    assert "escalate_privilege" in summary.lower()


# ---------------------------------------------------------------------------
# 3. exec query
# ---------------------------------------------------------------------------

def test_exec_query_network_summary(env, graph):
    code = "def query(env, graph):\n    return env.get_network_summary()"
    result = _exec_query(code, env, graph)
    assert "Query result" in result

def test_exec_query_returns_host_list(env, graph):
    from incalmo.core.models import Host
    env.add_host(Host(ip="10.0.0.2", is_external=True))
    code = "def query(env, graph):\n    return [h.ip for h in env.get_all_hosts()]"
    result = _exec_query(code, env, graph)
    assert "10.0.0.2" in result

def test_exec_query_wrong_function_name(env, graph):
    code = "def plan():\n    return 42"
    result = _exec_query(code, env, graph)
    assert "ERROR" in result

def test_exec_query_syntax_error(env, graph):
    code = "def query(env, graph):\n    return @@bad@@"
    result = _exec_query(code, env, graph)
    assert "ERROR" in result


# ---------------------------------------------------------------------------
# 4. format_results
# ---------------------------------------------------------------------------

def test_format_results_success():
    results = [{"task": "scan 10.0.0.0/24", "success": True,
                "message": "Discovered 1 host", "data": {}}]
    out = _format_results(results)
    assert "[Action: scan 10.0.0.0/24] SUCCESS" in out
    assert "Discovered 1 host" in out

def test_format_results_failure():
    results = [{"task": "lateral_move 10.0.0.2", "success": False,
                "message": "No reachable path", "data": {}}]
    out = _format_results(results)
    assert "FAILED" in out
    assert "No reachable path" in out

def test_format_results_hides_runner():
    """runner object must not appear in the summary sent back to the LLM."""
    results = [{"task": "lateral_move 10.0.0.2", "success": True,
                "message": "ok", "data": {"runner": MagicMock(), "paw": "abc123"}}]
    out = _format_results(results)
    assert "runner" not in out
    assert "abc123" in out

def test_format_results_empty():
    assert _format_results([]) == "No tasks were executed."


# ---------------------------------------------------------------------------
# 5. Full mock loop (no real API)
# ---------------------------------------------------------------------------

def test_mock_llm_loop(env, graph, mock_agents):
    """
    Run the orchestrator with a fake LLM that returns a pre-canned sequence:
      round 1: <action> scan
      round 2: <finished>
    Verify the loop terminates correctly and the scan agent was called.
    """
    scan, *_ = mock_agents

    responses = iter([
        "<action>\ndef action(env, graph):\n    scan('10.0.0.0/24')\n</action>",
        "<finished>",
    ])

    with patch("incalmo.orchestrator.IncalmoLLMClient") as MockClient:
        instance = MockClient.return_value
        instance.invoke.side_effect = lambda msgs: next(responses)
        instance.cost_summary.return_value = "tokens in=100 out=50 cost=$0.0010"

        from incalmo.orchestrator import (
            _exec_action, _exec_query, _extract_tag, _format_results
        )

        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user",   "content": "start"},
        ]

        llm = instance
        iteration = 0
        finished = False

        for _ in range(10):
            response = llm.invoke(messages)
            messages.append({"role": "assistant", "content": response})
            iteration += 1

            if "<finished>" in response:
                finished = True
                break
            elif "<action>" in response:
                fn_code = _extract_tag(response, "action")
                summary = _exec_action(fn_code, env, graph)
                messages.append({"role": "user", "content": summary})

        assert finished, "Loop should have terminated on <finished>"
        assert iteration == 2
        scan.run.assert_called_once_with("10.0.0.0/24")
