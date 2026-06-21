"""
Route planner: turns an attack-graph path into an ordered list of hops
the baseline can execute one-by-one. Pure orchestration logic — it only
decides WHICH host to pivot from next; it does not contain any exploit.
"""
from incalmo.core.services.attack_graph_service import AttackGraphService


def resolve_attack_route(graph: AttackGraphService, target_ip: str):
    """
    Ask the attack graph for the best route to `target_ip`.

    Returns a list of (pivot_from, attack_target) hops, e.g.
        [(attacker, web), (web, db)]
    meaning: from attacker hit web, then from web hit db.

    Returns [] if the target is currently unreachable (no pivot yet) —
    the caller should treat that as "need more recon / more footholds".
    """
    paths = graph.get_possible_attack_paths(target_ip)
    if not paths:
        return []

    best = paths[0]          # shortest-first, see unit test #6
    hops = []
    for i in range(len(best) - 1):
        pivot_from = best[i]      # the host we already control
        attack_target = best[i + 1]   # the next host to take over
        hops.append((pivot_from, attack_target))
    return hops


def resolve_exfil_route(graph: AttackGraphService, data_ip: str):
    """
    Ask the attack graph how to carry stolen data back home.

    Returns a list of (from_host, to_host) relay hops, e.g.
        [(db, web), (web, attacker)]
    meaning: db -> web -> attacker.
    """
    path = graph.get_shortest_exfil_path(data_ip)
    if not path:
        return []

    hops = []
    for i in range(len(path) - 1):
        hops.append((path[i], path[i + 1]))
    return hops