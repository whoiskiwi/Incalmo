"""
Unit tests for the AttackGraphService (paper service #2).

We build a tiny *segmented* network in memory (no real machines are touched):

    attacker(172.16.0.10) --+
                            +-- external 172.16.0.0/24
            web(172.16.0.2) --+   <- dual-homed: the ONLY bridge ext<->int
                            +-- internal 192.168.201.0/24
        db(192.168.201.100) --+   <- internal only; attacker cannot reach directly

This mirrors the segmented Equifax lab: the database is locked inside the
internal subnet, so any attack on it (or exfil from it) must pivot through the
dual-homed web server.
"""

from incalmo.core.services import EnvironmentStateService
from incalmo.core.services.attack_graph_service import AttackGraphService
from incalmo.core.models import Host

ATTACKER = "172.16.0.10"
WEB = "172.16.0.2"
DB = "192.168.201.100"
EXT = "172.16.0.0/24"
INT = "192.168.201.0/24"


def build_segmented_network() -> EnvironmentStateService:
    """Create the ext/int topology described in the module docstring."""
    env = EnvironmentStateService(attacker_ip=ATTACKER)
    env.add_initial_subnet(EXT, is_external=True)
    env.add_initial_subnet(INT, is_external=False)

    # web is dual-homed: its IP is a member of BOTH subnets, so it bridges them.
    env.add_host(Host(ip=WEB, is_external=True))
    env.add_host_to_subnet(WEB, EXT)
    env.add_host_to_subnet(WEB, INT)

    # db lives only on the internal subnet.
    env.add_host(Host(ip=DB, is_external=False))
    env.add_host_to_subnet(DB, INT)

    return env


def test_cannot_reach_internal_db_before_owning_web():
    """Before we control the web bridge, the internal db is unreachable."""
    env = build_segmented_network()
    graph = AttackGraphService(env)

    paths = graph.get_possible_attack_paths(DB)
    assert paths == [], f"expected no path to db before owning web, got {paths}"


def test_external_web_is_directly_reachable():
    """The web server sits on the external subnet, so the attacker reaches it directly."""
    env = build_segmented_network()
    graph = AttackGraphService(env)

    paths = graph.get_possible_attack_paths(WEB)
    assert paths == [[ATTACKER, WEB]], f"unexpected paths to web: {paths}"


def test_can_reach_db_after_owning_web():
    """Once the web bridge is compromised, the db becomes reachable through it."""
    env = build_segmented_network()
    env.mark_compromised(WEB)
    graph = AttackGraphService(env)

    paths = graph.get_possible_attack_paths(DB)
    assert paths == [[ATTACKER, WEB, DB]], f"unexpected paths to db: {paths}"


def test_shortest_exfil_path_pivots_through_web():
    """Data on the internal db must be carried out via the web bridge."""
    env = build_segmented_network()
    graph = AttackGraphService(env)

    path = graph.get_shortest_exfil_path(DB)
    assert path == [DB, WEB, ATTACKER], f"unexpected exfil path: {path}"


def test_isolated_host_has_no_exfil_path():
    """A host on no known subnet is fully isolated -> empty path, no crash."""
    env = build_segmented_network()
    graph = AttackGraphService(env)

    path = graph.get_shortest_exfil_path("10.99.99.99")
    assert path == [], f"isolated host should have no exfil path, got {path}"


def test_shortest_paths_returned_first():
    """With two bridges, both direct (shortest) routes are listed before detours."""
    env = build_segmented_network()
    # add a second dual-homed bridge web2, also compromised, plus the first.
    web2 = "172.16.0.3"
    env.add_host(Host(ip=web2, is_external=True))
    env.add_host_to_subnet(web2, EXT)
    env.add_host_to_subnet(web2, INT)
    env.mark_compromised(WEB)
    env.mark_compromised(web2)
    graph = AttackGraphService(env)

    paths = graph.get_possible_attack_paths(DB)
    # paths must come out shortest-first so the agent tries the cheapest route.
    lengths = [len(p) for p in paths]
    assert lengths == sorted(lengths), f"paths not shortest-first: {paths}"
    # both direct bridges give a length-3 route, and those are the first two.
    assert paths[:2].count([ATTACKER, WEB, DB]) == 1
    assert paths[:2].count([ATTACKER, web2, DB]) == 1


if __name__ == "__main__":
    test_cannot_reach_internal_db_before_owning_web()
    test_external_web_is_directly_reachable()
    test_can_reach_db_after_owning_web()
    test_shortest_exfil_path_pivots_through_web()
    test_isolated_host_has_no_exfil_path()
    test_shortest_paths_returned_first()
    print("OK all attack graph service tests passed")
