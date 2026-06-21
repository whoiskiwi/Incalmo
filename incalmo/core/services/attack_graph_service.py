from collections import deque


class AttackGraphService:
    """
    Attack graph service (paper service #2).

    Stores nothing itself -- it reads the latest network picture from the
    EnvironmentStateService and computes paths on demand, so it updates
    automatically as scanning / lateral movement discover more of the
network.

    Two questions it answers:
    - get_possible_attack_paths(target_ip): how do I reach a target to
attack it,
        pivoting ONLY through hosts I already control?
    - get_shortest_exfil_path(data_host_ip): what is the shortest chain of
hosts
        to carry stolen data from where it lives back to the attacker?
    """

    def __init__(self, env_service):
        self.env = env_service

    # ---------- reachability primitive: who can talk to whom ----------
    def _adjacency(self) -> dict[str, set[str]]:
        """
        Undirected 'can these two boxes talk over the network' graph.

        Rule: two machines are adjacent if they share a subnet. A dual-homed host
        (e.g. the webserver, listed in BOTH subnets' host_ips) therefore bridges
        those subnets -- exactly what makes it the only path from ext into int.
        The attacker is treated as a member of every EXTERNAL subnet.
        """
        attacker = self.env.state.attacker_ip
        adj: dict[str, set[str]] = {}

        for subnet in self.env.get_subnets():
            members = set(subnet.host_ips)
            if subnet.is_external:
                members.add(attacker)
            for a in members:
                for b in members:
                    if a != b:
                        adj.setdefault(a, set()).add(b)
        return adj

    # ---------- question 1: how do I get to a target to attack it ----------
    def get_possible_attack_paths(self, target_ip: str) -> list[list[str]]:
        """
        All paths from the attacker to `target_ip`, pivoting ONLY through hosts we
        already control. Each path is a list of IPs like [attacker, web, db].
        Shortest paths first, so the agent tries the cheapest one first.
        """
        attacker = self.env.state.attacker_ip
        adj = self._adjacency()
        compromised = {h.ip for h in self.env.get_compromised_hosts()}

        paths: list[list[str]] = []

        def walk(current: str, path: list[str]):
            for nxt in sorted(adj.get(current, ())):
                if nxt in path:
                    continue                      # never loop back
                if nxt == target_ip:
                    paths.append(path + [nxt])    # reached the target
                elif nxt in compromised:
                    walk(nxt, path + [nxt])       # pivot through a box we own

        walk(attacker, [attacker])
        paths.sort(key=len)
        return paths

    # ---------- question 2: shortest way to carry data home ----------
    def get_shortest_exfil_path(self, data_host_ip: str) -> list[str]:
        """
        Shortest chain of hosts to move data from `data_host_ip` back to the
        attacker, e.g. [db, web, attacker]. Empty list if no route exists.
        """
        attacker = self.env.state.attacker_ip
        adj = self._adjacency()

        queue = deque([[data_host_ip]])           # each item = a path-so-far
        seen = {data_host_ip}
        while queue:
            path = queue.popleft()
            here = path[-1]
            if here == attacker:
                return path                       # first pop of attacker = shortest
            for nxt in sorted(adj.get(here, ())):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(path + [nxt])
        return []                                 # data host is fully isolated