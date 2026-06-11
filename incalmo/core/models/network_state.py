# Vulnerability  <-+
# Service         +-  parts that make up a Host
# Credential     <-+

# Host           <-+
# Subnet          +-  parts that make up a NetworkState
# Credential     <-+

# NetworkState   <-  the container that holds everything together


from pydantic import BaseModel

from .credential import Credential
from .host import Host
from .subnet import Subnet


class NetworkState(BaseModel):
    hosts: dict[str, Host] = {}
    subnets: dict[str, Subnet] = {}
    credentials: list[Credential] = []
    attacker_ip: str = ''
    goal_hosts: list[str] = []
    goal_data_paths: list[str] = []

    def get_compromised_hosts(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.is_compromised]

    def get_external_hosts(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.is_external]

    def get_host_by_ip(self, ip: str) -> Host | None:
        return self.hosts.get(ip, None)

    def get_all_credentials(self) -> list[Credential]:
        return self.credentials

    def get_uncompromised_hosts(self) -> list[Host]:
        return [h for h in self.hosts.values() if not h.is_compromised]

    def add_host(self, host: Host):
        self.hosts[host.ip] = host

    def add_subnet(self, subnet: Subnet):
        self.subnets[subnet.cidr] = subnet

    def mark_compromised(self, ip: str):
        if ip in self.hosts:
            self.hosts[ip].is_compromised = True

    def mark_has_root(self, ip: str):
        if ip in self.hosts:
            self.hosts[ip].has_root = True

    def add_credential(self, credential: Credential):
        for existing in self.credentials:
            if (existing.username == credential.username and
                    existing.found_on_host == credential.found_on_host):
                return
        self.credentials.append(credential)

    def is_goal_complete(self) -> bool:
        for goal_ip in self.goal_hosts:
            host = self.get_host_by_ip(goal_ip)
            if not host or not host.has_root:
                return False
        return True
