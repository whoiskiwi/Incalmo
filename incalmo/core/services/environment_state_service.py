from incalmo.core.models import (
    NetworkState, Host, Subnet,
    Credential, Vulnerability, Service
)

class EnvironmentStateService:
    """
    Environment state service.

    Its role in Incalmo:
    - An agent finishes a task -> calls this service to update state.
    - The planning layer needs to decide -> calls this service to query state.
    - The attack graph service needs network info -> calls this service to get data.

    Core problem it solves:
    older systems stuffed all info into the LLM context (causing 150k-character bloat).
    This service stores the info in a structured database, and the LLM only
    queries it when needed, so the context always stays clean.
    """

    def __init__(self, attacker_ip: str):
        """
        Initialize the service.

        attacker_ip: the IP of the attacker's Kali machine.
        Create a new service instance at the start of each red-team trial.
        """
        self.state = NetworkState(attacker_ip=attacker_ip)

    # -----------------------------------------
    # Initialization methods (called at the start of a red-team trial)
    # -----------------------------------------

    def set_goal_hosts(self, host_ips: list[str]):
        """
        Set the list of goal hosts.
        Corresponds to the 30 "gain root" type environments in MHBench.
        Called by the main loop at the start of a red-team trial.
        """
        self.state.goal_hosts = host_ips

    def set_goal_data_paths(self, paths: list[str]):
        """
        Set the list of goal data file paths.
        Corresponds to the 10 "exfiltrate data file" type environments in MHBench.
        Called by the main loop at the start of a red-team trial.
        """
        self.state.goal_data_paths = paths

    def add_initial_subnet(self, cidr: str, is_external: bool):
        """
        Add an initially-known subnet.
        At the start of a red-team trial, at least the external IP range is known.
        Called by the main loop after reading the environment config file.
        """
        subnet = Subnet(
            cidr=cidr,
            is_external=is_external
        )
        self.state.add_subnet(subnet)

    # -----------------------------------------
    # Query methods (called by the planning layer and agents)
    # -----------------------------------------

    def get_all_hosts(self) -> list[Host]:
        """Return all discovered hosts."""
        return list(self.state.hosts.values())

    def get_external_hosts(self) -> list[Host]:
        """
        Return the list of external hosts.
        Called when the planning layer decides which subnet to scan first.
        """
        return self.state.get_external_hosts()

    def get_compromised_hosts(self) -> list[Host]:
        """
        Return all compromised hosts.
        Called when the planning layer decides which pivot host to launch the next attack from.
        """
        return self.state.get_compromised_hosts()

    def get_uncompromised_hosts(self) -> list[Host]:
        """
        Return hosts that are not yet compromised.
        Called when the planning layer looks for the next attack target.
        """
        return self.state.get_uncompromised_hosts()

    def get_host(self, ip: str) -> Host | None:
        """Look up a host by exact IP."""
        return self.state.get_host_by_ip(ip)

    def get_credentials(self) -> list[Credential]:
        """
        Return all discovered credentials.
        Called when the LateralMove agent decides which credential to log in with.
        """
        return self.state.get_all_credentials()

    def get_subnets(self) -> list[Subnet]:
        """Return all known subnets."""
        return list(self.state.subnets.values())

    def get_network_summary(self) -> dict:
        """
        Return a summary of the network state.
        Called when the planning layer builds a prompt, to tell the LLM the summary.

        Return format:
        {
            "total_hosts": 5,
            "compromised_hosts": ["10.0.0.2"],
            "external_hosts": ["10.0.0.2", "10.0.0.3"],
            "credentials_found": 2,
            "subnets": ["10.0.0.0/24", "192.168.1.0/24"]
        }
        """
        return {
            "total_hosts": len(self.state.hosts),
            "compromised_hosts": [
                h.ip for h in self.get_compromised_hosts()
            ],
            "external_hosts": [
                h.ip for h in self.get_external_hosts()
            ],
            "credentials_found": len(self.state.credentials),
            "subnets": list(self.state.subnets.keys())
        }

    def is_goal_complete(self) -> bool:
        """
        Check whether all goals are complete.
        Called by the main loop at the end of each round to decide whether to stop.
        """
        return self.state.is_goal_complete()

    # -----------------------------------------
    # Update methods (called after an agent finishes a task)
    # -----------------------------------------

    def add_host(self, host: Host):
        """
        Add or update a host.
        Called by the Scan agent whenever it discovers a new host.
        """
        self.state.add_host(host)

    def add_vulnerability_to_host(
        self,
        host_ip: str,
        vulnerability: Vulnerability
    ):
        """
        Add a vulnerability to a host.
        Called by the Scan agent after it discovers a vulnerability.
        """
        host = self.state.get_host_by_ip(host_ip)
        if host:
            # Check whether the same CVE already exists to avoid duplicates
            existing_cves = [v.cve_id for v in host.vulnerabilities]
            if vulnerability.cve_id not in existing_cves:
                host.vulnerabilities.append(vulnerability)

    def mark_compromised(self, host_ip: str):
        """
        Mark a host as compromised.
        Called by the LateralMove agent after it successfully installs the C&C implant.
        """
        self.state.mark_compromised(host_ip)

    def mark_has_root(self, host_ip: str):
        """
        Mark a host as having root privileges.
        Called by the EscalatePrivilege agent after a successful privilege escalation.
        """
        self.state.mark_has_root(host_ip)

    def add_credential(self, credential: Credential):
        """
        Add a discovered credential.
        Called by the FindInformation agent after it finds a password or key.
        """
        self.state.add_credential(credential)

    def update_credential_access(
        self,
        username: str,
        found_on_host: str,
        can_access: str
    ):
        """
        Update which hosts a credential can access.
        Called by the LateralMove agent after it logs in successfully with a credential.

        username: the credential's username
        found_on_host: which host the credential was found on
        can_access: the IP of the new host this credential can log into
        """
        for cred in self.state.credentials:
            if (cred.username == username and
                cred.found_on_host == found_on_host):
                if can_access not in cred.can_access_hosts:
                    cred.can_access_hosts.append(can_access)
                break

    def add_host_to_subnet(self, host_ip: str, cidr: str):
        """
        Add a host IP to the corresponding subnet record.
        Called by the Scan agent when it discovers a new host.
        """
        if cidr in self.state.subnets:
            subnet = self.state.subnets[cidr]
            if host_ip not in subnet.host_ips:
                subnet.host_ips.append(host_ip)
