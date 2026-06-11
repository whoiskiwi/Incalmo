import subprocess
from incalmo.core.services import EnvironmentStateService
from incalmo.core.models import Host
from .base_agent import BaseAgent
from .nmap_parser import NmapParser

class ScanAgent(BaseAgent):
    """
    Scan agent: the first step of the whole attack chain.

    In the Equifax scenario:
    planning layer says "scan 10.0.0.0/24"
    -> ScanAgent runs nmap
    -> discovers 10.0.0.2 and 10.0.0.3 (Web1 and Web2)
    -> finds both have CVE-2017-5638
    -> writes them to the environment state service
    -> planning layer sees the results and decides to attack Web1
    """

    def __init__(self, env_service: EnvironmentStateService):
        super().__init__(env_service)
        self.parser = NmapParser()

    def run(self, target: str, is_external: bool = False) -> dict:
        """
        Scan a target subnet or IP.

        target: the scan target, can be:
        - a single IP:   "10.0.0.2"
        - a whole subnet: "10.0.0.0/24"

        is_external: whether this target is on the external network.
        Provided by the planning layer; used to tag discovered hosts.

        Returns: the list of discovered hosts.
        """
        print(f"[ScanAgent] Starting scan: {target}")

        # Run the nmap scan
        nmap_output = self._run_nmap(target)

        if not nmap_output:
            return self._failure(f"nmap scan failed: {target}")

        # Parse the results
        discovered_hosts = self.parser.parse(nmap_output)

        if not discovered_hosts:
            return self._failure(
                f"No hosts discovered: {target}",
                {"target": target}
            )

        # Write the discovered hosts to the environment state service
        for host in discovered_hosts:
            host.is_external = is_external
            self.env_service.add_host(host)
            print(f"[ScanAgent] Discovered host: {host.ip}, "
                f"open ports: {host.get_open_ports()}, "
                f"vulnerabilities: {[v.cve_id for v in host.vulnerabilities]}")

        return self._success(
            f"Scan complete, discovered {len(discovered_hosts)} host(s)",
            {
                "discovered_hosts": [
                    {
                        "ip": h.ip,
                        "ports": h.get_open_ports(),
                        "vulnerabilities": [
                            v.cve_id for v in h.vulnerabilities
                        ]
                    }
                    for h in discovered_hosts
                ]
            }
        )

    def _run_nmap(self, target: str) -> str | None:
        """
        Run the nmap command and return XML output.

        nmap flags:
        -sV: probe service versions (used to match vulnerabilities)
        -oX -: output XML to stdout
        --open: only show open ports
        -T4: speed up the scan
        """
        command = [
            "nmap",
            "-sV",          # probe versions
            "--open",       # only show open ports
            "-T4",          # timing template 4 (faster)
            "-oX", "-",     # XML output to stdout
            target
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120  # wait at most 2 minutes
            )

            if result.returncode != 0:
                print(f"[ScanAgent] nmap error: {result.stderr}")
                return None

            return result.stdout

        except subprocess.TimeoutExpired:
            print(f"[ScanAgent] nmap scan timed out: {target}")
            return None
        except FileNotFoundError:
            print("[ScanAgent] nmap not found, please install it first: brew install nmap")
            return None
