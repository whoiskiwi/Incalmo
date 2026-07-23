import ipaddress
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

        # For subnet scans, follow up with version detection on web hosts
        # so the LLM can see which host has exploitable vulnerabilities
        if "/" in target or "-" in target:
            for host in discovered_hosts:
                if any(p in host.get_open_ports() for p in [80, 8080, 8443, 443]):
                    detailed_output = self._run_nmap(host.ip)
                    if detailed_output:
                        detailed = self.parser.parse(detailed_output)
                        if detailed:
                            host.vulnerabilities = detailed[0].vulnerabilities
                            host.services = detailed[0].services

        # Write the discovered hosts to the environment state service
        for host in discovered_hosts:
            host.is_external = is_external
            self.env_service.add_host(host)
            cidr = self._infer_cidr(host.ip, target)
            if cidr:
                self.env_service.add_host_to_subnet(host.ip, cidr)
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

        For subnet/range scans: fast host discovery only (no version probing).
        For single-IP scans: full version probe to detect vulnerabilities.
        """
        is_single_ip = "/" not in target and "-" not in target
        if is_single_ip:
            command = [
                "nmap",
                "-sV",              # probe versions (needed for vuln detection)
                "--open",
                "-T4",
                "-oX", "-",
                target
            ]
            timeout = 120
        else:
            command = [
                "nmap",
                "-sS",              # SYN scan (faster than -sV)
                "--open",
                "-T4",
                "-F",               # top 100 ports only
                "--host-timeout", "15s",  # skip slow hosts
                "-n",               # no DNS resolution
                "-oX", "-",
                target
            ]
            timeout = 180

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
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

    def _infer_cidr(self, host_ip: str, scan_target: str) -> str | None:
        """
        Find the CIDR this host belongs to.
        1. If scan_target is already a CIDR, use it (if host is inside it).
        2. Otherwise search the known subnets in the environment state service.
        """
        try:
            addr = ipaddress.ip_address(host_ip)
        except ValueError:
            return None

        if "/" in scan_target:
            try:
                net = ipaddress.ip_network(scan_target, strict=False)
                if addr in net:
                    return scan_target
            except ValueError:
                pass

        for subnet in self.env_service.get_subnets():
            try:
                if addr in ipaddress.ip_network(subnet.cidr, strict=False):
                    return subnet.cidr
            except ValueError:
                continue

        return None
