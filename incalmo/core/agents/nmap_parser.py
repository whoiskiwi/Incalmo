import subprocess
import xml.etree.ElementTree as ET
from incalmo.core.models import Host, Service, Vulnerability

# Known vulnerability database: service name + version -> CVE id.
# This is a simplified version of the "internal vulnerability library" from the paper.
# The real one would be larger; for now it only holds the vuln used in the paper.
KNOWN_VULNERABILITIES = {
    # Apache Struts 2.3.x -> CVE-2017-5638
    # This is the vulnerability used in the Equifax scenario.
    ("apache-struts", "2.3"): Vulnerability(
        cve_id="CVE-2017-5638",
        service="apache-struts",
        port=8080,
        description="Apache Struts remote code execution vulnerability",
        exploit_available=True,
        exploit_path="exploit/multi/http/struts2_content_type_ognl"
    ),
}

# Host-level fingerprint: if a host has ALL of these ports open, inject this vuln.
# Tomcat + AJP together = Struts servlet container (unique to the lab webserver).
HOST_FINGERPRINTS = [
    {
        "required_ports": {8009, 8080},   # AJP + HTTP both present
        "product_keyword": "ajp13",        # AJP service name unique to Tomcat
        "vulnerability": Vulnerability(
            cve_id="CVE-2017-5638",
            service="apache-struts",
            port=8080,
            description="Apache Struts remote code execution vulnerability",
            exploit_available=True,
            exploit_path="exploit/multi/http/struts2_content_type_ognl"
        ),
    },
]

class NmapParser:
    """
    Parser for nmap scan results.

    Workflow:
    1. ScanAgent runs nmap and gets XML output.
    2. This parser reads the XML.
    3. Extracts each host's IP, ports, services and versions.
    4. Compares against KNOWN_VULNERABILITIES to find known vulns.
    5. Builds Host objects and returns them to ScanAgent.
    6. ScanAgent writes the Host objects to the environment state service.
    """

    def parse(self, nmap_xml_output: str) -> list[Host]:
        """
        Parse nmap's XML output and return a list of Host objects.

        Why XML format:
        nmap supports the -oX flag to output XML, which is easier to parse than text.
        """
        hosts = []

        try:
            root = ET.fromstring(nmap_xml_output)
        except ET.ParseError as e:
            print(f"XML parse failed: {e}")
            return hosts

        # Iterate over each discovered host
        for host_elem in root.findall("host"):

            # Only handle hosts with state "up" (online)
            status = host_elem.find("status")
            if status is None:
                continue
            if status.get("state") != "up":
                continue

            # Get the IP address
            ip = None
            for addr in host_elem.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
                    break

            if not ip:
                continue

            # Parse all open ports and services
            services = []
            vulnerabilities = []

            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):

                    # Only handle ports with state "open"
                    state_elem = port_elem.find("state")
                    if state_elem is None:
                        continue
                    if state_elem.get("state") != "open":
                        continue

                    port_number = int(port_elem.get("portid"))
                    protocol = port_elem.get("protocol", "tcp")

                    # Get the service info
                    service_elem = port_elem.find("service")
                    service_name = "unknown"
                    service_version = None

                    product = ""
                    if service_elem is not None:
                        service_name = service_elem.get("name", "unknown")

                        product = service_elem.get("product", "")
                        version = service_elem.get("version", "")
                        if version:
                            service_version = version
                        elif product:
                            service_version = product

                    service = Service(
                        port=port_number,
                        protocol=protocol,
                        name=service_name,
                        version=service_version
                    )
                    services.append(service)

                    # Compare against the vuln database to check for known vulns
                    # Pass product so Tomcat-style fingerprints can be matched
                    vuln = self._check_vulnerability(
                        service_name,
                        service_version,
                        port_number,
                        product=product,
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

            # Host-level fingerprint check (e.g. Tomcat+AJP = Struts)
            open_ports = {s.port for s in services}
            service_names = " ".join(s.name for s in services).lower()
            for fp in HOST_FINGERPRINTS:
                if fp["required_ports"].issubset(open_ports) and \
                        fp["product_keyword"] in service_names:
                    vuln = fp["vulnerability"]
                    if not any(v.cve_id == vuln.cve_id for v in vulnerabilities):
                        vulnerabilities.append(vuln)

            # Build the Host object
            host = Host(
                ip=ip,
                services=services,
                vulnerabilities=vulnerabilities
            )
            hosts.append(host)

        return hosts

    def _check_vulnerability(
        self,
        service_name: str,
        version: str | None,
        port: int,
        product: str = "",
    ) -> Vulnerability | None:
        """
        Check whether a service has a known vulnerability.
        Matches on service_name OR product string, then version prefix.
        Empty vuln_version matches any version.
        """
        fingerprint = f"{service_name} {product}".lower()

        for (vuln_service, vuln_version), vuln in \
                KNOWN_VULNERABILITIES.items():

            if vuln_service.lower() not in fingerprint:
                continue

            # Empty vuln_version matches any version
            if vuln_version == "":
                return Vulnerability(
                    cve_id=vuln.cve_id,
                    service=vuln.service,
                    port=port,
                    description=vuln.description,
                    exploit_available=vuln.exploit_available,
                    exploit_path=vuln.exploit_path
                )

            if version and version.startswith(vuln_version):
                return Vulnerability(
                    cve_id=vuln.cve_id,
                    service=vuln.service,
                    port=port,
                    description=vuln.description,
                    exploit_available=vuln.exploit_available,
                    exploit_path=vuln.exploit_path
                )

        return None
