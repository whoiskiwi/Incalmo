from typing import Optional

from pydantic import BaseModel

from .credential import Credential
from .service import Service
from .vulnerability import Vulnerability


class Host(BaseModel):
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    subnet: Optional[str] = None
    is_external: bool = False
    is_compromised: bool = False
    has_root: bool = False
    services: list[Service] = []
    vulnerabilities: list[Vulnerability] = []
    credentials: list[Credential] = []
    reachable_from: list[str] = []

    def get_exploitable_vulnerabilities(self) -> list[Vulnerability]:
        return [v for v in self.vulnerabilities if v.exploit_available]

    def get_open_ports(self) -> list[int]:
        return [s.port for s in self.services]
