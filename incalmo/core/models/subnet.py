from pydantic import BaseModel


class Subnet(BaseModel):
    cidr: str
    is_external: bool = False
    host_ips: list[str] = []
    reachable_from_subnets: list[str] = []
