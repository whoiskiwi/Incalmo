from typing import Optional

from pydantic import BaseModel


class Credential(BaseModel):
    username: str
    password: Optional[str] = None
    ssh_key: Optional[str] = None
    found_on_host: str
    found_at_path: Optional[str] = None
    can_access_hosts: list[str] = []
