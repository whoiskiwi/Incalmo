from typing import Optional

from pydantic import BaseModel


class Service(BaseModel):
    port: int
    protocol: str = "tcp"
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None
