import json
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config" / "config.json"
_CONFIG_PATH = Path(os.environ.get("INCALMO_CONFIG", str(_DEFAULT_CONFIG)))


@dataclass
class Settings:
    portkey_api_key: str = ""
    caldera_api_key: str = ""
    model: str = "@openai/gpt-4o"
    attacker_ip: str = "10.0.0.50"
    extnet: str = "10.0.0.0/24"
    intnet: str = "192.168.1.0/24"
    web_intnet_ip: str = "192.168.1.2"  # webserver intnet-facing IP, used in exfil relay URL
    extnet_docker: str = "equifax-seg_extnet"  # Docker network name for the external subnet
    data_path: str = "/home/database/data.json"
    goal: str = ""
    timeout_minutes: int = 75
    max_rounds: int = 40
    max_tokens: int = 4096


def load_settings() -> Settings:
    s = Settings()
    s.portkey_api_key = os.environ.get("PORTKEY_API_KEY", "")
    s.caldera_api_key = os.environ.get("CALDERA_API_KEY", "")

    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH) as f:
            cfg = json.load(f)
        planner = cfg.get("planner", {})
        s.model = planner.get("model", s.model)
        s.max_rounds = planner.get("max_rounds", s.max_rounds)
        s.max_tokens = planner.get("max_tokens_per_call", s.max_tokens)
        timeout_sec = planner.get("timeout_seconds")
        if timeout_sec:
            s.timeout_minutes = timeout_sec // 60

        network = cfg.get("network", {})
        s.extnet = network.get("extnet", s.extnet)
        s.intnet = network.get("intnet", s.intnet)
        s.attacker_ip = network.get("attacker_ip", s.attacker_ip)
        s.web_intnet_ip = network.get("web_intnet_ip", s.web_intnet_ip)
        s.extnet_docker = network.get("extnet_docker", s.extnet_docker)

        target = cfg.get("target", {})
        s.data_path = target.get("data_path", s.data_path)
        s.goal = cfg.get("goal", s.goal)

    return s
