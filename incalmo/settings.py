import json
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.json"


@dataclass
class Settings:
    anthropic_api_key: str = ""
    caldera_api_key: str = ""
    model: str = "claude-sonnet-4-6"
    attacker_ip: str = "10.0.0.50"
    extnet: str = "10.0.0.0/24"
    intnet: str = "192.168.1.0/24"
    web_intnet_ip: str = "192.168.1.2"  # webserver intnet-facing IP, used in exfil relay URL
    timeout_minutes: int = 75
    max_rounds: int = 40
    max_tokens: int = 4096


def load_settings() -> Settings:
    s = Settings()
    s.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
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

    return s
