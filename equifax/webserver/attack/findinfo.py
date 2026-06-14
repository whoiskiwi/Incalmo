from dataclasses import dataclass
from runners import CommandRunner

@dataclass
class Credential:
    private_key: str
    host: str
    user: str

def find_ssh_key(shell: CommandRunner) -> Credential:
    config_text = shell.run("cat ~/.ssh/config")
    host = _field(config_text, "HostName")
    user = _field(config_text, "User")
    key_path = _field(config_text, "IdentityFile") or "~/.ssh/id_rsa"

    private_key = shell.run(f"cat {key_path}")
    return Credential(private_key=private_key, host=host, user=user)

def _field(config_text: str, name: str) -> str:
    for line in config_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == name.lower():
            return parts[1]
    return ""

if __name__ == "__main__":
    from runners import WebShell
    shell = WebShell()
    cred = find_ssh_key(shell)
    print("host:", cred.host)
    print("user:", cred.user)
    first_line = cred.private_key.splitlines()[0] if cred.private_key else "(empty)"
    print("key starts with:", first_line)