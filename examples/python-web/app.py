"""A small web service that remembers how many times it has been visited.

The count is kept in /data, a volume, so it survives restarts and new
versions of the capsule. Everything else in the capsule is read-only.
"""
import platform
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

COUNTER = Path("/data/visits")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        visits = int(COUNTER.read_text()) + 1 if COUNTER.exists() else 1
        COUNTER.write_text(str(visits))
        body = f"Hello from Python {platform.python_version()} in a capsule. Visit {visits}.\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the capsule's output quiet
        pass


if __name__ == "__main__":
    print("listening on 8000", flush=True)
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
