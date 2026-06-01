#!/usr/bin/env python3
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "0.0.0.0"
PORT = int(os.environ.get("MOCK_PORT", "8765"))
BINARY = b"frogbot-test-binary\n"
CHECKSUMS = {
    "md5": hashlib.md5(BINARY).hexdigest(),
    "sha1": hashlib.sha1(BINARY).hexdigest(),
    "sha256": hashlib.sha256(BINARY).hexdigest(),
}
def match_artifact(path: str) -> bool:
    p = path.rstrip("/")
    return p.startswith("/artifactory/frogbot/v2/") and p.endswith("/frogbot") and "/frogbot-" in p


def artifact_to_storage(path: str) -> str:
    p = path.rstrip("/")
    return "/artifactory/api/storage/" + p[len("/artifactory/") :]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_HEAD(self):
        if match_artifact(self.path.split("?", 1)[0]):
            self.send_response(200)
            self.send_header("Content-Length", str(len(BINARY)))
            self.end_headers()
            return
        self.send_error(404)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if match_artifact(path):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(BINARY)))
            self.end_headers()
            self.wfile.write(BINARY)
            return
        if path.rstrip("/").startswith("/artifactory/api/storage/frogbot/v2/"):
            body = json.dumps({"checksums": CHECKSUMS}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)


if __name__ == "__main__":
    HTTPServer((HOST, PORT), Handler).serve_forever()
