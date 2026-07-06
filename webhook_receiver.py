"""Webhook receiver para Evolution API → WhatsApp bridge."""
import json, time, os
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Lock

GRUPO = "120363354076179075@g.us"
msgs = []
lock = Lock()
MAX_MSGS = 50

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = json.loads(self.rfile.read(length)) if length > 0 else {}
        with lock:
            msgs.append({"id": str(time.time()), "ts": time.time(), "data": body})
            if len(msgs) > MAX_MSGS:
                msgs.pop(0)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if self.path == "/messages":
            with lock:
                self.wfile.write(json.dumps({"messages": list(msgs)}).encode())
        elif self.path == "/health":
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.wfile.write(b'{"status":"ok"}')

    def log_message(self, fmt, *args):
        pass

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5060))
    print(f"Webhook bridge on :{port} (group={GRUPO})")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
