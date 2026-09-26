"""
Lightweight HTTP server for the Statecraft visual dashboard.

Uses only Python stdlib (http.server). Serves the static HTML dashboard
and injects the real simulation payload as embedded JSON.

This server is ephemeral: it starts, serves the dashboard, and shuts down
when the user closes the browser tab or presses Ctrl+C.
"""

from __future__ import annotations

import html
import http.server
import json
import os
import socket
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any


STATIC_DIR = Path(__file__).parent / "static"


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """Serves the dashboard HTML with injected simulation data."""

    payload_json: str = "{}"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._serve_dashboard()
        elif self.path == "/api/payload":
            self._serve_payload_json()
        else:
            super().do_GET()

    def _serve_dashboard(self):
        """Serve index.html with the payload injected."""
        index_path = STATIC_DIR / "index.html"
        if not index_path.exists():
            self.send_error(404, "Dashboard not found")
            return

        content = index_path.read_text(encoding="utf-8")
        # Inject the payload JSON into a script tag
        injection = f'<script id="statecraft-payload" type="application/json">{self.payload_json}</script>'
        content = content.replace("<!-- PAYLOAD_INJECTION_POINT -->", injection)

        encoded = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(encoded)

    def _serve_payload_json(self):
        """Serve raw payload as JSON API endpoint."""
        encoded = self.payload_json.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        """Suppress default request logging."""
        pass


def find_free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve_dashboard(payload_json: str, port: int | None = None, auto_open: bool = True) -> None:
    """Start the visual dashboard server.

    Args:
        payload_json: The JSON string payload from the adapter.
        port: Port to listen on. If None, a free port is auto-selected.
        auto_open: Whether to open the browser automatically.
    """
    if port is None:
        port = find_free_port()

    DashboardHandler.payload_json = payload_json

    server = http.server.HTTPServer(("127.0.0.1", port), DashboardHandler)
    url = f"http://127.0.0.1:{port}"

    print(f"\n  [Statecraft Visual] Dashboard serving at: {url}")
    print(f"  [Statecraft Visual] Press Ctrl+C to stop.\n")

    if auto_open:
        # Small delay to ensure server is ready before browser opens
        def open_browser():
            time.sleep(0.5)
            webbrowser.open(url)
        threading.Thread(target=open_browser, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("\n  [Statecraft Visual] Server stopped.")
