"""The generic ticket-endpoint path, exercised against a loopback HTTP server.

This is the one place the library makes an outbound HTTP call that can be pinned
without an external service, and the property worth pinning is that the result
reports only what the destination returned. A ticket id or URL that agent-core
made up locally must never appear as evidence that a ticket was filed.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agent_core.config import BaseSettings
from agent_core.guardrails import ActionLimiter, ActionPolicy
from agent_core.sinks import Notifier


class _Handler(BaseHTTPRequestHandler):
    response_code = 201
    response_body = b'{"id": "OPS-77", "url": "https://tickets.internal/OPS-77"}'
    received: list = []

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", 0))
        _Handler.received.append(json.loads(self.rfile.read(length) or b"{}"))
        self.send_response(type(self).response_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(type(self).response_body)

    def log_message(self, *args):  # keep the test output quiet
        return


@pytest.fixture()
def endpoint():
    _Handler.received = []
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/tickets"
    server.shutdown()
    server.server_close()


def _notifier(endpoint_url: str) -> Notifier:
    settings = BaseSettings(github_repo="", github_token="", slack_webhook_url="",
                            ticket_endpoint=endpoint_url)
    return Notifier(settings, ActionLimiter(
        ActionPolicy(dry_run=False, max_actions_per_cycle=5, max_actions_per_hour=5)))


def test_endpoint_ticket_reports_the_backend_identifiers(endpoint):
    _Handler.response_code = 201
    _Handler.response_body = b'{"id": "OPS-77", "url": "https://tickets.internal/OPS-77"}'
    r = _notifier(endpoint).open_ticket("Revenue drop", "z ~ -7", priority="P1")
    assert r["status"] == "created"
    assert r["synthetic"] is False
    assert r["ticket_id"] == "OPS-77"                       # the backend's id
    assert r["url"] == "https://tickets.internal/OPS-77"    # the backend's url
    assert _Handler.received[0]["summary"] == "Revenue drop"


def test_endpoint_without_identifiers_reports_none_rather_than_inventing_them(endpoint):
    _Handler.response_code = 202
    _Handler.response_body = b"{}"
    r = _notifier(endpoint).open_ticket("Revenue drop", "z ~ -7")
    assert r["status"] == "created"
    assert r["ticket_id"] is None
    assert r["url"] is None


def test_endpoint_failure_is_an_error_not_a_ticket(endpoint):
    _Handler.response_code = 500
    _Handler.response_body = b"boom"
    r = _notifier(endpoint).open_ticket("Revenue drop", "z ~ -7")
    assert r["status"] == "error"
    assert r["synthetic"] is True
    assert "url" not in r or r["url"] is None
