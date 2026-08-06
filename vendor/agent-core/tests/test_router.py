"""Tests for the domain classifier + router - no network (stub Notifier sinks)."""

from agent_core.config import BaseSettings
from agent_core.guardrails import ActionLimiter, ActionPolicy
from agent_core.router import (
    DOMAIN_FINANCE,
    DOMAIN_INFRA,
    DOMAIN_SECURITY,
    DOMAIN_UNKNOWN,
    AlertHandler,
    Handler,
    KeywordClassifier,
    Route,
    Router,
    TicketHandler,
)
from agent_core.sinks import Notifier


class _FakeNotifier:
    """Records calls; returns what a no-op Notifier returns (nothing delivered)."""

    def __init__(self):
        self.alerts = []
        self.tickets = []

    def send_alert(self, channel, title, message, severity="warning"):
        self.alerts.append((channel, title, severity))
        return {"status": "logged", "delivery": "stub", "synthetic": True, "url": None}

    def open_ticket(self, summary, description, priority="P2", assignee=""):
        self.tickets.append((summary, priority))
        return {"status": "logged", "delivery": "stub", "synthetic": True,
                "ticket_id": "LOCAL-T-1", "url": None}


class _LiveNotifier(_FakeNotifier):
    """Stands in for a configured backend that really accepted the action."""

    def open_ticket(self, summary, description, priority="P2", assignee=""):
        self.tickets.append((summary, priority))
        return {"status": "created", "delivery": "github", "synthetic": False,
                "ticket_id": "#42", "url": "https://github.com/doom2quake/x/issues/42"}


def test_classifier_finance_precedence_over_infra():
    c = KeywordClassifier()
    # revenue collapse whose cause is a config push -> still finance
    incident = {"summary": "revenue dropped 10%, caused by a 14:00 config deployment"}
    assert c.classify(incident) == DOMAIN_FINANCE


def test_classifier_security_beats_finance():
    """A security incident that also mentions money must not be routed as finance."""
    c = KeywordClassifier()
    incident = {"summary": "unauthorized attacker exfiltrated payment tokens from checkout"}
    assert c.classify(incident) == DOMAIN_SECURITY
    # both labels are still visible for multi-label routing
    assert set(c.matches(incident)) >= {DOMAIN_SECURITY, DOMAIN_FINANCE}


def test_classifier_security_and_infra_and_unknown():
    c = KeywordClassifier()
    assert c.classify({"summary": "unauthorized credential exfiltration detected"}) == DOMAIN_SECURITY
    assert c.classify({"summary": "elevated 503 error rate after rollout"}) == DOMAIN_INFRA
    assert c.classify({"summary": "the weather is nice today"}) == DOMAIN_UNKNOWN
    assert c.matches({"summary": "the weather is nice today"}) == []


def test_router_fans_out_finance_to_alert_and_ticket():
    n = _FakeNotifier()
    router = Router([AlertHandler(n), TicketHandler(n)])
    rec = router.route({"summary": "revenue anomaly in EMEA", "title": "Rev drop"})
    assert rec["domain"] == DOMAIN_FINANCE
    assert rec["route"] == ["alert", "ticket"]
    assert len(n.alerts) == 1 and len(n.tickets) == 1


def test_security_route_actually_reaches_the_alert_handler():
    """DEFAULT_ROUTING sends security to `alert`; the handler must accept it."""
    n = _FakeNotifier()
    router = Router([AlertHandler(n), TicketHandler(n)])
    rec = router.route({"summary": "unauthorized intrusion detected", "title": "Breach"})
    assert rec["domain"] == DOMAIN_SECURITY
    assert [h["handler"] for h in rec["handlers"]] == ["alert", "ticket"]
    assert len(n.alerts) == 1


def test_undelivered_actions_produce_no_artifacts():
    """A no-op sink must never look like a filed ticket in the routing record."""
    n = _FakeNotifier()
    router = Router([AlertHandler(n), TicketHandler(n)])
    rec = router.route({"summary": "revenue anomaly in EMEA", "title": "Rev drop"})
    assert rec["delivery_mode"] == "synthetic"
    assert rec["artifacts"] == {}
    assert rec["primary_artifact_url"] is None
    ticket = [h for h in rec["handlers"] if h["handler"] == "ticket"][0]
    assert ticket["status"] == "noop"
    assert ticket["synthetic"] is True
    assert ticket["artifact_url"] is None


def test_real_delivery_surfaces_the_backend_artifact():
    n = _LiveNotifier()
    router = Router([AlertHandler(n), TicketHandler(n)])
    rec = router.route({"summary": "revenue anomaly in EMEA", "title": "Rev drop"})
    assert rec["delivery_mode"] == "live"
    assert rec["artifacts"]["ticket"] == "https://github.com/doom2quake/x/issues/42"
    assert rec["artifacts"]["ticket_id"] == "#42"
    assert rec["primary_artifact_url"] == "https://github.com/doom2quake/x/issues/42"


def test_router_infra_goes_ticket_only():
    n = _FakeNotifier()
    router = Router([AlertHandler(n), TicketHandler(n)])
    rec = router.route({"summary": "timeout spike after deploy", "title": "Infra"})
    assert rec["domain"] == DOMAIN_INFRA
    assert len(n.alerts) == 0 and len(n.tickets) == 1


def test_router_env_override(monkeypatch):
    monkeypatch.setenv("MYAPP_ROUTING_FINANCE", "ticket")
    n = _FakeNotifier()
    router = Router([AlertHandler(n), TicketHandler(n)], env_prefix="MYAPP")
    rec = router.route({"summary": "revenue drop", "title": "x"})
    assert rec["route"] == ["ticket"]
    assert len(n.alerts) == 0


def test_router_accepts_a_classify_only_classifier():
    """Apps duck-type the classifier with `classify` alone; that must keep working.

    Every app repo vendors this library, so an added requirement on a plugged-in
    classifier would break them all at once.
    """

    class VerdictOnly:
        default = DOMAIN_UNKNOWN

        def classify(self, incident):
            return DOMAIN_INFRA

    n = _FakeNotifier()
    router = Router([AlertHandler(n), TicketHandler(n)], classifier=VerdictOnly())
    rec = router.route({"summary": "revenue drop"})
    assert rec["domain"] == DOMAIN_INFRA
    assert rec["domains"] == [DOMAIN_INFRA]
    assert len(n.tickets) == 1


def test_router_never_raises_on_handler_error():
    class Boom(Handler):
        name = "ticket"

        def can_handle(self, domain):
            return True

        def execute(self, incident):
            raise RuntimeError("kaboom")

    router = Router([Boom()])
    rec = router.route({"summary": "revenue drop"})
    statuses = [h["status"] for h in rec["handlers"]]
    assert "error" in statuses  # captured, not raised


def test_unconfigured_notifier_reports_no_ticket_was_filed():
    """End to end through the real Notifier with no backend configured."""
    settings = BaseSettings(github_repo="", github_token="", ticket_endpoint="",
                            slack_webhook_url="")
    notifier = Notifier(
        settings,
        ActionLimiter(ActionPolicy(dry_run=False, max_actions_per_cycle=5, max_actions_per_hour=5)),
    )
    r = notifier.open_ticket("Revenue drop", "z ~ -7")
    assert r["status"] == "logged"          # not "created"
    assert r["synthetic"] is True
    assert r["url"] is None                 # no fabricated tracker URL
    assert r["ticket_id"].startswith("LOCAL-")
    assert "AGENT_GITHUB_REPO" in r["reason"]

    a = notifier.send_alert("#ops", "Revenue drop", "z ~ -7")
    assert a["status"] == "logged" and a["synthetic"] is True
