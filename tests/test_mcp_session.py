"""The load-bearing funder surface: a real MCP stdio session.

These tests launch `python -m auditpledge.mcp_server` as a subprocess, complete
the MCP handshake, and read `tools/list` over JSON-RPC. Nothing is stubbed. They
are the proof that `--source mcp` is a working code path rather than a flag in
the help text.
"""

import asyncio

import pytest

from auditpledge.main import audit
from auditpledge.mcp_audit import AuditError, load_manifest, run_audit
from auditpledge.mcp_client import ManifestUnavailable, fetch_manifest
from auditpledge.mcp_server import META_KEY, server_identity, tool_meta


def test_live_mcp_session_returns_an_identified_manifest():
    doc = asyncio.run(fetch_manifest("compound-position-agent"))
    ev = doc["evidence"]
    assert ev["source"] == "mcp/stdio"
    assert ev["protocol_calls"] == ["initialize", "tools/list"]
    assert ev["server_identity"] == server_identity("compound-position-agent")
    assert ev["tools_listed"] == 4
    assert {t["name"] for t in doc["tools"]} == {
        "comet-state-reader", "collateral-mover", "tx-builder", "rate-oracle"}


def test_live_and_fixture_sources_score_identically():
    """The offline fixture is the same data the MCP server serves, not a nicer one."""
    live = run_audit("compound-position-agent", "mcp")
    fixture = run_audit("compound-position-agent", "fixture")

    def shape(rep):
        return [(t["name"], t["severity"], t["score"], t["signed"])
                for t in rep["assessment"]["tools"]]

    assert shape(live) == shape(fixture)
    assert live["pricing"] == fixture["pricing"]
    assert live["evidence"]["source"] == "mcp/stdio"
    assert fixture["evidence"]["source"] == "fixture"


def test_live_audit_works_from_inside_a_running_event_loop():
    """Regression: the CLI and the ADK runner both call the sync audit from an
    already-running loop, where a naive `asyncio.run` blew up with
    'asyncio.run() cannot be called from a running event loop'."""
    out = asyncio.run(audit("compound-position-agent", use_llm=False, source="mcp"))
    assert out["report"]["evidence"]["source"] == "mcp/stdio"
    assert out["report"]["assessment"]["counts"]["unsigned_rce"] == 2
    assert out["status"] == "complete"


def test_identity_mismatch_fails_closed():
    with pytest.raises(ManifestUnavailable) as exc:
        asyncio.run(fetch_manifest("compound-position-agent",
                                   expect_identity="auditpledge-mcp/other"))
    assert "identity mismatch" in str(exc.value)


def test_unreachable_server_fails_closed_with_a_readable_reason():
    with pytest.raises(ManifestUnavailable) as exc:
        asyncio.run(fetch_manifest("compound-position-agent",
                                   command="/nonexistent/interpreter", args=[]))
    assert "could not read tools/list" in str(exc.value)


def test_live_source_for_an_unknown_server_fails_closed():
    """The subprocess exits non-zero; the audit must not report a clean manifest."""
    with pytest.raises(AuditError):
        load_manifest("does-not-exist", "mcp")


# --- evidence completeness ---------------------------------------------------

class _StubTool:
    def __init__(self, name, meta):
        self.name = name
        self.description = ""
        self.meta = meta


def test_a_tool_with_no_provenance_meta_is_refused_not_scored_clean():
    from auditpledge.mcp_client import _tool_record

    with pytest.raises(ManifestUnavailable) as exc:
        _tool_record(_StubTool("mystery", {}), "some-server")
    assert "refusing to score it as clean" in str(exc.value)


def test_a_tool_missing_required_evidence_is_refused():
    from auditpledge.mcp_client import _tool_record

    partial = {META_KEY: {"publisher": "compound-finance", "version": "1.0.0"}}   # no scopes/ops
    with pytest.raises(ManifestUnavailable) as exc:
        _tool_record(_StubTool("mystery", partial), "some-server")
    assert "scopes" in str(exc.value) and "ops" in str(exc.value)


def test_the_server_publishes_provenance_under_a_namespaced_meta_key():
    """MCP's Tool schema is not extended with bespoke top-level fields: the
    evidence rides in the spec's `_meta`, namespaced."""
    from auditpledge.catalogue import manifest

    entry = next(t for t in manifest("compound-position-agent")["tools"]
                 if t["name"] == "comet-state-reader")
    meta = tool_meta(entry)
    assert META_KEY == "auditpledge/provenance"
    assert meta["signature_algorithm"] == "ed25519"
    assert meta["signed_fields"] == ["name", "version", "publisher", "scopes", "ops"]
