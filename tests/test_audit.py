"""The deterministic audit: inventory, scoring, pricing, and failing closed."""

import pytest

from auditpledge.advisories import NullSource
from auditpledge.catalogue import manifest
from auditpledge.config import settings
from auditpledge.mcp_audit import (
    AuditError,
    assess_supply_chain,
    audit_server,
    inventory_tools,
    load_manifest,
    price_audit,
    run_audit,
)

AGENT = manifest("compound-position-agent")


def test_inventory_counts_tools():
    inv = inventory_tools(AGENT)
    assert inv["count"] == 4
    assert {t["name"] for t in inv["tools"]} == {
        "comet-state-reader", "collateral-mover", "tx-builder", "rate-oracle"}


def test_unsigned_rce_collateral_tool_is_critical():
    a = assess_supply_chain(AGENT)
    mover = next(t for t in a["tools"] if t["name"] == "collateral-mover")
    assert mover["severity"] == "critical"
    assert mover["rce_capable"] and not mover["signed"]
    assert mover["position_exposed"] is True
    # both the unsigned collateral mover and the unsigned tx-builder are RCE-class.
    assert a["counts"]["unsigned_rce"] == 2


def test_position_exposure_is_scored_for_the_signing_tools():
    """A Compound-tuned rule: tools that sign transactions or move collateral are
    flagged as position-exposed; read-only state readers are not."""
    a = assess_supply_chain(AGENT)
    exposed = {t["name"] for t in a["tools"] if t["position_exposed"]}
    assert exposed == {"collateral-mover", "tx-builder"}
    assert a["counts"]["position_exposed"] == 2
    reader = next(t for t in a["tools"] if t["name"] == "comet-state-reader")
    assert reader["position_exposed"] is False


def test_pricing_is_dominated_by_the_unsigned_rce_tools():
    pr = price_audit(assess_supply_chain(AGENT))
    top = {d["tool"] for d in pr["top_drivers"]}
    assert {"collateral-mover", "tx-builder"} <= top
    assert all(d["p_driver"] == "unsigned RCE floor"
               for d in pr["top_drivers"] if d["tool"] in {"collateral-mover", "tx-builder"})
    assert pr["suggested_annual_premium_usd"] > pr["expected_loss_usd"]  # the load


def test_per_tool_losses_sum_to_the_headline_expected_loss():
    """The UI ticks up per tool. Those numbers must add up to the headline."""
    pr = price_audit(assess_supply_chain(AGENT))
    assert sum(t["expected_loss_usd"] for t in pr["per_tool"]) == pr["expected_loss_usd"]
    assert round(pr["expected_loss_usd"] * settings.risk_load) == pr["suggested_annual_premium_usd"]


def test_known_vuln_is_flagged_and_labelled_simulated():
    a = assess_supply_chain(AGENT)
    builder = next(t for t in a["tools"] if t["name"] == "tx-builder")
    assert any("known vuln" in f for f in builder["findings"])
    assert all(adv["simulated"] for adv in builder["advisories"])
    assert any("[SIMULATED]" in f for f in builder["findings"])


# --- the --server argument is real, not decoration --------------------------

def test_server_argument_selects_a_different_manifest():
    """`--server` must select the named agent, not always report the same tools."""
    rep = run_audit("compound-treasury", "fixture")
    assert rep["server"] == "compound-treasury"
    names = {t["name"] for t in rep["inventory"]["tools"]}
    assert names == {"position-read", "rebalance-exec", "report-fetcher"}
    assert "collateral-mover" not in names


def test_unknown_server_fails_closed():
    with pytest.raises(AuditError) as exc:
        load_manifest("does-not-exist", "fixture")
    assert "unknown MCP server" in str(exc.value)


def test_unknown_source_fails_closed():
    with pytest.raises(AuditError):
        load_manifest("compound-position-agent", "carrier-pigeon")


def test_audit_server_tool_reports_the_error_instead_of_inventing_findings():
    out = audit_server("does-not-exist", "fixture")
    assert "error" in out and "assessment" not in out


# --- evidence ---------------------------------------------------------------

def test_fixture_evidence_declares_itself_as_a_fixture():
    doc = load_manifest("compound-position-agent", "fixture")
    ev = doc["evidence"]
    assert ev["source"] == "fixture"
    assert ev["protocol_calls"] == []          # no MCP session was opened
    assert doc["synthetic"] is True


def test_advisory_free_run_still_finds_the_unsigned_rce_path():
    """Turn the advisory feed off entirely: the capability finding stands alone."""
    a = assess_supply_chain(AGENT, advisories=NullSource())
    mover = next(t for t in a["tools"] if t["name"] == "collateral-mover")
    assert mover["severity"] == "critical"
    assert mover["advisories"] == []
    assert a["counts"]["unsigned_rce"] == 2
