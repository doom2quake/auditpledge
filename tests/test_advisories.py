"""Never claim a vulnerability you cannot back.

Placeholder IDs are rejected, simulated entries are labelled and can be excluded
from scoring, and a real OSV response is parsed by the real client through an
injected transport.
"""

import json

import pytest

from auditpledge.advisories import (
    Advisory,
    NullSource,
    OfflineSnapshot,
    OsvSource,
    build_source,
    valid_advisory_id,
)
from auditpledge.catalogue import manifest
from auditpledge.mcp_audit import assess_supply_chain

AGENT = manifest("compound-position-agent")


@pytest.mark.parametrize("bad", ["GHSA-xxxx", "GHSA-xxxx-xxxx-xxxx", "CVE-1234", "", "vuln-1",
                                 "GHSA-abcd-abcd-abcd"])
def test_placeholder_advisory_ids_are_rejected(bad):
    """Regression: `GHSA-xxxx` used to be emitted as a real 'known vuln'."""
    assert not valid_advisory_id(bad)
    with pytest.raises(ValueError):
        Advisory(id=bad, summary="made up", source="test")


@pytest.mark.parametrize("good", ["CVE-2026-31337", "GHSA-2c9q-w5x7-6h3j", "cve-2021-44228"])
def test_real_advisory_ids_are_accepted(good):
    assert valid_advisory_id(good)


def test_offline_entries_are_marked_simulated_and_carry_a_retrieval_time():
    hits = OfflineSnapshot().lookup("tx-builder", "0.9.1")
    assert len(hits) == 1
    assert hits[0].simulated is True
    assert hits[0].label.startswith("[SIMULATED]")
    assert hits[0].retrieved_at


def test_simulated_advisories_can_be_excluded_from_scoring():
    on = assess_supply_chain(AGENT, allow_simulated=True)
    off = assess_supply_chain(AGENT, allow_simulated=False)
    builder_on = next(t for t in on["tools"] if t["name"] == "tx-builder")
    builder_off = next(t for t in off["tools"] if t["name"] == "tx-builder")

    assert builder_off["score"] < builder_on["score"]      # the vuln weight is gone
    assert builder_off["advisories"] == []
    assert not any("known vuln" in f for f in builder_off["findings"])
    assert any("withheld" in f for f in builder_off["findings"])   # and it says so


def test_excluding_simulated_advisories_does_not_hide_the_unsigned_rce_path():
    off = assess_supply_chain(AGENT, allow_simulated=False)
    assert off["counts"]["unsigned_rce"] == 2
    mover = next(t for t in off["tools"] if t["name"] == "collateral-mover")
    assert mover["severity"] == "critical"


# --- the real OSV client, exercised offline through an injected transport -----

_OSV_RESPONSE = json.dumps({
    "vulns": [
        {"id": "GHSA-2c9q-w5x7-6h3j", "aliases": ["CVE-2026-31337"],
         "summary": "SSRF via unchecked redirect\nsecond line ignored"},
        {"id": "OSV-2026-0001", "aliases": ["CVE-2026-40881"], "details": "XXE in the parser"},
        {"id": "MAL-0000-0000", "aliases": [], "summary": "no usable identifier"},
    ]
}).encode()


def test_osv_client_parses_a_recorded_response():
    seen = {}

    def transport(url, body):
        seen["url"], seen["body"] = url, json.loads(body)
        return _OSV_RESPONSE

    hits = OsvSource(transport=transport).lookup("tx-builder", "0.9.1")
    assert seen["url"] == "https://api.osv.dev/v1/query"
    assert seen["body"] == {"version": "0.9.1",
                            "package": {"name": "tx-builder", "ecosystem": "PyPI"}}
    assert [h.id for h in hits] == ["GHSA-2c9q-w5x7-6h3j", "CVE-2026-40881"]
    assert all(h.simulated is False and h.source == "osv.dev" for h in hits)
    assert hits[0].summary == "SSRF via unchecked redirect"   # first line only
    # MAL-0000-0000 has no valid CVE/GHSA alias, so it is dropped rather than
    # printed as an unbacked claim.


def test_osv_client_raises_instead_of_reporting_no_vulnerabilities():
    """A network failure must not read as a clean bill of health."""
    def broken(url, body):
        raise OSError("connection refused")

    with pytest.raises(OSError):
        OsvSource(transport=broken).lookup("tx-builder", "0.9.1")


def test_build_source_selects_the_named_feed():
    assert isinstance(build_source("offline"), OfflineSnapshot)
    assert isinstance(build_source("osv"), OsvSource)
    assert isinstance(build_source("none"), NullSource)
    with pytest.raises(ValueError):
        build_source("wishful-thinking")


def test_osv_run_never_counts_simulated_entries():
    """`--advisories osv` must not quietly fall back to the fiction feed."""
    from auditpledge.mcp_audit import run_audit

    rep = run_audit("compound-position-agent", "fixture", "osv",
                    advisories=NullSource())
    assert rep["assessment"]["simulated_advisories_counted"] is False
    assert all(t["advisories"] == [] for t in rep["assessment"]["tools"])
