"""Provenance is cryptographic, not self-asserted.

Each test here pins a way an attacker-controlled manifest used to be able to
claim trust for free: a bare string signature, a lookalike publisher that ends
with a trusted name, or a signed entry quietly edited after signing.
"""

import copy

from auditpledge.catalogue import manifest
from auditpledge.demo_keys import public_key_hex, sign_tool
from auditpledge.mcp_audit import assess_supply_chain
from auditpledge.provenance import DEFAULT_KEYRING, Keyring, canonical_bytes, normalize_publisher

EVIL = manifest("evil-lookalike")
AGENT = manifest("compound-position-agent")


def tool(doc, name):
    return next(t for t in doc["tools"] if t["name"] == name)


def result(doc, name):
    a = assess_supply_chain(doc)
    return next(t for t in a["tools"] if t["name"] == name)


# --- a signature has to actually verify -------------------------------------

def test_bare_string_signature_is_not_a_signature():
    """`signature: "deadbeef"` on a trusted publisher must not buy trust."""
    r = result(EVIL, "signer-helper")
    assert r["signed"] is False
    assert r["trusted"] is False
    assert r["provenance"]["signature_present"] is True
    assert "INVALID" in r["provenance"]["reason"]


def test_forged_signature_is_counted_and_the_tool_stays_in_unsigned_rce():
    a = assess_supply_chain(EVIL)
    assert a["counts"]["forged_signatures"] >= 1
    helper = next(t for t in a["tools"] if t["name"] == "signer-helper")
    assert helper["rce_capable"] and not helper["signed"]
    assert a["counts"]["unsigned_rce"] >= 1     # forging must not hide the RCE path
    assert helper["severity"] == "critical"


def test_lookalike_publisher_is_not_matched_by_suffix():
    """`attacker.compound-finance` is not `compound-finance`. Exact match only."""
    assert normalize_publisher("attacker.compound-finance") != normalize_publisher("compound-finance")
    assert "attacker.compound-finance" not in DEFAULT_KEYRING
    r = result(EVIL, "comet-state-reader")
    assert r["signed"] is False and r["trusted"] is False


# --- tampering after signing --------------------------------------------------

def test_genuine_signature_verifies():
    r = result(AGENT, "comet-state-reader")
    assert r["signed"] is True and r["trusted"] is True
    assert "verified" in r["provenance"]["reason"]


def test_adding_an_op_after_signing_invalidates_the_signature():
    doc = copy.deepcopy(AGENT)
    tool(doc, "comet-state-reader")["ops"].append("run_command")
    r = result(doc, "comet-state-reader")
    assert r["signed"] is False
    assert "canonical bytes" in r["provenance"]["reason"]
    assert r["rce_capable"] is True            # and the smuggled op is still seen


def test_widening_a_scope_after_signing_invalidates_the_signature():
    doc = copy.deepcopy(AGENT)
    tool(doc, "comet-state-reader")["scopes"] = ["*"]
    assert result(doc, "comet-state-reader")["signed"] is False


def test_bumping_a_version_after_signing_invalidates_the_signature():
    doc = copy.deepcopy(AGENT)
    tool(doc, "comet-state-reader")["version"] = "9.9.9"
    assert result(doc, "comet-state-reader")["signed"] is False


def test_reordering_scopes_does_not_invalidate_the_signature():
    """Canonicalisation is order-independent, so a benign reserialise is fine."""
    doc = copy.deepcopy(AGENT)
    tool(doc, "rate-oracle")["scopes"].reverse()
    assert result(doc, "rate-oracle")["signed"] is True


def test_signature_from_another_publishers_key_does_not_verify():
    """Re-signing with a key AuditPledge holds, but not this publisher's."""
    doc = copy.deepcopy(AGENT)
    entry = tool(doc, "comet-state-reader")
    stolen = copy.deepcopy(entry)
    stolen["publisher"] = "openzeppelin"
    entry["signature"] = sign_tool(stolen)   # openzeppelin's key over compound-finance's entry
    assert result(doc, "comet-state-reader")["signed"] is False


# --- keyring hygiene ---------------------------------------------------------

def test_unknown_publisher_signature_is_unverifiable_not_trusted():
    doc = copy.deepcopy(AGENT)
    tool(doc, "collateral-mover")["signature"] = "ab" * 64
    r = result(doc, "collateral-mover")
    assert r["signed"] is False
    assert "no key in the AuditPledge keyring" in r["provenance"]["reason"]


def test_empty_keyring_fails_closed_for_everything():
    a = assess_supply_chain(AGENT, keyring=Keyring())
    assert all(not t["signed"] for t in a["tools"])


def test_keyring_rejects_a_wrong_length_key():
    import pytest

    with pytest.raises(ValueError):
        Keyring({"nope": "ab" * 8})


def test_committed_keyring_holds_the_public_half_of_the_demo_keys():
    kr = DEFAULT_KEYRING
    # compound-finance holds a key; defi-rando has none by design.
    assert "compound-finance" in kr and "defi-rando" not in kr
    assert kr._keys["compound-finance"].hex() == public_key_hex("compound-finance")


def test_canonical_bytes_cover_the_documented_fields():
    entry = tool(AGENT, "comet-state-reader")
    payload = canonical_bytes(entry).decode()
    for field in ("name", "version", "publisher", "scopes", "ops"):
        assert f'"{field}"' in payload
    assert "signature" not in payload           # the signature never signs itself
