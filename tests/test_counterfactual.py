"""Counterfactual repricing: the saving is recomputed, never asserted."""

from auditpledge.catalogue import manifest
from auditpledge.mcp_audit import (
    _drop_tool,
    _sign_and_sandbox,
    assess_supply_chain,
    counterfactuals,
    price_audit,
    run_audit,
)

AGENT = manifest("compound-position-agent")
WORST = "tx-builder"


def test_dropping_the_worst_tool_lowers_the_premium():
    cf = counterfactuals(AGENT, WORST)
    drop = next(v for v in cf["variants"] if v["action"] == "drop")
    assert drop["delta_premium_usd"] < 0
    assert drop["suggested_annual_premium_usd"] < cf["baseline"]["suggested_annual_premium_usd"]


def test_the_repriced_number_is_the_scorer_rerun_not_a_stored_constant():
    """Reprice by hand and demand the exact same figure."""
    cf = counterfactuals(AGENT, WORST)
    drop = next(v for v in cf["variants"] if v["action"] == "drop")
    by_hand = price_audit(assess_supply_chain(_drop_tool(AGENT, WORST)))
    assert drop["expected_loss_usd"] == by_hand["expected_loss_usd"]
    assert drop["suggested_annual_premium_usd"] == by_hand["suggested_annual_premium_usd"]


def test_the_remediated_variant_is_genuinely_re_signed():
    """The 'sign and sandbox' counterfactual must pass the same Ed25519 check as
    any other manifest, otherwise the discount is fiction."""
    fixed = _sign_and_sandbox(AGENT, WORST)
    a = assess_supply_chain(fixed)
    tool = next(t for t in a["tools"] if t["name"] == WORST)
    assert tool["signed"] is True and tool["trusted"] is True
    assert tool["rce_capable"] is False            # the sign_tx / write_file ops were removed
    # tx-builder is remediated; only the still-unsigned collateral-mover remains RCE.
    assert a["counts"]["unsigned_rce"] == 1


def test_the_remediated_variant_is_priced_lower_but_not_free():
    cf = counterfactuals(AGENT, WORST)
    fix = next(v for v in cf["variants"] if v["action"] == "sign_and_sandbox")
    drop = next(v for v in cf["variants"] if v["action"] == "drop")
    assert fix["delta_premium_usd"] < 0
    # Keeping a sandboxed tool still costs more than not having it at all.
    assert fix["suggested_annual_premium_usd"] > drop["suggested_annual_premium_usd"]


def test_counterfactual_for_an_absent_tool_produces_no_fantasy_saving():
    cf = counterfactuals(AGENT, "not-a-tool")
    drop = next(v for v in cf["variants"] if v["action"] == "drop")
    assert drop["delta_premium_usd"] == 0
    assert not any(v["action"] == "sign_and_sandbox" for v in cf["variants"])


def test_the_audit_reprices_the_worst_tool_it_named():
    rep = run_audit("compound-position-agent", "fixture")
    assert rep["counterfactual"]["tool"] == rep["assessment"]["worst"]["name"]
    assert rep["counterfactual"]["baseline"]["suggested_annual_premium_usd"] == \
        rep["pricing"]["suggested_annual_premium_usd"]
