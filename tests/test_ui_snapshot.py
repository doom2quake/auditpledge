"""The UI cannot claim a number the auditor does not produce.

`ui/index.html` is a static offline page, which makes it the easiest place in the
repo to paint a nicer story than the code tells. So the page carries a snapshot
captured from a real run, and this module re-runs the audit and fails on any
drift, plus fails if a hand-written dollar figure creeps back into the markup.
"""

import re

from auditpledge.ui_data import BEGIN, END, UI_PATH, build_snapshot, comparable, read_embedded

HTML = UI_PATH.read_text(encoding="utf-8")
SNAP = read_embedded()


def test_the_embedded_snapshot_still_matches_what_the_code_produces():
    assert comparable(SNAP) == comparable(build_snapshot())


def test_the_snapshot_records_a_real_mcp_session():
    ev = SNAP["evidence"]
    assert ev["source"] == "mcp/stdio"
    assert ev["protocol_calls"] == ["initialize", "tools/list"]
    assert ev["server_identity"] == "auditpledge-mcp/compound-position-agent"
    assert SNAP["command"].startswith("auditpledge audit ")


def test_the_page_holds_no_hand_written_money():
    """Every dollar figure must come from the snapshot, not from the markup."""
    outside = HTML[:HTML.index(BEGIN)] + HTML[HTML.index(END):]
    assert not re.findall(r"\$\s?\d[\d,]{2,}", outside)


def test_the_ticker_adds_up_to_the_headline_numbers():
    assert sum(t["expected_loss_usd"] for t in SNAP["tools"]) == SNAP["pricing"]["expected_loss_usd"]
    assert SNAP["pricing"]["suggested_annual_premium_usd"] == round(
        SNAP["pricing"]["expected_loss_usd"] * SNAP["pricing"]["risk_load"])


def test_the_severities_shown_are_the_severities_scored():
    """Regression: the page used to show a tool as a warning while the backend
    scored it critical."""
    from auditpledge.catalogue import manifest
    from auditpledge.mcp_audit import assess_supply_chain

    scored = {t["name"]: t["severity"]
              for t in assess_supply_chain(manifest("compound-position-agent"))["tools"]}
    assert {t["name"]: t["severity"] for t in SNAP["tools"]} == scored


def test_the_downloadable_report_is_the_actual_stdout():
    text = SNAP["cli_text"]
    assert text.startswith("MCP server: compound-position-agent")
    assert "evidence: mcp/stdio via" in text
    assert f"${SNAP['pricing']['expected_loss_usd']:,}" in text


def test_the_activity_log_is_the_measured_trace():
    keys = [s["key"] for s in SNAP["trace"]]
    assert keys == ["load_manifest", "inventory_tools", "verify_provenance",
                    "assess_supply_chain", "price_audit", "counterfactual"]
    assert all("ms" in s for s in SNAP["trace"])
    assert any(s["status"] == "crit" for s in SNAP["trace"])


def test_the_page_declares_itself_a_recorded_replay():
    assert "recorded run" in HTML
    assert "does not execute Python in your browser" in HTML
    assert "HONESTY.md" in HTML
