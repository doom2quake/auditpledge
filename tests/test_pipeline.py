"""Run lifecycle and pipeline ordering.

Two things are pinned here. First, a run never sits at `started`: it ends
`complete` after the report is persisted, or `error` on a terminal failure.
Second, the audit-then-remediate order is enforced by an ADK `SequentialAgent`
and by a required-output-key check, not by asking a model nicely.
"""

import asyncio

import pytest
from agent_core import StateStore

from auditpledge.agents import REQUIRED_OUTPUT_KEYS, missing_output_keys, root_agent
from auditpledge.config import settings
from auditpledge.main import audit, format_report, get_store
from auditpledge.mcp_audit import AuditError
from auditpledge.skills import AUDIT, PRIORITIZE


def store():
    return StateStore.create(settings)


# --- run lifecycle -----------------------------------------------------------

def test_a_successful_run_is_marked_complete_and_is_readable_afterwards():
    st = store()
    out = asyncio.run(audit("compound-position-agent", use_llm=False, store=st))
    assert out["status"] == "complete"
    doc = st.get(out["run_id"])
    assert doc["status"] == "complete"
    assert doc["data"]["report"]["assessment"]["counts"]["critical"] >= 1


def test_a_failed_audit_marks_the_run_error_and_re_raises():
    st = store()
    with pytest.raises(AuditError):
        asyncio.run(audit("does-not-exist", use_llm=False, store=st))
    runs = st.list()
    assert runs and runs[0]["status"] == "error"
    assert "unknown MCP server" in runs[0]["error"]


def test_the_store_is_long_lived_so_run_ids_stay_addressable():
    assert get_store() is get_store()
    st = store()
    first = asyncio.run(audit("compound-position-agent", use_llm=False, store=st))["run_id"]
    second = asyncio.run(audit("compound-position-agent", use_llm=False, store=st))["run_id"]
    assert first != second
    assert st.get(first) is not None and st.get(second) is not None


def test_a_repeat_audit_of_the_same_server_is_detected_as_recurrence():
    st = store()
    asyncio.run(audit("compound-position-agent", use_llm=False, store=st))
    again = asyncio.run(audit("compound-position-agent", use_llm=False, store=st))
    assert again["recurrence"] is not None


# --- ordering is structural --------------------------------------------------

def test_the_pipeline_is_a_sequential_agent_in_audit_then_remediate_order():
    from google.adk.agents import SequentialAgent

    assert isinstance(root_agent, SequentialAgent)
    assert [a.output_key for a in root_agent.sub_agents] == [AUDIT.output_key, PRIORITIZE.output_key]
    assert REQUIRED_OUTPUT_KEYS == ("audit", "remediation")


def test_a_run_that_skipped_remediation_is_incomplete():
    assert missing_output_keys({"audit": "found things"}) == ["remediation"]
    assert missing_output_keys({"audit": "x", "remediation": "   "}) == ["remediation"]
    assert missing_output_keys({"audit": "x", "remediation": "plan"}) == []


def test_final_text_is_not_accepted_as_a_remediation_plan(monkeypatch):
    """Regression: a transfer that ended at the auditor used to have its chatty
    final message reported as the remediation plan."""
    import auditpledge.main as main

    class _Result:
        final_text = "I audited the server and everything looks fine!"
        state = {"audit": "the audit output"}          # no 'remediation' key

    async def fake_run_agent(*args, **kwargs):
        return _Result()

    monkeypatch.setattr(main, "run_agent", fake_run_agent)
    narrative, status = asyncio.run(main._remediation("compound-position-agent", "fixture", "run-x"))
    assert narrative == ""
    assert "did not write remediation" in status


def test_a_complete_pipeline_run_is_accepted(monkeypatch):
    import auditpledge.main as main

    class _Result:
        final_text = "ignored"
        state = {"audit": "a", "remediation": "  1. drop collateral-mover  "}

    async def fake_run_agent(*args, **kwargs):
        return _Result()

    monkeypatch.setattr(main, "run_agent", fake_run_agent)
    narrative, status = asyncio.run(main._remediation("compound-position-agent", "fixture", "run-x"))
    assert narrative == "1. drop collateral-mover"
    assert status == "ok"


def test_an_llm_failure_degrades_to_a_stated_reason_not_a_crash(monkeypatch):
    import auditpledge.main as main

    async def boom(*args, **kwargs):
        raise RuntimeError("no credentials")

    monkeypatch.setattr(main, "run_agent", boom)
    st = store()
    out = asyncio.run(audit("compound-position-agent", use_llm=True, store=st))
    assert out["narrative"] == ""
    assert "unavailable" in out["llm_status"]
    assert out["status"] == "complete"        # the deterministic audit still stands


# --- reporting ---------------------------------------------------------------

def test_the_printed_report_states_its_evidence_and_its_numbers():
    st = store()
    out = asyncio.run(audit("compound-position-agent", use_llm=False, store=st))
    text = format_report(out)
    pr = out["report"]["pricing"]
    assert "evidence: fixture via" in text
    assert "synthetic demo catalogue" in text
    assert f"${pr['expected_loss_usd']:,}" in text
    assert f"${pr['suggested_annual_premium_usd']:,}" in text
    assert "Counterfactual repricing" in text
    assert "[remediation] skipped (--no-llm)" in text
