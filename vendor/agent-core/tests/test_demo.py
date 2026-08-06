"""The demo is executable evidence, so it is tested like the rest of the library.

Pinned here: with no sink configured the demo cannot report a delivery, and the
run document it prints is the one the run actually wrote.
"""

import json

from agent_core.demo import run_demo


def test_demo_runs_and_claims_no_delivery_without_sinks(monkeypatch, tmp_path, capsys):
    for var in ("AGENT_SLACK_WEBHOOK_URL", "AGENT_TICKET_ENDPOINT",
                "AGENT_GITHUB_REPO", "AGENT_GITHUB_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AGENT_IN_MEMORY_STATE", "1")

    out_path = tmp_path / "run.json"
    doc = run_demo(str(out_path))
    printed = capsys.readouterr().out

    assert doc["status"] == "complete"
    assert len(doc["guardrails"]) >= 6           # SQL + content screens recorded
    assert len(doc["routes"]) == 2
    for record in doc["routes"]:
        assert record["delivery_mode"] == "synthetic"
        assert record["artifacts"] == {}
        assert record["primary_artifact_url"] is None

    # nothing in the console output may imply a delivered artifact
    assert "SYNTHETIC" in printed
    assert "tracker.example" not in printed
    assert "LIVE   artifact" not in printed

    on_disk = json.loads(out_path.read_text())
    assert on_disk["run_id"] == doc["run_id"]


def test_demo_blocks_the_dangerous_sql_probes(monkeypatch):
    monkeypatch.setenv("AGENT_IN_MEMORY_STATE", "1")
    doc = run_demo()
    sql_decisions = [g for g in doc["guardrails"] if g["name"] == "READ_ONLY_SQL"]
    assert len(sql_decisions) == 4
    assert sum(1 for g in sql_decisions if g["outcome"] == "blocked") == 3
