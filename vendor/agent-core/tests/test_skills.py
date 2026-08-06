"""Pins the skill -> ADK Agent mapping against the installed google-adk.

`skills.py` claims the constructor arguments it uses are the real ADK ones. That
claim is only worth anything if something checks it, so these tests build the
agents for real (no model call is made by construction).
"""

import pytest

from agent_core.skills import Skill, agent_from_skill, build_supervisor

pytest.importorskip("google.adk.agents")


def detect_anomaly(metric: str) -> str:
    """Return a one-line verdict for a metric."""
    return f"{metric}: ok"


def _skill(name: str = "watch-it") -> Skill:
    return Skill(name=name, summary="Detect anomalies.", model="gemini-3.5-flash",
                 instruction="You are the Watcher.", tools=[detect_anomaly],
                 output_key="watch_report")


def test_agent_from_skill_uses_adk_safe_name_and_carries_the_skill():
    skill = _skill()
    agent = agent_from_skill(skill)
    assert agent.name == "watch_it_agent"  # ADK identifiers cannot contain hyphens
    assert agent.description == skill.summary
    assert agent.output_key == "watch_report"
    assert [t.__name__ for t in agent.tools] == ["detect_anomaly"]


def test_overrides_replace_agent_kwargs():
    agent = agent_from_skill(_skill(), tools=[], output_key="other")
    assert agent.tools == []
    assert agent.output_key == "other"


def test_build_supervisor_delegates_to_one_agent_per_skill():
    skills = [_skill("watch"), _skill("act")]
    root = build_supervisor(name="sup", description="Coordinates.",
                            instruction="Delegate in order.", skills=skills)
    assert root.model == "gemini-3.5-flash"  # defaults to the first skill's tier
    assert [c.name for c in root.sub_agents] == ["watch_agent", "act_agent"]


def test_build_supervisor_accepts_explicit_sub_agents():
    child = agent_from_skill(_skill("solo"))
    root = build_supervisor(name="sup", description="d", instruction="i",
                            skills=[_skill()], sub_agents=[child])
    assert [c.name for c in root.sub_agents] == ["solo_agent"]
