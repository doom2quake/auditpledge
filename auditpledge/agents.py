"""AuditPledge agent graph: audit first, then remediate, enforced by the graph.

The order is not a request in a prompt. `SequentialAgent` is an ADK workflow
agent that runs its sub-agents in the listed order, every time, so the Risk Lead
cannot produce a plan before the Auditor has written its findings into session
state. `REQUIRED_OUTPUT_KEYS` is then checked by the caller: a run that did not
write both keys is a failed run, and its text is discarded rather than passed off
as a remediation plan.

Reference: ADK workflow agents, SequentialAgent
(https://google.github.io/adk-docs/agents/workflow-agents/sequential-agents/).
"""

from __future__ import annotations

from agent_core import agent_from_skill

from .skills import AUDIT, PRIORITIZE

# Both keys must exist in session state for a run to count as complete.
REQUIRED_OUTPUT_KEYS: tuple[str, ...] = (AUDIT.output_key, PRIORITIZE.output_key)


def build_pipeline():
    """Build the deterministic audit -> remediate pipeline."""
    from google.adk.agents import SequentialAgent

    return SequentialAgent(
        name="auditpledge_pipeline",
        description=(
            "AuditPledge - a provenance-and-pricing auditor for the MCP tools a "
            "Compound-facing agent calls. Runs the audit and pricing, then the "
            "ranked remediation plan, in that fixed order."
        ),
        sub_agents=[agent_from_skill(AUDIT), agent_from_skill(PRIORITIZE)],
    )


def missing_output_keys(state: dict) -> list[str]:
    """Output keys the run failed to produce. Empty list means the run is complete."""
    return [k for k in REQUIRED_OUTPUT_KEYS if not str(state.get(k) or "").strip()]


root_agent = build_pipeline()
