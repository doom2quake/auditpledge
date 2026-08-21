"""AuditPledge skills: audit a Compound agent's MCP supply chain, then prioritize."""

from __future__ import annotations

from agent_core import Skill

from .config import settings
from .mcp_audit import audit_server

AUDIT = Skill(
    name="audit-supply-chain",
    summary="Runs the full MCP supply-chain audit for a Compound-facing agent: inventory, risk, and pricing.",
    model=settings.model_fast,
    instruction=(
        "You are AuditPledge's Auditor. Call `audit_server` on the requested MCP "
        "server, passing the requested source ('mcp' for a live tools/list session, "
        "'fixture' for the bundled synthetic Compound tool catalogue). If the result "
        "contains an 'error' key, report that the audit failed closed and stop: never "
        "invent findings. Otherwise report how many tools were listed, how many "
        "signatures verified, which tools are unsigned or carry a forged signature, "
        "which are RCE-capable, which are exposed to the Compound position (they build "
        "or sign transactions or move collateral), and the single worst tool. State "
        "the underwriter numbers (expected loss, suggested premium, counterfactual "
        "deltas) exactly as returned, and mark any advisory tagged [SIMULATED] as "
        "simulated. Do not soften the findings and do not round the numbers."
    ),
    tools=[audit_server],
    output_key="audit",
)

PRIORITIZE = Skill(
    name="prioritize-remediation",
    summary="Turns the audit into a ranked, underwriter-priceable remediation plan.",
    model=settings.model_deep,
    instruction=(
        "You are AuditPledge's Risk Lead. From the audit in session state, write a "
        "decision-ready remediation plan for the operator of a Compound-facing agent "
        "and their risk owner. Rank the fixes by expected-loss reduction: the "
        "unsigned, RCE-capable tool that can move collateral or sign a transaction is "
        "almost certainly the dominant driver (the MCP-to-signer path), so lead with "
        "it. For each top driver, give the concrete fix (require a verified signature, "
        "drop the tool, sandbox the op, narrow the scopes) and the dollar impact of "
        "fixing it, taken from the counterfactual repricing in the audit rather than "
        "estimated. Close with the premium before versus after the top fix, quoting "
        "both counterfactual variants. If the audit failed closed, say so and write no "
        "plan. Be concrete; a risk owner and an underwriter will both read this."
    ),
    tools=[],
    output_key="remediation",
)

CATALOGUE = [AUDIT, PRIORITIZE]
