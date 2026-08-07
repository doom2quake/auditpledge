"""AuditPledge configuration: extends agent-core's BaseSettings.

AuditPledge audits the MCP (Model Context Protocol) tool supply chain of a
Compound-facing AI agent: it inventories the tools the agent can call, checks
their provenance/signatures, flags the supply-chain risks (unsigned tools,
RCE-capable operations, over-broad scopes, untrusted publishers), and prices the
residual risk in Compound-position terms so a risk owner can act on a dollar
figure, not a vibe.

The load-bearing surface is MCP itself: AuditPledge reads `tools/list` from a
real MCP stdio session and its own audit is served back over MCP. A bundled
synthetic Compound tool catalogue lets the whole audit run keyless and offline,
and is labelled as synthetic wherever it surfaces.

The risk model is weighted for what a Compound position exposes. A tool that can
build and sign a COMP-related transaction or move collateral is scored harder
than a read-only market/account state reader, because the money at stake in a
Compound position sits behind exactly those capabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_core import BaseSettings, env_bool, env_int


def _env_float(name: str, default: float) -> float:
    import os

    raw = os.getenv(name, "").strip()
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


@dataclass(frozen=True)
class AuditPledgeSettings(BaseSettings):
    env_prefix: str = "AP"
    app_name: str = "auditpledge"

    # Publishers we accept as first-party roots for Compound-facing tooling.
    # Matched exactly after normalisation, and only ever after the signature has
    # verified. The reference keyring the Compound community can vet.
    trusted_publishers: tuple[str, ...] = ("compound-finance", "compound-community", "openzeppelin")
    # Underwriting: assumed loss if a tool that touches a Compound position is
    # compromised. A position-managing agent can move real collateral, so the
    # default breach loss is sized to a managed position, not a toy.
    breach_loss_usd: int = field(default_factory=lambda: env_int("AP_BREACH_LOSS_USD", 500_000))
    # Premium = expected loss x risk load.
    risk_load: float = field(default_factory=lambda: _env_float("AP_RISK_LOAD", 1.4))
    # The bundled advisory snapshot describes invented tools. Counting it is fine
    # for the demo and is labelled [SIMULATED]; set false for a real report.
    allow_simulated_advisories: bool = field(
        default_factory=lambda: env_bool("AP_ALLOW_SIMULATED_ADVISORIES", True))


settings = AuditPledgeSettings()
