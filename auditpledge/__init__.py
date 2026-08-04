"""AuditPledge: provenance and priced risk for the MCP tools a Compound agent calls.

An AI agent that manages a Compound position is only as trustworthy as the
weakest tool in its toolbelt. AuditPledge opens a real Model Context Protocol
session against the agent's tool servers, verifies Ed25519 provenance for every
tool, scores the supply-chain risk weighted for what a Compound position exposes
(state reads, transaction building, collateral movement), and prices the residual
risk so a risk owner can act on a dollar figure.

Adapted from the doom2quake ChainProof engine and re-scoped for the Compound
Grants Program (Security Tooling domain). Testnet only for the grant period.
"""

from .config import settings

__all__ = ["settings"]
__version__ = "0.1.0"
