"""AuditPledge CLI: audit a Compound agent's MCP tool supply chain and price the risk.

    auditpledge audit                                    # bundled synthetic catalogue
    auditpledge audit --source mcp                       # real MCP tools/list session
    auditpledge audit --server compound-treasury --no-llm
    auditpledge audit --advisories osv                   # real OSV.dev lookups (network)
    auditpledge audit --json                             # machine-readable report

The deterministic audit (manifest -> inventory -> provenance -> risk -> pricing ->
counterfactual repricing) always runs. With GCP credentials the agent pipeline
adds a prioritised remediation narrative; without them the audit is unaffected.
All Web3 interaction is testnet only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from agent_core import StateStore, run_agent, signature_of

from .catalogue import CATALOGUES
from .config import settings
from .mcp_audit import AuditError, SOURCES, run_audit

# One long-lived store per process so run IDs are addressable and recurrence
# detection has something to compare against.
_STORE: StateStore | None = None


def get_store() -> StateStore:
    global _STORE
    if _STORE is None:
        _STORE = StateStore.create(settings)
    return _STORE


async def audit(
    server: str,
    use_llm: bool = True,
    *,
    source: str = "fixture",
    advisories: str = "offline",
    store: StateStore | None = None,
) -> dict[str, Any]:
    """Run one audit, persist it, and return the run record.

    The run is marked `complete` only after the report is persisted; any failure
    marks it `error` and re-raises, so a run never sits at `started` forever.
    """
    st = store or get_store()
    run_id = st.start_run(trigger={"server": server, "source": source, "advisories": advisories})
    try:
        report = run_audit(server, source, advisories)
    except AuditError as exc:
        st.fail(run_id, str(exc))
        raise

    narrative, llm_status = "", "skipped (--no-llm)"
    if use_llm:
        narrative, llm_status = await _remediation(server, source, run_id)
        st.record_guardrail(run_id, "llm-remediation",
                            "pass" if narrative else "unavailable", llm_status)

    st.set_data(run_id, "report", report)
    st.set_data(run_id, "narrative", narrative)
    st.detect_recurrence(run_id, signature_of("mcp-server", server, source))
    st.set_status(run_id, "complete")
    doc = st.get(run_id) or {}
    return {"run_id": run_id, "status": doc.get("status"), "report": report,
            "narrative": narrative, "llm_status": llm_status,
            "recurrence": doc.get("recurrence"), "state_backend": st.backend_name}


async def _remediation(server: str, source: str, run_id: str) -> tuple[str, str]:
    """Run the audit -> remediate pipeline. Returns ("", reason) unless it completed.

    `result.final_text` is never accepted as the remediation: the pipeline must
    have written both `audit` and `remediation` into session state.
    """
    try:
        from .agents import missing_output_keys, root_agent

        result = await run_agent(
            root_agent,
            f"Audit the MCP server '{server}' with source '{source}' and prioritise remediation.",
            app_name=settings.app_name, session_id=run_id)
        missing = missing_output_keys(result.state)
        if missing:
            return "", f"incomplete: pipeline did not write {', '.join(missing)}"
        return str(result.state["remediation"]).strip(), "ok"
    except Exception as exc:
        return "", f"unavailable: {exc.__class__.__name__}: {exc}"


def format_report(out: dict[str, Any]) -> str:
    """Render one audit run as the text the CLI prints.

    The UI snapshot generator renders the same string, so the artifact a reviewer
    downloads from the page is byte-for-byte what `auditpledge audit` printed.
    """
    rep = out["report"]
    ev = rep["evidence"]
    a = rep["assessment"]
    c = a["counts"]
    pr = rep["pricing"]
    L: list[str] = []

    L.append(f"MCP server: {rep['server']}  ({rep['inventory']['count']} tools)")
    L.append(f"  evidence: {ev['source']} via {ev['transport']}")
    L.append(f"            identity={ev['server_identity']}  calls={ev['protocol_calls'] or 'none'}"
             f"  retrieved={ev['retrieved_at']}")
    if rep["synthetic_catalogue"]:
        L.append("            NOTE: synthetic demo catalogue, not a third-party MCP server.")
    L.append(f"  advisory source: {a['advisory_source']}"
             f"  (simulated advisories counted: {a['simulated_advisories_counted']})")
    L.append(f"  critical={c['critical']}  high={c['high']}  unsigned-RCE={c['unsigned_rce']}"
             f"  position-exposed={c['position_exposed']}  forged-signatures={c['forged_signatures']}")

    L.append("")
    L.append("Per-tool findings:")
    for t in a["tools"]:
        L.append(f"  {t['name']:<20} [{t['severity']:<8}] score={t['score']:<3} "
                 f"signed={'yes' if t['signed'] else 'NO':<3} publisher={t['publisher']}")
        for f in t["findings"]:
            L.append(f"      - {f}")

    worst = a["worst"]
    if worst:
        L.append("")
        L.append(f"  worst tool: {worst['name']} [{worst['severity']}] score={worst['score']}")

    L.append("")
    L.append(f"Underwriter pricing (breach loss assumption ${pr['breach_loss_assumption_usd']:,},"
             f" risk load {pr['risk_load']}x):")
    L.append(f"  expected loss: ${pr['expected_loss_usd']:,}"
             f"   suggested annual premium: ${pr['suggested_annual_premium_usd']:,}")
    for d in pr["top_drivers"]:
        L.append(f"    - {d['tool']}: p(compromise)={d['p_compromise']}  "
                 f"expected loss ${d['expected_loss_usd']:,}")

    cf = rep.get("counterfactual")
    if cf and cf["variants"]:
        L.append("")
        L.append(f"Counterfactual repricing for '{cf['tool']}' "
                 f"(same scorer rerun on a mutated manifest):")
        for v in cf["variants"]:
            L.append(f"    - {v['label']}")
            L.append(f"        premium ${cf['baseline']['suggested_annual_premium_usd']:,}"
                     f" -> ${v['suggested_annual_premium_usd']:,}"
                     f"   ({v['delta_premium_usd']:+,} USD)")

    L.append("")
    if out["narrative"]:
        L.append("=== remediation ===")
        L.append(out["narrative"])
    else:
        L.append(f"[remediation] {out['llm_status']}")

    L.append("")
    L.append(f"-- run={out['run_id']} status={out['status']} state={out['state_backend']}")
    return "\n".join(L)


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="auditpledge",
                                     description="Provenance-and-pricing auditor for a Compound agent's MCP tools.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="Audit a Compound-facing agent's MCP tool supply chain.")
    a.add_argument("--server", default="compound-position-agent",
                   help=f"MCP server to audit (bundled demo servers: {', '.join(CATALOGUES)})")
    a.add_argument("--source", default="fixture", choices=SOURCES,
                   help="'mcp' opens a real MCP stdio session and reads tools/list; "
                        "'fixture' reads the bundled synthetic catalogue in process")
    a.add_argument("--advisories", default="offline", choices=("offline", "osv", "none"),
                   help="'offline' is the bundled simulated snapshot; 'osv' queries "
                        "api.osv.dev over the network")
    a.add_argument("--no-llm", action="store_true")
    a.add_argument("--json", action="store_true", help="print the raw report as JSON")

    sub.add_parser("servers", help="List the bundled demo Compound-facing MCP servers.")

    args = parser.parse_args(argv)

    if args.cmd == "servers":
        for name in CATALOGUES:
            print(name)
        return 0

    if args.cmd == "audit":
        try:
            out = asyncio.run(audit(args.server, use_llm=not args.no_llm,
                                    source=args.source, advisories=args.advisories))
        except AuditError as exc:
            print(f"auditpledge: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(out["report"], indent=2, sort_keys=True))
        else:
            print(format_report(out))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(cli())
