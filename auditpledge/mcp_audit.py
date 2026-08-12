"""MCP supply-chain audit: the load-bearing analysis, tuned for Compound exposure.

Deterministic, auditable checks over an MCP tool manifest: provenance
(Ed25519-verified signature bound to an exactly-matched publisher), capability
risk (RCE / transaction-signing / filesystem / network), scope breadth, Compound
position exposure (tools that build or sign transactions or move collateral), and
advisories from a source that has to name its ID, origin, and retrieval time. An
underwriter pass then converts the findings into an expected-loss figure and a
premium, and reprices two counterfactuals so the dollar effect of a fix is
measured, not asserted.

Everything here is a pure function of the manifest plus the keyring, so a
reviewer can trace every number, and `tests/` pins each rule.
"""

from __future__ import annotations

import copy
import datetime as _dt
import time
from typing import Any, Callable

from .advisories import AdvisorySource, OfflineSnapshot, build_source
from .catalogue import UnknownServer, manifest as catalogue_manifest
from .config import settings
from .provenance import DEFAULT_KEYRING, Keyring, normalize_publisher

# Capabilities that make a tool dangerous if compromised. `sign_tx` is here
# because on a Compound-facing agent a compromised signer moves real value.
_RCE_OPS = ("shell", "exec", "eval", "run_command", "subprocess", "os.system",
            "write_file", "python", "sign_tx")
_NET_OPS = ("http", "fetch", "request", "webhook", "url", "rpc")
# Compound position exposure: a tool that can build or sign a transaction, or
# whose scope lets it move collateral, sits directly in front of the money in a
# Comet position. Scored on top of the generic capability weight.
_POSITION_OPS = ("sign_tx", "send_tx", "broadcast")
_POSITION_SCOPES = ("sign:tx", "build:tx", "write:comet", "move:collateral")

# Score weights. Named so the report can explain itself.
W_RCE, W_NET, W_UNSIGNED, W_UNTRUSTED, W_SCOPES, W_VULN, W_POSITION = 5, 1, 3, 2, 2, 5, 3

SOURCES = ("fixture", "mcp")


class AuditError(RuntimeError):
    """The audit could not be completed on real evidence. Never downgraded."""


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


# --- inventory ----------------------------------------------------------------

def inventory_tools(manifest: dict[str, Any]) -> dict[str, Any]:
    """List the tools an MCP server exposes with their declared metadata."""
    tools = manifest.get("tools", [])
    return {
        "server": manifest.get("server"),
        "count": len(tools),
        "tools": [{"name": t.get("name"), "publisher": t.get("publisher"),
                   "version": t.get("version"), "signature_present": bool(t.get("signature")),
                   "scopes": list(t.get("scopes") or []), "ops": list(t.get("ops") or [])}
                  for t in tools],
    }


# --- risk ---------------------------------------------------------------------

def _tool_risk(
    tool: dict[str, Any],
    keyring: Keyring,
    advisories: AdvisorySource,
    allow_simulated: bool,
) -> dict[str, Any]:
    findings: list[str] = []
    score = 0

    prov = keyring.verify(tool)
    signed = prov.verified  # only a verified signature counts as signed
    publisher = normalize_publisher(tool.get("publisher"))
    trusted = signed and publisher in {normalize_publisher(p) for p in settings.trusted_publishers}

    ops = [str(o).lower() for o in (tool.get("ops") or [])]
    scopes = list(tool.get("scopes") or [])
    scopes_l = [str(s).lower() for s in scopes]
    rce = [o for o in ops if any(k in o for k in _RCE_OPS)]
    net = [o for o in ops if any(k in o for k in _NET_OPS)]
    position_ops = [o for o in ops if any(k in o for k in _POSITION_OPS)]
    position_scopes = [s for s in scopes_l if any(k in s for k in _POSITION_SCOPES)]

    if rce:
        score += W_RCE
        findings.append(f"RCE-capable ops: {rce}")
    if net:
        score += W_NET
        findings.append(f"network ops: {net}")
    if position_ops or position_scopes:
        score += W_POSITION
        findings.append(
            "Compound position exposure: "
            f"{'ops ' + str(position_ops) if position_ops else ''}"
            f"{' ' if position_ops and position_scopes else ''}"
            f"{'scopes ' + str(position_scopes) if position_scopes else ''}".strip())
    if not signed:
        score += W_UNSIGNED
        findings.append(prov.reason)
    if not trusted:
        score += W_UNTRUSTED
        findings.append(f"untrusted publisher '{tool.get('publisher')}'"
                        + ("" if signed else " (identity unproven)"))
    if len(scopes) >= 4 or "*" in scopes:
        score += W_SCOPES
        findings.append(f"over-broad scopes: {scopes}")

    hits = advisories.lookup(str(tool.get("name")), str(tool.get("version")))
    counted = [a for a in hits if allow_simulated or not a.simulated]
    for a in counted:
        score += W_VULN
        findings.append(f"known vuln {a.label} (retrieved {a.retrieved_at})")
    for a in hits:
        if a not in counted:
            findings.append(f"advisory {a.id} withheld: simulated advisories are off")

    sev = "critical" if score >= 8 else "high" if score >= 5 else "medium" if score >= 3 else "low"
    return {
        "name": tool.get("name"), "score": score, "severity": sev, "findings": findings,
        "rce_capable": bool(rce), "signed": signed, "trusted": trusted,
        "position_exposed": bool(position_ops or position_scopes),
        "publisher": tool.get("publisher"),
        "provenance": {"verified": prov.verified, "signature_present": prov.signature_present,
                       "publisher_known": prov.publisher_known, "reason": prov.reason},
        "advisories": [a.as_dict() for a in counted],
    }


def assess_supply_chain(
    manifest: dict[str, Any],
    *,
    keyring: Keyring | None = None,
    advisories: AdvisorySource | None = None,
    allow_simulated: bool | None = None,
) -> dict[str, Any]:
    """Score every tool and summarise the supply-chain risk."""
    kr = keyring or DEFAULT_KEYRING
    src = advisories if advisories is not None else OfflineSnapshot()
    allow = settings.allow_simulated_advisories if allow_simulated is None else allow_simulated

    results = [_tool_risk(t, kr, src, allow) for t in manifest.get("tools", [])]
    unsigned_rce = [r for r in results if r["rce_capable"] and not r["signed"]]
    forged = [r for r in results
              if r["provenance"]["signature_present"] and not r["provenance"]["verified"]]
    return {
        "server": manifest.get("server"),
        "tools": results,
        "counts": {
            "critical": len([r for r in results if r["severity"] == "critical"]),
            "high": len([r for r in results if r["severity"] == "high"]),
            "unsigned_rce": len(unsigned_rce),
            "forged_signatures": len(forged),
            "position_exposed": len([r for r in results if r["position_exposed"]]),
            "total": len(results),
        },
        "advisory_source": src.name,
        "simulated_advisories_counted": allow,
        "keyring_publishers": list(kr.publishers),
        "worst": max(results, key=lambda r: r["score"], default=None),
    }


# --- pricing ------------------------------------------------------------------

P_MAP = {"critical": 0.25, "high": 0.10, "medium": 0.03, "low": 0.005}
P_UNSIGNED_RCE = 0.30


def price_audit(assessment: dict[str, Any]) -> dict[str, Any]:
    """Expected loss = per-tool p(compromise) x breach loss; premium adds a risk load."""
    expected_loss = 0.0
    per_tool = []
    for r in assessment.get("tools", []):
        p = P_MAP.get(r["severity"], 0.01)
        driver = "severity band"
        if r["rce_capable"] and not r["signed"]:
            if P_UNSIGNED_RCE > p:
                driver = "unsigned RCE floor"
            p = max(p, P_UNSIGNED_RCE)  # unsigned RCE dominates
        loss = p * settings.breach_loss_usd
        expected_loss += loss
        per_tool.append({"tool": r["name"], "severity": r["severity"],
                         "p_compromise": round(p, 3), "p_driver": driver,
                         "expected_loss_usd": round(loss)})
    drivers = sorted((d for d in per_tool
                      if d["expected_loss_usd"] >= settings.breach_loss_usd * 0.05),
                     key=lambda d: d["expected_loss_usd"], reverse=True)
    return {
        "expected_loss_usd": round(expected_loss),
        "suggested_annual_premium_usd": round(expected_loss * settings.risk_load),
        "breach_loss_assumption_usd": settings.breach_loss_usd,
        "risk_load": settings.risk_load,
        "per_tool": per_tool,
        "top_drivers": drivers[:5],
    }


# --- counterfactual repricing -------------------------------------------------

def _drop_tool(manifest: dict[str, Any], tool_name: str) -> dict[str, Any]:
    out = copy.deepcopy(manifest)
    out["tools"] = [t for t in out["tools"] if t.get("name") != tool_name]
    return out


def _sign_and_sandbox(manifest: dict[str, Any], tool_name: str) -> dict[str, Any] | None:
    """Rebuild the tool as a signed, sandboxed equivalent from a trusted publisher.

    The rewritten entry is genuinely re-signed with that publisher's demo key, so
    the counterfactual manifest passes the same Ed25519 verification as any other
    and the repricing is a real rerun of the scorer, not a hand-edited number.
    """
    from .demo_keys import DEMO_PUBLISHERS, sign_tool

    demo = {normalize_publisher(p) for p in DEMO_PUBLISHERS}
    publisher = next((p for p in settings.trusted_publishers if normalize_publisher(p) in demo), None)
    if publisher is None:  # pragma: no cover - configuration would have to remove every key
        return None

    out = copy.deepcopy(manifest)
    for t in out["tools"]:
        if t.get("name") != tool_name:
            continue
        t["publisher"] = publisher
        t["ops"] = [o for o in (t.get("ops") or [])
                    if not any(k in str(o).lower() for k in _RCE_OPS)]
        t["scopes"] = list(t.get("scopes") or [])[:1] or ["read:none"]
        if "*" in t["scopes"]:
            t["scopes"] = ["read:none"]
        t.pop("signature", None)
        t["signature"] = sign_tool(t)
        return out
    return None


def counterfactuals(
    manifest: dict[str, Any],
    tool_name: str,
    *,
    keyring: Keyring | None = None,
    advisories: AdvisorySource | None = None,
    allow_simulated: bool | None = None,
) -> dict[str, Any]:
    """Reprice the same manifest with one tool removed, and with it remediated.

    Both variants are scored by the identical `assess_supply_chain` +
    `price_audit` pair, so the deltas are measured, not asserted.
    """
    kw = {"keyring": keyring, "advisories": advisories, "allow_simulated": allow_simulated}
    base = price_audit(assess_supply_chain(manifest, **kw))
    variants = []
    for action, label, mutate in (
        ("drop", f"drop {tool_name} from the agent's toolset", _drop_tool),
        ("sign_and_sandbox",
         f"re-publish {tool_name} signed by a trusted publisher, with RCE/signing ops and wildcard scopes removed",
         _sign_and_sandbox),
    ):
        mutated = mutate(manifest, tool_name)
        if mutated is None:
            continue
        priced = price_audit(assess_supply_chain(mutated, **kw))
        variants.append({
            "action": action,
            "label": label,
            "expected_loss_usd": priced["expected_loss_usd"],
            "suggested_annual_premium_usd": priced["suggested_annual_premium_usd"],
            "delta_expected_loss_usd": priced["expected_loss_usd"] - base["expected_loss_usd"],
            "delta_premium_usd": (priced["suggested_annual_premium_usd"]
                                  - base["suggested_annual_premium_usd"]),
        })
    return {"tool": tool_name, "baseline": {
        "expected_loss_usd": base["expected_loss_usd"],
        "suggested_annual_premium_usd": base["suggested_annual_premium_usd"]},
        "variants": variants}


# --- orchestration ------------------------------------------------------------

class _Trace:
    """Wall-clock trace of the audit stages. Real measurements, not a script."""

    def __init__(self) -> None:
        self.steps: list[dict[str, Any]] = []

    def step(self, key: str, detail: str, status: str = "ok", tick: str = "") -> Callable[[], None]:
        t0 = time.perf_counter()
        entry = {"key": key, "detail": detail, "status": status, "tick": tick, "ms": 0.0}
        self.steps.append(entry)

        def done(status: str = status, tick: str = tick, detail: str | None = None) -> None:
            entry["ms"] = round((time.perf_counter() - t0) * 1000, 2)
            entry["status"] = status
            entry["tick"] = tick
            if detail is not None:
                entry["detail"] = detail

        return done


def load_manifest(server: str, source: str = "fixture") -> dict[str, Any]:
    """Load a manifest for `server`. `fixture` reads the bundled synthetic
    catalogue directly; `mcp` opens a real MCP stdio session and reads
    `tools/list`. Unknown servers and unreachable servers both fail closed."""
    source = (source or "fixture").lower()
    if source not in SOURCES:
        raise AuditError(f"unknown manifest source {source!r}; expected one of {', '.join(SOURCES)}")
    if source == "fixture":
        try:
            doc = catalogue_manifest(server)
        except UnknownServer as exc:
            raise AuditError(str(exc)) from exc
        doc["evidence"] = {
            "source": "fixture",
            "transport": "in-process synthetic catalogue (no MCP session)",
            "server_identity": f"fixture/{server}",
            "protocol_calls": [],
            "tools_listed": len(doc["tools"]),
            "retrieved_at": _now(),
        }
        return doc

    from .mcp_client import ManifestUnavailable, fetch_manifest

    try:
        return _run_sync(fetch_manifest(server))
    except ManifestUnavailable as exc:
        raise AuditError(f"live MCP audit failed closed: {exc}") from exc


def _run_sync(coro: Any) -> Any:
    """Run `coro` to completion from sync code, event loop or not.

    `run_audit` is a sync tool the agent calls, but the CLI and the ADK runner
    both call it from inside a running event loop, where `asyncio.run` raises.
    The coroutine then gets its own loop on a worker thread. Without this the
    entire `--source mcp` path dies with "asyncio.run() cannot be called from a
    running event loop" the first time anyone uses it.
    """
    import asyncio
    import concurrent.futures

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def run_audit(
    server: str = "compound-position-agent",
    source: str = "fixture",
    advisory_source: str = "offline",
    *,
    keyring: Keyring | None = None,
    advisories: AdvisorySource | None = None,
) -> dict[str, Any]:
    """Full audit: load manifest, inventory, score, price, reprice counterfactuals."""
    src = advisories if advisories is not None else build_source(advisory_source)
    allow = settings.allow_simulated_advisories and advisory_source != "osv"
    tr = _Trace()

    done = tr.step("load_manifest", f"Read the tool manifest for '{server}' via {source}.")
    doc = load_manifest(server, source)
    ev = doc.get("evidence", {})
    done(tick=f"{len(doc['tools'])} tools",
         detail=f"{ev.get('transport')} -> identity {ev.get('server_identity')}")

    done = tr.step("inventory_tools", "Inventory publisher, version, scopes and ops per tool.")
    inv = inventory_tools(doc)
    done(tick=f"{inv['count']} tools")

    # Each step below does the work it is timed for: the provenance step really
    # runs the Ed25519 verifications, the assess step really runs the scorer.
    done = tr.step("verify_provenance",
                   "Verify each detached Ed25519 signature over the tool's canonical bytes.")
    kr = keyring or DEFAULT_KEYRING
    prov = [kr.verify(t) for t in doc["tools"]]
    verified = len([p for p in prov if p.verified])
    forged = len([p for p in prov if p.signature_present and not p.verified])
    done(status="crit" if forged or verified < inv["count"] else "ok",
         tick=f"{verified}/{inv['count']} verified" + (f", {forged} forged" if forged else ""))

    done = tr.step("assess_supply_chain",
                   "Score capability, scope, provenance, Compound exposure and advisories.")
    assessment = assess_supply_chain(doc, keyring=kr, advisories=src, allow_simulated=allow)
    worst = assessment["worst"]
    done(status="crit" if assessment["counts"]["critical"] else "ok",
         tick=f"worst: {worst['name']}" if worst else "no tools")

    done = tr.step("price_audit", "Price the residual risk: p(compromise) x breach loss.")
    pricing = price_audit(assessment)
    done(tick=f"${pricing['expected_loss_usd']:,} loss")

    cf = None
    if worst:
        done = tr.step("counterfactual", f"Reprice the manifest with '{worst['name']}' fixed.")
        cf = counterfactuals(doc, worst["name"], keyring=kr, advisories=src,
                             allow_simulated=allow)
        best = min(cf["variants"], key=lambda v: v["suggested_annual_premium_usd"], default=None)
        done(tick=(f"premium -${abs(best['delta_premium_usd']):,}" if best else "n/a"))

    return {
        "server": doc.get("server", server),
        "generated_at": _now(),
        "evidence": ev,
        "synthetic_catalogue": bool(doc.get("synthetic")),
        "inventory": inv,
        "assessment": assessment,
        "pricing": pricing,
        "counterfactual": cf,
        "trace": tr.steps,
    }


def audit_server(server: str = "compound-position-agent", source: str = "fixture") -> dict[str, Any]:
    """Run the full MCP supply-chain audit for a named Compound-facing agent server.

    Args:
      server: the MCP server to audit, for example 'compound-position-agent' or
        'compound-treasury'.
      source: 'mcp' to read tools/list from a live MCP stdio session, or 'fixture'
        to read the bundled synthetic catalogue directly.

    Returns the tool inventory, the per-tool risk assessment with verified
    provenance, the underwriter pricing, and the counterfactual repricing of the
    worst tool. Fails closed with an error message if the manifest cannot be read.
    """
    try:
        return run_audit(server, source)
    except AuditError as exc:
        return {"error": str(exc), "server": server, "source": source}
