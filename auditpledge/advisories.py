"""Advisory sources: a validated offline snapshot and a real OSV.dev client.

Two rules, both aimed at "never claim a vulnerability you cannot back":

  * Every advisory ID is syntax-validated on construction: a real CVE, or a GHSA
    in its restricted base32 alphabet, and never a documentation placeholder such
    as `GHSA-xxxx` or `GHSA-xxxx-xxxx-xxxx`. A bad ID raises a `ValueError`
    instead of being printed as a "known vuln" finding.
  * Every advisory carries `source`, `retrieved_at`, and a `simulated` flag. The
    offline snapshot describes invented Compound-facing tools for the demo
    catalogue, so its entries are `simulated=True`, are printed as `[SIMULATED]`,
    and can be excluded from scoring entirely (`--advisories osv`, or
    `AP_ALLOW_SIMULATED_ADVISORIES=false`).

`OsvSource` is a real client for https://api.osv.dev/v1/query (free, no key). It
is exercised in tests through an injected transport with a recorded OSV response
so parsing is covered without a network; the live path needs outbound HTTPS and
is documented in HONESTY.md.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# CVE-YYYY-NNNN (4+ digits). GHSA uses a restricted base32 alphabet in three
# four-character groups, so a placeholder like `GHSA-xxxx` cannot pass.
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_GHSA_GROUP = "[23456789cfghjmpqrvwx]{4}"
_GHSA_RE = re.compile(rf"^GHSA-{_GHSA_GROUP}-{_GHSA_GROUP}-{_GHSA_GROUP}$")


def _is_placeholder_ghsa(groups: list[str]) -> bool:
    """`GHSA-xxxx-xxxx-xxxx` is the documentation placeholder, not an advisory.

    Awkwardly, `x` is a member of the GHSA alphabet, so the shape alone passes.
    Real GHSA suffixes are random, so three groups that are each the same
    character repeated four times is a template someone forgot to fill in. The
    odds of a genuine ID looking like that are one in 20^11.
    """
    return all(len(set(g)) == 1 for g in groups) and len(set("".join(groups))) == 1


def valid_advisory_id(advisory_id: str) -> bool:
    """True only for a syntactically real CVE or GHSA identifier."""
    aid = (advisory_id or "").strip()
    if _CVE_RE.match(aid.upper()):
        return True
    if aid[:5].upper() == "GHSA-":
        suffix = aid[5:].lower()
        if not _GHSA_RE.match("GHSA-" + suffix):
            return False
        return not _is_placeholder_ghsa(suffix.split("-"))
    return False


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Advisory:
    """One vulnerability claim, with the provenance needed to defend it."""

    id: str
    summary: str
    source: str
    retrieved_at: str = field(default_factory=_now)
    simulated: bool = False

    def __post_init__(self) -> None:
        if not valid_advisory_id(self.id):
            raise ValueError(
                f"refusing to emit advisory with malformed or placeholder id "
                f"{self.id!r}; expected a real CVE-YYYY-NNNN or GHSA identifier"
            )

    @property
    def label(self) -> str:
        tag = "SIMULATED" if self.simulated else self.source
        return f"[{tag}] {self.id}: {self.summary}"

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "summary": self.summary, "source": self.source,
                "retrieved_at": self.retrieved_at, "simulated": self.simulated}


class AdvisorySource(Protocol):
    name: str

    def lookup(self, tool_name: str, version: str) -> list[Advisory]: ...


class OfflineSnapshot:
    """Hand-written advisories for the demo catalogue. Always `simulated=True`.

    The demo catalogue's Compound-facing tools do not exist, so neither do their
    CVEs. These entries exercise the scoring path and are labelled as fiction
    everywhere they surface. They are excluded from scoring when simulated
    advisories are off.
    """

    name = "offline-snapshot (simulated)"

    _FEED: dict[str, tuple[str, str]] = {
        "tx-builder@0.9.1": ("CVE-2026-31337", "SSRF via unchecked redirect while fetching gas oracles"),
        "collateral-mover@1.2.0": ("GHSA-2c9q-w5x7-6h3j", "arbitrary command execution by design (no sandbox)"),
        "report-fetcher@3.0.2": ("CVE-2026-40881", "XXE in the report template parser"),
    }

    def __init__(self, retrieved_at: str = "2026-08-01T00:00:00+00:00") -> None:
        self.retrieved_at = retrieved_at

    def lookup(self, tool_name: str, version: str) -> list[Advisory]:
        hit = self._FEED.get(f"{tool_name}@{version}")
        if not hit:
            return []
        return [Advisory(id=hit[0], summary=hit[1], source=self.name,
                         retrieved_at=self.retrieved_at, simulated=True)]


Transport = Callable[[str, bytes], bytes]


def _urllib_transport(url: str, body: bytes) -> bytes:  # pragma: no cover - needs network
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read()


class OsvSource:
    """Real OSV.dev query client. Network required; no API key.

    `transport` is injected in tests with a recorded OSV response so the parser
    is covered offline. Lookup failures raise: an advisory source that silently
    returns "no vulnerabilities" on a network error would understate risk.
    """

    name = "osv.dev"

    def __init__(self, ecosystem: str = "PyPI", transport: Transport | None = None) -> None:
        self.ecosystem = ecosystem
        self._transport = transport or _urllib_transport

    def lookup(self, tool_name: str, version: str) -> list[Advisory]:
        body = json.dumps({"version": version,
                           "package": {"name": tool_name, "ecosystem": self.ecosystem}}).encode()
        raw = self._transport(OSV_QUERY_URL, body)
        doc = json.loads(raw.decode("utf-8"))
        retrieved = _now()
        out: list[Advisory] = []
        for vuln in doc.get("vulns", []) or []:
            aid = str(vuln.get("id", ""))
            if not valid_advisory_id(aid):
                # Prefer an alias that is a real CVE/GHSA over dropping the hit.
                aid = next((a for a in vuln.get("aliases", []) or [] if valid_advisory_id(a)), "")
            if not aid:
                continue
            summary = str(vuln.get("summary") or vuln.get("details") or "").strip().splitlines()[0][:160]
            out.append(Advisory(id=aid, summary=summary or "no summary provided",
                                source=self.name, retrieved_at=retrieved, simulated=False))
        return out


class NullSource:
    """No advisory feed. Used when simulated advisories are switched off."""

    name = "none"

    def lookup(self, tool_name: str, version: str) -> list[Advisory]:
        return []


def build_source(kind: str = "offline", **kwargs: Any) -> AdvisorySource:
    kind = (kind or "offline").lower()
    if kind in {"offline", "fixture", "snapshot"}:
        return OfflineSnapshot()
    if kind == "osv":
        return OsvSource(**kwargs)
    if kind in {"none", "off"}:
        return NullSource()
    raise ValueError(f"unknown advisory source {kind!r}; expected offline|osv|none")
