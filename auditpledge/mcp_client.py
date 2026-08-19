"""Fetch a tool manifest from a live MCP server over stdio, then fail closed.

`fetch_manifest` opens a real MCP session (`initialize` + `tools/list`) against a
subprocess, checks the server identity it was handed back, and converts each
`Tool` into the record the auditor scores. Every missing piece of evidence is an
error, never a default:

  * server identity does not match the requested server -> `ManifestUnavailable`
  * transport, handshake, or `tools/list` failure                -> `ManifestUnavailable`
  * a tool with no `_meta["auditpledge/provenance"]` block       -> `ManifestUnavailable`
  * a tool missing publisher, version, scopes, or ops            -> `ManifestUnavailable`

An unaudited tool must never be silently scored as "clean", so an incomplete
manifest stops the audit rather than producing a cheerful report.
"""

from __future__ import annotations

import datetime as _dt
import os
import sys
from typing import Any, Sequence

from .mcp_server import META_KEY, server_identity

DEFAULT_TIMEOUT_S = 30.0


class ManifestUnavailable(RuntimeError):
    """The MCP server could not supply a complete, identified tool manifest."""


def default_command(server: str) -> tuple[str, list[str]]:
    """Command that launches the bundled demo MCP server for `server`."""
    return sys.executable, ["-m", "auditpledge.mcp_server", "--server", server]


async def fetch_manifest(
    server: str,
    *,
    command: str | None = None,
    args: Sequence[str] | None = None,
    expect_identity: str | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Open an MCP stdio session and return the audited tool manifest.

    `command`/`args` point at any MCP server; they default to the bundled demo
    server for `server`. `expect_identity` defaults to that server's identity.
    """
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except Exception as exc:  # pragma: no cover - mcp is a hard dependency
        raise ManifestUnavailable(f"MCP client library unavailable: {exc}") from exc

    cmd, argv = default_command(server)
    if command:
        cmd, argv = command, list(args or [])
    want_identity = expect_identity if expect_identity is not None else server_identity(server)

    env = dict(os.environ)
    params = StdioServerParameters(command=cmd, args=list(argv), env=env)

    # Only the protocol conversation happens inside the session. Validation runs
    # after it closes, so a rejected manifest surfaces its own message instead of
    # being buried in the anyio TaskGroup ExceptionGroup.
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await _with_timeout(session.initialize(), timeout_s, "initialize")
                got_identity = getattr(getattr(init, "serverInfo", None), "name", "")
                listing = await _with_timeout(session.list_tools(), timeout_s, "tools/list")
                raw = list(listing.tools)
    except ManifestUnavailable:
        raise
    except BaseException as exc:  # anyio wraps failures in an ExceptionGroup
        inner = _first_manifest_error(exc)
        if inner is not None:
            raise inner
        raise ManifestUnavailable(
            f"could not read tools/list from MCP server {server!r} via "
            f"{cmd} {' '.join(argv)}: {exc.__class__.__name__}: {exc}") from exc

    if want_identity and got_identity != want_identity:
        raise ManifestUnavailable(
            f"MCP server identity mismatch: asked for {want_identity!r}, "
            f"handshake returned {got_identity!r}")

    tools = [_tool_record(t, server) for t in raw]
    if not tools:
        raise ManifestUnavailable(f"MCP server {server!r} advertised no tools")

    return {
        "server": server,
        "synthetic": False,
        "tools": tools,
        "evidence": {
            "source": "mcp/stdio",
            "transport": f"{cmd} {' '.join(argv)}",
            "server_identity": got_identity,
            "protocol_calls": ["initialize", "tools/list"],
            "tools_listed": len(tools),
            "retrieved_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        },
    }


def _first_manifest_error(exc: BaseException) -> ManifestUnavailable | None:
    """Dig a ManifestUnavailable out of a (possibly nested) ExceptionGroup."""
    if isinstance(exc, ManifestUnavailable):
        return exc
    for sub in getattr(exc, "exceptions", ()) or ():
        found = _first_manifest_error(sub)
        if found is not None:
            return found
    return None


async def _with_timeout(awaitable, timeout_s: float, what: str):
    import asyncio

    try:
        return await asyncio.wait_for(awaitable, timeout=timeout_s)
    except asyncio.TimeoutError as exc:
        raise ManifestUnavailable(f"MCP {what} timed out after {timeout_s}s") from exc


_REQUIRED_META = ("publisher", "version", "scopes", "ops")


def _tool_record(tool: Any, server: str) -> dict[str, Any]:
    meta = (getattr(tool, "meta", None) or {}).get(META_KEY)
    if not isinstance(meta, dict):
        raise ManifestUnavailable(
            f"tool {getattr(tool, 'name', '?')!r} on {server!r} carries no "
            f"'{META_KEY}' evidence in its MCP _meta; refusing to score it as clean")
    missing = [k for k in _REQUIRED_META if meta.get(k) is None]
    if missing:
        raise ManifestUnavailable(
            f"tool {getattr(tool, 'name', '?')!r} on {server!r} is missing required "
            f"provenance evidence: {', '.join(missing)}")
    return {
        "name": tool.name,
        "description": getattr(tool, "description", "") or "",
        "publisher": meta["publisher"],
        "version": meta["version"],
        "signature": meta.get("signature"),
        "scopes": list(meta["scopes"]),
        "ops": list(meta["ops"]),
    }
