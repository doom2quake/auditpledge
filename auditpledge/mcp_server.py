"""A real MCP stdio server that publishes a catalogue's tools over `tools/list`.

This is the thing AuditPledge audits. It speaks the actual Model Context Protocol
over stdio (JSON-RPC: `initialize`, then `tools/list`), and it advertises the
supply-chain evidence AuditPledge needs in the standard, spec-sanctioned place:
the `_meta` field of each `Tool`, under the `auditpledge/provenance` key. The MCP
tool schema is intentionally not extended with bespoke top-level fields.

    python -m auditpledge.mcp_server --server compound-position-agent

Calling any advertised tool returns a refusal: this process exists to be
inventoried, not to execute a Compound agent's transactions.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from .catalogue import CATALOGUES, UnknownServer, manifest

META_KEY = "auditpledge/provenance"
SERVER_PREFIX = "auditpledge-mcp"


def server_identity(server: str) -> str:
    """The MCP `serverInfo.name` a client must see before trusting the manifest."""
    return f"{SERVER_PREFIX}/{server}"


def tool_meta(tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "publisher": tool.get("publisher"),
        "version": tool.get("version"),
        "signature": tool.get("signature"),
        "scopes": list(tool.get("scopes") or []),
        "ops": list(tool.get("ops") or []),
        "signature_algorithm": "ed25519",
        "signed_fields": ["name", "version", "publisher", "scopes", "ops"],
    }


def build_server(server: str):
    """Build the low-level MCP `Server` for a catalogue. Raises on unknown names."""
    from mcp.server.lowlevel import Server
    from mcp.types import TextContent, Tool

    doc = manifest(server)  # raises UnknownServer -> the process exits non-zero
    tools = doc["tools"]
    app = Server(server_identity(server))
    if not hasattr(app, "list_tools"):  # pragma: no cover - depends on the installed SDK
        raise RuntimeError(
            "the installed mcp SDK has no lowlevel Server.list_tools decorator; "
            "AuditPledge is pinned to mcp>=1.9,<2 (mcp 2.0 renamed it). "
            "Run `pip install 'mcp>=1.9,<2'`.")

    @app.list_tools()
    async def _list_tools() -> list[Tool]:
        return [
            Tool(
                name=t["name"],
                description=t.get("description") or t["name"],
                inputSchema={"type": "object", "properties": {}},
                _meta={META_KEY: tool_meta(t)},
            )
            for t in tools
        ]

    @app.call_tool()
    async def _call_tool(name: str, arguments: dict | None) -> list[TextContent]:
        return [TextContent(
            type="text",
            text=f"{server_identity(server)} is an audit target: tool {name!r} is advertised for "
                 "inventory only and is not executed here.",
        )]

    return app


async def _serve(server: str) -> None:
    from mcp.server.stdio import stdio_server

    app = build_server(server)
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auditpledge.mcp_server",
        description="Serve a demo Compound-facing MCP tool catalogue over stdio for AuditPledge to audit.")
    parser.add_argument("--server", default="compound-position-agent",
                        help=f"catalogue to serve; one of {', '.join(CATALOGUES)}")
    args = parser.parse_args(argv)
    try:
        asyncio.run(_serve(args.server))
    except UnknownServer as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
