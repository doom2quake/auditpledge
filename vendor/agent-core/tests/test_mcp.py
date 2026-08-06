"""Tests for the MCP schema bridge.

The bug these pin: ADK moved the parameter schema from `declaration.parameters`
to `declaration.parameters_json_schema` (google-adk 2.7.1 leaves `parameters` as
None). Reading only the old field advertised an empty input schema over MCP, so
every parameterised tool became uncallable. Both shapes are exercised here, one
against the installed ADK and one against a synthetic old-style declaration.
"""

import pytest

from agent_core.mcp import tool_input_schema

adk_function_tool = pytest.importorskip("google.adk.tools.function_tool")


def query_orders(region: str, days: int = 7) -> str:
    """Return the order total for a region over the last N days."""
    return f"{region}:{days}"


def test_schema_from_installed_adk_declaration():
    ft = adk_function_tool.FunctionTool(query_orders)
    schema = tool_input_schema(ft)
    assert schema["type"] == "object"
    assert set(schema["properties"]) == {"region", "days"}
    assert schema["properties"]["region"]["type"] == "string"
    assert schema["required"] == ["region"]


class _OldStyleParams:
    """Mimics a genai `Schema` from an older google-adk release."""

    def model_dump(self, exclude_none=False):
        return {
            "type": "OBJECT",
            "properties": {
                "region": {"type": "STRING", "description": "region code"},
                "days": {"type": "INTEGER"},
            },
            "required": ["region"],
            "property_ordering": ["region", "days"],
        }


class _OldStyleTool:
    def _get_declaration(self):
        class _Decl:
            parameters_json_schema = None
            parameters = _OldStyleParams()

        return _Decl()


def test_schema_from_legacy_declaration_is_converted_to_json_schema():
    schema = tool_input_schema(_OldStyleTool())
    assert schema["type"] == "object"
    assert schema["properties"]["region"]["type"] == "string"
    assert schema["properties"]["days"]["type"] == "integer"
    assert schema["required"] == ["region"]
    assert "property_ordering" not in schema


class _NoDeclarationTool:
    def _get_declaration(self):
        raise RuntimeError("no declaration")


def test_schema_falls_back_to_empty_object():
    for tool in (None, _NoDeclarationTool()):
        schema = tool_input_schema(tool)
        assert schema == {"type": "object", "properties": {}}
