"""Tests for linear_bot.claude_client: pure helpers and the tool-use loop."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from linear_bot.claude_client import (
    ClaudeClient,
    _extract_text,
    _extract_tool_uses,
    mcp_tools_to_claude,
    SYSTEM_PROMPT,
)
from linear_bot.mcp_client import TokenInvalidError


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

class TestMcpToolsToClaude:
    def test_basic_mapping(self):
        mcp_tools = [
            {
                "name": "create_issue",
                "description": "Create a Linear issue",
                "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}}},
            }
        ]
        result = mcp_tools_to_claude(mcp_tools)
        assert result == [
            {
                "name": "create_issue",
                "description": "Create a Linear issue",
                "input_schema": {"type": "object", "properties": {"title": {"type": "string"}}},
            }
        ]

    def test_missing_description_defaults_to_empty(self):
        mcp_tools = [{"name": "do_thing"}]
        result = mcp_tools_to_claude(mcp_tools)
        assert result[0]["description"] == ""

    def test_missing_input_schema_defaults(self):
        mcp_tools = [{"name": "do_thing", "description": "desc"}]
        result = mcp_tools_to_claude(mcp_tools)
        assert result[0]["input_schema"] == {"type": "object", "properties": {}}

    def test_empty_list(self):
        assert mcp_tools_to_claude([]) == []


class TestExtractText:
    def test_joins_text_blocks(self):
        blocks = [
            {"type": "text", "text": "Hello"},
            {"type": "text", "text": "world"},
        ]
        assert _extract_text(blocks) == "Hello\nworld"

    def test_skips_non_text_blocks(self):
        blocks = [
            {"type": "tool_use", "name": "foo", "id": "1", "input": {}},
            {"type": "text", "text": "Done"},
        ]
        assert _extract_text(blocks) == "Done"

    def test_empty(self):
        assert _extract_text([]) == ""


class TestExtractToolUses:
    def test_filters_tool_use(self):
        blocks = [
            {"type": "text", "text": "thinking..."},
            {"type": "tool_use", "name": "foo", "id": "1", "input": {}},
            {"type": "tool_use", "name": "bar", "id": "2", "input": {}},
        ]
        result = _extract_tool_uses(blocks)
        assert len(result) == 2
        assert result[0]["name"] == "foo"
        assert result[1]["name"] == "bar"

    def test_empty_list(self):
        assert _extract_tool_uses([]) == []

    def test_no_tool_use_blocks(self):
        assert _extract_tool_uses([{"type": "text", "text": "hi"}]) == []


# ---------------------------------------------------------------------------
# ClaudeClient helpers
# ---------------------------------------------------------------------------

def _make_client():
    return ClaudeClient(api_key="test-key", model="claude-test", max_rounds=3)


def _api_response(text=None, tool_uses=None, stop_reason=None):
    """Build a fake Claude API response dict."""
    content = []
    if tool_uses:
        content.extend(tool_uses)
        stop_reason = stop_reason or "tool_use"
    if text is not None:
        content.append({"type": "text", "text": text})
        stop_reason = stop_reason or "end_turn"
    return {
        "content": content,
        "stop_reason": stop_reason or "end_turn",
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }


# ---------------------------------------------------------------------------
# ClaudeClient._call_api
# ---------------------------------------------------------------------------

async def test_call_api_non_200_raises():
    client = _make_client()
    mock_resp = MagicMock()
    mock_resp.status = 429
    mock_resp.text = AsyncMock(return_value="rate limited")
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)

    mock_http = MagicMock()
    mock_http.post = MagicMock(return_value=mock_resp)

    with pytest.raises(Exception, match="429"):
        await client._call_api(mock_http, "sys", [], [])


async def test_call_api_200_returns_json():
    client = _make_client()
    payload = {"content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn"}
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value=payload)
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)

    mock_http = MagicMock()
    mock_http.post = MagicMock(return_value=mock_resp)

    result = await client._call_api(mock_http, "sys", [], [])
    assert result == payload


# ---------------------------------------------------------------------------
# ClaudeClient.run
# ---------------------------------------------------------------------------

async def test_run_single_round_no_tools():
    client = _make_client()
    mock_mcp = MagicMock()
    mock_mcp.list_tools = AsyncMock(return_value=[])
    mock_http = MagicMock()

    with patch.object(client, "_call_api", new=AsyncMock(return_value=_api_response("All done!"))):
        result = await client.run(mock_http, mock_mcp, "tok", "Do something")

    assert result["text"] == "All done!"
    assert result["tool_calls"] == []
    assert result["usage"]["input_tokens"] == 10


async def test_run_two_rounds_with_tool_call():
    client = _make_client()

    tool_use_block = {
        "type": "tool_use",
        "id": "tu_1",
        "name": "create_issue",
        "input": {"title": "Bug"},
    }
    round1_resp = _api_response(tool_uses=[tool_use_block])
    round2_resp = _api_response("Created PROJ-1.")

    mock_mcp = MagicMock()
    mock_mcp.list_tools = AsyncMock(return_value=[{"name": "create_issue"}])
    mock_mcp.call_tool = AsyncMock(return_value={
        "content": [{"type": "text", "text": '{"id": "uuid-abc", "identifier": "PROJ-1"}'}]
    })
    mock_http = MagicMock()

    api_calls = [round1_resp, round2_resp]
    with patch.object(client, "_call_api", new=AsyncMock(side_effect=api_calls)):
        result = await client.run(mock_http, mock_mcp, "tok", "Create a bug")

    assert result["text"] == "Created PROJ-1."
    assert len(result["tool_calls"]) == 1
    assert result["tool_calls"][0]["name"] == "create_issue"
    assert not result["tool_calls"][0]["is_error"]
    assert result["usage"]["input_tokens"] == 20  # 10 + 10


async def test_run_tool_call_exception_continues():
    client = _make_client()

    tool_use_block = {
        "type": "tool_use",
        "id": "tu_err",
        "name": "broken_tool",
        "input": {},
    }
    round1_resp = _api_response(tool_uses=[tool_use_block])
    round2_resp = _api_response("Handled error.")

    mock_mcp = MagicMock()
    mock_mcp.list_tools = AsyncMock(return_value=[])
    mock_mcp.call_tool = AsyncMock(side_effect=RuntimeError("tool exploded"))
    mock_http = MagicMock()

    with patch.object(client, "_call_api", new=AsyncMock(side_effect=[round1_resp, round2_resp])):
        result = await client.run(mock_http, mock_mcp, "tok", "Do thing")

    assert result["tool_calls"][0]["is_error"] is True
    assert "tool exploded" in result["tool_calls"][0]["result"]


async def test_run_token_invalid_propagates():
    client = _make_client()

    tool_use_block = {
        "type": "tool_use",
        "id": "tu_1",
        "name": "some_tool",
        "input": {},
    }
    mock_mcp = MagicMock()
    mock_mcp.list_tools = AsyncMock(return_value=[])
    mock_mcp.call_tool = AsyncMock(side_effect=TokenInvalidError("expired"))
    mock_http = MagicMock()

    with patch.object(
        client, "_call_api", new=AsyncMock(return_value=_api_response(tool_uses=[tool_use_block]))
    ):
        with pytest.raises(TokenInvalidError):
            await client.run(mock_http, mock_mcp, "tok", "Do thing")


async def test_run_max_rounds_exhausted_calls_summary():
    """When all rounds use tool_use, a summary call is made with empty tools."""
    client = ClaudeClient(api_key="k", model="m", max_rounds=2)

    tool_block = {"type": "tool_use", "id": "tu_x", "name": "t", "input": {}}
    tool_resp = _api_response(tool_uses=[tool_block])
    summary_resp = _api_response("Summary here.")

    mock_mcp = MagicMock()
    mock_mcp.list_tools = AsyncMock(return_value=[])
    mock_mcp.call_tool = AsyncMock(return_value={"content": []})
    mock_http = MagicMock()

    api_mock = AsyncMock(side_effect=[tool_resp, tool_resp, summary_resp])
    with patch.object(client, "_call_api", new=api_mock):
        result = await client.run(mock_http, mock_mcp, "tok", "Do lots")

    # 3 calls: 2 tool rounds + 1 summary
    assert api_mock.await_count == 3
    assert result["text"] == "Summary here."

    # Last call should have empty tools list (passed as keyword arg in the summary call)
    last_call = api_mock.call_args_list[-1]
    tools_arg = last_call.kwargs.get("tools", last_call[0][3] if len(last_call[0]) > 3 else None)
    assert tools_arg == []


async def test_run_system_prompt_contains_user_and_context():
    """System prompt is built with linear_user_name and issue_context."""
    client = _make_client()
    mock_mcp = MagicMock()
    mock_mcp.list_tools = AsyncMock(return_value=[])
    mock_http = MagicMock()

    captured = {}

    async def fake_call_api(http, system, messages, tools):
        captured["system"] = system
        return _api_response("ok")

    with patch.object(client, "_call_api", new=fake_call_api):
        await client.run(
            mock_http, mock_mcp, "tok", "inst",
            linear_user_name="Alice",
            issue_context="PROJ-42 is broken",
        )

    assert "Alice" in captured["system"]
    assert "PROJ-42 is broken" in captured["system"]


async def test_run_no_user_name_defaults_to_unknown():
    client = _make_client()
    mock_mcp = MagicMock()
    mock_mcp.list_tools = AsyncMock(return_value=[])
    mock_http = MagicMock()
    captured = {}

    async def fake_call_api(http, system, messages, tools):
        captured["system"] = system
        return _api_response("ok")

    with patch.object(client, "_call_api", new=fake_call_api):
        await client.run(mock_http, mock_mcp, "tok", "inst")

    assert "Unknown" in captured["system"]


async def test_run_usage_accumulated():
    client = _make_client()
    mock_mcp = MagicMock()
    mock_mcp.list_tools = AsyncMock(return_value=[])
    mock_http = MagicMock()

    resp1 = {"content": [], "stop_reason": "end_turn", "usage": {"input_tokens": 100, "output_tokens": 50}}
    with patch.object(client, "_call_api", new=AsyncMock(return_value=resp1)):
        result = await client.run(mock_http, mock_mcp, "tok", "inst")

    assert result["usage"]["input_tokens"] == 100
    assert result["usage"]["output_tokens"] == 50
