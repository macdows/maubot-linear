"""Tests for linear_bot.mcp_client: pure helpers, SSE parsing, and request logic."""
from __future__ import annotations

import json
import time

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from linear_bot.mcp_client import MCPClient, MCPError, TokenInvalidError


# ---------------------------------------------------------------------------
# _token_hash
# ---------------------------------------------------------------------------

def test_token_hash_deterministic():
    client = MCPClient()
    assert client._token_hash("mytoken") == client._token_hash("mytoken")


def test_token_hash_16_hex_chars():
    client = MCPClient()
    h = client._token_hash("mytoken")
    assert len(h) == 16
    assert all(c in "0123456789abcdef" for c in h)


def test_token_hash_different_tokens():
    client = MCPClient()
    assert client._token_hash("tok_a") != client._token_hash("tok_b")


# ---------------------------------------------------------------------------
# _read_sse_response (static, no HTTP mock needed)
# ---------------------------------------------------------------------------

def _make_sse_resp(lines):
    """Build a minimal mock ClientResponse whose content yields the given lines as bytes."""
    async def _content():
        for line in lines:
            yield line.encode() if isinstance(line, str) else line

    mock_resp = MagicMock()
    mock_resp.content = _content()
    return mock_resp


async def test_sse_single_event_returned():
    payload = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
    lines = [
        f"data: {json.dumps(payload)}\r\n",
        "\r\n",
    ]
    result = await MCPClient._read_sse_response(_make_sse_resp(lines))
    assert result == payload


async def test_sse_multi_data_lines_merged():
    # SSE allows splitting a data payload across multiple data: lines
    part1 = '{"jsonrpc": "2.0", "id": 2, '
    part2 = '"result": {"tools": []}}'
    lines = [
        f"data: {part1}\r\n",
        f"data: {part2}\r\n",
        "\r\n",
    ]
    result = await MCPClient._read_sse_response(_make_sse_resp(lines))
    assert result["id"] == 2


async def test_sse_skips_non_id_events():
    """Events without an 'id' key are skipped; the first id-bearing one is returned."""
    notification = {"jsonrpc": "2.0", "method": "notifications/progress"}
    response = {"jsonrpc": "2.0", "id": 3, "result": {}}
    lines = [
        f"data: {json.dumps(notification)}\r\n",
        "\r\n",
        f"data: {json.dumps(response)}\r\n",
        "\r\n",
    ]
    result = await MCPClient._read_sse_response(_make_sse_resp(lines))
    assert result["id"] == 3


async def test_sse_empty_stream_raises():
    result_coro = MCPClient._read_sse_response(_make_sse_resp([]))
    with pytest.raises(MCPError):
        await result_coro


async def test_sse_invalid_json_raises():
    lines = [
        "data: {not valid json}\r\n",
        "\r\n",
    ]
    with pytest.raises(MCPError):
        await MCPClient._read_sse_response(_make_sse_resp(lines))


async def test_sse_trailing_data_without_blank_line():
    """Unparsed data at end of stream (no trailing blank line) is still attempted."""
    payload = {"jsonrpc": "2.0", "id": 5, "result": {}}
    lines = [f"data: {json.dumps(payload)}\r\n"]  # no trailing blank line
    result = await MCPClient._read_sse_response(_make_sse_resp(lines))
    assert result["id"] == 5


# ---------------------------------------------------------------------------
# MCPClient._request (mock aiohttp session)
# ---------------------------------------------------------------------------

def _make_resp(status=200, json_data=None, content_type="application/json",
               headers=None, text=""):
    mock_resp = MagicMock()
    mock_resp.status = status
    mock_resp.content_type = content_type
    mock_resp.headers = headers or {}
    mock_resp.json = AsyncMock(return_value=json_data or {})
    mock_resp.text = AsyncMock(return_value=text)
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)
    return mock_resp


def _make_session(resp):
    session = MagicMock()
    session.post = MagicMock(return_value=resp)
    return session


async def test_request_401_raises_token_invalid():
    client = MCPClient()
    resp = _make_resp(status=401)
    session = _make_session(resp)

    with pytest.raises(TokenInvalidError):
        await client._request(session, "bad_token", "tools/list")


async def test_request_401_clears_session():
    client = MCPClient()
    th = client._token_hash("tok")
    client._sessions[th] = "old-session"

    resp = _make_resp(status=401)
    session = _make_session(resp)

    with pytest.raises(TokenInvalidError):
        await client._request(session, "tok", "tools/list")

    assert th not in client._sessions


async def test_request_4xx_raises_mcp_error():
    client = MCPClient()
    resp = _make_resp(status=503, text="service unavailable")
    session = _make_session(resp)

    with pytest.raises(MCPError) as exc_info:
        await client._request(session, "tok", "tools/list")

    assert exc_info.value.code == 503


async def test_request_json_rpc_error_raises_mcp_error():
    client = MCPClient()
    body = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "Invalid Request"}}
    resp = _make_resp(json_data=body)
    session = _make_session(resp)

    with pytest.raises(MCPError, match="Invalid Request"):
        await client._request(session, "tok", "tools/list")


async def test_request_captures_session_id():
    client = MCPClient()
    body = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
    resp = _make_resp(json_data=body, headers={"Mcp-Session-Id": "sess-abc"})
    session = _make_session(resp)

    await client._request(session, "tok", "tools/list")

    th = client._token_hash("tok")
    assert client._sessions[th] == "sess-abc"


async def test_request_sends_session_id_if_known():
    client = MCPClient()
    th = client._token_hash("tok")
    client._sessions[th] = "existing-session"

    body = {"jsonrpc": "2.0", "id": 1, "result": {}}
    resp = _make_resp(json_data=body)
    session = _make_session(resp)

    await client._request(session, "tok", "tools/list")

    call_kwargs = session.post.call_args[1]
    sent_headers = call_kwargs.get("headers") or session.post.call_args[0][1] if len(session.post.call_args[0]) > 1 else {}
    # Headers are passed as keyword arg
    headers = session.post.call_args[1].get("headers", {}) if session.post.call_args[1] else {}
    assert headers.get("Mcp-Session-Id") == "existing-session"


async def test_request_sse_content_type_delegates():
    client = MCPClient()
    payload = {"jsonrpc": "2.0", "id": 1, "result": {"tools": ["t1"]}}

    async def _content():
        yield f"data: {json.dumps(payload)}\r\n".encode()
        yield b"\r\n"

    resp = MagicMock()
    resp.status = 200
    resp.content_type = "text/event-stream"
    resp.headers = {}
    resp.content = _content()
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=None)

    session = _make_session(resp)
    result, _ = await client._request(session, "tok", "tools/list")
    assert result == {"tools": ["t1"]}


# ---------------------------------------------------------------------------
# MCPClient.list_tools caching
# ---------------------------------------------------------------------------

async def test_list_tools_cache_hit():
    client = MCPClient()
    th = client._token_hash("tok")
    client._tools_cache[th] = [{"name": "cached_tool"}]
    client._tools_cache_time[th] = time.monotonic()

    # _ensure_session / _request should NOT be called
    with patch.object(client, "_request", new=AsyncMock()) as mock_req:
        result = await client.list_tools(MagicMock(), "tok")

    assert result == [{"name": "cached_tool"}]
    mock_req.assert_not_awaited()


async def test_list_tools_fetches_on_miss():
    client = MCPClient()
    tools = [{"name": "tool_a"}]

    async def fake_request(session, token, method, params=None):
        if method == "initialize":
            return {"protocolVersion": "2025-03-26"}, {}
        if method == "tools/list":
            return {"tools": tools}, {}
        return {}, {}

    with patch.object(client, "_request", new=fake_request):
        with patch.object(client, "_notify", new=AsyncMock()):
            result = await client.list_tools(MagicMock(), "tok")

    assert result == tools
    th = client._token_hash("tok")
    assert client._tools_cache[th] == tools


async def test_list_tools_cache_expires():
    client = MCPClient()
    th = client._token_hash("tok")
    client._tools_cache[th] = [{"name": "old_tool"}]
    client._tools_cache_time[th] = time.monotonic() - client._tools_cache_ttl - 1

    fresh_tools = [{"name": "fresh_tool"}]

    async def fake_request(session, token, method, params=None):
        if method == "tools/list":
            return {"tools": fresh_tools}, {}
        return {}, {}

    with patch.object(client, "_request", new=fake_request):
        with patch.object(client, "_notify", new=AsyncMock()):
            result = await client.list_tools(MagicMock(), "tok")

    assert result == fresh_tools


async def test_list_tools_fetch_failure_clears_cache():
    client = MCPClient()
    th = client._token_hash("tok")
    client._tools_cache[th] = [{"name": "stale"}]
    client._tools_cache_time[th] = time.monotonic() - client._tools_cache_ttl - 1
    client._sessions[th] = "sess"  # skip initialize

    async def fake_request(session, token, method, params=None):
        raise RuntimeError("network error")

    with patch.object(client, "_request", new=fake_request):
        with patch.object(client, "_notify", new=AsyncMock()):
            with pytest.raises(RuntimeError):
                await client.list_tools(MagicMock(), "tok")

    assert th not in client._tools_cache


# ---------------------------------------------------------------------------
# MCPClient.call_tool
# ---------------------------------------------------------------------------

async def test_call_tool_success():
    client = MCPClient()
    th = client._token_hash("tok")
    client._sessions[th] = "sess"

    async def fake_request(session, token, method, params=None):
        return {"content": [{"type": "text", "text": "created"}]}, {}

    with patch.object(client, "_request", new=fake_request):
        result = await client.call_tool(MagicMock(), "tok", "create_issue", {"title": "Bug"})

    assert result == {"content": [{"type": "text", "text": "created"}]}


async def test_call_tool_token_invalid_propagates():
    client = MCPClient()
    th = client._token_hash("tok")
    client._sessions[th] = "sess"

    async def fake_request(session, token, method, params=None):
        raise TokenInvalidError("expired")

    with patch.object(client, "_request", new=fake_request):
        with pytest.raises(TokenInvalidError):
            await client.call_tool(MagicMock(), "tok", "create_issue", {})


async def test_call_tool_generic_exception_retries():
    client = MCPClient()
    th = client._token_hash("tok")
    client._sessions[th] = "sess"

    call_count = {"n": 0}

    async def fake_request(session, token, method, params=None):
        if method == "initialize":
            return {}, {}
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("stale session")
        return {"content": []}, {}

    with patch.object(client, "_request", new=fake_request):
        with patch.object(client, "_notify", new=AsyncMock()):
            result = await client.call_tool(MagicMock(), "tok", "some_tool", {})

    assert result == {"content": []}
    assert call_count["n"] == 2  # failed once, succeeded on retry


async def test_call_tool_mcp_error_does_not_retry():
    """MCPError is re-raised immediately without retry."""
    client = MCPClient()
    th = client._token_hash("tok")
    client._sessions[th] = "sess"

    async def fake_request(session, token, method, params=None):
        raise MCPError("not found", code=404)

    with patch.object(client, "_request", new=fake_request):
        with pytest.raises(MCPError, match="not found"):
            await client.call_tool(MagicMock(), "tok", "some_tool", {})
