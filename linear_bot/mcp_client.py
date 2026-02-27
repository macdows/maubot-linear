from __future__ import annotations

import hashlib
import json
import logging
import time

import aiohttp

from . import __version__

log = logging.getLogger("maubot.linear.mcp")

MCP_URL = "https://mcp.linear.app/mcp"
GRAPHQL_URL = "https://api.linear.app/graphql"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=30)


class TokenInvalidError(Exception):
    pass


class MCPError(Exception):
    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class MCPClient:
    def __init__(self) -> None:
        self._sessions: dict[str, str] = {}  # token_hash -> session_id
        self._request_id = 0
        self._tools_cache: dict[str, list[dict]] = {}  # token_hash -> tools
        self._tools_cache_time: dict[str, float] = {}  # token_hash -> timestamp
        self._tools_cache_ttl = 3600  # 1 hour

    def _token_hash(self, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()[:16]

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    async def _request(
        self,
        session: aiohttp.ClientSession,
        token: str,
        method: str,
        params: dict | None = None,
    ) -> tuple[dict, dict]:
        """Send a JSON-RPC request and return (result, response_headers)."""
        th = self._token_hash(token)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        session_id = self._sessions.get(th)
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        body = {
            "jsonrpc": "2.0",
            "method": method,
            "id": self._next_id(),
        }
        if params is not None:
            body["params"] = params

        async with session.post(MCP_URL, json=body, headers=headers, timeout=REQUEST_TIMEOUT) as resp:
            if resp.status == 401:
                self._sessions.pop(th, None)
                raise TokenInvalidError("Linear token is invalid or expired")
            if resp.status >= 400:
                text = await resp.text()
                raise MCPError(f"MCP server returned {resp.status}: {text}", resp.status)

            resp_headers = dict(resp.headers)
            content_type = resp.content_type or ""

            if "text/event-stream" in content_type:
                data = await self._read_sse_response(resp)
            else:
                data = await resp.json()

            # Capture session ID from response
            new_session_id = resp.headers.get("Mcp-Session-Id")
            if new_session_id:
                self._sessions[th] = new_session_id

            if "error" in data:
                err = data["error"]
                raise MCPError(err.get("message", str(err)), err.get("code"))

            return data.get("result", {}), resp_headers

    @staticmethod
    async def _read_sse_response(resp: aiohttp.ClientResponse) -> dict:
        """Read an SSE stream and return the first JSON-RPC message."""
        data_buf = []
        async for raw_line in resp.content:
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            if line.startswith("data:"):
                data_buf.append(line[5:].strip())
            elif line == "" and data_buf:
                # Empty line = end of SSE event
                payload = "\n".join(data_buf)
                data_buf.clear()
                try:
                    msg = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                # Return first message that has an "id" (JSON-RPC response)
                if "id" in msg:
                    return msg
        if data_buf:
            try:
                return json.loads("\n".join(data_buf))
            except json.JSONDecodeError as e:
                raise MCPError(f"SSE stream ended with invalid JSON: {e}")
        raise MCPError("SSE stream ended without a JSON-RPC response")

    async def _notify(
        self,
        session: aiohttp.ClientSession,
        token: str,
        method: str,
        params: dict | None = None,
    ) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        th = self._token_hash(token)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        session_id = self._sessions.get(th)
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        body: dict = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            body["params"] = params

        async with session.post(MCP_URL, json=body, headers=headers, timeout=REQUEST_TIMEOUT) as resp:
            if resp.status >= 400:
                log.warning("MCP notification %s returned %d", method, resp.status)

    async def initialize(self, session: aiohttp.ClientSession, token: str) -> dict:
        """Initialize an MCP session. Must be called before other methods."""
        th = self._token_hash(token)
        self._sessions.pop(th, None)  # Clear any stale session

        result, _ = await self._request(session, token, "initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "maubot-linear", "version": __version__},
        })

        # MCP spec requires sending initialized notification after init response
        await self._notify(session, token, "notifications/initialized")

        log.debug("MCP session initialized for token %s", th)
        return result

    async def _ensure_session(self, session: aiohttp.ClientSession, token: str) -> None:
        """Ensure we have an active MCP session for this token."""
        th = self._token_hash(token)
        if th not in self._sessions:
            await self.initialize(session, token)

    async def list_tools(self, session: aiohttp.ClientSession, token: str) -> list[dict]:
        """Fetch available tools from Linear MCP. Cached per-token for 1 hour."""
        th = self._token_hash(token)
        now = time.monotonic()
        cached_time = self._tools_cache_time.get(th, 0)
        if th in self._tools_cache and (now - cached_time) < self._tools_cache_ttl:
            return self._tools_cache[th]

        await self._ensure_session(session, token)
        try:
            result, _ = await self._request(session, token, "tools/list")
        except TokenInvalidError:
            raise
        except Exception:
            self._tools_cache.pop(th, None)
            self._tools_cache_time.pop(th, None)
            raise

        tools = result.get("tools", [])
        self._tools_cache[th] = tools
        self._tools_cache_time[th] = now
        log.info("Cached %d MCP tools from Linear for token %s", len(tools), th)
        return tools

    async def call_tool(
        self,
        session: aiohttp.ClientSession,
        token: str,
        tool_name: str,
        arguments: dict,
    ) -> dict:
        """Call a tool on the Linear MCP server."""
        await self._ensure_session(session, token)
        try:
            result, _ = await self._request(session, token, "tools/call", {
                "name": tool_name,
                "arguments": arguments,
            })
        except TokenInvalidError:
            raise
        except MCPError:
            raise
        except Exception:
            # Session might be stale — re-initialize and retry once
            log.warning("MCP call_tool failed, retrying with fresh session")
            await self.initialize(session, token)
            result, _ = await self._request(session, token, "tools/call", {
                "name": tool_name,
                "arguments": arguments,
            })

        return result

    async def get_viewer(self, session: aiohttp.ClientSession, token: str) -> dict:
        """Fetch the authenticated user's identity from Linear's GraphQL API."""
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        async with session.post(
            GRAPHQL_URL,
            json={"query": "{ viewer { id name } }"},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        ) as resp:
            if resp.status == 401:
                raise TokenInvalidError("Linear token is invalid or expired")
            if resp.status >= 400:
                text = await resp.text()
                raise MCPError(f"Linear GraphQL returned {resp.status}: {text}", resp.status)
            data = await resp.json()
            viewer = data.get("data", {}).get("viewer") or {}
            return {"id": viewer.get("id"), "name": viewer.get("name")}
